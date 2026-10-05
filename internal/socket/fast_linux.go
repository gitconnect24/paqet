//go:build linux && (amd64 || arm64)

package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"paqet/internal/conf"
	"paqet/internal/pkg/iterator"
)

// Fast Linux packet IO: raw AF_PACKET sockets with sendmmsg/recvmmsg batching and
// hand-built headers, replacing per-packet pcap_sendpacket + gopacket serialization.

const (
	packetIgnoreOutgoing = 23 // PACKET_IGNORE_OUTGOING (Linux 4.20+)
	maxBatch             = 256
	frameBufSize         = 2048
	recvPollTimeout      = 100 * time.Millisecond
	enobufsRetries       = 20
)

type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func fastIODisabled() bool { return os.Getenv("PAQET_IO") == "pcap" }

// ---------------------------------------------------------------- send

type fastSender struct {
	fd       int
	mu       sync.RWMutex // held (R) during syscalls so Close can't race fd reuse
	closed   atomic.Bool
	srcMAC   net.HardwareAddr
	srcIPv4  net.IP
	gwIPv4   net.HardwareAddr
	srcIPv6  net.IP
	gwIPv6   net.HardwareAddr
	srcPort  uint16
	time     uint32
	counter  atomic.Uint32
	tcpF     tcpF
	sa4, sa6 unix.RawSockaddrLinklayer
	pool     sync.Pool
	dropped  atomic.Uint64
}

type sendBatch struct {
	frames [maxBatch][]byte
	iov    [maxBatch]unix.Iovec
	hdrs   [maxBatch]mmsghdr
}

func newFastSender(cfg *conf.Network) (*fastSender, error) {
	// protocol 0: this socket never receives, it only injects frames
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("af_packet send socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: cfg.Interface.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind send socket to %s: %w", cfg.Interface.Name, err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, 8<<20)

	s := &fastSender{
		fd:      fd,
		srcMAC:  cfg.Interface.HardwareAddr,
		srcPort: uint16(cfg.Port),
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		tcpF:    tcpF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
	}
	if cfg.IPv4.Addr != nil {
		s.srcIPv4 = cfg.IPv4.Addr.IP.To4()
		s.gwIPv4 = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		s.srcIPv6 = cfg.IPv6.Addr.IP.To16()
		s.gwIPv6 = cfg.IPv6.Router
	}
	for _, sa := range []struct {
		dst   *unix.RawSockaddrLinklayer
		proto uint16
	}{{&s.sa4, unix.ETH_P_IP}, {&s.sa6, unix.ETH_P_IPV6}} {
		sa.dst.Family = unix.AF_PACKET
		sa.dst.Protocol = htons(sa.proto)
		sa.dst.Ifindex = int32(cfg.Interface.Index)
		sa.dst.Halen = 6
	}
	s.pool.New = func() any {
		b := &sendBatch{}
		for i := range b.frames {
			b.frames[i] = make([]byte, frameBufSize)
		}
		return b
	}
	return s, nil
}

// buildFrame writes Ethernet+IP+TCP headers and payload into buf, returning the frame length
// and the link-layer address to send to. Header fields match the former gopacket encoder.
func (s *fastSender) buildFrame(buf, payload []byte, dst *net.UDPAddr) (int, *unix.RawSockaddrLinklayer, error) {
	f := s.tcpF.next(dst.IP, uint16(dst.Port))
	counter := s.counter.Add(1)
	tsVal := s.time + (counter >> 3)

	var optLen int
	if f.SYN {
		optLen = 20 // MSS(4) SACKPerm(2) TS(10) NOP(1) WS(3)
	} else {
		optLen = 12 // NOP NOP TS(10)
	}
	tcpLen := 20 + optLen

	dst4 := dst.IP.To4()
	var ipLen int
	var gw net.HardwareAddr
	var sa *unix.RawSockaddrLinklayer
	if dst4 != nil {
		if s.srcIPv4 == nil {
			return 0, nil, errors.New("no IPv4 source address configured")
		}
		ipLen, gw, sa = 20, s.gwIPv4, &s.sa4
	} else {
		if s.srcIPv6 == nil {
			return 0, nil, errors.New("no IPv6 source address configured")
		}
		ipLen, gw, sa = 40, s.gwIPv6, &s.sa6
	}
	total := 14 + ipLen + tcpLen + len(payload)
	if total > len(buf) {
		return 0, nil, fmt.Errorf("packet too large: %d bytes", total)
	}

	// Ethernet
	copy(buf[0:6], gw)
	copy(buf[6:12], s.srcMAC)
	ip := buf[14 : 14+ipLen]
	tcp := buf[14+ipLen : 14+ipLen+tcpLen]
	copy(buf[14+ipLen+tcpLen:], payload)
	segLen := tcpLen + len(payload)

	// TCP header
	binary.BigEndian.PutUint16(tcp[0:2], s.srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dst.Port))
	var seq, ack uint32
	if f.SYN {
		seq = 1 + (counter & 0x7)
		if f.ACK {
			ack = seq + 1
		}
	} else {
		seq = s.time + (counter << 7)
		ack = seq - (counter & 0x3FF) + 1400
	}
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte(tcpLen/4) << 4
	if f.NS {
		tcp[12] |= 1
	}
	var flags byte
	for _, b := range []struct {
		on  bool
		bit byte
	}{{f.FIN, 0x01}, {f.SYN, 0x02}, {f.RST, 0x04}, {f.PSH, 0x08}, {f.ACK, 0x10}, {f.URG, 0x20}, {f.ECE, 0x40}, {f.CWR, 0x80}} {
		if b.on {
			flags |= b.bit
		}
	}
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[16], tcp[17], tcp[18], tcp[19] = 0, 0, 0, 0 // checksum, urgent
	o := tcp[20:]
	if f.SYN {
		o[0], o[1], o[2], o[3] = 2, 4, 0x05, 0xb4 // MSS 1460
		o[4], o[5] = 4, 2                         // SACK permitted
		o[6], o[7] = 8, 10                        // timestamps
		binary.BigEndian.PutUint32(o[8:12], tsVal)
		binary.BigEndian.PutUint32(o[12:16], 0)
		o[16] = 1                     // NOP
		o[17], o[18], o[19] = 3, 3, 8 // window scale
	} else {
		o[0], o[1] = 1, 1 // NOP NOP
		o[2], o[3] = 8, 10
		binary.BigEndian.PutUint32(o[4:8], tsVal)
		binary.BigEndian.PutUint32(o[8:12], tsVal-(counter%200+50))
	}

	// IP header + TCP checksum (pseudo-header)
	var sum uint64
	if dst4 != nil {
		binary.BigEndian.PutUint16(buf[12:14], 0x0800)
		ip[0], ip[1] = 0x45, 184
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+segLen))
		ip[4], ip[5], ip[6], ip[7] = 0, 0, 0x40, 0 // id 0, DF
		ip[8], ip[9] = 64, 6
		ip[10], ip[11] = 0, 0
		copy(ip[12:16], s.srcIPv4)
		copy(ip[16:20], dst4)
		binary.BigEndian.PutUint16(ip[10:12], checksum(sumBytes(0, ip)))
		sum = sumBytes(0, ip[12:20])
	} else {
		binary.BigEndian.PutUint16(buf[12:14], 0x86dd)
		ip[0], ip[1], ip[2], ip[3] = 0x6b, 0x80, 0, 0 // version 6, traffic class 184
		binary.BigEndian.PutUint16(ip[4:6], uint16(segLen))
		ip[6], ip[7] = 6, 64
		copy(ip[8:24], s.srcIPv6)
		copy(ip[24:40], dst.IP.To16())
		sum = sumBytes(0, ip[8:40])
	}
	sum += 6 + uint64(segLen)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(sumBytes(sum, buf[14+ipLen:total])))
	return total, sa, nil
}

func (s *fastSender) writeBatch(ms []ipv4.Message) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	b := s.pool.Get().(*sendBatch)
	defer s.pool.Put(b)

	sent := 0
	for len(ms) > 0 {
		n := min(len(ms), maxBatch)
		k := 0
		for i := 0; i < n; i++ {
			addr, ok := ms[i].Addr.(*net.UDPAddr)
			if !ok {
				return sent, net.InvalidAddrError("invalid address")
			}
			fl, sa, err := s.buildFrame(b.frames[k], ms[i].Buffers[0], addr)
			if err != nil {
				return sent, err
			}
			b.iov[k].Base = &b.frames[k][0]
			b.iov[k].SetLen(fl)
			h := &b.hdrs[k].hdr
			*h = unix.Msghdr{Name: (*byte)(unsafe.Pointer(sa)), Namelen: uint32(unsafe.Sizeof(*sa)), Iov: &b.iov[k]}
			h.SetIovlen(1)
			k++
		}
		if err := s.sendmmsg(b.hdrs[:k]); err != nil {
			return sent, err
		}
		sent += n
		ms = ms[n:]
	}
	return sent, nil
}

// sendmmsg pushes all frames; on a full qdisc/driver queue (ENOBUFS) it backs off briefly
// and finally drops the remainder rather than failing the KCP session (KCP retransmits).
func (s *fastSender) sendmmsg(hdrs []mmsghdr) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	retries := 0
	for len(hdrs) > 0 {
		r, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(s.fd), uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), 0, 0, 0)
		switch {
		case errno == 0:
			hdrs = hdrs[int(r):]
			retries = 0
		case errno == unix.EINTR:
		case errno == unix.ENOBUFS || errno == unix.EAGAIN:
			if retries++; retries > enobufsRetries {
				s.dropped.Add(uint64(len(hdrs)))
				return nil
			}
			time.Sleep(time.Duration(retries) * 100 * time.Microsecond)
		default:
			return os.NewSyscallError("sendmmsg", errno)
		}
	}
	return nil
}

func (s *fastSender) close() {
	if s.closed.Swap(true) {
		return
	}
	s.mu.Lock()
	unix.Close(s.fd)
	s.mu.Unlock()
}

// ---------------------------------------------------------------- receive

type fastReceiver struct {
	fd     int
	port   uint16
	mu     sync.RWMutex
	closed atomic.Bool

	rmu    sync.Mutex // one reader at a time owns the frame buffers
	frames [maxBatch][]byte
	iov    [maxBatch]unix.Iovec
	hdrs   [maxBatch]mmsghdr

	last *net.UDPAddr // reused while the source stays the same, avoiding per-packet allocs
}

func newFastReceiver(cfg *conf.Network) (*fastReceiver, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("af_packet recv socket: %w", err)
	}
	fail := func(e error) (*fastReceiver, error) { unix.Close(fd); return nil, e }

	ins, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, fmt.Sprintf("tcp and dst port %d", cfg.Port))
	if err != nil {
		return fail(fmt.Errorf("compile BPF filter: %w", err))
	}
	filter := make([]unix.SockFilter, len(ins))
	for i, in := range ins {
		filter[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		return fail(fmt.Errorf("attach BPF filter: %w", err))
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, packetIgnoreOutgoing, 1)
	if cfg.PCAP.Sockbuf > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, cfg.PCAP.Sockbuf)
	}
	tv := unix.NsecToTimeval(recvPollTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail(fmt.Errorf("set receive timeout: %w", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: cfg.Interface.Index}); err != nil {
		return fail(fmt.Errorf("bind recv socket to %s: %w", cfg.Interface.Name, err))
	}

	r := &fastReceiver{fd: fd, port: uint16(cfg.Port)}
	for i := range r.frames {
		r.frames[i] = make([]byte, frameBufSize)
		r.iov[i].Base = &r.frames[i][0]
		r.iov[i].SetLen(frameBufSize)
		r.hdrs[i].hdr.Iov = &r.iov[i]
		r.hdrs[i].hdr.SetIovlen(1)
	}
	return r, nil
}

// readBatch fills ms with TCP payloads addressed to our port. It blocks until at least one
// valid packet arrives, the deadline passes, or the receiver is closed.
func (r *fastReceiver) readBatch(ms []ipv4.Message, deadline func() bool) (int, error) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	for {
		if deadline() {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := r.recvmmsg(min(len(ms), maxBatch))
		if err != nil {
			return 0, err
		}
		got := 0
		for i := 0; i < n; i++ {
			if r.hdrs[i].hdr.Flags&unix.MSG_TRUNC != 0 {
				continue
			}
			if r.parse(r.frames[i][:r.hdrs[i].len], &ms[got]) {
				got++
			}
		}
		if got > 0 {
			return got, nil
		}
	}
}

func (r *fastReceiver) recvmmsg(n int) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for {
		if r.closed.Load() {
			return 0, net.ErrClosed
		}
		cnt, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(r.fd), uintptr(unsafe.Pointer(&r.hdrs[0])), uintptr(n), unix.MSG_WAITFORONE, 0, 0)
		switch errno {
		case 0:
			return int(cnt), nil
		case unix.EAGAIN, unix.EINTR: // poll timeout: re-check closed/deadline
			return 0, nil
		default:
			return 0, os.NewSyscallError("recvmmsg", errno)
		}
	}
}

// parse extracts the TCP payload and source address from an Ethernet frame.
func (r *fastReceiver) parse(f []byte, m *ipv4.Message) bool {
	if len(f) < 14 {
		return false
	}
	et := binary.BigEndian.Uint16(f[12:14])
	p := f[14:]
	var srcIP []byte
	var seg []byte
	switch et {
	case 0x0800:
		if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
			return false
		}
		ihl := int(p[0]&0x0f) * 4
		tot := int(binary.BigEndian.Uint16(p[2:4]))
		if ihl < 20 || tot < ihl || tot > len(p) || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return false
		}
		srcIP, seg = p[12:16], p[ihl:tot]
	case 0x86dd:
		if len(p) < 40 || p[0]>>4 != 6 || p[6] != 6 {
			return false
		}
		pl := int(binary.BigEndian.Uint16(p[4:6]))
		if 40+pl > len(p) {
			return false
		}
		srcIP, seg = p[8:24], p[40:40+pl]
	default:
		return false
	}
	if len(seg) < 20 || binary.BigEndian.Uint16(seg[2:4]) != r.port {
		return false
	}
	off := int(seg[12]>>4) * 4
	if off < 20 || off >= len(seg) {
		return false // no payload
	}
	payload := seg[off:]
	buf := m.Buffers[0]
	if len(payload) > len(buf) {
		return false
	}
	m.N = copy(buf, payload)

	sport := int(binary.BigEndian.Uint16(seg[0:2]))
	if l := r.last; l != nil && l.Port == sport && net.IP(srcIP).Equal(l.IP) {
		m.Addr = l
	} else {
		a := &net.UDPAddr{IP: append(net.IP(nil), srcIP...), Port: sport}
		r.last, m.Addr = a, a
	}
	return true
}

func (r *fastReceiver) close() {
	if r.closed.Swap(true) {
		return
	}
	r.mu.Lock() // waits for an in-flight recvmmsg (bounded by recvPollTimeout)
	unix.Close(r.fd)
	r.mu.Unlock()
}

// ---------------------------------------------------------------- checksum

func sumBytes(sum uint64, b []byte) uint64 {
	for len(b) >= 8 {
		sum += uint64(binary.BigEndian.Uint32(b[0:4])) + uint64(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
	}
	if len(b) >= 4 {
		sum += uint64(binary.BigEndian.Uint32(b[0:4]))
		b = b[4:]
	}
	if len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b[0:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	return sum
}

func checksum(sum uint64) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
