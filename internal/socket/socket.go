package socket

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/ipv4"

	"paqet/internal/conf"
	"paqet/internal/flog"
)

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	fast          *fastSender // Linux AF_PACKET fast path; nil when using pcap
	fastRecv      *fastReceiver
	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

func New(cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	if !fastIODisabled() {
		if conn, err := newFast(cfg); err == nil {
			return conn, nil
		} else {
			flog.Warnf("fast packet IO unavailable, falling back to pcap: %v", err)
		}
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		sendHandle.Close()
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	conn := &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
	}

	return conn, nil
}

func newFast(cfg *conf.Network) (*PacketConn, error) {
	fs, err := newFastSender(cfg)
	if err != nil {
		return nil, err
	}
	fr, err := newFastReceiver(cfg)
	if err != nil {
		fs.close()
		return nil, err
	}
	return &PacketConn{cfg: cfg, fast: fs, fastRecv: fr}, nil
}

func (c *PacketConn) readDeadlinePassed() bool {
	d, ok := c.readDeadline.Load().(time.Time)
	return ok && !d.IsZero() && !time.Now().Before(d)
}

// ReadBatch and WriteBatch let kcp-go move many packets per syscall (recvmmsg/sendmmsg).
func (c *PacketConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	if c.fastRecv != nil {
		return c.fastRecv.readBatch(ms, c.readDeadlinePassed)
	}
	n, addr, err := c.ReadFrom(ms[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	ms[0].N, ms[0].Addr = n, addr
	return 1, nil
}

func (c *PacketConn) WriteBatch(ms []ipv4.Message, _ int) (int, error) {
	if c.fast != nil {
		if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
			return 0, os.ErrDeadlineExceeded
		}
		return c.fast.writeBatch(ms)
	}
	for i := range ms {
		if _, err := c.WriteTo(ms[i].Buffers[0], ms[i].Addr); err != nil {
			return i, err
		}
	}
	return len(ms), nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	if c.fastRecv != nil {
		ms := []ipv4.Message{{Buffers: [][]byte{data}}}
		if _, err := c.fastRecv.readBatch(ms, c.readDeadlinePassed); err != nil {
			return 0, nil, err
		}
		return ms[0].N, ms[0].Addr, nil
	}
	for {
		if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
			return 0, nil, os.ErrDeadlineExceeded
		}

		n, addr, err := c.recvHandle.Read(data)
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) || errors.Is(err, errNoPayload) {
				continue
			}
			return 0, nil, err
		}

		return n, addr, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() && !time.Now().Before(d) {
		return 0, os.ErrDeadlineExceeded
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	if c.fast != nil {
		if _, err := c.fast.writeBatch([]ipv4.Message{{Buffers: [][]byte{data}, Addr: daddr}}); err != nil {
			return 0, err
		}
		return len(data), nil
	}

	err = c.sendHandle.Write(data, daddr)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	if c.fast != nil {
		c.fast.close()
	}
	if c.fastRecv != nil {
		c.fastRecv.close()
	}
	if c.sendHandle != nil {
		c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		c.recvHandle.Close()
	}
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
	// return &net.UDPAddr{
	// 	IP:   append([]byte(nil), c.cfg.PrimaryAddr().IP...),
	// 	Port: c.cfg.PrimaryAddr().Port,
	// 	Zone: c.cfg.PrimaryAddr().Zone,
	// }
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	if c.fast != nil {
		c.fast.tcpF.set(addr, f)
		return
	}
	c.sendHandle.setClientTCPF(addr, f)
}

func (c *PacketConn) DeleteClientTCPF(addr net.Addr) {
	if c.fast != nil {
		c.fast.tcpF.delete(addr)
		return
	}
	c.sendHandle.deleteClientTCPF(addr)
}
