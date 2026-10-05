//go:build linux && (amd64 || arm64)

package socket

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"

	"paqet/internal/conf"
	"paqet/internal/pkg/iterator"
)

func testSender(flags []conf.TCPF) *fastSender {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	gw, _ := net.ParseMAC("02:00:00:00:00:02")
	return &fastSender{
		srcMAC: mac, gwIPv4: gw, gwIPv6: gw,
		srcIPv4: net.ParseIP("10.0.0.1").To4(), srcIPv6: net.ParseIP("2001:db8::1"),
		srcPort: 27015, time: 123456789,
		tcpF: tcpF{tcpF: iterator.Iterator[conf.TCPF]{Items: flags}, clientTCPF: map[uint64]*iterator.Iterator[conf.TCPF]{}},
	}
}

// Frames we build must be byte-identical to gopacket re-serializing them with fresh checksums.
func TestBuildFrameMatchesGopacket(t *testing.T) {
	cases := []struct {
		name  string
		flags conf.TCPF
		dst   string
		size  int
	}{
		{"v4 PA even", conf.TCPF{PSH: true, ACK: true}, "203.0.113.7", 1350},
		{"v4 PA odd", conf.TCPF{PSH: true, ACK: true}, "203.0.113.7", 77},
		{"v4 S", conf.TCPF{SYN: true}, "203.0.113.7", 1350},
		{"v4 SA odd", conf.TCPF{SYN: true, ACK: true}, "203.0.113.7", 101},
		{"v6 PA", conf.TCPF{PSH: true, ACK: true}, "2001:db8::99", 1301},
		{"v6 SA", conf.TCPF{SYN: true, ACK: true}, "2001:db8::99", 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSender([]conf.TCPF{tc.flags})
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i*7 + 3)
			}
			buf := make([]byte, frameBufSize)
			n, _, err := s.buildFrame(buf, payload, &net.UDPAddr{IP: net.ParseIP(tc.dst), Port: 40000})
			if err != nil {
				t.Fatal(err)
			}
			frame := buf[:n]

			pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
			tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			if tcp == nil {
				t.Fatalf("not decodable as TCP: %v", pkt.ErrorLayer())
			}
			if !bytes.Equal(tcp.Payload, payload) {
				t.Fatal("payload mismatch")
			}
			if tcp.SYN != tc.flags.SYN || tcp.ACK != tc.flags.ACK || tcp.PSH != tc.flags.PSH {
				t.Fatalf("flags mismatch: %+v", tcp)
			}

			var netLayer gopacket.SerializableLayer
			if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
				ip4.Checksum = 0
				tcp.SetNetworkLayerForChecksum(ip4)
				netLayer = ip4
			} else {
				ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				tcp.SetNetworkLayerForChecksum(ip6)
				netLayer = ip6
			}
			tcp.Checksum = 0
			out := gopacket.NewSerializeBuffer()
			eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			if err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
				eth, netLayer, tcp, gopacket.Payload(payload)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), frame) {
				t.Fatalf("frame differs from gopacket re-serialization\nours: %x\nref:  %x", frame[:80], out.Bytes()[:80])
			}
		})
	}
}

// The receive parser must recover payload and source from frames the sender builds.
func TestParseRoundTrip(t *testing.T) {
	s := testSender([]conf.TCPF{{PSH: true, ACK: true}})
	r := &fastReceiver{port: 40000}
	for _, dst := range []string{"203.0.113.7", "2001:db8::99"} {
		payload := []byte("hello paqet fast path")
		buf := make([]byte, frameBufSize)
		n, _, err := s.buildFrame(buf, payload, &net.UDPAddr{IP: net.ParseIP(dst), Port: 40000})
		if err != nil {
			t.Fatal(err)
		}
		m := ipv4.Message{Buffers: [][]byte{make([]byte, 1500)}}
		if !r.parse(buf[:n], &m) {
			t.Fatalf("%s: parse rejected our own frame", dst)
		}
		a := m.Addr.(*net.UDPAddr)
		want := s.srcIPv4
		if net.ParseIP(dst).To4() == nil {
			want = s.srcIPv6
		}
		if !bytes.Equal(m.Buffers[0][:m.N], payload) || !a.IP.Equal(want) || a.Port != 27015 {
			t.Fatalf("%s: got %q from %v", dst, m.Buffers[0][:m.N], a)
		}
		// wrong destination port must be ignored
		if (&fastReceiver{port: 1}).parse(buf[:n], &m) {
			t.Fatalf("%s: accepted frame for another port", dst)
		}
	}
}
