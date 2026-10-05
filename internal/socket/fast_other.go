//go:build !(linux && (amd64 || arm64))

package socket

import (
	"errors"

	"golang.org/x/net/ipv4"

	"paqet/internal/conf"
)

// The AF_PACKET fast path is Linux-only; other platforms always use pcap.

var errFastUnsupported = errors.New("fast packet IO not supported on this platform")

type fastSender struct{ tcpF tcpF }

type fastReceiver struct{}

func fastIODisabled() bool { return true }

func newFastSender(*conf.Network) (*fastSender, error) { return nil, errFastUnsupported }

func newFastReceiver(*conf.Network) (*fastReceiver, error) { return nil, errFastUnsupported }

func (*fastSender) writeBatch([]ipv4.Message) (int, error) { return 0, errFastUnsupported }

func (*fastSender) close() {}

func (*fastReceiver) readBatch([]ipv4.Message, func() bool) (int, error) {
	return 0, errFastUnsupported
}

func (*fastReceiver) close() {}
