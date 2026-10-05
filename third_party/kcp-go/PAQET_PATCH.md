# Vendored kcp-go v5.6.72 (patched for paqet)

Upstream: https://github.com/xtaci/kcp-go (tag v5.6.72), MIT licensed.

Single change, in `platform_linux.go` (`newBatchConn`): a `net.PacketConn` that implements
`WriteBatch`/`ReadBatch` itself is used directly for batch IO. Upstream only enables
`sendmmsg`/`recvmmsg` batching for real `*net.UDPConn`s, which left paqet's raw-packet
socket on the one-packet-per-syscall path.

To update: copy the new upstream tag here, re-apply the 4-line change, drop `*_test.go`.
