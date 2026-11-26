//go:build linux

package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests carry synthetic IPv4/TCP packets over Unix datagram sockets to
// exercise the real recvmsg and Go poller. They check BIG TCP's zero tot_len
// representation and truncation handling, not TCP GRO or hardware offload.
func newIPv4ReadTestSocket(t *testing.T) (*rawSocket, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	file := os.NewFile(uintptr(fds[0]), "faketcp-read-test")
	c, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	raw, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The kernel may clamp this to wmem_max. Only the optional 512 KiB case
	// depends on a larger per-socket limit; no global setting is changed.
	if err := unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_SNDBUF, 2*maxReceivePacketLen); err != nil {
		t.Fatal(err)
	}
	return &rawSocket{raw: raw, local: netip.MustParseAddrPort("192.0.2.2:6666")}, fds[1]
}

func ipv4ReadTestPacket(size int) []byte {
	b := make([]byte, size)
	b[0], b[9] = 0x45, unix.IPPROTO_TCP
	if size <= maxPacketLen {
		binary.BigEndian.PutUint16(b[2:4], uint16(size))
	}
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(b[20:22], 7001)
	binary.BigEndian.PutUint16(b[22:24], 6666)
	b[32], b[33] = 5<<4, flagACK
	for i := 40; i < len(b); i++ {
		b[i] = byte(i * 31)
	}
	return b
}

func sendIPv4ReadTestPacket(t *testing.T, fd int, b []byte) {
	t.Helper()
	if n, err := unix.SendmsgN(fd, b, nil, nil, unix.MSG_DONTWAIT); err != nil || n != len(b) {
		t.Fatalf("send test packet: n=%d want=%d err=%v", n, len(b), err)
	}
}

func checkIPv4ReadTestPacket(t *testing.T, s *rawSocket, buf, want []byte) {
	t.Helper()
	got, src, dst, err := s.ReadPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TCP payload differs: got %d bytes, want %d", len(got), len(want))
	}
	if src != netip.MustParseAddr("192.0.2.1") || dst != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("wrong IPv4 endpoints: %s -> %s", src, dst)
	}
}

func TestIPv4ReadPacketSizes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		size     int
		optional bool
	}{
		{"ordinary", 1500, false},
		{"max_ipv4_length", maxPacketLen, false},
		{"big_tcp_70k", 70 * 1024, false},
		{"receive_limit", maxReceivePacketLen, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fd := newIPv4ReadTestSocket(t)
			packet := ipv4ReadTestPacket(tc.size)
			n, err := unix.SendmsgN(fd, packet, nil, nil, unix.MSG_DONTWAIT)
			if tc.optional && errors.Is(err, unix.EMSGSIZE) {
				sndbuf, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
				t.Skipf("Unix datagram size exceeds SO_SNDBUF=%d; 70 KiB is covered separately", sndbuf)
			}
			if err != nil || n != len(packet) {
				t.Fatalf("send test packet: n=%d want=%d err=%v", n, len(packet), err)
			}
			checkIPv4ReadTestPacket(t, s, make([]byte, maxReceivePacketLen), packet[20:])
		})
	}
}

func TestIPv4ReadPacketSkipsMalformedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func([]byte) []byte
	}{
		{"short_header", func(b []byte) []byte { return b[:19] }},
		{"wrong_version", func(b []byte) []byte { b[0] = 0x65; return b }},
		{"short_ihl", func(b []byte) []byte { b[0] = 0x44; return b }},
		{"long_ihl", func(b []byte) []byte { b[0] = 0x4f; return b[:40] }},
		{"short_total_length", func(b []byte) []byte { binary.BigEndian.PutUint16(b[2:4], 19); return b }},
		{"long_total_length", func(b []byte) []byte { binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+1)); return b }},
		{"zero_total_length", func(b []byte) []byte { clear(b[2:4]); return b }},
		{"wrong_protocol", func(b []byte) []byte { b[9] = unix.IPPROTO_UDP; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fd := newIPv4ReadTestSocket(t)
			sendIPv4ReadTestPacket(t, fd, tc.bad(ipv4ReadTestPacket(80)))
			valid := ipv4ReadTestPacket(60)
			sendIPv4ReadTestPacket(t, fd, valid)
			checkIPv4ReadTestPacket(t, s, make([]byte, 128), valid[20:])
		})
	}
}

func TestIPv4ReadPacketSkipsTruncatedDatagram(t *testing.T) {
	s, fd := newIPv4ReadTestSocket(t)
	sendIPv4ReadTestPacket(t, fd, ipv4ReadTestPacket(256))
	valid := ipv4ReadTestPacket(60)
	sendIPv4ReadTestPacket(t, fd, valid)
	// recvmsg must report MSG_TRUNC for the first datagram. Its partial TCP
	// payload must not escape as a complete packet or consume the next one.
	checkIPv4ReadTestPacket(t, s, make([]byte, 64), valid[20:])
}
