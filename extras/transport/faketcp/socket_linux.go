//go:build linux

package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rawSocket uses Go's network poller, so deadlines and Close interrupt an
// already blocked syscall. It intentionally does not expose SyscallConn to
// QUIC: that would enable UDP-specific offload and bypass our framing.
type rawSocket struct {
	conn        *net.IPConn
	raw         syscall.RawConn
	local       netip.AddrPort
	reservation int
	closeOnce   sync.Once
	closeErr    error
	oob         [128]byte // single reader, serialized by conn.readMu
}

type rawWriter struct {
	socket *rawSocket
	addr   unix.Sockaddr
	oob    []byte // immutable per-peer source-IP selection
}

func socketAddress(addr netip.AddrPort) (unix.Sockaddr, error) {
	if addr.Addr().Is4() {
		return &unix.SockaddrInet4{Port: int(addr.Port()), Addr: addr.Addr().As4()}, nil
	}
	var zone uint32
	if z := addr.Addr().Zone(); z != "" {
		n, err := strconv.ParseUint(z, 10, 32)
		if err == nil {
			zone = uint32(n)
		} else {
			iface, err := net.InterfaceByName(z)
			if err != nil {
				return nil, err
			}
			zone = uint32(iface.Index)
		}
	}
	return &unix.SockaddrInet6{Port: int(addr.Port()), Addr: addr.Addr().As16(), ZoneId: zone}, nil
}

func openSocket(local netip.AddrPort) (_ packetIO, err error) {
	family, network := unix.AF_INET, "ip4:tcp"
	if local.Addr().Is6() {
		family, network = unix.AF_INET6, "ip6:tcp"
	}
	// Reserve a TCP port without listening or connecting. Kernel TCP responses
	// are suppressed by the deployment's scoped OUTPUT RST rule, not this fd.
	guard, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("reserve TCP port: %w", err)
	}
	defer func() {
		if err != nil {
			_ = unix.Close(guard)
		}
	}()
	if family == unix.AF_INET6 {
		if err = unix.SetsockoptInt(guard, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return nil, err
		}
	}
	sa, err := socketAddress(local)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(guard, sa); err != nil {
		return nil, fmt.Errorf("reserve TCP port: %w", err)
	}
	bound, err := unix.Getsockname(guard)
	if err != nil {
		return nil, err
	}
	var port int
	switch a := bound.(type) {
	case *unix.SockaddrInet4:
		port = a.Port
	case *unix.SockaddrInet6:
		port = a.Port
	}
	local = netip.AddrPortFrom(local.Addr(), uint16(port))
	ipconn, err := net.ListenIP(network, &net.IPAddr{IP: net.IP(local.Addr().AsSlice()), Zone: local.Addr().Zone()})
	if err != nil {
		return nil, fmt.Errorf("open raw TCP socket (CAP_NET_RAW required): %w", err)
	}
	defer func() {
		if err != nil {
			_ = ipconn.Close()
		}
	}()
	raw, err := ipconn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var setupErr error
	err = raw.Control(func(fd uintptr) { setupErr = configureSocket(int(fd), family, local.Port()) })
	if err != nil {
		return nil, err
	}
	if setupErr != nil {
		return nil, setupErr
	}
	return &rawSocket{conn: ipconn, raw: raw, local: local, reservation: guard}, nil
}

func configureSocket(fd, family int, port uint16) error {
	if family == unix.AF_INET {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return err
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO); err != nil {
			return err
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return err
		}
	}
	// Filter in the kernel before packets enter our receive queue. IPv4 raw
	// receives include the variable-length IP header; IPv6 starts at TCP.
	var filter []unix.SockFilter
	if family == unix.AF_INET {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(port), Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		}
	} else {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 2},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(port), Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
}

func (s *rawSocket) ReadPacket(b []byte) ([]byte, netip.Addr, netip.Addr, error) {
	for {
		var n, oobn, flags int
		var from unix.Sockaddr
		var recvErr error
		err := s.raw.Read(func(fd uintptr) bool {
			for {
				n, oobn, flags, from, recvErr = unix.Recvmsg(int(fd), b, s.oob[:], unix.MSG_DONTWAIT)
				if recvErr == unix.EINTR {
					continue
				}
				return recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK
			}
		})
		if err != nil {
			return nil, netip.Addr{}, netip.Addr{}, err
		}
		if recvErr != nil {
			return nil, netip.Addr{}, netip.Addr{}, recvErr
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		if s.local.Addr().Is4() {
			if n < 20 || b[0]>>4 != 4 {
				continue
			}
			h := int(b[0]&15) * 4
			size := int(binary.BigEndian.Uint16(b[2:4]))
			if h < 20 || h > n || size < h || size > n || b[9] != unix.IPPROTO_TCP {
				continue
			}
			src := netip.AddrFrom4([4]byte(b[12:16]))
			dst := netip.AddrFrom4([4]byte(b[16:20]))
			return b[h:size], src, dst, nil
		}
		source, ok := from.(*unix.SockaddrInet6)
		if !ok {
			continue
		}
		src := netip.AddrFrom16(source.Addr)
		var dst netip.Addr
		zone := source.ZoneId
		msgs, err := unix.ParseSocketControlMessage(s.oob[:oobn])
		if err != nil {
			continue
		}
		for _, msg := range msgs {
			if msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_PKTINFO && len(msg.Data) >= 20 {
				dst = netip.AddrFrom16([16]byte(msg.Data[:16]))
				zone = binary.NativeEndian.Uint32(msg.Data[16:20])
				if dst.IsLinkLocalUnicast() {
					dst = dst.WithZone(strconv.FormatUint(uint64(binary.NativeEndian.Uint32(msg.Data[16:20])), 10))
				}
			}
		}
		if !dst.IsValid() {
			continue
		}
		if src.IsLinkLocalUnicast() {
			src = src.WithZone(strconv.FormatUint(uint64(zone), 10))
		}
		return b[:n], src, dst, nil
	}
}

func (s *rawSocket) Writer(local, remote netip.AddrPort) (packetWriter, error) {
	// The raw destination sockaddr carries no transport port; it is in the
	// TCP header. IP_PKTINFO makes replies use the exact destination of SYN.
	sa, err := socketAddress(netip.AddrPortFrom(remote.Addr(), 0))
	if err != nil {
		return nil, err
	}
	var oob []byte
	if local.Addr().Is4() {
		oob = make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		h.Level, h.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
		info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
		info.Spec_dst = local.Addr().As4()
	} else {
		oob = make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		h.Level, h.Type = unix.IPPROTO_IPV6, unix.IPV6_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
		info.Addr = local.Addr().As16()
		if v6, ok := sa.(*unix.SockaddrInet6); ok {
			info.Ifindex = v6.ZoneId
		}
	}
	return &rawWriter{socket: s, addr: sa, oob: oob}, nil
}

func (w *rawWriter) WritePacket(b []byte) error {
	var sendErr error
	err := w.socket.raw.Write(func(fd uintptr) bool {
		for {
			n, err := unix.SendmsgN(int(fd), b, w.oob, w.addr, unix.MSG_DONTWAIT)
			sendErr = err
			if err == unix.EINTR {
				continue
			}
			if err == nil && n != len(b) {
				sendErr = errors.New("short raw TCP write")
			}
			return err != unix.EAGAIN && err != unix.EWOULDBLOCK
		}
	})
	if err != nil {
		return err
	}
	return sendErr
}

func (s *rawSocket) Close() error {
	s.closeOnce.Do(func() { s.closeErr = errors.Join(s.conn.Close(), unix.Close(s.reservation)) })
	return s.closeErr
}
func (s *rawSocket) LocalAddr() netip.AddrPort          { return s.local }
func (s *rawSocket) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *rawSocket) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *rawSocket) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
func (s *rawSocket) SetReadBuffer(n int) error          { return s.conn.SetReadBuffer(n) }
func (s *rawSocket) SetWriteBuffer(n int) error         { return s.conn.SetWriteBuffer(n) }
