package faketcp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// simNetwork transports actual encoded TCP segments, with an explicit fault
// injector. It tests the complete production state machine without claiming
// to test the kernel Raw Socket path. No state-machine methods are mocked.
type simNetwork struct {
	mu       sync.Mutex
	sockets  map[netip.AddrPort]*simSocket
	filter   func(netip.AddrPort, netip.AddrPort, []byte) [][]byte
	failNext error
	mtu      int
}
type simPacket struct {
	src, dst netip.Addr
	data     []byte
}
type simSocket struct {
	network                     *simNetwork
	addr                        netip.AddrPort
	queue                       chan simPacket
	done                        chan struct{}
	once                        sync.Once
	deadlineMu                  sync.Mutex
	readDeadline, writeDeadline time.Time
	changed                     chan struct{}
}
type simWriter struct {
	socket        *simSocket
	local, remote netip.AddrPort
}

func newSimNetwork() *simNetwork { return &simNetwork{sockets: make(map[netip.AddrPort]*simSocket)} }

func (n *simNetwork) socket(addr netip.AddrPort) *simSocket {
	s := &simSocket{network: n, addr: addr, queue: make(chan simPacket, 4096), done: make(chan struct{}), changed: make(chan struct{})}
	n.mu.Lock()
	n.sockets[addr] = s
	n.mu.Unlock()
	return s
}

func (s *simSocket) ReadPacket(b []byte) ([]byte, netip.Addr, netip.Addr, error) {
	for {
		s.deadlineMu.Lock()
		deadline, changed := s.readDeadline, s.changed
		s.deadlineMu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return nil, netip.Addr{}, netip.Addr{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case p := <-s.queue:
			if timer != nil {
				timer.Stop()
			}
			size := copy(b, p.data)
			return b[:size], p.src, p.dst, nil
		case <-s.done:
			if timer != nil {
				timer.Stop()
			}
			return nil, netip.Addr{}, netip.Addr{}, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-expired:
			return nil, netip.Addr{}, netip.Addr{}, os.ErrDeadlineExceeded
		}
	}
}

func (s *simSocket) Writer(local, remote netip.AddrPort) (packetWriter, error) {
	return &simWriter{s, local, remote}, nil
}
func (s *simSocket) LocalAddr() netip.AddrPort { return s.addr }
func (s *simSocket) Close() error              { s.once.Do(func() { close(s.done) }); return nil }
func (s *simSocket) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	close(s.changed)
	s.changed = make(chan struct{})
	s.deadlineMu.Unlock()
	return nil
}

func (s *simSocket) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

func (s *simSocket) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}
func (s *simSocket) SetReadBuffer(int) error  { return nil }
func (s *simSocket) SetWriteBuffer(int) error { return nil }
func (w *simWriter) WritePacket(b []byte) error {
	select {
	case <-w.socket.done:
		return net.ErrClosed
	default:
	}
	w.socket.deadlineMu.Lock()
	deadline := w.socket.writeDeadline
	w.socket.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	n := w.socket.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failNext != nil {
		err := n.failNext
		n.failNext = nil
		return err
	}
	if n.mtu != 0 && len(b)+ipHeaderLen(w.local.Addr()) > n.mtu {
		return syscall.EMSGSIZE
	}
	if checksum(b, pseudoSum(w.local.Addr(), w.remote.Addr(), len(b))) != 0 {
		return errors.New("invalid emitted TCP checksum")
	}
	target := n.sockets[w.remote]
	if target == nil {
		ip := netip.IPv4Unspecified()
		if w.remote.Addr().Is6() {
			ip = netip.IPv6Unspecified()
		}
		target = n.sockets[netip.AddrPortFrom(ip, w.remote.Port())]
	}
	if target == nil {
		return nil
	}
	packets := [][]byte{bytes.Clone(b)}
	if n.filter != nil {
		packets = n.filter(w.local, w.remote, packets[0])
	}
	for _, p := range packets {
		select {
		case target.queue <- simPacket{w.local.Addr(), w.remote.Addr(), p}:
		default:
		}
	}
	return nil
}

func simPair(t *testing.T, host string, v6 bool) (*conn, *conn, *simNetwork) {
	t.Helper()
	clientAddr, serverAddr := netip.MustParseAddrPort("192.0.2.1:30000"), netip.MustParseAddrPort("192.0.2.2:443")
	if v6 {
		clientAddr, serverAddr = netip.MustParseAddrPort("[2001:db8::1]:30000"), netip.MustParseAddrPort("[2001:db8::2]:443")
	}
	network := newSimNetwork()
	config, err := (Config{Host: host, HandshakeTimeout: 3 * time.Second}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	c, err := newConn(network.socket(clientAddr), config, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	config.Host = ""
	s, err := newConn(network.socket(serverAddr), config, zeroAddrPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s, network
}

func echoServer(t *testing.T, s *conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		b := make([]byte, maxPacketLen)
		for {
			n, addr, err := s.ReadFrom(b)
			if err != nil {
				done <- err
				return
			}
			if _, err = s.WriteTo(b[:n], addr); err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("echo server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("echo server leaked")
		}
	})
}

func roundTrip(t *testing.T, c *conn, payload []byte) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := c.WriteTo(payload, net.UDPAddrFromAddrPort(c.remote)); err != nil || n != len(payload) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	b := make([]byte, len(payload)+1)
	n, addr, err := c.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], payload) || addr.String() != c.remote.String() {
		t.Fatalf("read: n=%d addr=%v err=%v payload=%x", n, addr, err, b[:n])
	}
	_ = c.SetDeadline(time.Time{})
}

func TestHandshakeLossAndDuplicates(t *testing.T) {
	for _, host := range []string{"", "cover.example"} {
		for _, lost := range []string{"none", "syn", "synack", "ack", "hello", "welcome", "duplicates"} {
			t.Run(host+"/"+lost, func(t *testing.T) {
				c, s, network := simPair(t, host, false)
				dropped := false
				network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
					seg, ok := parseSegment(b)
					if !ok {
						t.Error("invalid segment")
						return nil
					}
					kind := ""
					switch {
					case seg.flags&(flagSYN|flagACK) == flagSYN:
						kind = "syn"
					case seg.flags&(flagSYN|flagACK) == flagSYN|flagACK:
						kind = "synack"
					case len(seg.payload) == 0 && src == c.client.key.local:
						kind = "ack"
					default:
						if _, ok := parseHello(seg.payload); ok {
							kind = "hello"
						}
						if isWelcome(seg.payload, host != "") {
							kind = "welcome"
						}
					}
					if kind == lost && !dropped {
						dropped = true
						return nil
					}
					if lost == "duplicates" {
						return [][]byte{b, bytes.Clone(b)}
					}
					return [][]byte{b}
				}
				echoServer(t, s)
				if err := c.handshake(); err != nil {
					t.Fatal(err)
				}
				roundTrip(t, c, []byte("payload after handshake"))
				if lost != "none" && lost != "duplicates" && !dropped {
					t.Fatalf("fault %s was never exercised", lost)
				}
			})
		}
	}
}

func TestSameTupleReconnect(t *testing.T) {
	c, s, network := simPair(t, "cover.example", false)
	echoServer(t, s)
	if err := c.handshake(); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, []byte("first connection"))
	_ = c.Close()
	next, err := newConn(network.socket(c.client.key.local), c.config, c.remote)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.handshake(); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, next, []byte("replacement connection"))
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	if len(s.peers) != 1 || len(s.replies) != 1 {
		t.Fatalf("stale peer retained: %d/%d", len(s.peers), len(s.replies))
	}
}

func TestDatagramLossReorderDuplicateGRO(t *testing.T) {
	c, s, network := simPair(t, "", false)
	echoServer(t, s)
	if err := c.handshake(); err != nil {
		t.Fatal(err)
	}
	var held, reorder []byte
	network.mu.Lock()
	network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
		seg, _ := parseSegment(b)
		kind, payload, _, ok := nextFrame(seg.payload)
		if src != c.client.key.local || !ok || kind != frameData {
			return [][]byte{b}
		}
		switch payload[0] {
		case 1:
			reorder = b
			return nil
		case 2:
			return [][]byte{b, reorder}
		case 3:
			return nil
		case 4:
			return [][]byte{b, bytes.Clone(b)}
		case 5:
			held = b
			return nil
		case 6:
			// GRO preserves the first TCP header and concatenates TCP payloads.
			// The checksum need not be valid as a normal wire-packet checksum.
			return [][]byte{append(held, b[tcpHeaderLen:]...)}
		}
		return [][]byte{b}
	}
	network.mu.Unlock()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	for i := byte(1); i <= 6; i++ {
		if _, err := c.WriteTo([]byte{i}, net.UDPAddrFromAddrPort(c.remote)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []byte{2, 1, 4, 4, 5, 6} {
		b := make([]byte, 8)
		n, _, err := c.ReadFrom(b)
		if err != nil || n != 1 || b[0] != want {
			t.Fatalf("want %d, got %x (%v)", want, b[:n], err)
		}
	}
}

func TestMTUWriteFailureAndSequenceWrap(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			c, s, network := simPair(t, "", v6)
			c.config.MTU, s.config.MTU = 1280, 1280
			echoServer(t, s)
			if err := c.handshake(); err != nil {
				t.Fatal(err)
			}
			before := c.client.sendSeq
			limit := 1280 - ipHeaderLen(c.remote.Addr()) - tcpHeaderLen - frameHeaderLen
			n, err := c.WriteTo(make([]byte, limit+1), net.UDPAddrFromAddrPort(c.remote))
			if n != 0 || !errors.Is(err, syscall.EMSGSIZE) || c.client.sendSeq != before {
				t.Fatalf("oversize consumed sequence: n=%d err=%v", n, err)
			}
			network.mu.Lock()
			network.failNext = syscall.EMSGSIZE
			network.mu.Unlock()
			_, err = c.WriteTo([]byte("kernel MTU error"), net.UDPAddrFromAddrPort(c.remote))
			if !errors.Is(err, syscall.EMSGSIZE) || c.client.sendSeq != before {
				t.Fatal("kernel EMSGSIZE did not preserve sequence")
			}
			roundTrip(t, c, make([]byte, limit))
			c.writeMu.Lock()
			c.client.sendSeq = ^uint32(0) - 2
			c.writeMu.Unlock()
			// Arrange the receiver's serial number near the same wrap point.
			s.peersMu.RLock()
			p := s.peers[c.client.keyReversed()]
			s.peersMu.RUnlock()
			if p == nil {
				t.Fatal("peer missing")
			}
			p.recvNext.Store(^uint32(0) - 10)
			roundTrip(t, c, []byte("wrap"))
			if c.client.sendSeq != 5 || p.recvNext.Load() != 5 {
				t.Fatalf("bad wrap: seq=%d ack=%d", c.client.sendSeq, p.recvNext.Load())
			}
			old := p.recvNext.Load()
			advanceACK(p, ^uint32(0)-5)
			if p.recvNext.Load() != old {
				t.Fatal("reordered packet moved ACK backwards")
			}
		})
	}
}
func (p *peer) keyReversed() peerKey { return peerKey{p.key.remote, p.key.local} }

func TestDeadlinesAndConcurrentClose(t *testing.T) {
	c, _, _ := simPair(t, "", false)
	done := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 8)); done <- err }()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt read")
	}
	_ = c.SetReadDeadline(time.Time{})
	go func() { _, _, err := c.ReadFrom(make([]byte, 8)); done <- err }()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt read")
	}
}

func TestConcurrentDatagrams(t *testing.T) {
	c, s, _ := simPair(t, "", false)
	echoServer(t, s)
	if err := c.handshake(); err != nil {
		t.Fatal(err)
	}
	const writers = 8
	const packets = 100
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var wg sync.WaitGroup
	failures := make(chan error, writers)
	for writer := range writers {
		wg.Go(func() {
			for packet := range packets {
				if _, err := c.WriteTo([]byte{byte(writer), byte(packet)}, net.UDPAddrFromAddrPort(c.remote)); err != nil {
					failures <- err
					return
				}
			}
		})
	}
	seen := make(map[[2]byte]bool)
	for range writers * packets {
		b := make([]byte, 2)
		n, _, err := c.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("short datagram: %d", n)
		}
		key := [2]byte{b[0], b[1]}
		if seen[key] {
			t.Fatalf("duplicate datagram %v", key)
		}
		seen[key] = true
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}

func TestCookieValidationAndExpiry(t *testing.T) {
	_, s, _ := simPair(t, "", false)
	key := peerKey{netip.MustParseAddrPort("192.0.2.2:443"), netip.MustParseAddrPort("192.0.2.1:30000")}
	seq := uint32(12345)
	minute := time.Now().Unix() / 60
	for _, cookie := range []uint32{s.cookie(key, seq, minute, nil) ^ 0x80000000, s.cookie(key, seq, minute-2, nil)} {
		_, err := s.accept(segment{seq: seq + 1, ack: cookie + 1, flags: flagACK}, key)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.peers) != 0 {
			t.Fatal("invalid or expired cookie allocated peer")
		}
	}
	_, err := s.accept(segment{seq: seq + 1, ack: s.cookie(key, seq, minute, nil) + 1, flags: flagACK}, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.peers) != 1 {
		t.Fatal("valid cookie rejected")
	}
	p := s.peers[key]
	p.lastActive.Store(time.Now().Add(-s.config.IdleTimeout - time.Second).UnixNano())
	s.lastSweep = time.Time{}
	s.sweep(time.Now())
	if len(s.peers) != 0 || len(s.replies) != 0 {
		t.Fatal("idle peer indexes not released")
	}
}

func TestServerRestartRequiresNewHandshake(t *testing.T) {
	c, s, network := simPair(t, "", false)
	echoServer(t, s)
	if err := c.handshake(); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, []byte("before restart"))
	_ = s.Close()
	next, err := newConn(network.socket(s.io.LocalAddr()), s.config, zeroAddrPort)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	echoServer(t, next)
	_ = c.Close()
	dial, err := newConn(network.socket(c.io.LocalAddr()), c.config, c.remote)
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()
	if err := dial.handshake(); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, dial, []byte("after restart"))
}

func TestWildcardReplyKeepsLocalIP(t *testing.T) {
	network := newSimNetwork()
	cfg, _ := (Config{}).normalized()
	serverAddr := netip.MustParseAddrPort("0.0.0.0:443")
	s, err := newConn(network.socket(serverAddr), cfg, zeroAddrPort)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	echoServer(t, s)
	clientAddr := netip.MustParseAddrPort("192.0.2.1:30000")
	// Two peers with an identical remote address but different local addresses
	// must coexist and keep the original return route, even on a wildcard bind.
	var clients []*conn
	for _, ip := range []string{"192.0.2.2:443", "192.0.2.3:443"} {
		c, err := newConn(network.socket(clientAddr), cfg, netip.MustParseAddrPort(ip))
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		defer c.Close()
		if err := c.handshake(); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, []byte(ip))
	}
	if len(s.peers) != 2 {
		t.Fatalf("want two local routes, got %d", len(s.peers))
	}
	network.mu.Lock()
	network.sockets[clientAddr] = clients[0].io.(*simSocket)
	network.mu.Unlock()
	roundTrip(t, clients[0], []byte("original local address retained"))
}

func TestHandshakeTimeout(t *testing.T) {
	c, _, _ := simPair(t, "", false)
	c.config.HandshakeTimeout = 25 * time.Millisecond
	err := c.handshake()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want handshake timeout, got %v", err)
	}
}

func TestLateACKDoesNotUndoReconnect(t *testing.T) {
	c, s, network := simPair(t, "", false)
	var oldACK []byte
	network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
		seg, _ := parseSegment(b)
		if oldACK == nil && src == c.client.key.local && seg.flags == flagACK && len(seg.payload) == 0 {
			oldACK = bytes.Clone(b)
		}
		return [][]byte{b}
	}
	echoServer(t, s)
	if err := c.handshake(); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, []byte("old session"))
	_ = c.Close()
	next, err := newConn(network.socket(c.io.LocalAddr()), c.config, c.remote)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.handshake(); err != nil {
		t.Fatal(err)
	}
	network.mu.Lock()
	delayed := bytes.Clone(oldACK)
	network.mu.Unlock()
	s.io.(*simSocket).queue <- simPacket{c.io.LocalAddr().Addr(), c.remote.Addr(), delayed}
	roundTrip(t, next, []byte("late ACK must not reset current session"))
}

func TestLateHelloDoesNotUndoReconnect(t *testing.T) {
	for _, host := range []string{"", "cover.example"} {
		t.Run(host, func(t *testing.T) {
			c, s, network := simPair(t, host, false)
			hellos := make(map[uint32][]byte)
			synACKs := make(map[uint32]uint32)
			network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
				seg, _ := parseSegment(b)
				if src == c.client.key.local {
					if _, ok := parseHello(seg.payload); ok {
						hellos[seg.seq-1] = bytes.Clone(b)
					}
				} else if seg.flags&(flagSYN|flagACK) == flagSYN|flagACK {
					synACKs[seg.ack-1] = seg.seq
				}
				return [][]byte{b}
			}
			echoServer(t, s)
			current := c
			for generation := 1; generation <= 3; generation++ {
				if generation > 1 {
					_ = current.Close()
					var err error
					current, err = newConn(network.socket(c.io.LocalAddr()), c.config, c.remote)
					if err != nil {
						t.Fatal(err)
					}
					defer current.Close()
				}
				// Fixed, distinct client ISNs make A -> B -> C deterministic.
				current.client.initialSeq = uint32(generation * 10000)
				current.client.sendSeq = current.client.initialSeq + 1
				if err := current.handshake(); err != nil {
					t.Fatal(err)
				}
				roundTrip(t, current, []byte("established generation"))
			}
			key := peerKey{c.remote, c.io.LocalAddr()}
			expected := s.findPeer(key)
			for _, seq := range []uint32{10000, 20000, 30000} {
				network.mu.Lock()
				hello := bytes.Clone(hellos[seq])
				network.mu.Unlock()
				if hello == nil {
					t.Fatalf("no hello captured for client ISN %d", seq)
				}
				// The following round trip is a barrier: the FIFO receiver must
				// process this replay before it echoes the following data packet.
				s.io.(*simSocket).queue <- simPacket{c.io.LocalAddr().Addr(), c.remote.Addr(), hello}
				roundTrip(t, current, []byte("data after replayed hello"))
				if got := s.findPeer(key); got != expected {
					t.Fatalf("hello from client ISN %d replaced current ISN %d with %d", seq, expected.remoteInitialSeq, got.remoteInitialSeq)
				}
			}
			// SYN retries for the current handshake must reuse its cookie,
			// including after the peer has already sent and received data.
			if err := current.sendAt(current.client, current.client.initialSeq, flagSYN, nil); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, current, []byte("data after repeated SYN"))
			network.mu.Lock()
			seq := synACKs[current.client.initialSeq]
			network.mu.Unlock()
			if seq != current.client.remoteInitialSeq {
				t.Fatalf("SYN retry changed server ISN from %d to %d", current.client.remoteInitialSeq, seq)
			}
		})
	}
}

func TestHandshakeRefreshesCookieAfterCompetingHandshake(t *testing.T) {
	for _, host := range []string{"", "cover.example"} {
		t.Run(host, func(t *testing.T) {
			c, s, network := simPair(t, host, false)
			c.client.initialSeq, c.client.sendSeq = 10000, 10001
			echoServer(t, s)
			if err := c.handshake(); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, c, []byte("first generation"))
			_ = c.Close()
			next, err := newConn(network.socket(c.io.LocalAddr()), c.config, c.remote)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			next.client.initialSeq, next.client.sendSeq = 20000, 20001
			const competingISN = 30000
			hello := helloPayload(host)
			var heldHello []byte
			var cookies []uint32
			competingReady := false
			injectClient := func(seq, ack uint32, flags byte, payload []byte) {
				b := make([]byte, tcpHeaderLen+8+len(payload))
				n := marshalSegment(b, next.client.key.local, next.remote, seq, ack, flags, payload, next.config.MTU)
				s.io.(*simSocket).queue <- simPacket{next.client.key.local.Addr(), next.remote.Addr(), b[:n]}
			}
			network.mu.Lock()
			network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
				seg, _ := parseSegment(b)
				if src == next.client.key.local {
					if _, ok := parseHello(seg.payload); ok && heldHello == nil {
						// Hold B's hello while a competing C handshake changes
						// the server generation. Neither state machine is mocked.
						heldHello = bytes.Clone(b)
						injectClient(competingISN, 0, flagSYN, nil)
						return nil
					}
				} else if seg.flags&(flagSYN|flagACK) == flagSYN|flagACK {
					if seg.ack == competingISN+1 {
						injectClient(competingISN+1, seg.seq+1, flagACK|flagPSH, hello)
						return nil
					}
					if seg.ack == next.client.initialSeq+1 {
						cookies = append(cookies, seg.seq)
					}
				} else if seg.ack == competingISN+1+uint32(len(hello)) && isWelcome(seg.payload, host != "") {
					competingReady = true
					// Deliver B's stale hello only after C has been accepted.
					s.io.(*simSocket).queue <- simPacket{next.client.key.local.Addr(), next.remote.Addr(), bytes.Clone(heldHello)}
					return nil
				}
				return [][]byte{b}
			}
			network.mu.Unlock()
			if err := next.handshake(); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, next, []byte("data after refreshed cookie"))
			network.mu.Lock()
			ready, received := competingReady, append([]uint32(nil), cookies...)
			network.mu.Unlock()
			if !ready || len(received) < 2 || received[0] == received[len(received)-1] {
				t.Fatalf("handshake did not refresh its stale cookie: competing ready=%v cookies=%v", ready, received)
			}
			p := s.findPeer(peerKey{next.remote, next.io.LocalAddr()})
			if p.remoteInitialSeq != next.client.initialSeq || p.initialSeq != next.client.remoteInitialSeq {
				t.Fatal("client and server disagree after cookie refresh")
			}
		})
	}
}

func TestDeadlineWithPendingGRO(t *testing.T) {
	c, _, _ := simPair(t, "", false)
	c.pending = append([]byte{frameMagic, frameData, 0, 1}, 7)
	c.pendingPeer = c.client
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	b := make([]byte, 4)
	if _, _, err := c.ReadFrom(b); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("pending GRO ignored deadline: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	n, _, err := c.ReadFrom(b)
	if err != nil || n != 1 || b[0] != 7 {
		t.Fatalf("deadline discarded pending packet: n=%d err=%v", n, err)
	}
}
