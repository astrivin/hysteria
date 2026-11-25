package faketcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	prand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

// These tests run real Hysteria, TLS, QUIC, Brutal and the production FakeTCP
// state machine. Only packetIO is simulated: they do not exercise Raw Sockets,
// kernel offloads, firewalls or NAT, and are not transport performance benchmarks.
const quicTestAuth = "faketcp-quic-test"

type quicTestFactory struct {
	network       *simNetwork
	local, remote netip.AddrPort
	config        Config
}

func (f quicTestFactory) New(net.Addr) (net.PacketConn, error) {
	s := f.network.socket(f.local)
	c, err := newConn(s, f.config, f.remote)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	if err = c.handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

type quicTestAuthenticator struct{}

func (quicTestAuthenticator) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == quicTestAuth, "test"
}

type quicTestOutbound struct{}

func (quicTestOutbound) TCP(_ *server.RequestInfo, _ string) (net.Conn, error) {
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		_, _ = io.Copy(remote, remote)
	}()
	return local, nil
}

func (quicTestOutbound) UDP(_ *server.RequestInfo, _ string) (server.UDPConn, error) {
	return &quicTestUDP{queue: make(chan []byte, 128), done: make(chan struct{})}, nil
}

func (quicTestOutbound) CheckUDP(_ *server.RequestInfo, _ string) error { return nil }

type quicTestUDP struct {
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func (c *quicTestUDP) ReadFrom(b []byte) (int, string, error) {
	select {
	case p := <-c.queue:
		return copy(b, p), "echo:1234", nil
	case <-c.done:
		return 0, "", net.ErrClosed
	}
}

func (c *quicTestUDP) WriteTo(b []byte, _ string) (int, error) {
	select {
	case c.queue <- bytes.Clone(b):
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *quicTestUDP) Close() error { c.once.Do(func() { close(c.done) }); return nil }

type quicTestFaults struct {
	network              *simNetwork
	random               *prand.Rand
	pending              map[peerKey]*quicTestPending
	hold                 bool
	initialLost          bool
	packets, dropped     int
	reordered, coalesced int
	maxWire              int
}

type quicTestPending struct {
	packet []byte
	gro    bool
}

func newQUICTestFaults(n *simNetwork) *quicTestFaults {
	f := &quicTestFaults{network: n, random: prand.New(prand.NewPCG(27, 61)), pending: make(map[peerKey]*quicTestPending)}
	n.filter = f.filter
	return f
}

// simWriter serializes the filter under network.mu. A delayed packet is released
// after 1ms even if no next packet arrives, so sparse traffic cannot deadlock the
// fault injector. Coalescing keeps the first TCP header, as a synthetic GRO skb
// does; its checksum is intentionally not a newly computed wire checksum.
func (f *quicTestFaults) filter(local, remote netip.AddrPort, b []byte) [][]byte {
	f.packets++
	f.maxWire = max(f.maxWire, len(b)+ipHeaderLen(local.Addr()))
	s, ok := parseSegment(b)
	if !ok || len(s.payload) < frameHeaderLen || s.payload[0] != frameMagic || s.payload[1] != frameData {
		return [][]byte{b}
	}
	// Also force a lost QUIC Initial, before authentication enables reordering.
	if !f.initialLost || f.random.IntN(100) < 2 {
		f.initialLost = true
		f.dropped++
		return nil
	}
	if !f.hold {
		return [][]byte{b}
	}
	key := peerKey{local, remote}
	if p := f.pending[key]; p != nil {
		delete(f.pending, key)
		previous, _ := parseSegment(p.packet)
		if p.gro {
			if previous.seq+uint32(len(previous.payload)) == s.seq && previous.ack == s.ack && previous.flags == s.flags && len(previous.payload) >= len(s.payload) {
				f.coalesced++
				return [][]byte{append(p.packet, s.payload...)}
			}
			return [][]byte{p.packet, b}
		}
		f.reordered++
		return [][]byte{b, p.packet}
	}
	choice := f.random.IntN(100)
	if choice >= 20 {
		return [][]byte{b}
	}
	p := &quicTestPending{packet: b, gro: choice >= 5}
	f.pending[key] = p
	time.AfterFunc(time.Millisecond, func() {
		f.network.mu.Lock()
		defer f.network.mu.Unlock()
		if f.pending[key] != p {
			return
		}
		delete(f.pending, key)
		target := f.network.sockets[remote]
		select {
		case <-target.done:
		case target.queue <- simPacket{local.Addr(), remote.Addr(), p.packet}:
		default:
		}
	})
	return nil
}

func (f *quicTestFaults) check(t *testing.T) {
	t.Helper()
	f.network.mu.Lock()
	defer f.network.mu.Unlock()
	t.Logf("simulated TCP packets=%d, dropped=%d, reordered=%d, GRO merges=%d, largest wire packet=%d", f.packets, f.dropped, f.reordered, f.coalesced, f.maxWire)
	if f.dropped == 0 || f.reordered == 0 || f.coalesced == 0 {
		t.Error("fault profile did not exercise every configured impairment")
	}
	if f.maxWire > 1280 {
		t.Errorf("emitted packet exceeds path MTU: %d", f.maxWire)
	}
}

func quicTestClient(t *testing.T, ipv6, impaired bool) (client.Client, *quicTestFaults) {
	t.Helper()
	local, remote := netip.MustParseAddrPort("192.0.2.1:31000"), netip.MustParseAddrPort("192.0.2.2:443")
	if ipv6 {
		local, remote = netip.MustParseAddrPort("[2001:db8::1]:31000"), netip.MustParseAddrPort("[2001:db8::2]:443")
	}
	n := newSimNetwork()
	n.mtu = 1280
	var faults *quicTestFaults
	if impaired {
		faults = newQUICTestFaults(n)
	}
	cfg, err := (Config{MTU: 1280, HandshakeTimeout: 5 * time.Second}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	pc, err := newConn(n.socket(remote), cfg, zeroAddrPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"quic.faketcp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	const bandwidth = 5 * 1024 * 1024
	s, err := server.NewServer(&server.Config{
		Conn: pc, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		Authenticator: quicTestAuthenticator{}, Outbound: quicTestOutbound{},
		QUICConfig:      server.QUICConfig{InitialPacketSize: 1200, DisableGSO: true, MaxIdleTimeout: 10 * time.Second},
		BandwidthConfig: server.BandwidthConfig{MaxTx: bandwidth, MaxRx: bandwidth},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Serve() }()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("Hysteria server did not stop")
		}
	})
	if impaired {
		cfg.Host = "cover.faketcp.test"
	}
	c, info, err := client.NewClient(&client.Config{
		ConnFactory: quicTestFactory{n, local, remote, cfg}, ServerAddr: net.UDPAddrFromAddrPort(remote), Auth: quicTestAuth,
		TLSConfig:       client.TLSConfig{ServerName: "quic.faketcp.test", RootCAs: roots},
		QUICConfig:      client.QUICConfig{InitialPacketSize: 1200, DisableChromeParrot: true, DisableGSO: true, MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: 2 * time.Second},
		BandwidthConfig: client.BandwidthConfig{MaxTx: bandwidth, MaxRx: bandwidth},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if info.Tx != bandwidth || !info.UDPEnabled {
		t.Fatalf("unexpected negotiation: Brutal Tx=%d, UDP=%v", info.Tx, info.UDPEnabled)
	}
	if faults != nil {
		n.mu.Lock()
		faults.hold = true
		n.mu.Unlock()
	}
	return c, faults
}

func quicTestTCP(c client.Client, size int) error {
	// TCP() itself waits for the server response before returning a deadlineable
	// stream, so bound that wait as well as the subsequent reads and writes.
	timer := time.AfterFunc(10*time.Second, func() { _ = c.Close() })
	defer timer.Stop()
	s, err := c.TCP("echo:1234")
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	if _, err = rand.Read(payload); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() { _, e := io.Copy(s, bytes.NewReader(payload)); written <- e }()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(s, got)
	if err == nil && !bytes.Equal(got, payload) {
		err = errors.New("TCP payload corruption")
	}
	if err != nil {
		_ = s.Close()
	}
	return errors.Join(err, <-written)
}

func quicTestUDPPayload(seq uint64) []byte {
	// Stay below Hysteria's 4096-byte message buffer, including its address
	// header; 4000 bytes still needs several QUIC DATAGRAM fragments.
	sizes := [...]int{32, 1000, 1400, 4000}
	p := make([]byte, sizes[seq%uint64(len(sizes))])
	binary.BigEndian.PutUint64(p, seq)
	for i := 8; i < len(p); i++ {
		p[i] = byte(seq + uint64(i))
	}
	return p
}

func quicTestUDPTransfer(c client.Client, count int) error {
	u, err := c.UDP()
	if err != nil {
		return err
	}
	type result struct {
		data []byte
		addr string
		err  error
	}
	results, stop, joined := make(chan result, 128), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		for {
			b, addr, err := u.Receive()
			select {
			case results <- result{bytes.Clone(b), addr, err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { close(stop); _ = u.Close(); <-joined }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(20 * time.Millisecond)
	defer retry.Stop()
	for seq := uint64(0); seq < uint64(count); seq++ {
		payload := quicTestUDPPayload(seq)
		if err = u.Send(payload, "echo:1234"); err != nil {
			return err
		}
		for {
			select {
			case r := <-results:
				if r.err != nil {
					return r.err
				}
				if len(r.data) < 8 || r.addr != "echo:1234" {
					return fmt.Errorf("invalid UDP echo: %d bytes from %q", len(r.data), r.addr)
				}
				gotSeq := binary.BigEndian.Uint64(r.data)
				if gotSeq > seq || !bytes.Equal(r.data, quicTestUDPPayload(gotSeq)) {
					return errors.New("UDP payload corruption")
				}
				if gotSeq == seq {
					goto next
				}
			case <-retry.C:
				// QUIC DATAGRAM is unreliable. Application retries here require a
				// valid echo of each size without pretending transport is reliable.
				if err = u.Send(payload, "echo:1234"); err != nil {
					return err
				}
			case <-deadline.C:
				return fmt.Errorf("UDP echo timed out at datagram %d", seq)
			}
		}
	next:
	}
	return nil
}

func quicTestBatch(c client.Client) error {
	const streams = 4
	results := make(chan error, streams+1)
	for range streams {
		go func() { results <- quicTestTCP(c, 256*1024) }()
	}
	go func() { results <- quicTestUDPTransfer(c, 16) }()
	var err error
	for range streams + 1 {
		err = errors.Join(err, <-results)
	}
	return err
}

func TestQUICBrutalMTU1280(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, impaired := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%v/faults=%v", ipv6, impaired), func(t *testing.T) {
				t.Parallel()
				c, faults := quicTestClient(t, ipv6, impaired)
				if err := quicTestBatch(c); err != nil {
					t.Fatal(err)
				}
				if faults != nil {
					faults.check(t)
				}
			})
		}
	}
}

func TestQUICBrutalShortSoak(t *testing.T) {
	value := os.Getenv("FAKETCP_SIM_SOAK")
	if value == "" || testing.Short() {
		t.Skip("set FAKETCP_SIM_SOAK=1m for an explicit simulated short soak; this is not Raw Socket validation")
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Second {
		t.Fatalf("invalid FAKETCP_SIM_SOAK duration: %q", value)
	}
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
			t.Parallel()
			c, faults := quicTestClient(t, ipv6, true)
			start := time.Now()
			batches := 0
			for time.Since(start) < duration {
				if err := quicTestBatch(c); err != nil {
					t.Fatal(err)
				}
				batches++
			}
			if batches < 2 {
				t.Error("soak did not complete multiple batches")
			}
			t.Logf("simulated short soak: duration=%s, verified TCP bytes=%d, TCP streams=%d, UDP sessions=%d", time.Since(start), batches*1024*1024, batches*4, batches)
			faults.check(t)
		})
	}
}
