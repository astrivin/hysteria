// Command integration exercises the real Hysteria client/server over FakeTCP
// or UDP. It is a test harness, not a proxy server for production use.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/transport/faketcp"
)

const defaultTestAuth = "faketcp-isolated-test"

type options struct {
	role, transport, address, localAddr, host, traffic string
	mtu, parallel, size, reconnect, udpPPS             int
	bandwidth                                          uint64
	duration                                           time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.role, "role", "client", "server or client")
	flag.StringVar(&o.transport, "transport", "faketcp", "faketcp or udp")
	flag.StringVar(&o.address, "address", "10.203.0.1:6666", "server listen/dial address")
	flag.StringVar(&o.localAddr, "local-addr", "", "client source IP:port (empty selects a route and ephemeral port)")
	flag.StringVar(&o.host, "host", "", "optional FakeTCP HTTP Host")
	flag.StringVar(&o.traffic, "traffic", "tcp", "tcp (reliable streams) or udp (QUIC DATAGRAM)")
	flag.IntVar(&o.mtu, "mtu", 1500, "FakeTCP IP MTU")
	flag.IntVar(&o.parallel, "parallel", 2, "concurrent streams per client")
	flag.IntVar(&o.size, "size", 1<<20, "bytes per verified TCP transfer")
	flag.IntVar(&o.reconnect, "reconnect", 0, "reconnect after this many transfer batches (zero disables)")
	flag.IntVar(&o.udpPPS, "udp-pps", 8000, "target application UDP datagrams per second (1400 bytes each)")
	flag.Uint64Var(&o.bandwidth, "bandwidth", 12500000, "Brutal bandwidth in bytes/s in each direction")
	flag.DurationVar(&o.duration, "duration", 15*time.Second, "load duration, excluding at most 30s completion grace")
	flag.Parse()
	if o.parallel < 1 || o.parallel > 128 || o.size < 1 || o.duration <= 0 || o.bandwidth == 0 || o.reconnect < 0 || o.udpPPS < 1 {
		fatal(errors.New("invalid load parameters"))
	}
	if o.transport != "faketcp" && o.transport != "udp" {
		fatal(errors.New("transport must be faketcp or udp"))
	}
	if o.traffic != "tcp" && o.traffic != "udp" {
		fatal(errors.New("traffic must be tcp or udp"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch o.role {
	case "server":
		err = runServer(ctx, o)
	case "client":
		err = runClient(ctx, o)
	default:
		err = errors.New("role must be server or client")
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func packetConn(o options, listening bool) (net.PacketConn, *net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", o.address)
	if err != nil {
		return nil, nil, err
	}
	var pc net.PacketConn
	if o.transport == "faketcp" {
		cfg := faketcp.Config{MTU: o.mtu, Host: o.host, HandshakeTimeout: 10 * time.Second}
		if listening {
			cfg.Host = ""
			pc, err = faketcp.Listen(addr, cfg)
		} else {
			pc, err = faketcp.Dial(o.localAddr, addr, cfg)
		}
	} else {
		network := "udp4"
		if addr.IP.To4() == nil {
			network = "udp6"
		}
		var local *net.UDPAddr
		if listening {
			local = addr
		} else if o.localAddr != "" {
			local, err = net.ResolveUDPAddr(network, o.localAddr)
			if err != nil {
				return nil, nil, err
			}
		}
		pc, err = net.ListenUDP(network, local)
	}
	return pc, addr, err
}

func runServer(ctx context.Context, o options) error {
	pc, _, err := packetConn(o, true)
	if err != nil {
		return err
	}
	defer pc.Close()
	cert, err := testCertificate()
	if err != nil {
		return err
	}
	s, err := server.NewServer(&server.Config{
		Conn: pc, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{cert}},
		Authenticator: authenticator{password: testAuth()}, Outbound: echoOutbound{},
		QUICConfig:      server.QUICConfig{DisableGSO: true, InitialPacketSize: 1200},
		BandwidthConfig: server.BandwidthConfig{MaxTx: o.bandwidth, MaxRx: o.bandwidth},
	})
	if err != nil {
		return err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	fmt.Fprintln(os.Stdout, "READY", pc.LocalAddr())
	if err = s.Serve(); ctx.Err() != nil {
		return nil
	}
	return err
}

func testAuth() string {
	if auth := os.Getenv("FAKETCP_TEST_AUTH"); auth != "" {
		return auth
	}
	return defaultTestAuth
}

type authenticator struct{ password string }

func (a authenticator) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	return auth == a.password, "integration"
}

type echoOutbound struct{}

func (echoOutbound) TCP(_ *server.RequestInfo, _ string) (net.Conn, error) {
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		_, _ = io.Copy(remote, remote)
	}()
	return local, nil
}

func (echoOutbound) UDP(_ *server.RequestInfo, _ string) (server.UDPConn, error) {
	return &echoUDP{queue: make(chan []byte, 128), done: make(chan struct{})}, nil
}

func (echoOutbound) CheckUDP(_ *server.RequestInfo, _ string) error { return nil }

type echoUDP struct {
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func (c *echoUDP) ReadFrom(b []byte) (int, string, error) {
	select {
	case p := <-c.queue:
		return copy(b, p), "echo:1234", nil
	case <-c.done:
		return 0, "", net.ErrClosed
	}
}

func (c *echoUDP) WriteTo(b []byte, _ string) (int, error) {
	select {
	case c.queue <- bytes.Clone(b):
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *echoUDP) Close() error { c.once.Do(func() { close(c.done) }); return nil }

func testCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"faketcp.test"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, err
}

type factory struct{ net.PacketConn }

func (f factory) New(net.Addr) (net.PacketConn, error) { return f.PacketConn, nil }

func dial(ctx context.Context, o options) (client.Client, func(), error) {
	pc, addr, err := packetConn(o, false)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	c, info, err := client.NewClient(&client.Config{
		ConnFactory: factory{pc}, ServerAddr: addr, Auth: testAuth(),
		TLSConfig:       client.TLSConfig{InsecureSkipVerify: true, ServerName: "faketcp.test"},
		QUICConfig:      client.QUICConfig{DisableGSO: true, DisableChromeParrot: true, InitialPacketSize: 1200},
		BandwidthConfig: client.BandwidthConfig{MaxTx: o.bandwidth, MaxRx: o.bandwidth},
	})
	if err != nil {
		stop()
		_ = pc.Close()
		return nil, nil, err
	}
	if info.Tx == 0 {
		stop()
		_ = c.Close()
		return nil, nil, errors.New("Brutal was not negotiated")
	}
	return c, func() { stop(); _ = c.Close() }, nil
}

type stats struct {
	Transport   string  `json:"transport"`
	Traffic     string  `json:"traffic"`
	Address     string  `json:"address"`
	Host        string  `json:"host,omitempty"`
	MTU         int     `json:"mtu"`
	Parallel    int     `json:"parallel"`
	Connections uint64  `json:"connections"`
	Bytes       uint64  `json:"verified_payload_bytes"`
	Datagrams   uint64  `json:"verified_datagrams"`
	Sent        uint64  `json:"sent_datagrams"`
	Elapsed     float64 `json:"elapsed_seconds"`
	Mbps        float64 `json:"verified_payload_mbps"`
	HeapBytes   uint64  `json:"final_heap_bytes"`
	Goroutines  int     `json:"final_goroutines"`
	GoVersion   string  `json:"go_version"`
	BrutalBytes uint64  `json:"brutal_bytes_per_second"`
	UDPpps      int     `json:"requested_udp_packets_per_second,omitempty"`
}

func runClient(parent context.Context, o options) error {
	start := time.Now()
	until := start.Add(o.duration)
	ctx, cancel := context.WithDeadline(parent, until.Add(30*time.Second))
	defer cancel()
	s := stats{
		Transport: o.transport, Traffic: o.traffic, Address: o.address, Host: o.host,
		MTU: o.mtu, Parallel: o.parallel, BrutalBytes: o.bandwidth, GoVersion: runtime.Version(),
	}
	if o.traffic == "udp" {
		s.UDPpps = o.udpPPS
	}
	var verified atomic.Uint64
	verifiedLogged := false
	monitorDone := make(chan struct{})
	monitorJoined := make(chan struct{})
	go func() {
		defer close(monitorJoined)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-monitorDone:
				return
			case <-ticker.C:
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)
				_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
					"event": "checkpoint", "elapsed_seconds": time.Since(start).Seconds(),
					"verified_payload_bytes": verified.Load(), "heap_bytes": mem.HeapAlloc,
					"goroutines": runtime.NumGoroutine(),
				})
			}
		}
	}()
	defer func() { close(monitorDone); <-monitorJoined }()
	for time.Now().Before(until) {
		c, closeClient, err := dial(ctx, o)
		if err != nil {
			return err
		}
		s.Connections++
		if o.traffic == "udp" {
			s.Datagrams, s.Sent, err = transferUDP(ctx, c, until, o.udpPPS)
			verified.Add(s.Datagrams * 1400)
		} else {
			for batch := 0; time.Now().Before(until); batch++ {
				var wg sync.WaitGroup
				failures := make(chan error, o.parallel)
				for i := 0; i < o.parallel; i++ {
					wg.Go(func() {
						if e := transferTCP(ctx, c, o.size); e != nil {
							failures <- e
						} else {
							verified.Add(uint64(o.size))
						}
					})
				}
				wg.Wait()
				close(failures)
				for e := range failures {
					err = errors.Join(err, e)
				}
				if err == nil && !verifiedLogged {
					_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
						"event": "verified_data", "verified_payload_bytes": verified.Load(),
					})
					verifiedLogged = true
				}
				if err != nil || (o.reconnect > 0 && (batch+1)%o.reconnect == 0) {
					break
				}
			}
		}
		closeClient()
		if err != nil {
			return err
		}
	}
	s.Bytes = verified.Load()
	if s.Bytes == 0 {
		return errors.New("no verified payload was received")
	}
	if o.reconnect > 0 && s.Connections < 2 {
		return errors.New("reconnect case did not establish a second connection")
	}
	s.Elapsed = time.Since(start).Seconds()
	s.Mbps = float64(s.Bytes) * 8 / s.Elapsed / 1e6
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	s.HeapBytes = mem.HeapAlloc
	s.Goroutines = runtime.NumGoroutine()
	return json.NewEncoder(os.Stdout).Encode(s)
}

func transferTCP(ctx context.Context, c client.Client, size int) error {
	conn, err := c.TCP("echo:1234")
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	payload := make([]byte, 32*1024)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() {
		for n := size; n > 0; {
			part := payload[:min(n, len(payload))]
			if _, e := io.Copy(conn, bytes.NewReader(part)); e != nil {
				written <- e
				return
			}
			n -= len(part)
		}
		written <- nil
	}()
	buf := make([]byte, len(payload))
	for n := size; n > 0; {
		part := buf[:min(n, len(buf))]
		if _, err = io.ReadFull(conn, part); err != nil {
			break
		}
		if !bytes.Equal(part, payload[:len(part)]) {
			err = errors.New("TCP payload corruption")
			break
		}
		n -= len(part)
	}
	if err != nil {
		_ = conn.Close()
	}
	return errors.Join(err, <-written)
}

// Keep the default eight-packet millisecond burst, but use fewer wakeups for
// low-rate tests. The achieved rate is measured by sent_datagrams, not the timer.
func udpPacing(pps int) (time.Duration, int) {
	burst := min(8, 1+(pps-1)/1000)
	interval := max(time.Nanosecond, time.Duration(burst)*time.Second/time.Duration(pps))
	return interval, burst
}

func transferUDP(ctx context.Context, c client.Client, until time.Time, pps int) (uint64, uint64, error) {
	u, err := c.UDP()
	if err != nil {
		return 0, 0, err
	}
	defer u.Close()
	var sent, received atomic.Uint64
	readDone := make(chan error, 1)
	go func() {
		for {
			p, _, err := u.Receive()
			if err != nil {
				readDone <- err
				return
			}
			if len(p) != 1400 {
				readDone <- fmt.Errorf("UDP length: %d", len(p))
				return
			}
			seq := binary.BigEndian.Uint64(p)
			for i, b := range p[8:] {
				if b != byte(seq+uint64(i)) {
					readDone <- errors.New("UDP payload corruption")
					return
				}
			}
			received.Add(1)
		}
	}()
	interval, burstSize := udpPacing(pps)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var receiveErr error
	for time.Now().Before(until) {
		select {
		case receiveErr = <-readDone:
			return received.Load(), sent.Load(), receiveErr
		case <-ctx.Done():
			_ = u.Close()
			<-readDone
			return received.Load(), sent.Load(), ctx.Err()
		case <-ticker.C:
		}
		for burst := 0; burst < burstSize; burst++ {
			seq := sent.Load()
			p := make([]byte, 1400)
			binary.BigEndian.PutUint64(p, seq)
			for i := range p[8:] {
				p[i+8] = byte(seq + uint64(i))
			}
			if err = u.Send(p, "echo:1234"); err != nil {
				_ = u.Close()
				<-readDone
				return received.Load(), sent.Load(), err
			}
			sent.Add(1)
		}
	}
	// DATAGRAM permits loss. Require substantial delivery, while stream cases
	// verify byte-for-byte reliable delivery under the same impairment profile.
	_ = u.Close()
	receiveErr = <-readDone
	if received.Load()*2 < sent.Load() {
		return received.Load(), sent.Load(), fmt.Errorf("UDP delivery below 50%%: %d/%d", received.Load(), sent.Load())
	}
	if receiveErr != nil && !errors.Is(receiveErr, net.ErrClosed) && !errors.Is(receiveErr, io.EOF) {
		return received.Load(), sent.Load(), receiveErr
	}
	return received.Load(), sent.Load(), nil
}
