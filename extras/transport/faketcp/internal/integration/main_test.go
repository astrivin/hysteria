package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

func TestUDPPacing(t *testing.T) {
	for _, tc := range []struct {
		pps      int
		interval time.Duration
		burst    int
	}{
		{1, time.Second, 1},
		{50, 20 * time.Millisecond, 1},
		{1000, time.Millisecond, 1},
		{1500, 1333333 * time.Nanosecond, 2},
		{8000, time.Millisecond, 8},
		{10000, 800 * time.Microsecond, 8},
	} {
		interval, burst := udpPacing(tc.pps)
		if interval != tc.interval || burst != tc.burst {
			t.Errorf("%d pps: got %s / %d packets, want %s / %d", tc.pps, interval, burst, tc.interval, tc.burst)
		}
	}
}

func TestTestAuthentication(t *testing.T) {
	t.Setenv("FAKETCP_TEST_AUTH", "")
	if got := testAuth(); got != defaultTestAuth {
		t.Fatalf("empty environment did not preserve the isolated-test default")
	}
	t.Setenv("FAKETCP_TEST_AUTH", "custom-test-auth")
	a := authenticator{password: testAuth()}
	if ok, _ := a.Authenticate(nil, "custom-test-auth", 0); !ok {
		t.Fatal("configured test authentication was rejected")
	}
	if ok, _ := a.Authenticate(nil, defaultTestAuth, 0); ok {
		t.Fatal("default authentication accepted after an override")
	}
}

func TestUDPClientUsesRequestedSourcePort(t *testing.T) {
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	pc, _, err := packetConn(options{
		transport: "udp", address: "127.0.0.1:7777", localAddr: reservation.LocalAddr().String(),
	}, false)
	if err == nil && pc != nil {
		_ = pc.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("client did not reserve the requested source port: %v", err)
	}
}

type udpProgressClient struct {
	client.Client
	conn *udpProgressConn
}

func (c udpProgressClient) UDP() (client.HyUDPConn, error) {
	return c.conn, nil
}

type udpProgressConn struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
	corrupt bool
}

func (c *udpProgressConn) Send(p []byte, _ string) error {
	p = bytes.Clone(p)
	if c.corrupt {
		p[8] ^= 1
	}
	select {
	case c.packets <- p:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *udpProgressConn) Receive() ([]byte, string, error) {
	select {
	case p := <-c.packets:
		return p, "echo:1234", nil
	case <-c.closed:
		return nil, "", net.ErrClosed
	}
}

func (c *udpProgressConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestUDPProgressBeforeCompletion(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name := "valid"
		if corrupt {
			name = "corrupt"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn := &udpProgressConn{packets: make(chan []byte, 8), closed: make(chan struct{}), corrupt: corrupt}
			defer conn.Close()
			var verified atomic.Uint64
			done := make(chan error, 1)
			go func() {
				_, _, err := transferUDP(ctx, udpProgressClient{conn: conn}, time.Now().Add(time.Minute), 100, &verified)
				done <- err
			}()
			if corrupt {
				err := <-done
				if err == nil || err.Error() != "UDP payload corruption" {
					t.Fatalf("corrupt payload was not rejected: %v", err)
				}
				if verified.Load() != 0 {
					t.Fatal("corrupt payload was reported as verified progress")
				}
				return
			}
			for verified.Load() == 0 {
				select {
				case err := <-done:
					t.Fatalf("transfer ended before reporting progress: %v", err)
				case <-ctx.Done():
					t.Fatal("no verified progress while UDP transfer was active")
				case <-time.After(time.Millisecond):
				}
			}
			select {
			case err := <-done:
				t.Fatalf("progress was only reported after completion: %v", err)
			default:
			}
			cancel()
			<-done
		})
	}
}
