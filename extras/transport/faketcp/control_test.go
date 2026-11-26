package faketcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// A control reply must not use WritePacket: a shared socket can remain
// unwritable until it is closed, independently of the reader's deadline.
type controlTestIO struct {
	*simSocket
	readPacket    chan struct{}
	blockingWrite chan struct{}
	tryWrite      chan struct{}
}

func (s *controlTestIO) ReadPacket(b []byte) ([]byte, netip.Addr, netip.Addr, error) {
	p, src, dst, err := s.simSocket.ReadPacket(b)
	if err == nil {
		s.readPacket <- struct{}{}
	}
	return p, src, dst, err
}

func (s *controlTestIO) Writer(netip.AddrPort, netip.AddrPort) (packetWriter, error) {
	return s, nil
}

func (s *controlTestIO) WritePacket([]byte) error {
	s.blockingWrite <- struct{}{}
	<-s.done
	return net.ErrClosed
}

func (s *controlTestIO) TryWritePacket([]byte) error {
	s.tryWrite <- struct{}{}
	return syscall.EAGAIN
}

func controlTestConn(t *testing.T, kind string) (*conn, *controlTestIO) {
	t.Helper()
	clientAddr := netip.MustParseAddrPort("192.0.2.1:7001")
	serverAddr := netip.MustParseAddrPort("192.0.2.2:6666")
	local, remote := serverAddr, zeroAddrPort
	if kind == "client_duplicate_synack" {
		local, remote = clientAddr, serverAddr
	}
	s := &controlTestIO{
		simSocket:     newSimNetwork().socket(local),
		readPacket:    make(chan struct{}, 1),
		blockingWrite: make(chan struct{}, 1),
		tryWrite:      make(chan struct{}, 1),
	}
	config, err := (Config{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	c, err := newConn(s, config, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	var seq, ack uint32
	var flags byte
	var payload []byte
	src, dst := clientAddr, serverAddr
	switch kind {
	case "server_syn":
		seq, flags = 100, flagSYN
	case "server_hello":
		seq, flags, payload = 101, flagACK|flagPSH, helloPayload("cover.example", 1)
		ack = c.cookie(peerKey{serverAddr, clientAddr}, seq-1, time.Now().Unix()/60, nil) + 1
	case "client_duplicate_synack":
		c.client.remoteInitialSeq = 200
		c.client.recvNext.Store(201)
		c.client.ready.Store(true)
		src, dst = serverAddr, clientAddr
		seq, ack, flags = c.client.remoteInitialSeq, c.client.initialSeq+1, flagSYN|flagACK
	default:
		t.Fatalf("unknown control packet %q", kind)
	}
	b := make([]byte, tcpHeaderLen+40+len(payload))
	n := marshalSegment(b, src, dst, seq, ack, flags, payload, config.MTU)
	s.queue <- simPacket{src.Addr(), dst.Addr(), b[:n]}
	return c, s
}

func TestControlReadDeadlineWithBusyWriter(t *testing.T) {
	for _, kind := range []string{"server_syn", "server_hello", "client_duplicate_synack"} {
		t.Run(kind, func(t *testing.T) {
			c, socket := controlTestConn(t, kind)
			c.writeMu.Lock()
			defer c.writeMu.Unlock()
			readResult, exited := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(exited)
				_, _, err := c.ReadFrom(make([]byte, 128))
				readResult <- err
			}()
			t.Cleanup(func() {
				_ = c.Close()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					t.Error("ReadFrom did not exit after cleanup")
				}
			})
			select {
			case <-socket.readPacket:
			case <-time.After(2 * time.Second):
				t.Fatal("control packet was not read")
			}
			if err := c.SetReadDeadline(time.Now()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-readResult:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("ReadFrom: got %v, want deadline exceeded", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ReadFrom waited for writeMu after its read deadline")
			}
			select {
			case <-socket.blockingWrite:
				t.Error("control reply called blocking WritePacket")
			case <-socket.tryWrite:
				t.Error("control reply used the send buffer while writeMu was held")
			default:
			}
		})
	}
}

func TestControlRepliesDoNotBlockQUICClose(t *testing.T) {
	for _, kind := range []string{"server_syn", "server_hello", "client_duplicate_synack"} {
		t.Run(kind, func(t *testing.T) {
			c, socket := controlTestConn(t, kind)
			transport := &quic.Transport{Conn: c}
			ctx, cancel := context.WithCancel(context.Background())
			readResult, readExited := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(readExited)
				_, _, err := transport.ReadNonQUICPacket(ctx, make([]byte, 128))
				readResult <- err
			}()
			var closeExited chan struct{}
			t.Cleanup(func() {
				_ = c.Close()
				cancel()
				if closeExited == nil {
					closeExited = make(chan struct{})
					go func() {
						_ = transport.Close()
						close(closeExited)
					}()
				}
				for _, done := range []chan struct{}{closeExited, readExited} {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("QUIC transport goroutine did not exit after cleanup")
					}
				}
			})
			select {
			case <-socket.tryWrite:
			case <-socket.blockingWrite:
				t.Error("control reply called blocking WritePacket")
			case <-time.After(2 * time.Second):
				t.Fatal("QUIC reader did not attempt a control reply")
			}
			closeResult := make(chan error, 1)
			closeExited = make(chan struct{})
			go func() {
				defer close(closeExited)
				closeResult <- transport.Close()
			}()
			select {
			case err := <-closeResult:
				if err != nil {
					t.Fatalf("Transport.Close: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Transport.Close waited for a control write on its external PacketConn")
			}
			if c.closed.Load() {
				t.Error("Transport.Close unexpectedly closed the external PacketConn")
			}
			select {
			case err := <-readResult:
				if err == nil {
					t.Error("ReadNonQUICPacket unexpectedly returned a datagram")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("ReadNonQUICPacket did not exit after Transport.Close")
			}
		})
	}
}
