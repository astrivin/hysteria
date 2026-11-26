//go:build linux

package faketcp

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type writeWaitRawConn struct {
	syscall.RawConn
	waiting chan struct{}
	once    sync.Once
}

func (r *writeWaitRawConn) Write(f func(uintptr) bool) error {
	return r.RawConn.Write(func(fd uintptr) bool {
		ready := f(fd)
		if !ready {
			r.once.Do(func() { close(r.waiting) })
		}
		return ready
	})
}

// Unix datagram sockets exercise the real Go poller and SendmsgN without
// CAP_NET_RAW. The receiver stays idle so the send queue remains full.
func TestTryWritePacketWhileWriteWaits(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	file := os.NewFile(uintptr(fds[0]), "faketcp-write-test")
	t.Cleanup(func() { _ = file.Close() })
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 8192); err != nil {
		t.Fatal(err)
	}
	c, err := net.FileConn(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	t.Cleanup(func() { _ = c.Close() })
	raw, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024)
	var fillErr error
	if err := raw.Control(func(fd uintptr) {
		for range 1024 {
			_, fillErr = unix.SendmsgN(int(fd), payload, nil, nil, unix.MSG_DONTWAIT)
			if fillErr != nil {
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(fillErr, unix.EAGAIN) {
		t.Fatalf("fill send queue: got %v, want EAGAIN", fillErr)
	}
	observed := &writeWaitRawConn{RawConn: raw, waiting: make(chan struct{})}
	w := &rawWriter{socket: &rawSocket{raw: observed}}
	writeResult, writeExited := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(writeExited)
		writeResult <- w.WritePacket(payload)
	}()
	var tryExited chan struct{}
	t.Cleanup(func() {
		_ = c.Close()
		for _, done := range []chan struct{}{writeExited, tryExited} {
			if done == nil {
				continue
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("raw writer did not exit after close")
			}
		}
	})
	select {
	case <-observed.waiting:
	case err := <-writeResult:
		t.Fatalf("WritePacket returned before waiting for writability: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("WritePacket did not reach a full send queue")
	}
	tryResult := make(chan error, 1)
	tryExited = make(chan struct{})
	go func() {
		defer close(tryExited)
		tryResult <- w.TryWritePacket(payload)
	}()
	select {
	case err := <-tryResult:
		if !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("TryWritePacket: got %v, want EAGAIN", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TryWritePacket waited for the poller's write lock")
	}
	select {
	case err := <-writeResult:
		t.Fatalf("blocking WritePacket returned before close: %v", err)
	default:
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeResult:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WritePacket after close: got %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not interrupt WritePacket")
	}
}
