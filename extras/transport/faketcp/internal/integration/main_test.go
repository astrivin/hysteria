package main

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
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
