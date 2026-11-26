package faketcp

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// These tests replay actual WriteTo output through the production parser and
// handshake. The synthetic aggregate tests exercise record boundaries; they
// do not claim to reproduce the kernel's GRO admission rules.

func replayEstablish(t *testing.T, client, server *conn) {
	t.Helper()
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer server.SetReadDeadline(time.Time{})
	type result struct {
		payload []byte
		addr    net.Addr
		err     error
	}
	read := make(chan result, 1)
	go func() {
		b := make([]byte, 64)
		n, addr, err := server.ReadFrom(b)
		read <- result{b[:n], addr, err}
	}()
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	marker := []byte("ready")
	if _, err := client.WriteTo(marker, net.UDPAddrFromAddrPort(client.remote)); err != nil {
		t.Fatal(err)
	}
	var got result
	select {
	case got = <-read:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the handshake barrier")
	}
	if got.err != nil || !bytes.Equal(got.payload, marker) {
		t.Fatalf("handshake barrier: payload=%q err=%v", got.payload, got.err)
	}
	packet := replaySend(t, server, client, marker)
	replayRead(t, client, marker, packet)
}

func replaySend(t *testing.T, sender, receiver *conn, payload []byte) simPacket {
	t.Helper()
	if n, err := sender.WriteTo(payload, receiver.LocalAddr()); err != nil || n != len(payload) {
		t.Fatalf("send: n=%d err=%v", n, err)
	}
	select {
	case p := <-receiver.io.(*simSocket).queue:
		return p
	case <-time.After(time.Second):
		t.Fatal("no encoded TCP segment was sent")
		return simPacket{}
	}
}

func replayRead(t *testing.T, receiver *conn, want []byte, packets ...simPacket) {
	t.Helper()
	for _, p := range packets {
		receiver.io.(*simSocket).queue <- p
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer receiver.SetReadDeadline(time.Time{})
	b := make([]byte, len(want)+1)
	n, _, err := receiver.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], want) {
		t.Fatalf("received payload=%q, want=%q, err=%v", b[:n], want, err)
	}
}

func replayReconnect(t *testing.T, previous *conn, network *simNetwork, isn uint32) *conn {
	t.Helper()
	if err := previous.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := newConn(network.socket(previous.client.key.local), previous.config, previous.remote)
	if err != nil {
		t.Fatal(err)
	}
	next.client.initialSeq = isn
	next.client.sendSeq = isn + 1
	t.Cleanup(func() { _ = next.Close() })
	return next
}

func replayPacketEnd(t *testing.T, p simPacket) uint32 {
	t.Helper()
	s, ok := parseSegment(p.data)
	if !ok {
		t.Fatal("invalid encoded TCP segment")
	}
	return s.seq + uint32(len(s.payload))
}

func TestRetiredDataBothDirections(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "ipv4"
		if v6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			first, server, network := simPair(t, "", v6)
			first.client.initialSeq, first.client.sendSeq = 1_000_000, 1_000_001
			replayEstablish(t, first, server)
			oldClient := replaySend(t, first, server, []byte("retired client data"))
			oldServer := replaySend(t, server, first, []byte("retired server data"))
			previousSession := first.client.session

			next := replayReconnect(t, first, network, 10_000)
			replayEstablish(t, next, server)
			if next.client.session == previousSession {
				t.Fatal("a replacement peer reused the retired session ID")
			}
			current := replaySend(t, next, server, []byte("current client data"))
			replayRead(t, server, []byte("current client data"), oldClient, current)
			peer := server.findPeer(peerKey{next.client.key.remote, next.client.key.local})
			if got, want := peer.recvNext.Load(), replayPacketEnd(t, current); got != want {
				t.Fatalf("server ACK=%d, want current frame end %d", got, want)
			}

			current = replaySend(t, server, next, []byte("current server data"))
			replayRead(t, next, []byte("current server data"), oldServer, current)
			if got, want := next.client.recvNext.Load(), replayPacketEnd(t, current); got != want {
				t.Fatalf("client ACK=%d, want current frame end %d", got, want)
			}
		})
	}
}

func TestRetiredGROTailDoesNotAdvanceACK(t *testing.T) {
	for _, wrap := range []bool{false, true} {
		name := "ordinary-sequence"
		if wrap {
			name = "sequence-wrap"
		}
		t.Run(name, func(t *testing.T) {
			first, server, network := simPair(t, "", false)
			replayEstablish(t, first, server)
			old := replaySend(t, first, server, []byte("old tail"))
			isn := uint32(10_000)
			if wrap {
				isn = ^uint32(0) - 100
			}
			next := replayReconnect(t, first, network, isn)
			replayEstablish(t, next, server)
			marker := bytes.Repeat([]byte("g"), 128)
			current := replaySend(t, next, server, marker)
			good, _ := parseSegment(current.data)
			stale, _ := parseSegment(old.data)
			payload := append(bytes.Clone(good.payload), stale.payload...)
			aggregate := make([]byte, tcpHeaderLen+len(payload))
			n := marshalSegment(aggregate, next.client.key.local, next.client.key.remote, good.seq, good.ack, flagACK, payload, next.config.MTU)
			replayRead(t, server, marker, simPacket{current.src, current.dst, aggregate[:n]})
			peer := server.findPeer(peerKey{next.client.key.remote, next.client.key.local})
			wantACK := replayPacketEnd(t, current)
			activity := peer.lastActive.Load()
			if got := peer.recvNext.Load(); got != wantACK {
				t.Fatalf("ACK after first GRO record=%d, want %d", got, wantACK)
			}
			if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 64)
			if n, _, err := server.ReadFrom(b); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("retired tail was delivered: payload=%q err=%v", b[:n], err)
			}
			if got := peer.recvNext.Load(); got != wantACK {
				t.Fatalf("retired tail changed ACK to %d, want %d", got, wantACK)
			}
			if peer.lastActive.Load() != activity {
				t.Fatal("retired tail refreshed the current peer's activity")
			}
		})
	}
}

func TestSameISNReconnectRejectsRetiredWelcome(t *testing.T) {
	for _, host := range []string{"", "cover.example"} {
		t.Run(host, func(t *testing.T) {
			first, server, network := simPair(t, host, false)
			var oldWelcome []byte
			network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
				s, ok := parseSegment(b)
				if ok && src == first.client.key.remote {
					if _, ok := parseWelcome(s.payload, host != "", first.client.nonce); ok {
						oldWelcome = bytes.Clone(b)
					}
				}
				return [][]byte{b}
			}
			replayEstablish(t, first, server)
			network.mu.Lock()
			network.filter = nil
			network.mu.Unlock()
			if len(oldWelcome) == 0 {
				t.Fatal("did not capture the previous generation's welcome")
			}
			next := replayReconnect(t, first, network, first.client.initialSeq)
			// Identical TCP sequence numbers must still identify a fresh handshake.
			next.client.nonce = first.client.nonce + 1
			synacks := 0
			network.mu.Lock()
			network.filter = func(src, dst netip.AddrPort, b []byte) [][]byte {
				s, ok := parseSegment(b)
				if ok && src == next.client.key.remote && s.flags&(flagSYN|flagACK) == flagSYN|flagACK {
					synacks++
					if synacks == 1 {
						// This old welcome has matching TCP sequence/ACK fields;
						// only its echoed client nonce distinguishes it.
						return [][]byte{b, bytes.Clone(oldWelcome)}
					}
				}
				return [][]byte{b}
			}
			network.mu.Unlock()
			replayEstablish(t, next, server)
			network.mu.Lock()
			network.filter = nil
			challenges := synacks
			network.mu.Unlock()
			if challenges < 2 {
				t.Fatal("same-ISN restart did not refresh the cookie challenge")
			}
			peer := server.findPeer(peerKey{next.client.key.remote, next.client.key.local})
			if peer.nonce != next.client.nonce || peer.session != next.client.session || next.client.session == first.client.session {
				t.Fatal("same-ISN restart accepted a retired welcome or peer")
			}
		})
	}
}

func TestDataSegmentsAllowGRO(t *testing.T) {
	client, server, _ := simPair(t, "", false)
	replayEstablish(t, client, server)
	for _, direction := range []struct {
		name             string
		sender, receiver *conn
	}{{"client", client, server}, {"server", server, client}} {
		t.Run(direction.name, func(t *testing.T) {
			p := replaySend(t, direction.sender, direction.receiver, []byte("data"))
			s, ok := parseSegment(p.data)
			if !ok || s.flags&flagACK == 0 || s.flags&flagPSH != 0 {
				t.Fatalf("data flags=%#x, want ACK without PSH", s.flags)
			}
			replayRead(t, direction.receiver, []byte("data"), p)
		})
	}
}
