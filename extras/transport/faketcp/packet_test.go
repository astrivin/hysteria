package faketcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// This reference constructs the actual pseudo-header, separately from the
// implementation's incremental checksum. Fold each word to avoid sharing its
// unrolled summation or final-carry logic.
func referenceChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		word := uint32(b[i]) << 8
		if i+1 < len(b) {
			word |= uint32(b[i+1])
		}
		sum += word
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func referenceTCPChecksum(src, dst netip.Addr, segment []byte) uint16 {
	var pseudo []byte
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		pseudo = append(pseudo, s[:]...)
		pseudo = append(pseudo, d[:]...)
		pseudo = append(pseudo, 0, 6, byte(len(segment)>>8), byte(len(segment)))
	} else {
		s, d := src.As16(), dst.As16()
		pseudo = append(pseudo, s[:]...)
		pseudo = append(pseudo, d[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(segment)))
		pseudo = append(pseudo, 0, 0, 0, 6)
	}
	return referenceChecksum(append(pseudo, segment...))
}

func TestChecksumReference(t *testing.T) {
	// The worked byte sequence from RFC 1071, section 3.
	known := []byte{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := referenceChecksum(known); got != 0x220d {
		t.Fatalf("reference checksum = %04x, want 220d", got)
	}
	for _, length := range []int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 1200, 1201, 65535} {
		for _, fill := range []byte{0, 0x7f, 0xff} {
			data := bytes.Repeat([]byte{fill}, length)
			if got, want := checksum(data, 0), referenceChecksum(data); got != want {
				t.Fatalf("length=%d fill=%02x checksum=%04x want=%04x", length, fill, got, want)
			}
		}
	}
}

func TestSegmentChecksumAndRoundTrip(t *testing.T) {
	for _, family := range []struct {
		name, local, remote string
	}{
		{"IPv4", "192.0.2.1:65535", "198.51.100.2:443"},
		{"IPv6", "[2001:db8:1234::1]:65535", "[2001:db8:abcd::2]:443"},
	} {
		t.Run(family.name, func(t *testing.T) {
			local, remote := netip.MustParseAddrPort(family.local), netip.MustParseAddrPort(family.remote)
			for _, flags := range []byte{flagACK, flagACK | flagPSH, flagSYN, flagSYN | flagACK, flagFIN | flagACK} {
				for _, length := range []int{0, 1, 7, 8, 9, 1200, 1201, 1400} {
					for _, seq := range []uint32{0, 1, 0x80000000, 0xffffffff} {
						payload := make([]byte, length)
						for i := range payload {
							payload[i] = byte(i*31 + 7)
						}
						buf := bytes.Repeat([]byte{0xff}, 1600)
						ack := ^seq
						n := marshalSegment(buf, local, remote, seq, ack, flags, payload, 1500)
						h := 20
						if flags&flagSYN != 0 {
							h = 28
							ipLength := 20
							if family.name == "IPv6" {
								ipLength = 40
							}
							mss := uint16(1500 - ipLength - 20)
							if !bytes.Equal(buf[20:28], []byte{2, 4, byte(mss >> 8), byte(mss), 1, 3, 3, 14}) {
								t.Fatalf("invalid SYN options: %x", buf[20:28])
							}
						}
						if n != h+length || buf[12] != byte(h/4)<<4 || binary.BigEndian.Uint16(buf[14:]) != 65535 {
							t.Fatalf("invalid TCP header: length=%d header=%x", n, buf[:20])
						}
						if got := referenceTCPChecksum(local.Addr(), remote.Addr(), buf[:n]); got != 0 {
							t.Fatalf("flags=%02x length=%d sequence=%x residual checksum=%04x", flags, length, seq, got)
						}
						s, ok := parseSegment(buf[:n])
						if !ok || s.srcPort != local.Port() || s.dstPort != remote.Port() || s.seq != seq || s.ack != ack || s.flags != flags || !bytes.Equal(s.payload, payload) {
							t.Fatalf("round trip failed: flags=%02x length=%d sequence=%x", flags, length, seq)
						}
						buf[n-1] ^= 1
						if referenceTCPChecksum(local.Addr(), remote.Addr(), buf[:n]) == 0 {
							t.Fatal("single-bit corruption did not invalidate TCP checksum")
						}
					}
				}
			}
		})
	}
}

func TestParseSegmentLengths(t *testing.T) {
	for length := 0; length < 20; length++ {
		if _, ok := parseSegment(make([]byte, length)); ok {
			t.Fatalf("accepted a %d-byte TCP header", length)
		}
	}
	for offset := 0; offset < 16; offset++ {
		buf := make([]byte, 65)
		buf[12] = byte(offset << 4)
		for length := 20; length <= len(buf); length++ {
			s, ok := parseSegment(buf[:length])
			want := offset >= 5 && offset*4 <= length
			if ok != want {
				t.Fatalf("offset=%d length=%d accepted=%v want=%v", offset, length, ok, want)
			}
			if ok && len(s.payload) != length-offset*4 {
				t.Fatalf("offset=%d length=%d payload length=%d", offset, length, len(s.payload))
			}
		}
	}
}

func TestPacketMTUBoundaries(t *testing.T) {
	for _, family := range []struct {
		address  string
		ipLength int
	}{
		{"192.0.2.1:443", 20},
		{"[2001:db8::1]:443", 40},
	} {
		local := netip.MustParseAddrPort(family.address)
		for _, mtu := range []int{1280, 1500, 9000, 65535} {
			t.Run(fmt.Sprintf("%s/%d", local.Addr(), mtu), func(t *testing.T) {
				size := mtu - family.ipLength - 20 - 4
				frame := make([]byte, size+4)
				putFrameHeader(frame, frameData, size)
				for i := range frame[4:] {
					frame[i+4] = byte(i)
				}
				buf := make([]byte, mtu)
				n := marshalSegment(buf, local, local, 0xffffffff, 0, flagACK|flagPSH, frame, mtu)
				if n+family.ipLength != mtu {
					t.Fatalf("IP packet length=%d want=%d", n+family.ipLength, mtu)
				}
				if referenceTCPChecksum(local.Addr(), local.Addr(), buf[:n]) != 0 {
					t.Fatal("invalid checksum at MTU boundary")
				}
				s, ok := parseSegment(buf[:n])
				if !ok {
					t.Fatal("could not parse MTU-sized packet")
				}
				kind, p, rest, ok := nextFrame(s.payload)
				if !ok || kind != frameData || len(p) != size || len(rest) != 0 || !bytes.Equal(p, frame[4:]) {
					t.Fatalf("MTU-sized datagram did not survive framing (payload=%d)", size)
				}
			})
		}
	}
}

func makeTestFrame(kind byte, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	putFrameHeader(b, kind, len(payload))
	copy(b[4:], payload)
	return b
}

func TestGROFrameBoundaries(t *testing.T) {
	payloads := [][]byte{bytes.Repeat([]byte{0x11}, 1200), {}, bytes.Repeat([]byte{0x22}, 1201), []byte("tail")}
	var combined []byte
	for _, p := range payloads {
		combined = append(combined, makeTestFrame(frameData, p)...)
	}
	rest := combined
	for i, expected := range payloads {
		kind, p, next, ok := nextFrame(rest)
		if !ok || kind != frameData || !bytes.Equal(p, expected) || len(next) != len(rest)-4-len(expected) {
			t.Fatalf("GRO record %d lost its boundary", i)
		}
		rest = next
	}
	if len(rest) != 0 {
		t.Fatalf("extra data after final GRO record: %d bytes", len(rest))
	}
	// Earlier complete datagrams remain readable when the last record is
	// truncated; the incomplete record must never be returned as payload.
	rest = combined[:len(combined)-1]
	for range len(payloads) - 1 {
		_, _, next, ok := nextFrame(rest)
		if !ok {
			t.Fatal("truncation affected an earlier complete record")
		}
		rest = next
	}
	if _, _, _, ok := nextFrame(rest); ok {
		t.Fatal("accepted a truncated final GRO record")
	}
}

func TestFrameRejectsTruncationAndBadMagic(t *testing.T) {
	frame := makeTestFrame(frameData, []byte("payload"))
	for length := 0; length < len(frame); length++ {
		if _, _, _, ok := nextFrame(frame[:length]); ok {
			t.Fatalf("accepted frame truncated to %d bytes", length)
		}
	}
	frame[0] ^= 0xff
	if _, _, _, ok := nextFrame(frame); ok {
		t.Fatal("accepted incorrect frame magic")
	}
	frame[0] = frameMagic
	frame[2], frame[3] = 0xff, 0xff
	if _, _, _, ok := nextFrame(frame); ok {
		t.Fatal("accepted an oversized declared payload")
	}
	for _, kind := range []byte{frameHello, frameWelcome, frameData, 0, 0xff} {
		// nextFrame is structural. State-machine code decides which kinds may
		// be acted on; unknown kinds must not change record boundaries.
		b := makeTestFrame(kind, []byte{1, 2, 3})
		got, p, rest, ok := nextFrame(b)
		if !ok || got != kind || len(p) != 3 || len(rest) != 0 {
			t.Fatalf("kind %d was not preserved", kind)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{
		{},
		{MTU: 1280},
		{MTU: 65535},
		{Host: "www.example.com:443"},
		{Host: "[2001:db8::1]:443"},
		{Host: strings.Repeat("a", 253)},
		{HandshakeTimeout: time.Nanosecond, IdleTimeout: time.Second},
	} {
		if err := c.Validate(); err != nil {
			t.Fatalf("valid config rejected: %+v: %v", c, err)
		}
	}
	for _, c := range []Config{
		{MTU: -1},
		{MTU: 1279},
		{MTU: 65536},
		{HandshakeTimeout: -time.Nanosecond},
		{IdleTimeout: -time.Second},
		{Host: strings.Repeat("a", 254)},
		{Host: "example.com\r\nX-Injected: yes"},
		{Host: "example.com\n"},
		{Host: "example.com\x00"},
		{Host: "example.com evil"},
		{Host: "http://example.com"},
		{Host: "example.com\t"},
		{Host: "你好.example"},
	} {
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
	c, err := (Config{}).normalized()
	if err != nil || c.MTU != 1500 || c.HandshakeTimeout <= 0 || c.IdleTimeout <= 0 {
		t.Fatalf("invalid normalized defaults: %+v: %v", c, err)
	}
	explicit := Config{MTU: 1280, Host: "cover.example", HandshakeTimeout: time.Second, IdleTimeout: 3 * time.Minute}
	if got, err := explicit.normalized(); err != nil || got != explicit {
		t.Fatalf("normalization changed explicit values: %+v: %v", got, err)
	}
}

func TestHTTPPreface(t *testing.T) {
	for _, host := range []string{"", "camouflage.example", "www.example.com:8080", "[2001:db8::1]", strings.Repeat("a", 253)} {
		request := helloPayload(host)
		isHTTP, ok := parseHello(request)
		if !ok || isHTTP != (host != "") {
			t.Fatalf("Host %q did not round trip", host)
		}
		if host != "" {
			if !bytes.Contains(request, []byte("\r\nHost: "+host+"\r\n")) || len(request) > 512 {
				t.Fatalf("HTTP Host not encoded correctly: %q", host)
			}
		}
		response := welcomePayload(isHTTP)
		if !isWelcome(response, isHTTP) {
			t.Fatal("welcome did not match the negotiated preface mode")
		}
		if isWelcome(response, !isHTTP) {
			t.Fatal("welcome accepted for the other preface mode")
		}
		for length := 0; length < len(request); length++ {
			if _, ok := parseHello(request[:length]); ok {
				t.Fatalf("accepted truncated hello at %d/%d", length, len(request))
			}
		}
		for length := 0; length < len(response); length++ {
			if isWelcome(response[:length], isHTTP) {
				t.Fatalf("accepted truncated welcome at %d/%d", length, len(response))
			}
		}
		if _, ok := parseHello(append(request, 0)); ok {
			t.Fatal("accepted trailing bytes after hello")
		}
		if isWelcome(append(response, 0), isHTTP) {
			t.Fatal("accepted trailing bytes after welcome")
		}
	}
	bad := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: example.com"),
		helloPayload(strings.Repeat("a", 512)),
		makeTestFrame(frameHello, []byte{1}),
		makeTestFrame(frameData, nil),
	}
	for i, b := range bad {
		if _, ok := parseHello(b); ok {
			t.Fatalf("accepted malformed hello %d", i)
		}
	}
}

func FuzzParseSegmentAndFrames(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0},
		make([]byte, 20),
		makeTestFrame(frameData, []byte("a datagram")),
		helloPayload(""), helloPayload("cover.example"), welcomePayload(true),
	} {
		f.Add(seed)
	}
	for _, flags := range []byte{flagSYN, flagACK | flagPSH} {
		var packet [1500]byte
		local, remote := netip.MustParseAddrPort("192.0.2.1:443"), netip.MustParseAddrPort("198.51.100.2:54321")
		n := marshalSegment(packet[:], local, remote, 0xffffffff, 0, flags, makeTestFrame(frameData, bytes.Repeat([]byte{0x99}, 1200)), 1500)
		f.Add(bytes.Clone(packet[:n]))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, ok := parseSegment(b)
		if ok {
			header := int(b[12]>>4) * 4
			if header < 20 || header > len(b) || len(s.payload) != len(b)-header {
				t.Fatal("accepted invalid segment boundary")
			}
			if s.srcPort != binary.BigEndian.Uint16(b) || s.dstPort != binary.BigEndian.Uint16(b[2:]) || s.seq != binary.BigEndian.Uint32(b[4:]) || s.ack != binary.BigEndian.Uint32(b[8:]) || s.flags != b[13] {
				t.Fatal("TCP fields did not match the wire")
			}
			if !bytes.Equal(s.payload, b[header:]) {
				t.Fatal("payload changed while parsing")
			}
		} else if len(b) >= 20 && int(b[12]>>4) >= 5 && int(b[12]>>4)*4 <= len(b) {
			t.Fatal("valid segment boundary rejected")
		}
		for _, records := range [][]byte{b, s.payload} {
			for len(records) > 0 {
				kind, p, rest, valid := nextFrame(records)
				if !valid {
					if len(records) >= 4 && records[0] == frameMagic && int(binary.BigEndian.Uint16(records[2:])) <= len(records)-4 {
						t.Fatal("valid frame boundary rejected")
					}
					break
				}
				if len(records) < 4 || records[0] != frameMagic || kind != records[1] || len(p) != int(binary.BigEndian.Uint16(records[2:])) || len(rest)+len(p)+4 != len(records) {
					t.Fatal("invalid frame accepted or boundary lost")
				}
				if !bytes.Equal(p, records[4:4+len(p)]) || !bytes.Equal(rest, records[4+len(p):]) {
					t.Fatal("frame contents changed while parsing")
				}
				records = rest
			}
		}
		_, _ = parseHello(b)
		_ = isWelcome(b, false)
		_ = isWelcome(b, true)
	})
}

var benchmarkPacketResult int

func BenchmarkMarshalSegment(b *testing.B) {
	for _, address := range []struct{ name, local, remote string }{
		{"IPv4", "192.0.2.1:1234", "198.51.100.2:443"},
		{"IPv6", "[2001:db8::1]:1234", "[2001:db8::2]:443"},
	} {
		for _, size := range []int{64, 1200, 1400} {
			b.Run(fmt.Sprintf("%s/%d", address.name, size), func(b *testing.B) {
				local, remote := netip.MustParseAddrPort(address.local), netip.MustParseAddrPort(address.remote)
				payload := bytes.Repeat([]byte{0x5a}, size)
				var packet [1500]byte
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				n := 0
				for i := 0; i < b.N; i++ {
					n = marshalSegment(packet[:], local, remote, uint32(i), 1234, flagACK|flagPSH, payload, 1500)
				}
				benchmarkPacketResult = n + int(packet[16])
			})
		}
	}
}

func BenchmarkFrameGRO(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			var frames []byte
			for range count {
				frames = append(frames, makeTestFrame(frameData, make([]byte, 1200))...)
			}
			b.ReportAllocs()
			b.ResetTimer()
			consumed := 0
			for i := 0; i < b.N; i++ {
				rest := frames
				for len(rest) > 0 {
					_, p, tail, ok := nextFrame(rest)
					if !ok {
						b.Fatal("invalid benchmark frame")
					}
					consumed += len(p)
					rest = tail
				}
			}
			benchmarkPacketResult = consumed
			b.ReportMetric(float64(count), "records/op")
		})
	}
}
