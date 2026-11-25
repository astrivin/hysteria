package faketcp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

const (
	flagFIN      = 0x01
	flagSYN      = 0x02
	flagRST      = 0x04
	flagPSH      = 0x08
	flagACK      = 0x10
	frameMagic   = 0x48
	frameHello   = 1
	frameWelcome = 2
	frameData    = 3
)

var (
	httpRequestStart = []byte("GET / HTTP/1.1\r\n")
	httpResponse     = []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n")
	headerEnd        = []byte("\r\n\r\n")
)

type segment struct {
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            byte
	payload          []byte
}

func parseSegment(b []byte) (segment, bool) {
	if len(b) < tcpHeaderLen {
		return segment{}, false
	}
	h := int(b[12]>>4) * 4
	if h < tcpHeaderLen || h > len(b) {
		return segment{}, false
	}
	return segment{
		srcPort: binary.BigEndian.Uint16(b), dstPort: binary.BigEndian.Uint16(b[2:]),
		seq: binary.BigEndian.Uint32(b[4:]), ack: binary.BigEndian.Uint32(b[8:]),
		flags: b[13], payload: b[h:],
	}, true
}

// marshalSegment writes into reusable storage. Only SYNs carry options: MSS
// and window scale keep ordinary stateful NATs' TCP window tracking usable.
func marshalSegment(b []byte, local, remote netip.AddrPort, seq, ack uint32, flags byte, payload []byte, mtu int) int {
	h := tcpHeaderLen
	if flags&flagSYN != 0 {
		h += 8
	}
	clear(b[:h])
	binary.BigEndian.PutUint16(b, local.Port())
	binary.BigEndian.PutUint16(b[2:], remote.Port())
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12], b[13] = byte(h/4)<<4, flags
	binary.BigEndian.PutUint16(b[14:], 65535)
	if h > tcpHeaderLen {
		mss := mtu - ipHeaderLen(local.Addr()) - tcpHeaderLen
		b[20], b[21] = 2, 4
		binary.BigEndian.PutUint16(b[22:], uint16(mss))
		b[24], b[25], b[26], b[27] = 1, 3, 3, 14 // NOP, window scale 14
	}
	copy(b[h:], payload)
	n := h + len(payload)
	sum := pseudoSum(local.Addr(), remote.Addr(), n)
	binary.BigEndian.PutUint16(b[16:], checksum(b[:n], sum))
	return n
}

func ipHeaderLen(ip netip.Addr) int {
	if ip.Is4() {
		return 20
	}
	return 40
}

func addChecksum(b []byte, sum uint32) uint32 {
	// Eight-byte chunks reduce loop overhead without alignment assumptions.
	for len(b) >= 8 {
		sum += uint32(binary.BigEndian.Uint16(b)) + uint32(binary.BigEndian.Uint16(b[2:])) + uint32(binary.BigEndian.Uint16(b[4:])) + uint32(binary.BigEndian.Uint16(b[6:]))
		b = b[8:]
	}
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func pseudoSum(src, dst netip.Addr, n int) uint32 {
	sum := uint32(n) + 6 // IPPROTO_TCP
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		return addChecksum(d[:], addChecksum(s[:], sum))
	}
	s, d := src.As16(), dst.As16()
	return addChecksum(d[:], addChecksum(s[:], sum))
}

func checksum(b []byte, sum uint32) uint16 {
	sum = addChecksum(b, sum)
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}

func putFrameHeader(b []byte, kind byte, n int) {
	b[0], b[1] = frameMagic, kind
	binary.BigEndian.PutUint16(b[2:], uint16(n))
}

// nextFrame only accepts whole records. Raw TCP senders never segment a
// record, while GRO may concatenate several. No stream reassembly or waiting
// for missing sequence numbers is needed, so loss cannot cause TCP HOL.
func nextFrame(b []byte) (kind byte, payload, rest []byte, ok bool) {
	if len(b) < frameHeaderLen || b[0] != frameMagic {
		return 0, nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > len(b)-frameHeaderLen {
		return 0, nil, nil, false
	}
	return b[1], b[frameHeaderLen : frameHeaderLen+n], b[frameHeaderLen+n:], true
}

func helloPayload(host string) []byte {
	var b []byte
	if host != "" {
		b = []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: keep-alive\r\n\r\n")
	}
	b = append(b, frameMagic, frameHello, 0, 0)
	return b
}

func parseHello(b []byte) (http, ok bool) {
	if bytes.HasPrefix(b, httpRequestStart) {
		if len(b) > 512 {
			return false, false
		}
		i := bytes.Index(b, headerEnd)
		if i < 0 {
			return false, false
		}
		b = b[i+len(headerEnd):]
		http = true
	}
	kind, payload, rest, valid := nextFrame(b)
	return http, valid && kind == frameHello && len(payload) == 0 && len(rest) == 0
}

func welcomePayload(http bool) []byte {
	var b []byte
	if http {
		b = append(b, httpResponse...)
	}
	return append(b, frameMagic, frameWelcome, 0, 0)
}

func isWelcome(b []byte, http bool) bool {
	if http {
		if !bytes.HasPrefix(b, httpResponse) {
			return false
		}
		b = b[len(httpResponse):]
	}
	kind, payload, rest, ok := nextFrame(b)
	return ok && kind == frameWelcome && len(payload) == 0 && len(rest) == 0
}
