package faketcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type packetWriter interface {
	WritePacket([]byte) error
	TryWritePacket([]byte) error
}

type packetIO interface {
	ReadPacket([]byte) ([]byte, netip.Addr, netip.Addr, error)
	Writer(local, remote netip.AddrPort) (packetWriter, error)
	LocalAddr() netip.AddrPort
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

type peerKey struct{ local, remote netip.AddrPort }

type peer struct {
	key              peerKey
	addr             *net.UDPAddr
	writer           packetWriter
	initialSeq       uint32
	remoteInitialSeq uint32
	nonce            uint64
	session          uint64
	// sendSeq is protected by conn.writeMu; ACK and activity also change on read.
	sendSeq    uint32
	recvNext   atomic.Uint32
	lastActive atomic.Int64
	ready      atomic.Bool
	// Only the single reader accesses the handshake response cache.
	helloSeq   uint32
	helloLen   int
	welcomeSeq uint32
	welcome    []byte
}

type conn struct {
	io           packetIO
	config       Config
	local        *net.UDPAddr
	remote       netip.AddrPort
	client       *peer
	secret       [32]byte
	closed       atomic.Bool
	readDeadline atomic.Int64
	readMu       sync.Mutex
	writeMu      sync.Mutex
	peersMu      sync.RWMutex
	peers        map[peerKey]*peer
	replies      map[*net.UDPAddr]*peer
	lastSweep    time.Time // protected by readMu
	readBuf      [maxReceivePacketLen]byte
	writeBuf     [maxPacketLen]byte
	pending      []byte // remaining records in readBuf after GRO
	pendingPeer  *peer
	pendingSeq   uint32
}

func newConn(io packetIO, config Config, remote netip.AddrPort) (*conn, error) {
	c := &conn{io: io, config: config, local: net.UDPAddrFromAddrPort(io.LocalAddr()), remote: remote, peers: make(map[peerKey]*peer), replies: make(map[*net.UDPAddr]*peer)}
	if _, err := rand.Read(c.secret[:]); err != nil {
		return nil, err
	}
	if remote.IsValid() {
		p, err := c.newPeer(peerKey{io.LocalAddr(), remote}, binary.BigEndian.Uint32(c.secret[:4]), 0)
		if err != nil {
			return nil, err
		}
		c.client = p
		p.nonce = binary.BigEndian.Uint64(c.secret[4:12])
	}
	return c, nil
}

func (c *conn) newPeer(key peerKey, seq, remoteSeq uint32) (*peer, error) {
	w, err := c.io.Writer(key.local, key.remote)
	if err != nil {
		return nil, err
	}
	p := &peer{key: key, addr: net.UDPAddrFromAddrPort(key.remote), writer: w, initialSeq: seq, remoteInitialSeq: remoteSeq, sendSeq: seq + 1}
	p.recvNext.Store(remoteSeq + 1)
	p.lastActive.Store(time.Now().UnixNano())
	return p, nil
}

func (c *conn) opError(op string, addr net.Addr, err error) error {
	return &net.OpError{Op: op, Net: "faketcp", Source: c.local, Addr: addr, Err: err}
}

// sendAt is used for retransmitted handshake segments, whose sequence number
// must not consume additional TCP sequence space.
func (c *conn) sendAt(p *peer, seq uint32, flags byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeAt(p, seq, flags, payload, false)
}

// Control replies must not wait for a writer: ReadFrom's deadline also drives
// QUIC transport shutdown. The client retries a dropped SYN-ACK or welcome.
func (c *conn) replyAt(p *peer, seq uint32, flags byte, payload []byte) error {
	if !c.writeMu.TryLock() {
		return syscall.EAGAIN
	}
	defer c.writeMu.Unlock()
	return c.writeAt(p, seq, flags, payload, true)
}

// writeAt requires writeMu. Only the initial client handshake may wait to send;
// it has a write deadline and does not run inside ReadFrom.
func (c *conn) writeAt(p *peer, seq uint32, flags byte, payload []byte, nonblocking bool) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	ack := p.recvNext.Load()
	if flags == flagSYN|flagACK {
		ack = p.remoteInitialSeq + 1
	}
	n := marshalSegment(c.writeBuf[:], p.key.local, p.key.remote, seq, ack, flags, payload, c.config.MTU)
	var err error
	if nonblocking {
		err = p.writer.TryWritePacket(c.writeBuf[:n])
	} else {
		err = p.writer.WritePacket(c.writeBuf[:n])
	}
	if err == nil && flags&flagSYN == 0 {
		p.lastActive.Store(time.Now().UnixNano())
	}
	return err
}

func advanceACK(p *peer, seq uint32) {
	for {
		old := p.recvNext.Load()
		if int32(seq-old) <= 0 || p.recvNext.CompareAndSwap(old, seq) {
			return
		}
	}
}

// The cookie binds both endpoints and the client ISN. A replacement also binds
// the current peer's ISNs and session, so an old hello cannot restore a retired generation.
// SYNs retain no new half-open peer state or timer. Accept cookies from the
// current and prior minute.
func (c *conn) cookie(key peerKey, seq uint32, minute int64, previous *peer) uint32 {
	var b [65]byte
	local, remote := key.local.Addr().As16(), key.remote.Addr().As16()
	copy(b[:16], local[:])
	copy(b[16:32], remote[:])
	binary.BigEndian.PutUint16(b[32:34], key.local.Port())
	binary.BigEndian.PutUint16(b[34:36], key.remote.Port())
	binary.BigEndian.PutUint32(b[36:40], seq)
	binary.BigEndian.PutUint64(b[40:48], uint64(minute))
	if previous != nil {
		b[48] = 1
		binary.BigEndian.PutUint32(b[49:53], previous.initialSeq)
		binary.BigEndian.PutUint32(b[53:57], previous.remoteInitialSeq)
		binary.BigEndian.PutUint64(b[57:], previous.session)
	}
	h := hmac.New(sha256.New, c.secret[:])
	_, _ = h.Write(b[:])
	return binary.BigEndian.Uint32(h.Sum(nil))
}

func (c *conn) readSegment() (segment, peerKey, error) {
	for {
		data, src, dst, err := c.io.ReadPacket(c.readBuf[:])
		if err != nil {
			return segment{}, peerKey{}, err
		}
		s, ok := parseSegment(data)
		if !ok || s.dstPort != c.io.LocalAddr().Port() || s.srcPort == 0 || !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
			continue
		}
		key := peerKey{netip.AddrPortFrom(dst, s.dstPort), netip.AddrPortFrom(src, s.srcPort)}
		if c.remote.IsValid() && (key.remote != c.remote || key.local != c.client.key.local) {
			continue
		}
		return s, key, nil
	}
}

func retryDeadline(end time.Time) time.Time {
	next := time.Now().Add(250 * time.Millisecond)
	if next.After(end) {
		return end
	}
	return next
}

func (c *conn) handshake() error {
	p := c.client
	end := time.Now().Add(c.config.HandshakeTimeout)
	defer c.io.SetDeadline(time.Time{})
	if err := c.io.SetWriteDeadline(end); err != nil {
		return err
	}
	hello := helloPayload(c.config.Host, p.nonce)
	helloSeq := p.sendSeq
	haveCookie := false
	// Retry SYN as well as hello: another handshake can replace the server
	// generation before our hello arrives, making its previous cookie stale.
	for {
		if !time.Now().Before(end) {
			message := "TCP handshake timed out (check the endpoint and OUTPUT RST firewall rule)"
			if haveCookie {
				message = "FakeTCP handshake timed out"
			}
			return c.opError("dial", p.addr, fmt.Errorf("%s: %w", message, os.ErrDeadlineExceeded))
		}
		if err := c.sendAt(p, p.initialSeq, flagSYN, nil); err != nil {
			return c.opError("dial", p.addr, err)
		}
		if err := c.io.SetReadDeadline(retryDeadline(end)); err != nil {
			return err
		}
		for {
			s, _, err := c.readSegment()
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
				return c.opError("dial", p.addr, err)
			}
			if s.flags&(flagSYN|flagACK|flagRST|flagFIN) == flagSYN|flagACK && s.ack == helloSeq {
				p.remoteInitialSeq = s.seq
				p.recvNext.Store(s.seq + 1)
				haveCookie = true
				if err := c.sendAt(p, helloSeq, flagACK, nil); err != nil {
					return c.opError("dial", p.addr, err)
				}
				if err := c.sendAt(p, helloSeq, flagACK|flagPSH, hello); err != nil {
					return c.opError("dial", p.addr, err)
				}
				continue
			}
			session, welcome := parseWelcome(s.payload, c.config.Host != "", p.nonce)
			if !haveCookie || s.flags&(flagACK|flagSYN|flagRST|flagFIN) != flagACK || s.seq != p.remoteInitialSeq+1 || s.ack != helloSeq+uint32(len(hello)) || !welcome {
				continue
			}
			p.session = session
			p.sendSeq = helloSeq + uint32(len(hello))
			p.recvNext.Store(s.seq + uint32(len(s.payload)))
			p.ready.Store(true)
			if err := c.sendAt(p, p.sendSeq, flagACK, nil); err != nil {
				return c.opError("dial", p.addr, err)
			}
			return nil
		}
	}
}

func (c *conn) findPeer(key peerKey) *peer {
	if c.client != nil {
		return c.client
	}
	c.peersMu.RLock()
	p := c.peers[key]
	c.peersMu.RUnlock()
	return p
}

func (c *conn) sweep(now time.Time) {
	if now.Sub(c.lastSweep) < time.Second {
		return
	}
	c.lastSweep = now
	cutoff := now.Add(-c.config.IdleTimeout).UnixNano()
	c.peersMu.Lock()
	for key, p := range c.peers {
		if p.lastActive.Load() < cutoff {
			delete(c.peers, key)
			delete(c.replies, p.addr)
		}
	}
	c.peersMu.Unlock()
}

// accept handles the control plane in the reader. No per-peer goroutine or
// retransmission queue is needed; the client drives handshake retries.
func (c *conn) accept(s segment, key peerKey) (*peer, error) {
	now := time.Now()
	c.sweep(now)
	if s.flags&(flagSYN|flagACK|flagRST|flagFIN) == flagSYN {
		previous := c.findPeer(key)
		var seq uint32
		if previous != nil && s.seq == previous.remoteInitialSeq {
			// ACK or welcome may have been lost. Reuse this handshake's
			// cookie instead of generating a replacement for the same ISN.
			seq = previous.initialSeq
		} else {
			seq = c.cookie(key, s.seq, now.Unix()/60, previous)
		}
		p, err := c.newPeer(key, seq, s.seq)
		if err != nil {
			return nil, err
		}
		// An unrelated peer must not be able to terminate the shared listener by
		// provoking a route error while it sends a SYN.
		_ = c.replyAt(p, seq, flagSYN|flagACK, nil)
		return nil, nil
	}
	if s.flags&(flagACK|flagSYN|flagRST|flagFIN) != flagACK {
		return nil, nil
	}
	p := c.findPeer(key)
	nonce, http, hello := parseHello(s.payload)
	if p == nil && !hello {
		return nil, nil
	}
	// Reuse of the same four-tuple after a client restart must replace stale
	// state, but only after the new peer proves the SYN cookie. A bare SYN
	// cannot tear down an established QUIC session.
	if p == nil || (hello && (s.seq != p.remoteInitialSeq+1 || s.ack != p.initialSeq+1 || nonce != p.nonce)) {
		seq := s.ack - 1
		minute := now.Unix() / 60
		valid := seq == c.cookie(key, s.seq-1, minute, p) || seq == c.cookie(key, s.seq-1, minute-1, p)
		if !valid {
			if p != nil && s.seq == p.remoteInitialSeq+1 && nonce != p.nonce {
				// A restarted client can reuse its ISN. Challenge its new nonce
				// with a cookie bound to the current session before replacing it.
				seq = c.cookie(key, s.seq-1, minute, p)
				_ = c.replyAt(p, seq, flagSYN|flagACK, nil)
			}
			return nil, nil
		} else {
			c.peersMu.RLock()
			full := p == nil && len(c.peers) >= maxPeers
			c.peersMu.RUnlock()
			if full {
				return nil, nil
			}
			next, err := c.newPeer(key, seq, s.seq-1)
			if err != nil {
				return nil, err
			}
			var session [sessionIDLen]byte
			if _, err := rand.Read(session[:]); err != nil {
				return nil, err
			}
			next.nonce, next.session = nonce, binary.BigEndian.Uint64(session[:])
			c.peersMu.Lock()
			if p != nil {
				delete(c.replies, p.addr)
			}
			c.peers[key] = next
			c.replies[next.addr] = next
			c.peersMu.Unlock()
			p = next
		}
	}
	if len(s.payload) == 0 {
		return nil, nil
	}
	if s.seq == p.remoteInitialSeq+1 {
		if !hello {
			if p.ready.Load() {
				return p, nil
			}
			return nil, nil
		}
		if p.welcome == nil {
			p.helloSeq = s.seq
			p.helloLen = len(s.payload)
			p.welcomeSeq = p.initialSeq + 1
			p.welcome = welcomePayload(http, p.nonce, p.session)
		}
		if s.seq != p.helloSeq || len(s.payload) != p.helloLen {
			return nil, nil
		}
		advanceACK(p, s.seq+uint32(len(s.payload)))
		if err := c.replyAt(p, p.welcomeSeq, flagACK|flagPSH, p.welcome); err != nil {
			return nil, nil
		}
		if !p.ready.Load() {
			// Writers cannot use this peer until ready publishes its send state.
			p.sendSeq = p.welcomeSeq + uint32(len(p.welcome))
			p.ready.Store(true)
		}
		return nil, nil
	}
	if !p.ready.Load() {
		return nil, nil
	}
	return p, nil
}

func (c *conn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.closed.Load() {
			return 0, nil, c.opError("read", nil, net.ErrClosed)
		}
		if len(c.pending) > 0 {
			if deadline := c.readDeadline.Load(); deadline != 0 && time.Now().UnixNano() >= deadline {
				return 0, nil, c.opError("read", nil, os.ErrDeadlineExceeded)
			}
			kind, payload, rest, ok := nextFrame(c.pending)
			if !ok {
				c.pending = nil
				continue
			}
			c.pending = rest
			c.pendingSeq += uint32(frameHeaderLen + len(payload))
			p := c.pendingPeer
			if kind != frameData || len(payload) < sessionIDLen || binary.BigEndian.Uint64(payload) != p.session {
				continue
			}
			// Validate the generation before changing outer ACK/activity.
			// QUIC still handles duplicate, reordered and unauthenticated data.
			advanceACK(p, c.pendingSeq)
			p.lastActive.Store(time.Now().UnixNano())
			return copy(b, payload[sessionIDLen:]), p.addr, nil
		}
		s, key, err := c.readSegment()
		if err != nil {
			return 0, nil, c.opError("read", nil, err)
		}
		var p *peer
		if c.client == nil {
			p, err = c.accept(s, key)
			if err != nil {
				return 0, nil, c.opError("read", nil, err)
			}
			if p == nil {
				continue
			}
		} else {
			p = c.client
			if s.flags&(flagSYN|flagACK|flagRST) == flagSYN|flagACK && s.seq == p.remoteInitialSeq {
				if c.writeMu.TryLock() {
					_ = c.writeAt(p, p.sendSeq, flagACK, nil, true)
					c.writeMu.Unlock()
				}
				continue
			}
			if s.flags&(flagACK|flagSYN|flagRST|flagFIN) != flagACK || len(s.payload) == 0 {
				continue
			}
			// A lost handshake ACK can cause the last response to be duplicated.
			if _, welcome := parseWelcome(s.payload, c.config.Host != "", p.nonce); s.seq == p.remoteInitialSeq+1 && welcome {
				continue
			}
		}
		c.pending, c.pendingPeer = s.payload, p
		c.pendingSeq = s.seq
	}
}

func (c *conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, c.opError("write", addr, errors.New("expected *net.UDPAddr"))
	}
	remote, err := addrPort(a)
	if err != nil {
		return 0, c.opError("write", addr, err)
	}
	if len(b) > c.config.MTU-ipHeaderLen(remote.Addr())-tcpHeaderLen-dataHeaderLen {
		return 0, c.opError("write", addr, syscall.EMSGSIZE)
	}
	if c.closed.Load() {
		return 0, c.opError("write", addr, net.ErrClosed)
	}
	var p *peer
	if c.client != nil {
		if remote != c.remote {
			return 0, c.opError("write", addr, errors.New("address differs from the connected peer"))
		}
		p = c.client
	} else {
		c.peersMu.RLock()
		// QUIC retains the address returned by ReadFrom. Its pointer also keeps
		// the local destination on wildcard listeners, without a global scan
		// or a custom net.Addr that changes QUIC's address-family handling.
		p = c.replies[a]
		if p == nil {
			if !c.io.LocalAddr().Addr().IsUnspecified() {
				p = c.peers[peerKey{c.io.LocalAddr(), remote}]
			} else {
				// Only callers constructing a new address take this fallback.
				// A copied address cannot identify two different local IPs.
				for key, candidate := range c.peers {
					if key.remote != remote {
						continue
					}
					if p != nil {
						p = nil
						break
					}
					p = candidate
				}
			}
		}
		c.peersMu.RUnlock()
	}
	if p == nil || !p.ready.Load() {
		return 0, c.opError("write", addr, errors.New("FakeTCP peer is not established"))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, c.opError("write", addr, net.ErrClosed)
	}
	// Build the data record directly in the send buffer: one payload copy and
	// no packet objects, encryption, intermediate UDP socket, or goroutine hop.
	payload := c.writeBuf[tcpHeaderLen : tcpHeaderLen+dataHeaderLen+len(b)]
	putFrameHeader(payload, frameData, sessionIDLen+len(b))
	binary.BigEndian.PutUint64(payload[frameHeaderLen:], p.session)
	copy(payload[dataHeaderLen:], b)
	// PSH would force Linux software GRO to flush every data segment.
	n := marshalSegment(c.writeBuf[:], p.key.local, p.key.remote, p.sendSeq, p.recvNext.Load(), flagACK, payload, c.config.MTU)
	if err := p.writer.WritePacket(c.writeBuf[:n]); err != nil {
		return 0, c.opError("write", addr, err)
	}
	p.sendSeq += uint32(len(payload))
	p.lastActive.Store(time.Now().UnixNano())
	return len(b), nil
}

func (c *conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	// Close first to wake readers/writers even when they currently hold a lock.
	return c.io.Close()
}
func (c *conn) LocalAddr() net.Addr { return c.local }
func (c *conn) SetDeadline(t time.Time) error {
	c.storeReadDeadline(t)
	return c.io.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.storeReadDeadline(t)
	return c.io.SetReadDeadline(t)
}
func (c *conn) SetWriteDeadline(t time.Time) error { return c.io.SetWriteDeadline(t) }
func (c *conn) SetReadBuffer(n int) error          { return c.io.SetReadBuffer(n) }
func (c *conn) SetWriteBuffer(n int) error         { return c.io.SetWriteBuffer(n) }

var _ net.PacketConn = (*conn)(nil)

func (c *conn) storeReadDeadline(t time.Time) {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
}
