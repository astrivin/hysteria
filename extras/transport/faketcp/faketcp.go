// Package faketcp carries unreliable datagrams in raw TCP packets. Reliability
// and congestion control belong to the caller (normally QUIC), not this layer.
// Both endpoints must use this transport; its wire format is not udp2raw's.
package faketcp

import (
	"errors"
	"net"
	"time"
)

const (
	defaultMTU              = 1500
	defaultHandshakeTimeout = 5 * time.Second
	defaultIdleTimeout      = 2 * time.Minute
	tcpHeaderLen            = 20
	frameHeaderLen          = 4
	maxPacketLen            = 65535
	maxPeers                = 4096
)

// Config controls the outer transport, independently of QUIC's TLS settings.
// The application needs CAP_NET_RAW. Before opening the socket, arrange for
// the host firewall to drop kernel-generated TCP RSTs for the chosen endpoint.
// No firewall rules, network interfaces or kernel modules are changed here.
type Config struct {
	// MTU includes the IP header, TCP header and datagram framing.
	MTU int
	// Host adds a small HTTP preface to the client handshake. It is camouflage,
	// not HTTP tunnelling, TLS, WebSocket, or authentication.
	Host             string
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

func (c Config) Validate() error {
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 65535) {
		return errors.New("MTU must be between 1280 and 65535")
	}
	if c.HandshakeTimeout < 0 || c.IdleTimeout < 0 {
		return errors.New("timeouts must not be negative")
	}
	if len(c.Host) > 253 {
		return errors.New("Host must not exceed 253 bytes")
	}
	for _, ch := range c.Host {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']') {
			return errors.New("Host must contain only a hostname or IP address and optional port")
		}
	}
	return nil
}

func (c Config) normalized() (Config, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	if c.MTU == 0 {
		c.MTU = defaultMTU
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	return c, nil
}

// Dial opens a raw TCP endpoint and completes its handshake. localAddr may be
// empty for a route-selected IP and an ephemeral TCP port. Addresses are
// represented as UDPAddr to retain QUIC's address-family/packet-size handling.
func Dial(localAddr string, remote *net.UDPAddr, config Config) (net.PacketConn, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	local, remoteAP, err := resolveDialAddr(localAddr, remote)
	if err != nil {
		return nil, err
	}
	io, err := openSocket(local)
	if err != nil {
		return nil, err
	}
	c, err := newConn(io, config, remoteAP)
	if err != nil {
		_ = io.Close()
		return nil, err
	}
	if err := c.handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Listen opens a server endpoint. An unspecified address defaults to IPv4;
// use [::]:port explicitly for an IPv6-only endpoint.
func Listen(localAddr *net.UDPAddr, config Config) (net.PacketConn, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if config.Host != "" {
		return nil, errors.New("Host is a client-only option")
	}
	local, err := listenAddr(localAddr)
	if err != nil {
		return nil, err
	}
	io, err := openSocket(local)
	if err != nil {
		return nil, err
	}
	c, err := newConn(io, config, zeroAddrPort)
	if err != nil {
		_ = io.Close()
		return nil, err
	}
	return c, nil
}
