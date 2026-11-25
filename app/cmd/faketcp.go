package cmd

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/transport/faketcp"
)

type clientConfigTransportFakeTCP struct {
	LocalAddr        string        `mapstructure:"localAddr"`
	MTU              int           `mapstructure:"mtu"`
	Host             string        `mapstructure:"host"`
	HandshakeTimeout time.Duration `mapstructure:"handshakeTimeout"`
}

func (c clientConfigTransportFakeTCP) config() faketcp.Config {
	return faketcp.Config{
		MTU:              c.MTU,
		Host:             c.Host,
		HandshakeTimeout: c.HandshakeTimeout,
	}
}

type serverConfigTransport struct {
	Type    string                       `mapstructure:"type"`
	FakeTCP serverConfigTransportFakeTCP `mapstructure:"faketcp"`
}

type serverConfigTransportFakeTCP struct {
	MTU         int           `mapstructure:"mtu"`
	IdleTimeout time.Duration `mapstructure:"idleTimeout"`
}

func (c serverConfigTransportFakeTCP) config() faketcp.Config {
	return faketcp.Config{
		MTU:         c.MTU,
		IdleTimeout: c.IdleTimeout,
	}
}

func validateFakeTCPOptions(mimicEnabled bool, obfsType string) error {
	if mimicEnabled {
		return configError{Field: "mimic", Err: errors.New("cannot be used with the faketcp transport")}
	}
	switch strings.ToLower(obfsType) {
	case "", "plain":
		return nil
	default:
		return configError{Field: "obfs.type", Err: errors.New("cannot be used with the faketcp transport")}
	}
}

func (c *clientConfig) validateFakeTCP() error {
	if !strings.EqualFold(c.Transport.Type, "faketcp") {
		return nil
	}
	if err := validateFakeTCPOptions(c.Mimic.Enabled, c.Obfs.Type); err != nil {
		return err
	}
	if _, ok, err := c.parseRealmAddr(); ok || err != nil {
		return configError{Field: "server", Err: errors.New("realm cannot be used with the faketcp transport")}
	}
	_, port, _ := parseServerAddrString(c.Server)
	if isPortHoppingPort(port) {
		return configError{Field: "server", Err: errors.New("port hopping cannot be used with the faketcp transport")}
	}
	so := c.QUIC.Sockopts
	if so.BindInterface != nil || so.FirewallMark != nil || so.FdControlUnixSocket != nil {
		return configError{Field: "quic.sockopts", Err: errors.New("UDP socket options cannot be used with the faketcp transport")}
	}
	if err := c.Transport.FakeTCP.config().Validate(); err != nil {
		return configError{Field: "transport.faketcp", Err: err}
	}
	return nil
}

func (c *clientConfig) fillFakeTCPConnFactory(hyConfig *client.Config) error {
	if err := c.validateFakeTCP(); err != nil {
		return err
	}
	addr, ok := hyConfig.ServerAddr.(*net.UDPAddr)
	if !ok {
		return configError{Field: "server", Err: errors.New("faketcp requires a single IP address and port")}
	}
	config := c.Transport.FakeTCP.config()
	localAddr := c.Transport.FakeTCP.LocalAddr
	hyConfig.ConnFactory = &singleUseConnFactory{
		Open: func() (net.PacketConn, error) {
			return faketcp.Dial(localAddr, addr, config)
		},
	}
	return nil
}

func (c *serverConfig) validateFakeTCP() error {
	if err := validateFakeTCPOptions(c.Mimic.Enabled, c.Obfs.Type); err != nil {
		return err
	}
	if _, ok, err := parseServerRealmAddr(c.Listen); ok || err != nil {
		return configError{Field: "listen", Err: errors.New("realm cannot be used with the faketcp transport")}
	}
	if err := c.Transport.FakeTCP.config().Validate(); err != nil {
		return configError{Field: "transport.faketcp", Err: err}
	}
	return nil
}

func (c *serverConfig) fillFakeTCPConn(hyConfig *server.Config) error {
	if err := c.validateFakeTCP(); err != nil {
		return err
	}
	listenAddr := c.Listen
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}
	addr, portUnion, err := resolveServerListenAddr(listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	if len(portUnion) > 0 {
		return configError{Field: "listen", Err: errors.New("port hopping cannot be used with the faketcp transport")}
	}
	conn, err := faketcp.Listen(addr, c.Transport.FakeTCP.config())
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	hyConfig.Conn = conn
	return nil
}
