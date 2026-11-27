package cmd

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/firewall"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/transport/faketcp"
)

type clientConfigTransportFakeTCP struct {
	AutoFirewall     bool          `mapstructure:"autoFirewall"`
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
	AutoFirewall bool          `mapstructure:"autoFirewall"`
	MTU          int           `mapstructure:"mtu"`
	IdleTimeout  time.Duration `mapstructure:"idleTimeout"`
}

func (c serverConfigTransportFakeTCP) config() faketcp.Config {
	return faketcp.Config{
		MTU:         c.MTU,
		IdleTimeout: c.IdleTimeout,
	}
}

// Rules belong to the application, not to individual reconnect attempts. Keep
// the resolved destination fixed for this run so reconnects stay within the
// startup rule, while Dial continues to select the current local source IP.
func (c *clientConfig) startFakeTCPFirewall() (io.Closer, error) {
	if !strings.EqualFold(c.Transport.Type, "faketcp") || !c.Transport.FakeTCP.AutoFirewall {
		return nil, nil
	}
	c.parseURI()
	if err := c.validateFakeTCP(); err != nil {
		return nil, err
	}
	hyConfig := &client.Config{}
	if err := c.fillServerAddr(hyConfig); err != nil {
		return nil, err
	}
	addr := hyConfig.ServerAddr.(*net.UDPAddr)
	cleanup, err := firewall.SetupFakeTCP(addr.AddrPort(), false)
	if err != nil {
		return nil, configError{Field: "transport.faketcp.autoFirewall", Err: err}
	}
	if c.TLS.SNI == "" {
		c.TLS.SNI = hyConfig.TLSConfig.ServerName
	}
	c.Server = addr.String()
	return cleanup, nil
}

func closeFakeTCPFirewall(cleanup io.Closer) error {
	if cleanup == nil {
		return nil
	}
	err := cleanup.Close()
	if err != nil {
		logger.Error("failed to remove FakeTCP firewall rule", zap.Error(err))
	}
	return err
}

// Wrap only the outer reconnectable client. Its internal transport closes do
// not remove the process rule, including when a handshake or network fails.
type fakeTCPFirewallClient struct {
	client.Client
	cleanup io.Closer
}

func withFakeTCPFirewall(c client.Client, cleanup io.Closer) client.Client {
	if cleanup == nil {
		return c
	}
	return &fakeTCPFirewallClient{Client: c, cleanup: cleanup}
}

func (c *fakeTCPFirewallClient) Close() error {
	return errors.Join(c.Client.Close(), closeFakeTCPFirewall(c.cleanup))
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
	if c.Transport.FakeTCP.AutoFirewall {
		cleanup, err := firewall.SetupFakeTCP(conn.LocalAddr().(*net.UDPAddr).AddrPort(), true)
		if err != nil {
			_ = conn.Close()
			return configError{Field: "transport.faketcp.autoFirewall", Err: err}
		}
		hyConfig.Cleanup = cleanup
	}
	hyConfig.Conn = conn
	return nil
}
