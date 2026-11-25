package cmd

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/transport/faketcp"
)

func TestFakeTCPClientConfig(t *testing.T) {
	c := clientConfig{
		Server: "127.0.0.1:8443",
		Transport: clientConfigTransport{
			Type: "faketcp",
			FakeTCP: clientConfigTransportFakeTCP{
				LocalAddr:        "127.0.0.1:30443",
				MTU:              1280,
				Host:             "cover.example.org",
				HandshakeTimeout: 8 * time.Second,
			},
		},
		TLS: clientConfigTLS{SNI: "tunnel.example.org"},
	}
	hyConfig, err := c.Config()
	require.NoError(t, err)
	assert.Equal(t, "tunnel.example.org", hyConfig.TLSConfig.ServerName)
	assert.Equal(t, "127.0.0.1:8443", hyConfig.ServerAddr.String())
	assert.True(t, hyConfig.QUICConfig.DisableGSO)
	assert.True(t, hyConfig.QUICConfig.DisableChromeParrot)
	assert.Equal(t, uint16(1200), hyConfig.QUICConfig.InitialPacketSize)
	assert.False(t, hyConfig.QUICConfig.DisablePathMTUDiscovery)
	// Loading a config must not require raw socket permissions. Allocation is
	// deferred to the factory, including on reconnects.
	require.IsType(t, &singleUseConnFactory{}, hyConfig.ConnFactory)
	assert.Equal(t, faketcp.Config{
		MTU:              1280,
		Host:             "cover.example.org",
		HandshakeTimeout: 8 * time.Second,
	}, c.Transport.FakeTCP.config())
}

func TestFakeTCPClientIncompatibleOptions(t *testing.T) {
	tests := []struct {
		name   string
		change func(*clientConfig)
		field  string
	}{
		{"mimic", func(c *clientConfig) { c.Mimic.Enabled = true }, "mimic"},
		{"realm", func(c *clientConfig) { c.Server = "realm://token@example.com/realm" }, "server"},
		{"malformed realm", func(c *clientConfig) { c.Server = "realm://example.com/realm" }, "server"},
		{"port hopping", func(c *clientConfig) { c.Server = "127.0.0.1:8000-9000" }, "server"},
		{"URI port hopping", func(c *clientConfig) { c.Server = "hy2://token@127.0.0.1:8000-9000/" }, "server"},
		{"obfs", func(c *clientConfig) { c.Obfs.Type = "salamander" }, "obfs.type"},
		{"URI obfs", func(c *clientConfig) { c.Server = "hy2://token@127.0.0.1:8443/?obfs=gecko" }, "obfs.type"},
		{"interface", func(c *clientConfig) { c.QUIC.Sockopts.BindInterface = stringRef("eth0") }, "quic.sockopts"},
		{"mark", func(c *clientConfig) { c.QUIC.Sockopts.FirewallMark = uint32Ref(1) }, "quic.sockopts"},
		{"fd control", func(c *clientConfig) { c.QUIC.Sockopts.FdControlUnixSocket = stringRef("control.sock") }, "quic.sockopts"},
		{"small MTU", func(c *clientConfig) { c.Transport.FakeTCP.MTU = 1279 }, "transport.faketcp"},
		{"invalid Host", func(c *clientConfig) { c.Transport.FakeTCP.Host = "example.com\r\nX-Test: injected" }, "transport.faketcp"},
		{"negative timeout", func(c *clientConfig) { c.Transport.FakeTCP.HandshakeTimeout = -time.Second }, "transport.faketcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientConfig{Server: "127.0.0.1:8443", Transport: clientConfigTransport{Type: "faketcp"}}
			tt.change(&c)
			_, err := c.Config()
			var configErr configError
			require.ErrorAs(t, err, &configErr)
			assert.Equal(t, tt.field, configErr.Field)
		})
	}
}

func TestFakeTCPMimicRejectedBeforeStartup(t *testing.T) {
	c := clientConfig{Server: "127.0.0.1:8443", Transport: clientConfigTransport{Type: "FakeTCP"}, Mimic: mimicConfig{Enabled: true}}
	require.ErrorContains(t, c.validateMimic(), "cannot be used with the faketcp transport")
}

func TestFakeTCPServerIncompatibleOptions(t *testing.T) {
	tests := []struct {
		name   string
		change func(*serverConfig)
		field  string
	}{
		{"mimic", func(c *serverConfig) { c.Mimic.Enabled = true }, "mimic"},
		{"realm", func(c *serverConfig) { c.Listen = "realm://token@example.com/realm" }, "listen"},
		{"port hopping", func(c *serverConfig) { c.Listen = "127.0.0.1:8000-9000" }, "listen"},
		{"obfs", func(c *serverConfig) { c.Obfs.Type = "gecko" }, "obfs.type"},
		{"small MTU", func(c *serverConfig) { c.Transport.FakeTCP.MTU = 1279 }, "transport.faketcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := serverConfig{Listen: "127.0.0.1:8443", Transport: serverConfigTransport{Type: "faketcp"}}
			tt.change(&c)
			err := c.fillConn(&server.Config{})
			var configErr configError
			require.ErrorAs(t, err, &configErr)
			assert.Equal(t, tt.field, configErr.Field)
		})
	}
}

func TestFakeTCPServerQUICConfig(t *testing.T) {
	c := serverConfig{Transport: serverConfigTransport{Type: "FakeTCP"}}
	hyConfig := &server.Config{}
	require.NoError(t, c.fillQUICConfig(hyConfig))
	assert.True(t, hyConfig.QUICConfig.DisableGSO)
	assert.Equal(t, uint16(1200), hyConfig.QUICConfig.InitialPacketSize)
	assert.False(t, hyConfig.QUICConfig.DisablePathMTUDiscovery)
}

func TestTransportDefaultRemainsUDP(t *testing.T) {
	for _, transportType := range []string{"", "udp"} {
		t.Run(transportType, func(t *testing.T) {
			cc := clientConfig{Server: "127.0.0.1:8443", Transport: clientConfigTransport{Type: transportType}}
			hyClient, err := cc.Config()
			require.NoError(t, err)
			assert.False(t, hyClient.QUICConfig.DisableGSO)
			assert.False(t, hyClient.QUICConfig.DisableChromeParrot)
			assert.Zero(t, hyClient.QUICConfig.InitialPacketSize)
			conn, err := hyClient.ConnFactory.New(hyClient.ServerAddr)
			require.NoError(t, err)
			defer conn.Close()
			assert.IsType(t, &net.UDPConn{}, conn)

			sc := serverConfig{Listen: "127.0.0.1:0", Transport: serverConfigTransport{Type: transportType}}
			hyServer := &server.Config{}
			require.NoError(t, sc.fillConn(hyServer))
			defer hyServer.Conn.Close()
			assert.IsType(t, &net.UDPConn{}, hyServer.Conn)
			require.NoError(t, sc.fillQUICConfig(hyServer))
			assert.Zero(t, hyServer.QUICConfig.InitialPacketSize)
		})
	}
}

func TestUnknownServerTransport(t *testing.T) {
	c := serverConfig{Transport: serverConfigTransport{Type: "unknown"}}
	err := c.fillConn(&server.Config{})
	var configErr configError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "transport.type", configErr.Field)
}

func TestFakeTCPFactoryRequiresSingleAddress(t *testing.T) {
	c := clientConfig{Transport: clientConfigTransport{Type: "faketcp"}}
	err := c.fillFakeTCPConnFactory(&client.Config{ServerAddr: &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}})
	require.ErrorContains(t, err, "single IP address and port")
}

func TestServerConfigClosesConnOnError(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := probe.LocalAddr().(*net.UDPAddr)
	require.NoError(t, probe.Close())

	c := serverConfig{Listen: addr.String()}
	_, err = c.Config()
	var configErr configError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "tls", configErr.Field)
	// A later config error must release the transport opened by fillConn.
	conn, err := net.ListenUDP("udp4", addr)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}
