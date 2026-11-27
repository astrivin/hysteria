//go:build linux

package cmd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/apernet/hysteria/core/v2/client"
)

func TestFakeTCPFirewallDisabledPreservesConfig(t *testing.T) {
	commands := fakeTCPFirewallCommandLog(t, "iptables")
	queries, _ := fakeTCPFirewallDNS(t)
	for _, transport := range []clientConfigTransport{
		{Type: "faketcp"},
		{Type: "udp", FakeTCP: clientConfigTransportFakeTCP{AutoFirewall: true}},
		{FakeTCP: clientConfigTransportFakeTCP{AutoFirewall: true}},
	} {
		for _, address := range []string{
			"hy2://uri-auth@server.faketcp.invalid:7443/?sni=uri.example.org",
			"server.faketcp.invalid:not-a-port",
		} {
			c := clientConfig{Server: address, Auth: "original-auth", Transport: transport}
			before := c
			cleanup, err := c.startFakeTCPFirewall()
			require.NoError(t, err)
			assert.Nil(t, cleanup)
			assert.Equal(t, before, c, "disabled setup must preserve lazy URI/config evaluation")
		}
	}
	assert.Empty(t, commands())
	assert.Zero(t, queries.Load())
}

func TestFakeTCPFirewallPinsDestinationPreservingTLS(t *testing.T) {
	for _, backend := range []string{"iptables", "nftables"} {
		t.Run(backend, func(t *testing.T) {
			for _, tt := range []struct {
				name, address, sni, wantSNI, wantAuth string
				insecure                              bool
			}{
				{"hostname", "server.faketcp.invalid:7443", "", "server.faketcp.invalid", "config-auth", false},
				{"explicit SNI", "server.faketcp.invalid:7443", "tls.example.org", "tls.example.org", "config-auth", false},
				{"URI hostname", "hy2://uri-auth@server.faketcp.invalid:7443/", "", "server.faketcp.invalid", "uri-auth", false},
				{"URI options", "hysteria2://user:p%40ss%3Aword@server.faketcp.invalid:7443/?sni=uri.example.org&insecure=1", "config.example.org", "uri.example.org", "user:p@ss:word", true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					commands := fakeTCPFirewallCommandLog(t, backend)
					queries, dnsAddress := fakeTCPFirewallDNS(t)
					c := clientConfig{
						Server: tt.address,
						Auth:   "config-auth",
						Transport: clientConfigTransport{
							Type: "FakeTCP",
							FakeTCP: clientConfigTransportFakeTCP{
								AutoFirewall: true,
								LocalAddr:    ":37777",
								Host:         "cover.example.org",
							},
						},
						TLS: clientConfigTLS{SNI: tt.sni},
					}
					transport := c.Transport
					cleanup, err := c.startFakeTCPFirewall()
					require.NoError(t, err)
					require.NotNil(t, cleanup)
					t.Cleanup(func() { assert.NoError(t, cleanup.Close()) })
					assert.Equal(t, "192.0.2.10:7443", c.Server)
					assert.Equal(t, tt.wantSNI, c.TLS.SNI)
					assert.Equal(t, transport, c.Transport, "source address and outer Host must remain unchanged")
					installed := commands()
					require.NotEmpty(t, installed)
					rules := strings.Join(installed, "\n")
					assert.Contains(t, rules, "<192.0.2.10>", "the client rule must match the resolved destination")
					assert.Contains(t, rules, "<7443>")
					assert.NotContains(t, rules, "<37777>", "the client rule must not bind the local port")
					resolved := queries.Load()
					require.Positive(t, resolved)

					// A DNS change must not move a reconnect outside the startup rule.
					// Reconnects still need a fresh, unused transport factory.
					dnsAddress.Store(netip.MustParseAddr("192.0.2.20"))
					factories := make(map[*singleUseConnFactory]bool)
					for range 3 {
						hyConfig, err := c.Config()
						require.NoError(t, err)
						assert.Equal(t, c.Server, hyConfig.ServerAddr.String())
						assert.Equal(t, tt.wantSNI, hyConfig.TLSConfig.ServerName)
						assert.Equal(t, tt.insecure, hyConfig.TLSConfig.InsecureSkipVerify)
						assert.Equal(t, tt.wantAuth, hyConfig.Auth)
						factory, ok := hyConfig.ConnFactory.(*singleUseConnFactory)
						require.True(t, ok)
						assert.False(t, factories[factory], "each reconnect needs its own factory")
						assert.False(t, factory.used)
						factories[factory] = true
					}
					assert.Equal(t, resolved, queries.Load(), "reconnect must not resolve the destination again")
					assert.Equal(t, installed, commands(), "building reconnect configs must not alter firewall rules")
				})
			}
		})
	}
}

func TestFakeTCPFirewallRejectsIncompatibleStartup(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*clientConfig)
	}{
		{"URI port hopping", func(c *clientConfig) { c.Server = "hy2://auth@127.0.0.1:7000-7777/" }},
		{"URI obfs", func(c *clientConfig) { c.Server = "hy2://auth@127.0.0.1:7443/?obfs=salamander&obfs-password=secret" }},
		{"mimic", func(c *clientConfig) { c.Mimic.Enabled = true }},
		{"invalid address", func(c *clientConfig) { c.Server = "127.0.0.1:not-a-port" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			commands := fakeTCPFirewallCommandLog(t, "iptables")
			c := fakeTCPFirewallTestConfig()
			tt.change(&c)
			cleanup, err := c.startFakeTCPFirewall()
			require.Error(t, err)
			assert.Nil(t, cleanup)
			assert.Empty(t, commands(), "invalid startup must not install a rule")
		})
	}
}

func TestFakeTCPFirewallSurvivesReconnectFailures(t *testing.T) {
	for _, backend := range []string{"iptables", "nftables"} {
		t.Run(backend, func(t *testing.T) {
			commands := fakeTCPFirewallCommandLog(t, backend)
			config := fakeTCPFirewallTestConfig()
			cleanup, err := config.startFakeTCPFirewall()
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, cleanup.Close()) })
			installed := commands()
			require.NotEmpty(t, installed)
			connectErr := errors.New("controlled reconnect failure")
			attempts := 0
			rc, err := client.NewReconnectableClient(func() (*client.Config, error) {
				attempts++
				_, err := config.Config()
				require.NoError(t, err)
				return nil, connectErr
			}, nil, true)
			require.NoError(t, err)
			c := withFakeTCPFirewall(rc, cleanup)
			t.Cleanup(func() { assert.NoError(t, c.Close()) })
			for range 3 {
				_, err = c.TCP("destination.example.org:443")
				assert.ErrorIs(t, err, connectErr)
				_, err = c.UDP()
				assert.ErrorIs(t, err, connectErr)
				assert.Equal(t, installed, commands())
			}
			assert.Equal(t, 6, attempts)
			require.NoError(t, c.Close())
			closed := commands()
			require.Len(t, closed, len(installed)+1, "only final client Close removes the process rule")
			if backend == "iptables" {
				assert.Contains(t, closed[len(closed)-1], "<-D> <OUTPUT>")
			} else {
				assert.Contains(t, closed[len(closed)-1], "<delete> <table>")
			}
			require.NoError(t, c.Close())
			require.NoError(t, cleanup.Close())
			assert.Equal(t, closed, commands(), "repeated shutdown must not remove another process's rule")
			_, err = c.TCP("destination.example.org:443")
			require.Error(t, err)
			assert.Equal(t, 6, attempts, "a closed outer client must not restart")
		})
	}
}

func TestFakeTCPFirewallClosesAfterClientError(t *testing.T) {
	commands := fakeTCPFirewallCommandLog(t, "iptables")
	config := fakeTCPFirewallTestConfig()
	cleanup, err := config.startFakeTCPFirewall()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, cleanup.Close()) })
	installed := commands()
	closeErr := errors.New("controlled client close failure")
	c := withFakeTCPFirewall(&fakeTCPFirewallCloseClient{close: func() error {
		assert.Equal(t, installed, commands(), "close the client before removing its process rule")
		return closeErr
	}}, cleanup)
	assert.ErrorIs(t, c.Close(), closeErr)
	assert.Len(t, commands(), len(installed)+1, "client errors must not skip firewall cleanup")
}

type fakeTCPFirewallCloseClient struct {
	client.Client
	close func() error
}

func (c *fakeTCPFirewallCloseClient) Close() error { return c.close() }

func fakeTCPFirewallTestConfig() clientConfig {
	return clientConfig{
		Server: "127.0.0.1:7443",
		Transport: clientConfigTransport{
			Type:    "faketcp",
			FakeTCP: clientConfigTransportFakeTCP{AutoFirewall: true},
		},
	}
}

// Use actual exec calls, but only allow these unprivileged recording commands.
func fakeTCPFirewallCommandLog(t *testing.T, backend string) func() []string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	const script = `#!/bin/sh
{ printf '%s' "${0##*/}"; printf ' <%s>' "$@"; printf '\n'; } >> "$HYSTERIA_TEST_FIREWALL_LOG"
`
	for _, name := range []string{"iptables", "ip6tables", "nft"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700))
	}
	t.Setenv("PATH", dir)
	t.Setenv("HYSTERIA_TEST_FIREWALL_LOG", logPath)
	t.Setenv("HYSTERIA_FIREWALL_BACKEND", backend)
	return func() []string {
		data, err := os.ReadFile(logPath)
		if os.IsNotExist(err) {
			return nil
		}
		require.NoError(t, err)
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

// A local DNS responder keeps the tests independent of public DNS and lets
// them change the answer after startup without changing the system resolver.
func fakeTCPFirewallDNS(t *testing.T) (*atomic.Int32, *atomic.Value) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	var queries atomic.Int32
	var address atomic.Value
	address.Store(netip.MustParseAddr("192.0.2.10"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if !assert.NoError(t, request.Unpack(buf[:n])) {
				return
			}
			queries.Add(1)
			response := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 request.ID,
					Response:           true,
					RecursionDesired:   request.RecursionDesired,
					RecursionAvailable: true,
				},
				Questions: request.Questions,
			}
			for _, question := range request.Questions {
				if question.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
						Body:   &dnsmessage.AResource{A: address.Load().(netip.Addr).As4()},
					})
				}
			}
			data, err := response.Pack()
			if !assert.NoError(t, err) {
				return
			}
			if _, err = conn.WriteToUDP(data, peer); !assert.NoError(t, err) {
				return
			}
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp4", conn.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = previous
		_ = conn.Close()
		<-done
	})
	return &queries, &address
}
