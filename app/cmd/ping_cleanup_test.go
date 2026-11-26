package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type cleanupAddressAuthenticator struct{ addresses chan *net.UDPAddr }

func (a *cleanupAddressAuthenticator) Authenticate(addr net.Addr, _ string, _ uint64) (bool, string) {
	a.addresses <- addr.(*net.UDPAddr)
	return true, "review"
}

type cleanupRejectedOutbound struct{ server.Outbound }

func (*cleanupRejectedOutbound) TCP(*server.RequestInfo, string) (net.Conn, error) {
	return nil, errors.New("controlled destination rejection")
}

type pingFatalPortProbe struct {
	t         *testing.T
	addresses chan *net.UDPAddr
	called    bool
}

func (p *pingFatalPortProbe) OnWrite(entry *zapcore.CheckedEntry, fields []zapcore.Field) {
	p.called = true
	if entry.Message != "failed to connect" {
		p.t.Errorf("unexpected fatal point: %s %v", entry.Message, fields)
	}
	select {
	case address := <-p.addresses:
		rebound, err := net.ListenUDP("udp4", address)
		if err != nil {
			p.t.Errorf("ping fatal still owns authenticated client's UDP socket: %v", err)
		} else {
			_ = rebound.Close()
		}
	default:
		p.t.Error("client did not complete Hysteria authentication")
	}
	panic(p)
}

func TestPingFailureClosesBeforeFatal(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = oldLogger })
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, err := runCert(certOptions{Hosts: "localhost", CertFile: cert, KeyFile: key, ValidFor: time.Hour})
	require.NoError(t, err)
	sc := serverConfig{Listen: "127.0.0.1:0", TLS: &serverConfigTLS{Cert: cert, Key: key}, Auth: serverConfigAuth{Type: "password", Password: "test"}}
	serverConfig, err := sc.Config()
	require.NoError(t, err)
	addresses := make(chan *net.UDPAddr, 1)
	serverConfig.Authenticator = &cleanupAddressAuthenticator{addresses: addresses}
	serverConfig.Outbound = &cleanupRejectedOutbound{}
	serverConfig.DisableUDP = true
	// The server fixture does not use the CLI logger that this test replaces.
	serverConfig.EventLogger = nil
	s, err := server.NewServer(serverConfig)
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() { _ = s.Serve(); close(stopped) }()
	t.Cleanup(func() { _ = s.Close(); <-stopped })
	configPath := filepath.Join(dir, "client.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf("server: %q\nauth: test\ntls:\n  sni: localhost\n  ca: %q\n", serverConfig.Conn.LocalAddr().String(), cert)), 0o600))
	v := viper.New()
	v.SetConfigFile(configPath)
	fatal := &pingFatalPortProbe{t: t, addresses: addresses}
	logger = zap.NewNop().WithOptions(zap.WithFatalHook(fatal))
	func() {
		defer func() {
			if got := recover(); got != fatal {
				t.Fatalf("expected fatal interception, got %v", got)
			}
		}()
		runPing(v, "rejected.example:443")
	}()
	require.True(t, fatal.called)
}
