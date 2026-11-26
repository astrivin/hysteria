package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type serverFatalPortProbe struct {
	t      *testing.T
	addr   *net.UDPAddr
	called bool
}

func (p *serverFatalPortProbe) OnWrite(entry *zapcore.CheckedEntry, fields []zapcore.Field) {
	p.called = true
	if entry.Message != "failed to initialize server" {
		p.t.Errorf("unexpected fatal point: %s %v", entry.Message, fields)
	}
	// Probe before Fatal could terminate the process or run any artificial
	// test unwind. A cleanup placed only in defer would not run on os.Exit.
	rebound, err := net.ListenUDP("udp4", p.addr)
	if err != nil {
		p.t.Errorf("server initialization failure still owns UDP socket at Fatal: %v", err)
	} else {
		_ = rebound.Close()
	}
	panic(p)
}

func TestServerInitFailureClosesBeforeFatal(t *testing.T) {
	oldLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = oldLogger })
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := probe.LocalAddr().(*net.UDPAddr)
	require.NoError(t, probe.Close())
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, err = runCert(certOptions{Hosts: "localhost", CertFile: cert, KeyFile: key, ValidFor: time.Hour})
	require.NoError(t, err)
	config := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("listen: %q\ntls:\n  cert: %q\n  key: %q\nauth:\n  type: password\n  password: test\nquic:\n  maxIdleTimeout: 1s\n", addr.String(), cert, key)), 0o600))
	v := viper.New()
	v.SetConfigFile(config)
	fatal := &serverFatalPortProbe{t: t, addr: addr}
	logger = zap.NewNop().WithOptions(zap.WithFatalHook(fatal))
	func() {
		defer func() {
			if got := recover(); got != fatal {
				t.Fatalf("expected interception at real Fatal call, got %v", got)
			}
		}()
		runServer(v)
	}()
	require.True(t, fatal.called)
}
