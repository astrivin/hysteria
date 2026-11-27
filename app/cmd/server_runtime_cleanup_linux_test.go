//go:build linux

package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type serverRuntimeFatal struct {
	message string
	cleaned bool
}

type serverRuntimeFatalProbe struct {
	done   string
	result chan serverRuntimeFatal
}

func (p *serverRuntimeFatalProbe) OnWrite(entry *zapcore.CheckedEntry, fields []zapcore.Field) {
	_, err := os.Stat(p.done)
	p.result <- serverRuntimeFatal{entry.Message, err == nil}
	runtime.Goexit()
}

func TestServerServeFailureWaitsForCleanup(t *testing.T) {
	dir := t.TempDir()
	started, release, done := filepath.Join(dir, "started"), filepath.Join(dir, "release"), filepath.Join(dir, "done")
	// Replace only the external firewall command. Real runServer, QUIC, UDP
	// sockets, port-range cleanup and the auxiliary bind failure still execute.
	const nft = `#!/bin/sh
if [ "$1" = delete ] && [ "$2" = table ]; then
  : > "$HY2_TEST_NFT_STARTED"
  tries=0
  while [ ! -e "$HY2_TEST_NFT_RELEASE" ]; do
    tries=$((tries+1))
    [ "$tries" -lt 1000 ] || exit 1
    sleep 0.01
  done
  : > "$HY2_TEST_NFT_DONE"
fi
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nft"), []byte(nft), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HYSTERIA_FIREWALL_BACKEND", "nft")
	t.Setenv("HY2_TEST_NFT_STARTED", started)
	t.Setenv("HY2_TEST_NFT_RELEASE", release)
	t.Setenv("HY2_TEST_NFT_DONE", done)
	releaseCleanup := sync.OnceFunc(func() { _ = os.WriteFile(release, nil, 0o600) })
	defer releaseCleanup()

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := udp.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, udp.Close())
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	oldLogger, oldUpdateCheck := logger, disableUpdateCheck
	logger, disableUpdateCheck = zap.NewNop(), true
	t.Cleanup(func() { logger, disableUpdateCheck = oldLogger, oldUpdateCheck })
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, err = runCert(certOptions{Hosts: "localhost", CertFile: cert, KeyFile: key, ValidFor: time.Hour})
	require.NoError(t, err)
	configPath := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf("listen: \"127.0.0.1:%d-%d\"\ntls:\n  cert: %q\n  key: %q\nauth:\n  type: password\n  password: test\ntrafficStats:\n  listen: %q\n", port, port+1, cert, key, occupied.Addr().String())
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
	v := viper.New()
	v.SetConfigFile(configPath)
	up := make(chan struct{})
	probe := &serverRuntimeFatalProbe{done: done, result: make(chan serverRuntimeFatal, 2)}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(io.Discard), zap.InfoLevel)
	logger = zap.New(core, zap.WithFatalHook(probe), zap.Hooks(func(entry zapcore.Entry) error {
		switch entry.Message {
		case "traffic stats server up and running":
			<-up
		case "server up and running":
			close(up)
		}
		return nil
	}))
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		runServer(v)
	}()
	// Delay deletion long enough to exercise the competing Serve error path.
	// Always release it, including if an assertion fails, so no command hangs.
	controllerDone := make(chan struct{})
	go func() {
		defer close(controllerDone)
		defer releaseCleanup()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if _, err := os.Stat(started); err == nil {
					<-time.After(100 * time.Millisecond)
					return
				}
			case <-deadline.C:
				return
			}
		}
	}()
	for range 2 {
		select {
		case result := <-probe.result:
			require.Contains(t, []string{"failed to serve", "failed to serve traffic stats"}, result.message)
			if !result.cleaned {
				t.Errorf("Fatal %q ran before firewall cleanup completed", result.message)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("server did not finish both failure paths")
		}
	}
	<-runDone
	<-controllerDone
}
