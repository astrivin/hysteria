package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type blockedPingOutbound struct {
	server.Outbound
	started chan struct{}
	release chan struct{}
}

func (o *blockedPingOutbound) TCP(*server.RequestInfo, string) (net.Conn, error) {
	close(o.started)
	<-o.release
	return nil, errors.New("test destination closed")
}

// The child stays alive after runPing returns. Rebinding its actual UDP port
// proves cleanup occurred before process exit could reclaim the socket.
func TestPingSignalClosesClient(t *testing.T) {
	const helperEnv = "HYSTERIA_TEST_PING_SIGNAL_CONFIG"
	if path := os.Getenv(helperEnv); path != "" {
		logger = zap.NewNop()
		v := viper.New()
		v.SetConfigFile(path)
		runPing(v, "blocked.example:443")
		_, err := fmt.Fprintln(os.Stdout, "ping returned")
		require.NoError(t, err)
		_, err = io.ReadFull(os.Stdin, make([]byte, 1))
		require.NoError(t, err)
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX process signals")
	}
	oldLogger := logger
	logger = zap.NewNop()
	t.Cleanup(func() { logger = oldLogger })
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, err := runCert(certOptions{Hosts: "localhost", CertFile: cert, KeyFile: key, ValidFor: time.Hour})
	require.NoError(t, err)
	sc := serverConfig{Listen: "127.0.0.1:0", TLS: &serverConfigTLS{Cert: cert, Key: key}, Auth: serverConfigAuth{Type: "password", Password: "test"}}
	config, err := sc.Config()
	require.NoError(t, err)
	addresses := make(chan *net.UDPAddr, 1)
	outbound := &blockedPingOutbound{started: make(chan struct{}), release: make(chan struct{})}
	config.Authenticator = &cleanupAddressAuthenticator{addresses: addresses}
	config.Outbound, config.EventLogger, config.DisableUDP = outbound, nil, true
	s, err := server.NewServer(config)
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() { _ = s.Serve(); close(stopped) }()
	t.Cleanup(func() { close(outbound.release); _ = s.Close(); <-stopped })
	path := filepath.Join(dir, "client.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("server: %q\nauth: test\ntls:\n  sni: localhost\n  ca: %q\n", config.Conn.LocalAddr().String(), cert)), 0o600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestPingSignalClosesClient$")
	cmd.Env = append(os.Environ(), helperEnv+"="+path)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	returned := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "ping returned" {
				returned <- true
				return
			}
		}
		returned <- false
	}()
	select {
	case <-outbound.started:
	case <-time.After(10 * time.Second):
		t.Fatal("ping did not reach the blocked destination")
	}
	address := <-addresses
	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	select {
	case ok := <-returned:
		require.True(t, ok, "ping exited instead of returning with resources closed")
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not interrupt ping")
	}
	rebound, err := net.ListenUDP("udp4", address)
	require.NoError(t, err, "ping must release its UDP socket while the process is still alive")
	require.NoError(t, rebound.Close())
	_, err = stdin.Write([]byte{1})
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
}
