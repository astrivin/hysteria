package cmd

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/apernet/hysteria/core/v2/server"
)

type serverAuxiliaryCleanupProbe struct{ closed atomic.Bool }

func (c *serverAuxiliaryCleanupProbe) Close() error {
	c.closed.Store(true)
	return nil
}

type serverAuxiliaryFatalProbe struct {
	addr     *net.UDPAddr
	result   chan error
	expected string
}

func (p *serverAuxiliaryFatalProbe) OnWrite(entry *zapcore.CheckedEntry, fields []zapcore.Field) {
	if entry.Message != p.expected {
		p.result <- fmt.Errorf("unexpected Fatal: %s", entry.Message)
	} else {
		rebound, err := net.ListenUDP("udp4", p.addr)
		if err == nil {
			_ = rebound.Close()
		} else {
			err = fmt.Errorf("transport still open at %s Fatal: %w", p.expected, err)
		}
		p.result <- err
	}
	// Intercept the real Fatal without exiting the test process. Production's
	// os.Exit does not unwind runServer's deferred cleanup.
	runtime.Goexit()
}

func TestServerAuxiliaryFailureClosesBeforeFatal(t *testing.T) {
	for _, auxiliary := range []string{"trafficStats", "masquerade"} {
		t.Run(auxiliary, func(t *testing.T) {
			transport, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = transport.Close() })
			occupied, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = occupied.Close() })
			probe := &serverAuxiliaryFatalProbe{
				addr:     transport.LocalAddr().(*net.UDPAddr),
				result:   make(chan error, 1),
				expected: "failed to serve traffic stats",
			}
			if auxiliary == "masquerade" {
				probe.expected = "failed to serve masquerade HTTP(S)"
			}
			oldLogger := logger
			logger = zap.NewNop().WithOptions(zap.WithFatalHook(probe))
			t.Cleanup(func() { logger = oldLogger })
			cleanup := &serverAuxiliaryCleanupProbe{}
			hyConfig := &server.Config{Conn: transport, Cleanup: cleanup}
			if auxiliary == "trafficStats" {
				c := serverConfig{TrafficStats: serverConfigTrafficStats{Listen: occupied.Addr().String()}}
				require.NoError(t, c.fillTrafficLogger(hyConfig))
			} else {
				c := serverConfig{Masquerade: serverConfigMasquerade{ListenHTTPS: occupied.Addr().String()}}
				require.NoError(t, c.fillMasqHandler(hyConfig))
			}
			select {
			case err := <-probe.result:
				require.NoError(t, err)
				require.True(t, cleanup.closed.Load(), "additional resources must be closed before Fatal")
			case <-time.After(3 * time.Second):
				t.Fatal("no auxiliary server Fatal observed")
			}
		})
	}
}
