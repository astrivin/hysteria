package cmd

import (
	"net"
	"testing"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type reservedPortClient struct {
	client.Client
	reservation net.Listener
	dialErr     error
	stream      net.Conn
}

func (c *reservedPortClient) TCP(string) (net.Conn, error) { return c.stream, c.dialErr }
func (c *reservedPortClient) Close() error                 { return c.reservation.Close() }

type clientFatalPortProbe struct {
	t       *testing.T
	address string
	message string
	called  bool
}

func (p *clientFatalPortProbe) OnWrite(entry *zapcore.CheckedEntry, fields []zapcore.Field) {
	p.called = true
	if entry.Message != p.message {
		p.t.Errorf("unexpected fatal point: %s %v", entry.Message, fields)
	}
	rebound, err := net.Listen("tcp4", p.address)
	if err != nil {
		p.t.Errorf("speedtest fatal still owns client resource: %v", err)
	} else {
		_ = rebound.Close()
	}
	panic(p)
}

func TestSpeedtestFailureClosesBeforeFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialErr error
		message string
	}{
		{"dial rejection", coreErrs.DialError{Message: "speed test disabled"}, "failed to connect (server may not support speed test)"},
		{"connection closed", coreErrs.ClosedError{}, "failed to connect"},
		{"transfer failure", nil, "download test failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = reservation.Close() })
			c := &reservedPortClient{reservation: reservation, dialErr: tc.dialErr}
			if tc.dialErr == nil {
				var peer net.Conn
				c.stream, peer = net.Pipe()
				require.NoError(t, peer.Close())
				t.Cleanup(func() { _ = c.stream.Close() })
			}
			oldLogger := logger
			t.Cleanup(func() { logger = oldLogger })
			fatal := &clientFatalPortProbe{t: t, address: reservation.Addr().String(), message: tc.message}
			logger = zap.NewNop().WithOptions(zap.WithFatalHook(fatal))
			func() {
				defer func() {
					if got := recover(); got != fatal {
						t.Fatalf("expected fatal interception, got %v", got)
					}
				}()
				runSingleTest(c, true, true)
			}()
			require.True(t, fatal.called)
		})
	}
}
