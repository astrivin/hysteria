package client

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

type reconnectTestClient struct {
	err       error
	closeFunc func() error
}

func (c *reconnectTestClient) TCP(string) (net.Conn, error) { return nil, c.err }
func (c *reconnectTestClient) UDP() (HyUDPConn, error)      { return nil, c.err }
func (c *reconnectTestClient) Close() error                 { return c.closeFunc() }

func reserveReconnectTestPort(t *testing.T, addr *net.TCPAddr) *net.TCPListener {
	t.Helper()
	conn, err := net.ListenTCP("tcp4", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestReconnectableClientReleasesClosedClientPort(t *testing.T) {
	for _, method := range []string{"TCP", "UDP"} {
		for _, closeError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/closeError=%t", method, closeError), func(t *testing.T) {
				reserved := reserveReconnectTestPort(t, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				addr := reserved.Addr().(*net.TCPAddr)
				closeCalls := 0
				old := &reconnectTestClient{
					err: coreErrs.ClosedError{},
					closeFunc: func() error {
						closeCalls++
						err := reserved.Close()
						if closeError {
							return errors.New("cleanup error")
						}
						return err
					},
				}
				attempts := 0
				nextAttemptErr := errors.New("stop after reserving the same port")
				rc := &reconnectableClientImpl{
					client: old,
					configFunc: func() (*Config, error) {
						attempts++
						// A reconnect must release the old transport's port before
						// evaluating or opening the replacement connection.
						replacement, err := net.ListenTCP("tcp4", addr)
						if err != nil {
							return nil, fmt.Errorf("reserve TCP port: %w", err)
						}
						_ = replacement.Close()
						return nil, nextAttemptErr
					},
				}
				t.Cleanup(func() { _ = rc.Close() })
				call := func() error {
					if method == "TCP" {
						_, err := rc.TCP("unused:80")
						return err
					}
					_, err := rc.UDP()
					return err
				}

				assert.Equal(t, coreErrs.ClosedError{}, call())
				assert.Equal(t, 1, closeCalls)
				for range 3 {
					assert.ErrorIs(t, call(), nextAttemptErr)
				}
				assert.Equal(t, 3, attempts)
				assert.Equal(t, 1, closeCalls)
			})
		}
	}
}

func TestReconnectableClientIgnoresRetiredClientFailure(t *testing.T) {
	reserved := reserveReconnectTestPort(t, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	oldCloseCalls := 0
	old := &reconnectTestClient{
		err: coreErrs.ClosedError{},
		closeFunc: func() error {
			oldCloseCalls++
			return reserved.Close()
		},
	}
	rc := &reconnectableClientImpl{client: old}
	entered := make(chan struct{})
	release := make(chan struct{})
	releaseCall := sync.OnceFunc(func() { close(release) })
	done := make(chan struct{})
	var lateErr error
	go func() {
		_, lateErr = rc.clientDo(func(Client) (interface{}, error) {
			close(entered)
			<-release
			return nil, coreErrs.ClosedError{}
		})
		close(done)
	}()
	defer func() {
		releaseCall()
		<-done
		_ = rc.Close()
	}()
	<-entered

	_, err := rc.TCP("unused:80")
	assert.Equal(t, coreErrs.ClosedError{}, err)
	replacement := reserveReconnectTestPort(t, reserved.Addr().(*net.TCPAddr))
	newCloseCalls := 0
	current := &reconnectTestClient{
		closeFunc: func() error {
			newCloseCalls++
			return replacement.Close()
		},
	}
	rc.m.Lock()
	rc.client = current
	rc.m.Unlock()
	releaseCall()
	<-done
	assert.Equal(t, coreErrs.ClosedError{}, lateErr)
	assert.Same(t, current, rc.client)
	assert.Equal(t, 1, oldCloseCalls)
	assert.Zero(t, newCloseCalls)
}

func TestReconnectableClientKeepsClientAfterDialError(t *testing.T) {
	closeCalls := 0
	client := &reconnectTestClient{
		err: coreErrs.DialError{Message: "target refused the request"},
		closeFunc: func() error {
			closeCalls++
			return nil
		},
	}
	rc := &reconnectableClientImpl{client: client}
	defer rc.Close()
	_, err := rc.TCP("unused:80")
	assert.Equal(t, client.err, err)
	assert.Same(t, client, rc.client)
	assert.Zero(t, closeCalls)
}
