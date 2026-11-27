//go:build !linux

package firewall

import (
	"errors"
	"io"
	"net/netip"
)

func SetupFakeTCP(endpoint netip.AddrPort, server bool) (io.Closer, error) {
	return nil, errors.New("automatic FakeTCP firewall rules are only supported on Linux")
}
