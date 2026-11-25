//go:build !linux

package faketcp

import (
	"errors"
	"net/netip"
)

func openSocket(netip.AddrPort) (packetIO, error) {
	return nil, errors.New("native FakeTCP is supported only on Linux (including WSL2 and Android)")
}
