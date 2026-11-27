//go:build linux

package firewall

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
)

// SetupFakeTCP installs a process-lifetime rule suppressing kernel TCP resets
// before conntrack. A client endpoint is its fixed server destination; a server
// endpoint determines the listening address family and source port.
func SetupFakeTCP(endpoint netip.AddrPort, server bool) (io.Closer, error) {
	cleanup, err := setupFakeTCPWithRunner(osCommandRunner{}, endpoint, server)
	if err != nil {
		return nil, fmt.Errorf("set up FakeTCP firewall: %w", err)
	}
	return cleanup, nil
}

func setupFakeTCPWithRunner(r commandRunner, endpoint netip.AddrPort, server bool) (io.Closer, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return nil, errors.New("a valid endpoint with a nonzero port is required")
	}
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
	switch strings.ToLower(os.Getenv(firewallBackendEnv)) {
	case "nftables", "nft":
		return setupFakeTCPNFTables(r, endpoint, server)
	case "iptables", "ipt":
		return setupFakeTCPIPTables(r, endpoint, server)
	default:
		if _, err := r.LookPath("nft"); err == nil {
			return setupFakeTCPNFTables(r, endpoint, server)
		}
		return setupFakeTCPIPTables(r, endpoint, server)
	}
}

type fakeTCPCleanup struct {
	once sync.Once
	fn   func() error
	err  error
}

func (c *fakeTCPCleanup) Close() error {
	c.once.Do(func() { c.err = c.fn() })
	return c.err
}

func setupFakeTCPIPTables(r commandRunner, endpoint netip.AddrPort, server bool) (io.Closer, error) {
	bin := "iptables"
	if endpoint.Addr().Is6() {
		bin = "ip6tables"
	}
	if _, err := r.LookPath(bin); err != nil {
		return nil, err
	}
	ipt := func(args ...string) error {
		return r.Run(bin, append([]string{"-w", "5", "-t", "raw"}, args...)...)
	}
	port := strconv.Itoa(int(endpoint.Port()))
	match := []string{"-p", "tcp"}
	if server {
		match = append(match, "--sport", port)
	} else {
		match = append(match, "-d", endpoint.Addr().WithZone("").String(), "--dport", port)
	}
	match = append(match, "--tcp-flags", "RST", "RST", "-j", "DROP")
	// Always insert one rule and delete one matching rule on exit. Identical
	// rules from other processes or manual setup retain their total count.
	if err := ipt(append([]string{"-I", "OUTPUT", "1"}, match...)...); err != nil {
		return nil, err
	}
	return &fakeTCPCleanup{fn: func() error {
		return ipt(append([]string{"-D", "OUTPUT"}, match...)...)
	}}, nil
}

func setupFakeTCPNFTables(r commandRunner, endpoint netip.AddrPort, server bool) (io.Closer, error) {
	if _, err := r.LookPath("nft"); err != nil {
		return nil, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	table := "hysteria_faketcp_" + hex.EncodeToString(id[:])
	family := "ip"
	if endpoint.Addr().Is6() {
		family = "ip6"
	}
	nft := func(args ...string) error { return r.Run("nft", args...) }
	if err := nft("create", "table", family, table); err != nil {
		return nil, err
	}
	cleanup := &fakeTCPCleanup{fn: func() error { return nft("delete", "table", family, table) }}
	if err := nft("add", "chain", family, table, "output", "{", "type", "filter", "hook", "output", "priority", "-300;", "policy", "accept;", "}"); err != nil {
		return nil, errors.Join(err, cleanup.Close())
	}
	args := []string{"add", "rule", family, table, "output"}
	port := strconv.Itoa(int(endpoint.Port()))
	if server {
		args = append(args, "tcp", "sport", port)
	} else {
		args = append(args, family, "daddr", endpoint.Addr().WithZone("").String(), "tcp", "dport", port)
	}
	args = append(args, "tcp", "flags", "&", "rst", "==", "rst", "drop")
	if err := nft(args...); err != nil {
		return nil, errors.Join(err, cleanup.Close())
	}
	return cleanup, nil
}
