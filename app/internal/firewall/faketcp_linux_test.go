//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeTCPIPTablesRules(t *testing.T) {
	t.Setenv(firewallBackendEnv, "iptables")
	for _, tc := range []struct {
		name, endpoint, bin string
		server              bool
		match               []string
	}{
		{"client4", "198.51.100.1:6666", "iptables", false, []string{"-d", "198.51.100.1", "--dport", "6666"}},
		{"client6", "[2001:db8::1]:6666", "ip6tables", false, []string{"-d", "2001:db8::1", "--dport", "6666"}},
		{"client mapped4", "[::ffff:198.51.100.1]:6666", "iptables", false, []string{"-d", "198.51.100.1", "--dport", "6666"}},
		{"client zone", "[fe80::1%eth0]:6666", "ip6tables", false, []string{"-d", "fe80::1", "--dport", "6666"}},
		{"server wildcard4", "0.0.0.0:6666", "iptables", true, []string{"--sport", "6666"}},
		{"server specific4", "192.0.2.1:6666", "iptables", true, []string{"--sport", "6666"}},
		{"server wildcard6", "[::]:6666", "ip6tables", true, []string{"--sport", "6666"}},
		{"server specific6", "[2001:db8::1]:6666", "ip6tables", true, []string{"--sport", "6666"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{paths: map[string]bool{"iptables": true, "ip6tables": true}}
			cleanup, err := setupFakeTCPWithRunner(r, netip.MustParseAddrPort(tc.endpoint), tc.server)
			require.NoError(t, err)
			match := append([]string{"-p", "tcp"}, tc.match...)
			match = append(match, "--tcp-flags", "RST", "RST", "-j", "DROP")
			require.Equal(t, [][]string{append([]string{tc.bin, "-w", "5", "-t", "raw", "-I", "OUTPUT", "1"}, match...)}, r.cmds)
			require.NoError(t, cleanup.Close())
			require.Equal(t, append([]string{tc.bin, "-w", "5", "-t", "raw", "-D", "OUTPUT"}, match...), r.cmds[1])
			require.NoError(t, cleanup.Close())
			require.Len(t, r.cmds, 2, "one insertion and one deletion per process")
		})
	}
}

func TestFakeTCPNFTablesRules(t *testing.T) {
	t.Setenv(firewallBackendEnv, "nft")
	for _, tc := range []struct {
		endpoint, family string
		server           bool
		match            []string
	}{
		{"198.51.100.1:6666", "ip", false, []string{"ip", "daddr", "198.51.100.1", "tcp", "dport", "6666"}},
		{"[2001:db8::1]:6666", "ip6", false, []string{"ip6", "daddr", "2001:db8::1", "tcp", "dport", "6666"}},
		{"192.0.2.1:6666", "ip", true, []string{"tcp", "sport", "6666"}},
		{"[::]:6666", "ip6", true, []string{"tcp", "sport", "6666"}},
	} {
		t.Run(fmt.Sprintf("%s/server=%v", tc.family, tc.server), func(t *testing.T) {
			r := &fakeRunner{paths: map[string]bool{"nft": true}}
			cleanup, err := setupFakeTCPWithRunner(r, netip.MustParseAddrPort(tc.endpoint), tc.server)
			require.NoError(t, err)
			require.Len(t, r.cmds, 3)
			table := r.cmds[0][4]
			require.True(t, strings.HasPrefix(table, "hysteria_faketcp_"))
			require.Equal(t, []string{"nft", "create", "table", tc.family, table}, r.cmds[0])
			require.Contains(t, strings.Join(r.cmds[1], " "), "hook output priority -300;")
			rule := append([]string{"nft", "add", "rule", tc.family, table, "output"}, tc.match...)
			rule = append(rule, "tcp", "flags", "&", "rst", "==", "rst", "drop")
			require.Equal(t, rule, r.cmds[2])
			require.NoError(t, cleanup.Close())
			require.NoError(t, cleanup.Close())
			require.Len(t, r.cmds, 4)
			require.Equal(t, []string{"nft", "delete", "table", tc.family, table}, r.cmds[3])
		})
	}
}

// iptables deletes the first matching rule, not a process-owned identity. Model
// its rule counts to verify that every successful insertion is balanced once.
type fakeTCPRuleCounter struct {
	fakeRunner
	mu    sync.Mutex
	rules map[string]int
}

func (r *fakeTCPRuleCounter) Run(name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.fakeRunner.Run(name, args...); err != nil {
		return err
	}
	switch args[4] {
	case "-I":
		r.rules[name+" "+strings.Join(args[7:], " ")]++
	case "-D":
		key := name + " " + strings.Join(args[6:], " ")
		if r.rules[key] == 0 {
			return errors.New("no matching rule")
		}
		r.rules[key]--
	default:
		return errors.New("unexpected operation")
	}
	return nil
}

func TestFakeTCPIPTablesRuleCounts(t *testing.T) {
	t.Setenv(firewallBackendEnv, "iptables")
	for _, server := range []bool{false, true} {
		key := "iptables -p tcp -d 198.51.100.1 --dport 6666 --tcp-flags RST RST -j DROP"
		if server {
			key = "iptables -p tcp --sport 6666 --tcp-flags RST RST -j DROP"
		}
		for _, manual := range []int{0, 1} {
			for _, order := range [][2]int{{0, 1}, {1, 0}} {
				t.Run(fmt.Sprintf("server=%v/manual=%d/order=%v", server, manual, order), func(t *testing.T) {
					r := &fakeTCPRuleCounter{fakeRunner: fakeRunner{paths: map[string]bool{"iptables": true}}, rules: map[string]int{key: manual}}
					var instances [2]io.Closer
					for i := range instances {
						var err error
						instances[i], err = setupFakeTCPWithRunner(r, netip.MustParseAddrPort("198.51.100.1:6666"), server)
						require.NoError(t, err)
					}
					require.Equal(t, manual+2, r.rules[key])
					for i, instance := range order {
						require.NoError(t, instances[instance].Close())
						require.NoError(t, instances[instance].Close())
						require.Equal(t, manual+1-i, r.rules[key])
					}
					require.Len(t, r.cmds, 4)
				})
			}
		}
	}
}

func TestFakeTCPIPTablesConcurrentInstances(t *testing.T) {
	t.Setenv(firewallBackendEnv, "iptables")
	const key = "iptables -p tcp -d 198.51.100.1 --dport 6666 --tcp-flags RST RST -j DROP"
	r := &fakeTCPRuleCounter{fakeRunner: fakeRunner{paths: map[string]bool{"iptables": true}}, rules: map[string]int{key: 1}}
	var instances [8]io.Closer
	var failures [8]error
	var wg sync.WaitGroup
	for i := range instances {
		wg.Go(func() {
			instances[i], failures[i] = setupFakeTCPWithRunner(r, netip.MustParseAddrPort("198.51.100.1:6666"), false)
		})
	}
	wg.Wait()
	for _, err := range failures {
		require.NoError(t, err)
	}
	require.Equal(t, 9, r.rules[key])
	for i := range instances {
		wg.Go(func() { failures[i] = instances[i].Close() })
		wg.Go(func() { _ = instances[i].Close() })
	}
	wg.Wait()
	for _, err := range failures {
		require.NoError(t, err)
	}
	require.Equal(t, 1, r.rules[key], "the manually installed rule count must remain")
	require.Len(t, r.cmds, 16)
}

func TestFakeTCPFirewallBackend(t *testing.T) {
	for _, tc := range []struct {
		name, setting, want string
		paths               map[string]bool
		fail                int
	}{
		{"auto prefers nft", "", "nft", map[string]bool{"nft": true, "iptables": true}, 0},
		{"auto iptables", "", "iptables", map[string]bool{"iptables": true}, 0},
		{"forced iptables", "iptables", "iptables", map[string]bool{"nft": true, "iptables": true}, 0},
		{"iptables alias", "ipt", "iptables", map[string]bool{"iptables": true}, 0},
		{"nft alias", "nft", "nft", map[string]bool{"nft": true}, 0},
		{"no downgrade after nft error", "", "nft", map[string]bool{"nft": true, "iptables": true}, 1},
		{"missing forced nft", "nft", "", map[string]bool{"iptables": true}, 0},
		{"missing forced iptables", "iptables", "", map[string]bool{"nft": true}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(firewallBackendEnv, tc.setting)
			r := &fakeRunner{paths: tc.paths, fail: tc.fail}
			cleanup, err := setupFakeTCPWithRunner(r, netip.MustParseAddrPort("198.51.100.1:6666"), false)
			if tc.want == "" {
				require.Error(t, err)
				require.Nil(t, cleanup)
				require.Empty(t, r.cmds)
				return
			}
			if tc.fail != 0 {
				require.Error(t, err)
				require.Nil(t, cleanup)
				require.Len(t, r.cmds, 1)
			} else {
				require.NoError(t, err)
				require.NoError(t, cleanup.Close())
			}
			for _, cmd := range r.cmds {
				require.Equal(t, tc.want, cmd[0])
			}
		})
	}
}

func TestFakeTCPFirewallSetupFailures(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.51.100.1:6666")
	t.Setenv(firewallBackendEnv, "iptables")
	r := &fakeRunner{paths: map[string]bool{"iptables": true}, fail: 1}
	cleanup, err := setupFakeTCPWithRunner(r, endpoint, false)
	require.Error(t, err)
	require.Nil(t, cleanup)
	require.Len(t, r.cmds, 1, "a failed insertion must not delete another rule")
	t.Setenv(firewallBackendEnv, "nft")
	for fail := 1; fail <= 3; fail++ {
		r := &fakeRunner{paths: map[string]bool{"nft": true}, fail: fail}
		cleanup, err := setupFakeTCPWithRunner(r, endpoint, false)
		require.Error(t, err)
		require.Nil(t, cleanup)
		if fail == 1 {
			require.Len(t, r.cmds, 1, "a failed create must not delete an existing table")
		} else {
			require.Len(t, r.cmds, fail+1)
			require.Equal(t, []string{"nft", "delete", "table", "ip", r.cmds[0][4]}, r.cmds[fail])
		}
	}
}

func TestFakeTCPFirewallCleanupErrors(t *testing.T) {
	for _, backend := range []string{"iptables", "nft"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv(firewallBackendEnv, backend)
			fail := 2
			if backend == "nft" {
				fail = 4
			}
			r := &fakeRunner{paths: map[string]bool{"iptables": true, "nft": true}, fail: fail}
			cleanup, err := setupFakeTCPWithRunner(r, netip.MustParseAddrPort("198.51.100.1:6666"), false)
			require.NoError(t, err)
			err = cleanup.Close()
			require.ErrorContains(t, err, "boom")
			require.Equal(t, err, cleanup.Close())
			require.Len(t, r.cmds, fail)
		})
	}
}

func TestFakeTCPFirewallInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []netip.AddrPort{{}, netip.MustParseAddrPort("198.51.100.1:0")} {
		r := &fakeRunner{}
		cleanup, err := setupFakeTCPWithRunner(r, endpoint, false)
		require.Error(t, err)
		require.Nil(t, cleanup)
		require.Empty(t, r.cmds)
	}
}
