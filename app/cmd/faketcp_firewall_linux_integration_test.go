//go:build linux

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This test runs only through scripts/test-faketcp-firewall.sh. The outer
// mount/network/PID namespaces contain both the named namespaces and children.
func TestFakeTCPAutoFirewallIntegration(t *testing.T) {
	if os.Getenv("HYSTERIA_FAKETCP_FIREWALL_INTEGRATION") != "1" {
		t.Skip("run scripts/test-faketcp-firewall.sh for privileged application tests")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NotEmpty(t, os.Getenv("HYSTERIA_FAKETCP_PARENT_NETNS"), "use the isolated shell wrapper")
	require.NotEqual(t, os.Getenv("HYSTERIA_FAKETCP_PARENT_NETNS"), afwCommand(t, "readlink", "/proc/self/ns/net"))
	for _, backend := range []string{"iptables", "nftables"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("HYSTERIA_FIREWALL_BACKEND", backend)
			for _, ipv6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("ipv6=%t", ipv6), func(t *testing.T) {
					afwRunCase(t, backend, ipv6)
				})
			}
		})
	}
}

func afwRunCase(t *testing.T, backend string, ipv6 bool) {
	dir, err := os.MkdirTemp(os.Getenv("HYSTERIA_FAKETCP_FIREWALL_RESULTS"), backend+"-")
	require.NoError(t, err)
	serverNS, clientNS := afwNamespaces(t)
	serverIP, sourceA, sourceB, bin := "10.209.0.1", "10.206.0.2", "10.207.0.2", "iptables"
	if ipv6 {
		serverIP, sourceA, sourceB, bin = "fd73:209::1", "fd73:206::2", "fd73:207::2", "ip6tables"
	}
	afwCommandWrappers(t, dir)
	cert, key := afwCertificate(t, dir)
	serverConfig := func(name, auto string, port int, extra string) string {
		return afwWrite(t, dir, name+".yaml", fmt.Sprintf(`listen: %q
transport:
  type: faketcp
  faketcp:
    mtu: 1280
%s
tls:
  cert: %q
  key: %q
auth:
  type: password
  password: test-firewall-password
%s
`, net.JoinHostPort(serverIP, fmt.Sprint(port)), auto, cert, key, extra))
	}
	clientConfig := func(name, auto, local, password string, port, socks int) string {
		return afwWrite(t, dir, name+".yaml", fmt.Sprintf(`server: %q
auth: %q
transport:
  type: faketcp
  faketcp:
    localAddr: %q
    mtu: 1280
    handshakeTimeout: 1s
%s
tls:
  sni: faketcp.test
  ca: %q
quic:
  maxIdleTimeout: 4s
  keepAlivePeriod: 2s
socks5:
  listen: 127.0.0.1:%d
`, net.JoinHostPort(serverIP, fmt.Sprint(port)), password, local, auto, cert, socks))
	}
	const enabled = "    autoFirewall: true"
	const password = "test-firewall-password"
	baseServer := serverConfig("server", enabled, 6666, "")
	baseClient := clientConfig("client", enabled, ":0", password, 6666, 7770)
	fixedConfig := clientConfig("fixed-client", enabled, ":7001", password, 6666, 7771)
	for _, ns := range []string{serverNS, clientNS} {
		afwNS(t, ns, bin, "-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "7777", "--tcp-flags", "RST", "RST", "-j", "DROP")
	}
	serverBaseline, clientBaseline := afwRules(t, serverNS), afwRules(t, clientNS)
	afwWrite(t, dir, "server-rules-baseline.txt", serverBaseline)
	afwWrite(t, dir, "client-rules-baseline.txt", clientBaseline)
	echo := afwStart(t, dir, serverNS, "echo", "", "", nil)
	echo.ready(t, "echo ready")

	// Default-off uses manually installed fixed rules without managing them.
	manualServer := []string{"-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", "6666", "--tcp-flags", "RST", "RST", "-j", "DROP"}
	manualClient := []string{"-t", "raw", "-A", "OUTPUT", "-p", "tcp", "-d", serverIP, "--dport", "6666", "--tcp-flags", "RST", "RST", "-j", "DROP"}
	afwNS(t, serverNS, append([]string{bin}, manualServer...)...)
	afwNS(t, clientNS, append([]string{bin}, manualClient...)...)
	manualServerRules, manualClientRules := afwRules(t, serverNS), afwRules(t, clientNS)
	s := afwStart(t, dir, serverNS, "server", serverConfig("manual-server", "", 6666, ""), "manual", nil)
	s.ready(t, "server up and running")
	c := afwStart(t, dir, clientNS, "client", clientConfig("manual-client", "", ":7001", password, 6666, 7770), "manual", nil)
	c.ready(t, "SOCKS5 server listening")
	afwProbe(t, clientNS, 7770)
	c.stop(t, syscall.SIGTERM)
	s.stop(t, syscall.SIGINT)
	require.Empty(t, c.actions(t))
	require.Empty(t, s.actions(t))
	require.Equal(t, manualServerRules, afwRules(t, serverNS))
	require.Equal(t, manualClientRules, afwRules(t, clientNS))
	manualServer[2], manualClient[2] = "-D", "-D"
	afwNS(t, serverNS, append([]string{bin}, manualServer...)...)
	afwNS(t, clientNS, append([]string{bin}, manualClient...)...)
	require.Equal(t, serverBaseline, afwRules(t, serverNS))
	require.Equal(t, clientBaseline, afwRules(t, clientNS))

	s = afwStart(t, dir, serverNS, "server", baseServer, "auto", nil)
	s.ready(t, "server up and running")
	c = afwStart(t, dir, clientNS, "client", baseClient, "ephemeral", nil)
	c.ready(t, "SOCKS5 server listening")
	fixed := afwStart(t, dir, clientNS, "client", fixedConfig, "fixed", nil)
	fixed.ready(t, "SOCKS5 server listening")
	afwRecovered(t, clientNS, s, 0, sourceA)
	t.Logf("persistent client PIDs: fixed=%d ephemeral=%d", fixed.cmd.Process.Pid, c.cmd.Process.Pid)
	if backend == "iptables" {
		require.Equal(t, 2, afwClientRules(t, clientNS, bin))
	}
	serverActions := s.actions(t)
	require.NotContains(t, serverActions, serverIP)
	require.NotContains(t, serverActions, "--dport")
	require.NotContains(t, serverActions, "daddr")
	require.NotContains(t, serverActions, "saddr")
	require.Contains(t, serverActions, "sport 6666")
	fixedActions, ephemeralActions := fixed.actions(t), c.actions(t)
	for _, actions := range []string{fixedActions, ephemeralActions} {
		require.NotContains(t, actions, "--sport")
		require.NotContains(t, actions, " -s ")
		require.NotContains(t, actions, "saddr")
		require.NotContains(t, actions, "tcp sport")
		require.Contains(t, actions, serverIP)
		require.Contains(t, actions, "6666")
		if backend == "iptables" {
			require.Equal(t, 1, strings.Count(actions, " -I OUTPUT "))
			require.Equal(t, 1, len(strings.Split(strings.TrimSpace(actions), "\n")))
		}
	}
	clientRules := afwRules(t, clientNS)
	afwWrite(t, dir, "client-rules-before-migration.txt", clientRules)
	for _, leg := range []struct{ path, old, source string }{{"b", "a", sourceB}, {"a", "b", sourceA}} {
		offset := s.logSize(t)
		afwSwitchPath(t, clientNS, leg.path, leg.old)
		afwRecovered(t, clientNS, s, offset, leg.source)
		require.NoError(t, fixed.cmd.Process.Signal(syscall.Signal(0)))
		require.NoError(t, c.cmd.Process.Signal(syscall.Signal(0)))
		afwWrite(t, dir, "client-rules-after-path-"+leg.path+".txt", afwRules(t, clientNS))
		require.Equal(t, clientRules, afwRules(t, clientNS))
		require.Equal(t, fixedActions, fixed.actions(t))
		require.Equal(t, ephemeralActions, c.actions(t))
	}
	// One more reconnect, with the same client PIDs and no firewall commands.
	s.stop(t, syscall.SIGTERM)
	afwBalancedCommands(t, backend, s)
	require.Equal(t, serverBaseline, afwRules(t, serverNS))
	s = afwStart(t, dir, serverNS, "server", baseServer, "restart", nil)
	s.ready(t, "server up and running")
	oldPort := afwRecovered(t, clientNS, s, 0, sourceA)
	require.Equal(t, clientRules, afwRules(t, clientNS))
	require.Equal(t, fixedActions, fixed.actions(t))
	require.Equal(t, ephemeralActions, c.actions(t))
	afwWrite(t, dir, "client-rules-after-server-restart.txt", afwRules(t, clientNS))

	// Closing one of two identical rules leaves the other client operational.
	c.stop(t, syscall.SIGINT)
	if backend == "iptables" {
		require.Equal(t, 1, afwClientRules(t, clientNS, bin))
	}
	afwProbe(t, clientNS, 7771)
	afwLateSYNACK(t, serverNS, serverIP, sourceA, oldPort, false)
	// Preserve a manually installed identical rule before and after another
	// instance starts. Multiplicity matters: -C/skip would fail this check.
	manualClient[2] = "-A"
	afwNS(t, clientNS, append([]string{bin}, manualClient...)...)
	fixed.stop(t, syscall.SIGTERM)
	afwBalancedCommands(t, backend, fixed)
	afwBalancedCommands(t, backend, c)
	manualOnly := afwRules(t, clientNS)
	manualClient[2] = "-C"
	afwNS(t, clientNS, append([]string{bin}, manualClient...)...)
	third := afwStart(t, dir, clientNS, "client", baseClient, "preexisting-rule", nil)
	third.ready(t, "SOCKS5 server listening")
	afwProbe(t, clientNS, 7770)
	if backend == "iptables" {
		require.Equal(t, 2, afwClientRules(t, clientNS, bin))
	}
	third.stop(t, syscall.SIGTERM)
	afwBalancedCommands(t, backend, third)
	require.Equal(t, manualOnly, afwRules(t, clientNS))
	manualClient[2] = "-D"
	afwNS(t, clientNS, append([]string{bin}, manualClient...)...)
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	// Positive control: the exact same late SYN-ACK elicits a kernel RST once
	// the process rule is absent. This confirms the earlier suppression.
	afwLateSYNACK(t, serverNS, serverIP, sourceA, oldPort, true)

	commandConfig := clientConfig("command-client", enabled, ":7001", password, 6666, 7770)
	afwStart(t, dir, clientNS, "speedtest", commandConfig, "unsupported", nil).failed(t, "server may not support speed test")
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	afwStart(t, dir, clientNS, "ping", commandConfig, "refused", nil).failed(t, "connection refused")
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	badAuth := clientConfig("bad-auth", enabled, ":7001", "wrong", 6666, 7770)
	afwStart(t, dir, clientNS, "client", badAuth, "auth-failure", nil).failed(t, "authentication")
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	noServer := clientConfig("no-server", enabled, ":7001", password, 6668, 7770)
	afwStart(t, dir, clientNS, "client", noServer, "handshake-failure", nil).failed(t, "handshake timed out")
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	serverRules := afwRules(t, serverNS)
	badTLS := afwWrite(t, dir, "bad-tls.yaml", fmt.Sprintf("listen: %q\ntransport:\n  type: faketcp\n  faketcp:\n    autoFirewall: true\n", net.JoinHostPort(serverIP, "6667")))
	afwStart(t, dir, serverNS, "server", badTLS, "config-failure", nil).failed(t, "tls")
	require.Equal(t, serverRules, afwRules(t, serverNS))
	badQUIC := serverConfig("bad-quic", enabled, 6667, "quic:\n  maxIdleTimeout: 1s")
	afwStart(t, dir, serverNS, "server", badQUIC, "core-config-failure", nil).failed(t, "MaxIdleTimeout")
	require.Equal(t, serverRules, afwRules(t, serverNS))
	afwStart(t, dir, serverNS, "server", baseServer, "port-in-use", nil).failed(t, "address already in use")
	require.Equal(t, serverRules, afwRules(t, serverNS))
	for name, extra := range map[string]string{
		"stats": "trafficStats:\n  listen: 127.0.0.1:7776",
		"masq":  "masquerade:\n  type: string\n  string:\n    content: firewall-test\n  listenHTTPS: 127.0.0.1:7776",
	} {
		failed := afwStart(t, dir, serverNS, "server", serverConfig("bad-"+name, enabled, 6667, extra), name+"-port-in-use", nil)
		require.Error(t, failed.wait(t))
		require.Equal(t, serverRules, afwRules(t, serverNS))
		failed.logged(t, "failed to serve")
	}
	for _, role := range []string{"client", "ping"} {
		waiting := afwStart(t, dir, clientNS, role, noServer, "startup-signal", nil)
		require.Eventually(t, func() bool { return afwRules(t, clientNS) != clientBaseline }, time.Second, 10*time.Millisecond)
		require.NoError(t, waiting.cmd.Process.Signal(syscall.SIGTERM))
		_ = waiting.wait(t)
		require.Equal(t, clientBaseline, afwRules(t, clientNS))
	}
	s.stop(t, syscall.SIGINT)
	afwBalancedCommands(t, backend, s)
	afwWrite(t, dir, "server-rules-after.txt", afwRules(t, serverNS))
	afwWrite(t, dir, "client-rules-after.txt", afwRules(t, clientNS))
	require.Equal(t, serverBaseline, afwRules(t, serverNS))
	require.Equal(t, clientBaseline, afwRules(t, clientNS))
	t.Logf("PASS %s IPv6=%t: fixed+ephemeral clients, A-B-A source migration, stable rules/commands, reconnect, late SYN-ACK, ownership and cleanup", backend, ipv6)
}

// The child enters a network namespace before executing production CLI paths.
func TestFakeTCPFirewallProcess(t *testing.T) {
	role := os.Getenv("HYSTERIA_FAKETCP_TEST_ROLE")
	if role == "" {
		t.Skip("integration subprocess")
	}
	switch role {
	case "server", "client", "speedtest", "ping":
		os.Args = []string{"hysteria", role, "--disable-update-check", "--log-format", "json", "-c", os.Getenv("HYSTERIA_FAKETCP_TEST_CONFIG")}
		if role == "speedtest" {
			os.Args = append(os.Args, "--skip-upload", "--duration", "1s")
		} else if role == "ping" {
			os.Args = append(os.Args, "127.0.0.1:7775")
		}
		Execute()
	case "echo":
		ln, err := net.Listen("tcp4", "127.0.0.1:7776")
		require.NoError(t, err)
		fmt.Println("echo ready")
		for {
			conn, err := ln.Accept()
			require.NoError(t, err)
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	case "late-synack":
		afwSendLateSYNACK(t)
	case "probe":
		conn, err := net.DialTimeout("tcp4", "127.0.0.1:"+os.Getenv("HYSTERIA_FAKETCP_TEST_SOCKS"), time.Second)
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		_, err = conn.Write([]byte{5, 1, 0})
		require.NoError(t, err)
		var method [2]byte
		_, err = io.ReadFull(conn, method[:])
		require.NoError(t, err)
		require.Equal(t, [2]byte{5, 0}, method)
		_, err = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 30, 96}) // 127.0.0.1:7776
		require.NoError(t, err)
		var reply [10]byte
		_, err = io.ReadFull(conn, reply[:])
		require.NoError(t, err)
		require.Equal(t, byte(0), reply[1])
		payload := bytes.Repeat([]byte("native-faketcp-firewall"), 256)
		_, err = conn.Write(payload)
		require.NoError(t, err)
		received := make([]byte, len(payload))
		_, err = io.ReadFull(conn, received)
		require.NoError(t, err)
		require.Equal(t, payload, received)
	default:
		t.Fatalf("unknown subprocess role %q", role)
	}
}

type afwProcess struct {
	cmd     *exec.Cmd
	log     string
	ruleLog string
	done    chan error
	stopped bool
}

func afwStart(t *testing.T, dir, ns, role, config, name string, extraEnv []string) *afwProcess {
	t.Helper()
	p := &afwProcess{cmd: afwChild(ns, role), log: filepath.Join(dir, role+"-"+name+".log"), done: make(chan error, 1)}
	p.ruleLog = afwWrite(t, dir, role+"-"+name+".commands", "")
	p.cmd.Env = append(p.cmd.Env,
		"HYSTERIA_FAKETCP_TEST_CONFIG="+config,
		"HYSTERIA_FAKETCP_COMMAND_LOG="+p.ruleLog,
		"PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"))
	p.cmd.Env = append(p.cmd.Env, extraEnv...)
	log, err := os.Create(p.log)
	require.NoError(t, err)
	p.cmd.Stdout, p.cmd.Stderr = log, log
	require.NoError(t, p.cmd.Start())
	go func() { err := p.cmd.Wait(); _ = log.Close(); p.done <- err }()
	t.Cleanup(func() {
		if !p.stopped {
			_ = p.cmd.Process.Kill()
			_ = p.wait(t)
		}
	})
	return p
}

func (p *afwProcess) ready(t *testing.T, message string) {
	t.Helper()
	require.Eventually(t, func() bool { b, _ := os.ReadFile(p.log); return bytes.Contains(b, []byte(message)) }, 10*time.Second, 20*time.Millisecond, "missing %q in %s", message, p.log)
}

func (p *afwProcess) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.done:
		p.stopped = true
		return err
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		p.stopped = true
		t.Fatalf("process did not exit: %s", p.log)
		return nil
	}
}

func (p *afwProcess) stop(t *testing.T, signal syscall.Signal) {
	t.Helper()
	require.NoError(t, p.cmd.Process.Signal(signal))
	require.NoError(t, p.wait(t), "log: %s", p.log)
}

func (p *afwProcess) failed(t *testing.T, message string) {
	t.Helper()
	require.Error(t, p.wait(t), "log: %s", p.log)
	p.logged(t, message)
}

func (p *afwProcess) logged(t *testing.T, message string) {
	t.Helper()
	b, err := os.ReadFile(p.log)
	require.NoError(t, err)
	require.Contains(t, string(b), message)
}

func afwChild(ns, role string) *exec.Cmd {
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestFakeTCPFirewallProcess$", "-test.timeout=6m")
	cmd.Env = append(os.Environ(), "HYSTERIA_FAKETCP_TEST_ROLE="+role)
	return cmd
}

func afwProbeOK(ns string, port int) bool {
	cmd := afwChild(ns, "probe")
	cmd.Env = append(cmd.Env, "HYSTERIA_FAKETCP_TEST_SOCKS="+fmt.Sprint(port))
	return cmd.Run() == nil
}

func afwProbe(t *testing.T, ns string, port int) {
	t.Helper()
	cmd := afwChild(ns, "probe")
	cmd.Env = append(cmd.Env, "HYSTERIA_FAKETCP_TEST_SOCKS="+fmt.Sprint(port))
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", b)
}

func afwNamespaces(t *testing.T) (string, string) {
	t.Helper()
	server, client := fmt.Sprintf("hy2-fw-%d-s", os.Getpid()), fmt.Sprintf("hy2-fw-%d-c", os.Getpid())
	for _, ns := range []string{server, client} {
		afwCommand(t, "ip", "netns", "add", ns)
		t.Cleanup(func() { afwCommand(t, "ip", "netns", "del", ns) })
		afwCommand(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	for i, path := range []string{"a", "b"} {
		afwCommand(t, "ip", "-n", server, "link", "add", path, "type", "veth", "peer", "name", path, "netns", client)
		for host, ns := range []string{server, client} {
			afwCommand(t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("10.%d.0.%d/24", 206+i, host+1), "dev", path)
			afwCommand(t, "ip", "-n", ns, "-6", "addr", "add", fmt.Sprintf("fd73:%d::%d/64", 206+i, host+1), "dev", path, "nodad")
			afwCommand(t, "ip", "-n", ns, "link", "set", path, "up")
		}
	}
	afwCommand(t, "ip", "-n", server, "addr", "add", "10.209.0.1/32", "dev", "lo")
	afwCommand(t, "ip", "-n", server, "-6", "addr", "add", "fd73:209::1/128", "dev", "lo", "nodad")
	afwSwitchPath(t, client, "a", "")
	afwNS(t, client, "sysctl", "-qw", "net.ipv4.ip_local_port_range=7000 7399")
	afwNS(t, client, "sysctl", "-qw", "net.ipv4.ip_local_reserved_ports=7001")
	return server, client
}

func afwSwitchPath(t *testing.T, ns, path, old string) {
	t.Helper()
	network := 206
	if path == "b" {
		network = 207
	}
	afwCommand(t, "ip", "-n", ns, "link", "set", path, "up")
	afwCommand(t, "ip", "-n", ns, "route", "replace", "10.209.0.1/32", "via", fmt.Sprintf("10.%d.0.1", network), "dev", path, "src", fmt.Sprintf("10.%d.0.2", network))
	afwCommand(t, "ip", "-n", ns, "-6", "route", "replace", "fd73:209::1/128", "via", fmt.Sprintf("fd73:%d::1", network), "dev", path, "src", fmt.Sprintf("fd73:%d::2", network))
	if old != "" {
		afwCommand(t, "ip", "-n", ns, "link", "set", old, "down")
	}
}

func afwRules(t *testing.T, ns string) string {
	t.Helper()
	rules := afwNS(t, ns, "iptables", "-t", "raw", "-S") + afwNS(t, ns, "ip6tables", "-t", "raw", "-S") + afwNS(t, ns, "nft", "list", "ruleset")
	// iptables-nft adds counters even when the original rule has no -c flag.
	return regexp.MustCompile(`counter packets [0-9]+ bytes [0-9]+`).ReplaceAllString(rules, "counter")
}

func afwClientRules(t *testing.T, ns, bin string) int {
	t.Helper()
	return strings.Count(afwNS(t, ns, bin, "-t", "raw", "-S", "OUTPUT"), "--dport 6666")
}

func afwNS(t *testing.T, ns string, args ...string) string {
	t.Helper()
	if args[0] == "iptables" || args[0] == "ip6tables" {
		args = append([]string{args[0], "-w", "5"}, args[1:]...)
	}
	return afwCommand(t, append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func afwCommand(t *testing.T, args ...string) string {
	t.Helper()
	b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	require.NoError(t, err, "%v: %s", args, b)
	return strings.TrimSpace(string(b))
}

func afwWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func afwCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "faketcp.test"}, DNSNames: []string{"faketcp.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return afwWrite(t, dir, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), afwWrite(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
}

// Wrappers only enter each application subprocess's PATH. Parent observations
// use the real binaries, so the log records only commands issued by production.
func afwCommandWrappers(t *testing.T, dir string) {
	t.Helper()
	binDir := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(binDir, 0o700))
	for _, bin := range []string{"iptables", "ip6tables", "nft"} {
		real, err := exec.LookPath(bin)
		require.NoError(t, err)
		script := "#!/bin/sh\nprintf '%s' '" + bin + "' >> \"$HYSTERIA_FAKETCP_COMMAND_LOG\"\nprintf ' %s' \"$@\" >> \"$HYSTERIA_FAKETCP_COMMAND_LOG\"\nprintf '\\n' >> \"$HYSTERIA_FAKETCP_COMMAND_LOG\"\nexec '" + strings.ReplaceAll(real, "'", "'\\''") + "' \"$@\"\n"
		path := afwWrite(t, binDir, bin, script)
		require.NoError(t, os.Chmod(path, 0o700))
	}
}

func (p *afwProcess) actions(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(p.ruleLog)
	require.NoError(t, err)
	return string(b)
}

func (p *afwProcess) logSize(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(p.log)
	require.NoError(t, err)
	return len(b)
}

func afwBalancedCommands(t *testing.T, backend string, p *afwProcess) {
	t.Helper()
	actions := p.actions(t)
	lines := strings.Split(strings.TrimSpace(actions), "\n")
	if backend == "iptables" {
		require.Len(t, lines, 2, actions)
		require.Contains(t, lines[0], " -I OUTPUT 1 ")
		require.Equal(t, strings.Replace(lines[0], " -I OUTPUT 1 ", " -D OUTPUT ", 1), lines[1])
	} else {
		require.Len(t, lines, 4, actions)
		require.Contains(t, lines[0], "nft create table ")
		require.Contains(t, lines[1], "nft add chain ")
		require.Contains(t, lines[2], "nft add rule ")
		require.Equal(t, strings.Replace(lines[0], "nft create table ", "nft delete table ", 1), lines[3])
	}
}

// Require fresh authenticated peers from both processes, in addition to successful
// SOCKS traffic. The server log gives the actual outer source address and port.
func afwRecovered(t *testing.T, ns string, server *afwProcess, offset int, source string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var ephemeral string
	for time.Now().Before(deadline) {
		okEphemeral := afwProbeOK(ns, 7770)
		okFixed := afwProbeOK(ns, 7771)
		b, err := os.ReadFile(server.log)
		require.NoError(t, err)
		fixed := false
		for line := range strings.SplitSeq(string(b[offset:]), "\n") {
			var entry struct {
				Message string `json:"msg"`
				Address string `json:"addr"`
			}
			if json.Unmarshal([]byte(line), &entry) != nil || entry.Message != "client connected" {
				continue
			}
			host, port, err := net.SplitHostPort(entry.Address)
			if err == nil && host == source {
				if port == "7001" {
					fixed = true
				} else {
					ephemeral = port
				}
			}
		}
		if okEphemeral && okFixed && fixed && ephemeral != "" {
			t.Logf("both client processes recovered: source=%s fixed=7001 ephemeral=%s", source, ephemeral)
			return ephemeral
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("SOCKS clients did not reconnect within 20s with source %s; server log: %s", source, server.log)
	return ""
}

func afwLateSYNACK(t *testing.T, ns, serverIP, clientIP, clientPort string, wantRST bool) {
	t.Helper()
	cmd := afwChild(ns, "late-synack")
	cmd.Env = append(cmd.Env,
		"HYSTERIA_FAKETCP_TEST_SERVER_IP="+serverIP,
		"HYSTERIA_FAKETCP_TEST_CLIENT_IP="+clientIP,
		"HYSTERIA_FAKETCP_TEST_CLIENT_PORT="+clientPort,
		"HYSTERIA_FAKETCP_TEST_WANT_RST="+strconv.FormatBool(wantRST))
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", b)
	t.Logf("late SYN-ACK to %s: observed RST=%t", net.JoinHostPort(clientIP, clientPort), wantRST)
}

func afwSendLateSYNACK(t *testing.T) {
	serverIP := net.ParseIP(os.Getenv("HYSTERIA_FAKETCP_TEST_SERVER_IP"))
	clientIP := net.ParseIP(os.Getenv("HYSTERIA_FAKETCP_TEST_CLIENT_IP"))
	port, err := strconv.ParseUint(os.Getenv("HYSTERIA_FAKETCP_TEST_CLIENT_PORT"), 10, 16)
	require.NoError(t, err)
	wantRST, err := strconv.ParseBool(os.Getenv("HYSTERIA_FAKETCP_TEST_WANT_RST"))
	require.NoError(t, err)
	network := "ip6:tcp"
	pseudo := make([]byte, 40)
	copy(pseudo, serverIP.To16())
	copy(pseudo[16:], clientIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:], 20)
	pseudo[39] = 6
	if serverIP.To4() != nil {
		network = "ip4:tcp"
		pseudo = make([]byte, 12)
		copy(pseudo, serverIP.To4())
		copy(pseudo[4:], clientIP.To4())
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], 20)
	}
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment, 6666)
	binary.BigEndian.PutUint16(segment[2:], uint16(port))
	binary.BigEndian.PutUint32(segment[4:], 0x12345678)
	binary.BigEndian.PutUint32(segment[8:], 0x87654321)
	segment[12], segment[13] = 5<<4, 0x12 // SYN | ACK
	binary.BigEndian.PutUint16(segment[14:], 65535)
	var sum uint32
	for _, block := range [][]byte{pseudo, segment} {
		for i := 0; i < len(block); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(block[i:]))
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(segment[16:], ^uint16(sum))
	conn, err := net.ListenIP(network, &net.IPAddr{IP: serverIP})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(1500*time.Millisecond)))
	_, err = conn.WriteToIP(segment, &net.IPAddr{IP: clientIP})
	require.NoError(t, err)
	buffer := make([]byte, 1500)
	gotRST := false
	for {
		n, peer, err := conn.ReadFromIP(buffer)
		if err != nil {
			var netErr net.Error
			require.ErrorAs(t, err, &netErr)
			require.True(t, netErr.Timeout(), err)
			break
		}
		packet := buffer[:n]
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			packet = packet[int(packet[0]&15)*4:]
		}
		if peer.IP.Equal(clientIP) && len(packet) >= 20 && binary.BigEndian.Uint16(packet) == uint16(port) && binary.BigEndian.Uint16(packet[2:]) == 6666 && packet[13]&0x04 != 0 {
			gotRST = true
			break
		}
	}
	require.Equal(t, wantRST, gotRST, "late SYN-ACK RST suppression")
}
