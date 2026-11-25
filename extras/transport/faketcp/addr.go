package faketcp

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

var zeroAddrPort netip.AddrPort

func addrPort(addr *net.UDPAddr) (netip.AddrPort, error) {
	if addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return zeroAddrPort, errors.New("invalid address or port")
	}
	ap := addr.AddrPort()
	if !ap.IsValid() {
		return zeroAddrPort, errors.New("invalid IP address")
	}
	ip := ap.Addr().Unmap()
	if z := ip.Zone(); z != "" {
		if n, err := strconv.ParseUint(z, 10, 32); err == nil {
			ip = ip.WithZone(strconv.FormatUint(n, 10))
		} else {
			iface, err := net.InterfaceByName(z)
			if err != nil {
				return zeroAddrPort, err
			}
			ip = ip.WithZone(strconv.Itoa(iface.Index))
		}
	}
	return netip.AddrPortFrom(ip, ap.Port()), nil
}

func listenAddr(addr *net.UDPAddr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), 0), nil
	}
	if len(addr.IP) == 0 {
		return addrPort(&net.UDPAddr{IP: net.IPv4zero, Port: addr.Port})
	}
	return addrPort(addr)
}

func resolveDialAddr(local string, remote *net.UDPAddr) (netip.AddrPort, netip.AddrPort, error) {
	r, err := addrPort(remote)
	if err != nil || r.Port() == 0 || r.Addr().IsUnspecified() || r.Addr().IsMulticast() {
		return zeroAddrPort, zeroAddrPort, errors.New("remote must be a unicast IP address and nonzero port")
	}
	network := "udp4"
	if r.Addr().Is6() {
		network = "udp6"
	}
	var l *net.UDPAddr
	if local != "" {
		l, err = net.ResolveUDPAddr(network, local)
		if err != nil {
			return zeroAddrPort, zeroAddrPort, err
		}
	}
	port := 0
	if l != nil {
		port = l.Port
	}
	// Ask the routing table for the source IP. No UDP datagram is sent. The
	// actual port is reserved in the TCP namespace by openSocket, not here.
	routeLocal := &net.UDPAddr{}
	if l != nil {
		routeLocal.IP, routeLocal.Zone = l.IP, l.Zone
	}
	probe, err := net.DialUDP(network, routeLocal, net.UDPAddrFromAddrPort(r))
	if err != nil {
		return zeroAddrPort, zeroAddrPort, err
	}
	source := probe.LocalAddr().(*net.UDPAddr)
	_ = probe.Close()
	source.Port = port
	a, err := addrPort(source)
	return a, r, err
}
