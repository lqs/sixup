//go:build !linux

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Non-Linux builds exist only to compile and run pure-logic tests; every kernel operation returns errUnsupported.
var errUnsupported = errors.New("linux only")

const infiniteLft = 0xffffffff

type ifAddr struct {
	Addr      netip.Addr
	PrefixLen int
	Flags     uint32
	Preferred uint32
	Valid     uint32
}

type linkEvent struct {
	Name  string
	Index int
	Up    bool
	Gone  bool
}

var errConntrackUnavailable = errors.New("conntrack unavailable")

func skipOrUnsupported(what string) error {
	if dryRun {
		debugf("[dry-run] skipping %s", what)
		return nil
	}
	return errUnsupported
}

func addrSet(_ int, a netip.Addr, plen int, _, _ time.Duration, _ bool, _ uint32) error {
	return skipOrUnsupported(fmt.Sprintf("address set %s/%d", a, plen))
}
func addrDel(_ int, a netip.Addr, plen int) error {
	return skipOrUnsupported(fmt.Sprintf("address delete %s/%d", a, plen))
}
func addrList(int) ([]ifAddr, error) { return nil, errUnsupported }
func routeSet(_ int, dst netip.Prefix, gw netip.Addr, _ uint32, _ time.Duration) error {
	return skipOrUnsupported(fmt.Sprintf("route %s → %s", dst, gw))
}
func routeDel(_ int, dst netip.Prefix, gw netip.Addr, _ uint32) error {
	return skipOrUnsupported(fmt.Sprintf("route delete %s → %s", dst, gw))
}
func prefixRouteDel(_ int, dst netip.Prefix) error {
	return skipOrUnsupported("prefix route delete " + dst.String())
}
func routeUnreachable(dst netip.Prefix, _ time.Duration, _ bool) error {
	return skipOrUnsupported("unreachable route " + dst.String())
}
func neighProxySet(_ int, a netip.Addr, _ bool) error {
	return skipOrUnsupported("proxy neighbor " + a.String())
}
func linkWatch(chan<- linkEvent) error { return errUnsupported }
func sysctlSet(iface, key, val string) error {
	return skipOrUnsupported(fmt.Sprintf("sysctl %s/%s=%s", iface, key, val))
}
func sysctlWrite(path, val string) error {
	return skipOrUnsupported(fmt.Sprintf("sysctl %s=%s", path, val))
}
func sysctlGet(string, string) (string, error)                            { return "", errUnsupported }
func sockDiagInUse(netip.Addr) (int, error)                               { return 0, errUnsupported }
func conntrackInUse(netip.Addr) (int, error)                              { return 0, errConntrackUnavailable }
func ifaceByName(name string) (*net.Interface, error)                     { return net.InterfaceByName(name) }
func setAllMulti(name string) error                                       { return skipOrUnsupported("allmulti " + name) }
func reusePort(string, string, syscall.RawConn) error                     { return nil }
func packetCapture(int, chan<- []byte, frameKind, func()) (func(), error) { return nil, errUnsupported }
func tunnelSet(name string, _ int, local, remote netip.Addr, mtu int) error {
	return skipOrUnsupported(fmt.Sprintf("tunnel device %s: %s → %s mtu %d", name, local, remote, mtu))
}
func addr4Set(dev string, p netip.Prefix) error {
	return skipOrUnsupported(fmt.Sprintf("IPv4 %s on %s", p, dev))
}
