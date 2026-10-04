//go:build linux

package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// In dry-run mode no kernel call is made, so even an interface that does not exist is fine.
func TestNetlinkDryRun(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	a := netip.MustParseAddr("2001:db8::1")
	for name, err := range map[string]error{
		"addrSet":          addrSet(9999, a, 64, 0, 0, false, 0),
		"addrDel":          addrDel(9999, a, 64),
		"routeSet":         routeSet(9999, netip.MustParsePrefix("2001:db8::/64"), netip.Addr{}, 0, 0),
		"neighProxySet":    neighProxySet(9999, a, false),
		"sysctlWrite":      sysctlWrite("/nonexistent/sysctl", "1"),
		"setAllMulti":      setAllMulti("nonexistent0"),
		"tunnelSet":        tunnelSet("nonexistent0", 9999, a, a, 1460),
		"addr4Set":         addr4Set("nonexistent0", netip.MustParsePrefix("192.0.2.1/32")),
		"routeUnreachable": routeUnreachable(netip.MustParsePrefix("2001:db8::/56"), 0, true),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNetlinkConntrackError(t *testing.T) {
	err := errErrConntrack(unix.ENOENT)
	if !errors.Is(err, errConntrackUnavailable) {
		t.Fatalf("%v does not wrap errConntrackUnavailable", err)
	}
}

func TestNetlinkReusePort(t *testing.T) {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := reusePort("udp6", "", rc); err != nil {
		t.Fatalf("on a socket: %v", err)
	}
	c.Close()
	if err := reusePort("udp6", "", rc); err == nil {
		t.Fatal("a closed socket gives no error")
	}
	// a pipe is no socket, so the socket option is refused
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	prc, err := r.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := reusePort("udp6", "", prc); !errors.Is(err, unix.ENOTSOCK) {
		t.Fatalf("on a pipe: %v", err)
	}
}

func TestNetlinkHtons(t *testing.T) {
	if got := htons(0x86dd); got != 0xdd86 {
		t.Fatalf("htons(0x86dd) = %#x", got)
	}
}
