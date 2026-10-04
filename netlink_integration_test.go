//go:build linux && integration

package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// netlinkWithoutFDs runs fn with no file descriptor left to open, so that every socket fails.
// The limit is process-wide: call it only in a process of its own (ownNetns).
func netlinkWithoutFDs(t *testing.T, fn func()) {
	t.Helper()
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	none := old
	none.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &none); err != nil {
		t.Fatal(err)
	}
	defer unix.Setrlimit(unix.RLIMIT_NOFILE, &old)
	fn()
}

// netlinkWaitFor polls cond every 10ms for up to 3s.
func netlinkWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 300 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Every kernel call reports a socket it cannot open instead of going on without it.
func TestNetlinkWithoutFDsAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	a := netip.MustParseAddr("2001:db8::1")
	netlinkWithoutFDs(t, func() {
		errs := map[string]error{
			"addrSet":       addrSet(1, a, 64, 0, 0, true, 0),
			"addrDel":       addrDel(1, a, 64),
			"routeSet":      routeSet(1, netip.MustParsePrefix("2001:db8::/64"), netip.Addr{}, 0, 0),
			"neighProxySet": neighProxySet(1, a, false),
			"linkWatch":     linkWatch(make(chan linkEvent)),
			"tunnelSet":     tunnelSet("tnl0", 1, a, a, 1460),
			"addr4Set":      addr4Set("lo", netip.MustParsePrefix("192.0.2.1/32")),
		}
		_, errs["addrList"] = addrList(1)
		_, errs["localListeners"] = localListeners(unix.IPPROTO_TCP, a)
		_, errs["sockDiagInUse"] = sockDiagInUse(a)
		_, errs["packetCapture"] = packetCapture(1, make(chan []byte), kindTunnel, func() {})
		for name, err := range errs {
			if err == nil {
				t.Errorf("%s: no error without a socket", name)
			}
		}
		if _, err := conntrackInUse(a); !errors.Is(err, errConntrackUnavailable) {
			t.Errorf("conntrackInUse: %v", err)
		}
		if defaultRouteVia(1) {
			t.Error("defaultRouteVia: a default route without a socket")
		}
	})
}

func TestNetlinkMiscAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	a := netip.MustParseAddr("2001:db8::1")
	if err := addrSet(9999, a, 64, time.Hour, time.Hour, false, 0); err == nil {
		t.Error("addrSet on a missing interface")
	}
	if err := routeUnreachable(netip.MustParsePrefix("2001:db8:1::/56"), 0, true); err != nil {
		t.Errorf("deleting an unreachable route already gone: %v", err)
	}
	if v, err := sysctlGet("lo", "mtu"); err != nil || v == "" {
		t.Errorf("sysctlGet lo mtu: %q, %v", v, err)
	}
	if err := setAllMulti("lo"); err != nil {
		t.Errorf("setAllMulti lo: %v", err)
	}
	if err := setAllMulti("none0"); err == nil {
		t.Error("setAllMulti on a missing interface")
	}
	if err := addr4Set("lo", netip.MustParsePrefix("192.0.2.1/32")); err != nil {
		t.Errorf("addr4Set lo: %v", err)
	}
	if err := addr4Set("none0", netip.MustParsePrefix("192.0.2.1/32")); err == nil {
		t.Error("addr4Set on a missing interface")
	}
	if err := neighProxySet(1, a, false); err != nil {
		t.Errorf("adding a proxy entry: %v", err)
	}
	if err := neighProxySet(1, a, true); err != nil {
		t.Errorf("deleting a proxy entry: %v", err)
	}
	if err := neighProxySet(1, a, true); err != nil {
		t.Errorf("deleting a proxy entry already gone: %v", err)
	}
	if err := neighProxySet(9999, a, false); err == nil {
		t.Error("a proxy entry on a missing interface")
	}
}

// netlinkTCPListen opens a listening TCP socket bound to addr, which may be IPv4-mapped on an
// AF_INET6 socket, and returns its port.
func netlinkTCPListen(t *testing.T, family int, addr netip.Addr) uint16 {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	var sa unix.Sockaddr = &unix.SockaddrInet6{Addr: addr.As16()}
	if family == unix.AF_INET {
		sa = &unix.SockaddrInet4{Addr: addr.As4()}
	}
	if err := unix.Bind(fd, sa); err != nil {
		t.Fatalf("bind %s: %v", addr, err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	got, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	switch got := got.(type) {
	case *unix.SockaddrInet4:
		return uint16(got.Port)
	case *unix.SockaddrInet6:
		return uint16(got.Port)
	}
	t.Fatalf("unexpected socket address %T", got)
	return 0
}

// An IPv6 socket bound to the IPv4-mapped form of an address listens on it; a socket bound to
// another IPv4 address does not.
func TestNetlinkLocalListenersAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	lo4 := netip.MustParseAddr("127.0.0.1")
	mapped := netlinkTCPListen(t, unix.AF_INET6, netip.AddrFrom16(lo4.As16()))
	other := netlinkTCPListen(t, unix.AF_INET, netip.MustParseAddr("127.0.0.2"))
	got, err := localListeners(unix.IPPROTO_TCP, lo4)
	if err != nil {
		t.Fatal(err)
	}
	if !got[mapped] || got[other] {
		t.Fatalf("listeners %v: want port %d, not %d", got, mapped, other)
	}
	if n, err := sockDiagInUse(netip.AddrFrom16(lo4.As16())); err != nil || n != 1 {
		t.Fatalf("sockDiagInUse of the mapped address: %d, %v", n, err)
	}
}

// A flow through conntrack counts for its addresses.
func TestNetlinkConntrackAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	// a rule that looks at conntrack makes the namespace track its flows
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "sixup-ct"})
	out := c.AddChain(&nftables.Chain{Name: "out", Table: tbl, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: tbl, Chain: out, Exprs: []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, &expr.Counter{}}})
	if err := c.Flush(); err != nil {
		t.Skipf("no conntrack in nftables: %v", err)
	}
	u, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.WriteToUDP([]byte("x"), u.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if n, err := conntrackInUse(netip.IPv6Loopback()); err != nil || n < 1 {
		t.Fatalf("conntrackInUse(::1) = %d, %v", n, err)
	}
	if n, err := conntrackInUse(netip.MustParseAddr("2001:db8::99")); err != nil || n != 0 {
		t.Fatalf("conntrackInUse of an idle address = %d, %v", n, err)
	}
}

func TestNetlinkTunnelAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	local, remote := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	if err := tunnelSet("sixup-tnl0", 1, local, remote, 1460); err != nil {
		t.Skipf("no ip6tnl: %v", err)
	}
	if err := tunnelSet("sixup-tnl0", 1, local, netip.MustParseAddr("2001:db8::3"), 1400); err != nil {
		t.Fatalf("modifying the tunnel: %v", err)
	}
	ifi, err := net.InterfaceByName("sixup-tnl0")
	if err != nil {
		t.Fatal(err)
	}
	if ifi.MTU != 1400 || ifi.Flags&net.FlagUp == 0 {
		t.Fatalf("tunnel MTU %d flags %v", ifi.MTU, ifi.Flags)
	}
	if err := tunnelSet(strings.Repeat("x", 70000), 1, local, remote, 1460); err == nil {
		t.Fatal("a name too long for an attribute is accepted")
	}
}

// captureVeth creates the veth pair cap0/cap1 and returns cap0, an IPv4-in-IPv6 frame that the
// filter lets through, and a function that sends it from cap1 to cap0.
func captureVeth(t *testing.T) (*net.Interface, []byte, func()) {
	t.Helper()
	// no IPv6 on the pair, so that only the frames below cross it
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1"); err != nil {
		t.Fatal(err)
	}
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd("cap0", "cap1", int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	cap0, err := net.InterfaceByName("cap0")
	if err != nil {
		t.Fatal(err)
	}
	cap1, err := net.InterfaceByName("cap1")
	if err != nil {
		t.Fatal(err)
	}
	linkUp(t, cap0.Index)
	linkUp(t, cap1.Index)

	// an IPv4-in-IPv6 frame from cap1 to cap0, which the filter lets through
	frame := make([]byte, 14+40)
	copy(frame[0:6], cap0.HardwareAddr)
	copy(frame[6:12], cap1.HardwareAddr)
	frame[12], frame[13] = 0x86, 0xdd
	frame[14] = 0x60
	frame[20] = 4
	frame[21] = 64
	tx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(tx) })
	to := &unix.SockaddrLinklayer{Protocol: htons(0x86dd), Ifindex: cap1.Index, Halen: 6}
	copy(to.Addr[:], cap0.HardwareAddr)
	return cap0, frame, func() {
		t.Helper()
		if err := unix.Sendto(tx, frame, 0, to); err != nil {
			t.Fatal(err)
		}
	}
}

// Frames reach the capture channel until it is full, and the reader ends both when stopped and
// when the interface goes down.
func TestNetlinkPacketCaptureAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	cap0, frame, send := captureVeth(t)

	if _, err := packetCapture(9999, make(chan []byte), kindTunnel, func() {}); err == nil {
		t.Fatal("capture on a missing interface")
	}

	frames := make(chan []byte, 1)
	exited := make(chan struct{})
	stop, err := packetCapture(cap0.Index, frames, kindTunnel, func() { close(exited) })
	if err != nil {
		t.Fatal(err)
	}
	send()
	select {
	case f := <-frames:
		if !bytes.Equal(f, frame) {
			t.Fatalf("captured %x, sent %x", f, frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame captured")
	}
	send()
	netlinkWaitFor(t, "the second frame", func() bool { return len(frames) == 1 })
	send() // dropped: the channel is full
	time.Sleep(50 * time.Millisecond)
	stop()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("the reader did not end after stop")
	}
	if f, ok := <-frames; !ok || !bytes.Equal(f, frame) {
		t.Fatal("the buffered frame is lost")
	}
	if _, ok := <-frames; ok {
		t.Fatal("the frames channel is not closed")
	}

	// Without room for the filter, capture goes on unfiltered; the interface going down ends it
	const optmem = "/proc/sys/net/core/optmem_max"
	old, err := os.ReadFile(optmem)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysctlWrite(optmem, "0"); err != nil {
		t.Logf("cannot shrink %s, the filter will attach: %v", optmem, err)
	}
	exited = make(chan struct{})
	stop, err = packetCapture(cap0.Index, make(chan []byte, 1), kindTunnel, func() { close(exited) })
	sysctlWrite(optmem, strings.TrimSpace(string(old)))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	linkDown(t, cap0.Index)
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("the reader did not end when the interface went down")
	}
}

// A stopped reader ends at once and leaves the next socket, which may reuse its descriptor number,
// to its own reader: every frame reaches the new channel.
func TestNetlinkPacketCaptureStopReuseAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	cap0, frame, send := captureVeth(t)

	old := make(chan []byte, 16)
	exited := make(chan struct{})
	stop, err := packetCapture(cap0.Index, old, kindTunnel, func() { close(exited) })
	if err != nil {
		t.Fatal(err)
	}
	send()
	select {
	case <-old:
	case <-time.After(3 * time.Second):
		t.Fatal("no frame captured")
	}
	time.Sleep(50 * time.Millisecond) // the reader is back in its read
	stop()
	frames := make(chan []byte, 16)
	stop, err = packetCapture(cap0.Index, frames, kindTunnel, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for i := range 10 {
		send()
		select {
		case f := <-frames:
			if !bytes.Equal(f, frame) {
				t.Fatalf("frame %d: captured %x, sent %x", i, f, frame)
			}
		case <-time.After(time.Second):
			t.Fatalf("frame %d did not reach the new capture", i)
		}
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("the stopped reader is still running")
	}
}
