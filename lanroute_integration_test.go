//go:build linux && integration

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// lanState is what a LAN holds in the kernel: the routes sixup put there, the addresses answered
// for, the global addresses on the LAN itself and on the WAN.
type lanState struct {
	routes  []netip.Prefix
	proxies []netip.Addr
	lan     []netip.Addr
	wan     []netip.Addr
}

func (s lanState) String() string {
	return fmt.Sprintf("routes %v, proxy entries %v, LAN %v, WAN %v", s.routes, s.proxies, s.lan, s.wan)
}

func lanStateOf(t *testing.T, lan, wan string) lanState {
	t.Helper()
	var st lanState
	global := func(name string) []netip.Addr {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil
		}
		list, _ := addrList(ifi.Index)
		var out []netip.Addr
		for _, ia := range list {
			if !ia.Addr.IsLinkLocalUnicast() {
				out = append(out, ia.Addr)
			}
		}
		slices.SortFunc(out, netip.Addr.Compare)
		return out
	}
	st.lan, st.wan = global(lan), global(wan)
	if ifi, err := net.InterfaceByName(lan); err == nil {
		st.routes, _ = lanRouteList(ifi.Index)
		st.proxies, _ = neighProxyList(ifi.Index)
	}
	slices.SortFunc(st.routes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	slices.SortFunc(st.proxies, netip.Addr.Compare)
	return st
}

// sourceTo returns the source address the kernel picks to reach dst, invalid without a route.
func sourceTo(dst netip.Addr) netip.Addr {
	c, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

// lanRoutesSetup creates the WAN pair wan-rt0/up-rt0 and the LAN pair lan-rt0/host-rt0 in the
// namespace of the process, with DAD on the LAN quick to wait for, and returns the LAN.
func lanRoutesSetup(t *testing.T) *net.Interface {
	t.Helper()
	loUp(t)
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/default/dad_transmits", "1"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"wan-rt0", "up-rt0"}, {"lan-rt0", "host-rt0"}} {
		a, b := linkVeth(t, pair[0], pair[1])
		linkUp(t, a)
		linkUp(t, b)
	}
	if err := sysctlWrite("/proc/sys/net/ipv6/neigh/lan-rt0/retrans_time_ms", "300"); err != nil {
		t.Fatal(err)
	}
	lan, err := net.InterfaceByName("lan-rt0")
	if err != nil {
		t.Fatal(err)
	}
	return lan
}

// The LAN holds the on-link route of every prefix and an address only in its ULA, deprecated, which
// the ULA route names as its source: traffic to a LAN host's ULA leaves from it, traffic to its
// GUA from the WAN's /128 in the LAN prefix, which the LAN answers for. What an earlier run left
// goes: its GUA address, routes and proxy entries in the LAN prefixes. The routes follow the
// prefixes and the proxy entries the addresses of this router.
func TestLANRoutesAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	lan := lanRoutesSetup(t)
	wan := mustIface(t, "wan-rt0")
	gua, ula := netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("fd00:1::/64")
	wanAddr := netip.MustParseAddr("2001:db8:1::1") // the WAN's /128 in the delegation
	addrMust(t, wan, wanAddr, 128, false)
	// left by an earlier run: the LAN's GUA address with its prefix route, a route of a prefix
	// gone, and proxy entries, one in a LAN prefix and one outside them
	old := netip.MustParseAddr("2001:db8:1::abcd")
	if err := addrSet(lan.Index, old, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	gone := netip.MustParsePrefix("2001:db8:dead::/64")
	if err := lanRouteSet(lan.Index, gone, netip.Addr{}, 0); err != nil {
		t.Fatal(err)
	}
	foreign := netip.MustParseAddr("2001:db8:77::1")
	for _, a := range []netip.Addr{netip.MustParseAddr("2001:db8:1::beef"), foreign} {
		if err := neighProxySet(lan.Index, a, false); err != nil {
			t.Fatal(err)
		}
	}
	// the WAN's own proxy entries are none of the LAN's business
	wanProxy := netip.MustParseAddr("2001:db8:1::cafe")
	if err := neighProxySet(wan, wanProxy, false); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := newLinkHub(ctx)
	store := newStore("pd", []lanDef{{"lan-rt0", 0}}, time.Second, []netip.Prefix{netip.MustParsePrefix("fd00:1::/48")}, false, 0, 0, "")
	pd := func(p string) SourceUpdate {
		now := time.Now()
		return SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix(p), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: sourcePD}}}
	}
	store.Set(sourcePD, pd("2001:db8:1::/56"))
	m := &addrManager{ifname: "lan-rt0", secret: make([]byte, 32), iids: []iidPolicy{lanIID},
		pick: func(s Snapshot) []Prefix { return s.lanULA("lan-rt0") }, side: sideLAN, layout: "lan"}
	go m.run(ctx, hub, store, store.Subscribe())
	r := &lanRoutes{ifname: "lan-rt0", layout: "lan", sysctl: true}
	done := make(chan struct{})
	go func() {
		r.run(ctx, hub, store, store.Subscribe())
		close(done)
	}()

	self := netip.MustParseAddr("fd00:1::1")
	reached := func(want lanState) func() bool {
		return func() bool {
			st := lanStateOf(t, "lan-rt0", "wan-rt0")
			return slices.Equal(st.routes, want.routes) && slices.Equal(st.proxies, want.proxies) && slices.Equal(st.lan, want.lan) &&
				sourceTo(netip.MustParseAddr("fd00:1::99")) == self
		}
	}
	netlinkWaitFor(t, "the LAN routed, with only its ULA address", reached(lanState{
		routes: []netip.Prefix{gua, ula}, proxies: []netip.Addr{wanAddr, foreign}, lan: []netip.Addr{self},
	}))
	if f, _ := addrFlags(t, lan.Index, self); f&(ifaFDeprecated|ifaFNoprefixroute) != ifaFDeprecated|ifaFNoprefixroute {
		t.Errorf("the ULA address has flags %#x, want deprecated without a prefix route", f)
	}
	if got, err := neighProxyList(wan); err != nil || !slices.Equal(got, []netip.Addr{wanProxy}) {
		t.Errorf("the WAN's proxy entries: %v, %v", got, err)
	}
	if src := sourceTo(netip.MustParseAddr("2001:db8:1::99")); src != wanAddr {
		t.Errorf("a LAN host's GUA is reached from %s, want the WAN's %s", src, wanAddr)
	}
	for path, val := range map[string]string{
		"/proc/sys/net/ipv6/conf/lan-rt0/proxy_ndp":    "1",
		"/proc/sys/net/ipv6/neigh/lan-rt0/proxy_delay": "0",
	} {
		if b, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(b)) != val {
			t.Errorf("%s = %q, %v; want %s", path, b, err, val)
		}
	}

	// another address of this router in the LAN prefix is answered for while it is there
	extra := netip.MustParseAddr("2001:db8:1::2")
	addrMust(t, wan, extra, 128, false)
	netlinkWaitFor(t, "the new address answered for", func() bool {
		return slices.Contains(lanStateOf(t, "lan-rt0", "wan-rt0").proxies, extra)
	})
	if err := addrDel(wan, extra, 128); err != nil {
		t.Fatal(err)
	}
	netlinkWaitFor(t, "the removed address no longer answered for", func() bool {
		return !slices.Contains(lanStateOf(t, "lan-rt0", "wan-rt0").proxies, extra)
	})

	// a new delegation: the old prefix is withdrawn over the hold, then its route goes
	next := netip.MustParsePrefix("2001:db8:2::/64")
	store.Set(sourcePD, pd("2001:db8:2::/56"))
	netlinkWaitFor(t, "the route of the withdrawn prefix gone", func() bool {
		return slices.Equal(lanStateOf(t, "lan-rt0", "wan-rt0").routes, []netip.Prefix{next, ula})
	})

	// a LAN going down stops the work until it comes back
	linkDown(t, lan.Index)
	time.Sleep(100 * time.Millisecond)
	linkUp(t, lan.Index)
	netlinkWaitFor(t, "the routes back after the LAN returns", func() bool {
		return slices.Equal(lanStateOf(t, "lan-rt0", "wan-rt0").routes, []netip.Prefix{next, ula})
	})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not end with its context")
	}
}

// Every change the kernel refuses is reported and skipped: here none is allowed, since the
// effective user is no longer root, while reading the tables still is.
func TestLANRoutesRefusedAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	lan := lanRoutesSetup(t)
	wan := mustIface(t, "wan-rt0")
	gua := netip.MustParsePrefix("2001:db8:1::/64")
	wanAddr, stale := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::beef")
	addrMust(t, wan, wanAddr, 128, false)
	gone := netip.MustParsePrefix("2001:db8:dead::/64")
	if err := lanRouteSet(lan.Index, gone, netip.Addr{}, 0); err != nil {
		t.Fatal(err)
	}
	if err := neighProxySet(lan.Index, stale, false); err != nil {
		t.Fatal(err)
	}
	old := netip.MustParseAddr("2001:db8:1::abcd")
	if err := addrSet(lan.Index, old, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p := Prefix{Prefix: gua, Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: sourcePD}
	r := &lanRoutes{ifname: "lan-rt0", layout: "lan", snap: Snapshot{LAN: map[string][]Prefix{"lan-rt0": {p}}}}
	m := addrTestManager(sideLAN)
	m.ifname, m.ifi, m.snap = "lan-rt0", lan, r.snap
	list, err := addrList(lan.Index)
	if err != nil {
		t.Fatal(err)
	}

	if err := syscall.Setresuid(-1, 65534, -1); err != nil {
		t.Fatal(err)
	}
	r.apply(lan)
	m.dropStrays(list, nil)
	if err := syscall.Setresuid(-1, 0, -1); err != nil {
		t.Fatal(err)
	}
	st := lanStateOf(t, "lan-rt0", "wan-rt0")
	if !slices.Equal(st.routes, []netip.Prefix{gone}) || !slices.Equal(st.proxies, []netip.Addr{stale}) || !slices.Contains(st.lan, old) {
		t.Fatalf("a refused change was taken for done: %+v", st)
	}
}

// An address left on the LAN by an earlier run in one of its prefixes is deleted at once, and one
// configured by hand stays; the LAN's own address goes in its ULA only.
func TestAddressLANDropsStraysAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	oldGUA, oldULA := netip.MustParseAddr("2001:db8:1::dead"), netip.MustParseAddr("fd00:1::dead")
	for _, a := range []netip.Addr{oldGUA, oldULA} {
		if err := addrSet(lo.Index, a, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
			t.Fatal(err)
		}
	}
	hand, outside := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:9::dead")
	needTools(t, "ip")
	// configured as an administrator would, with both lifetimes infinite
	if out, err := exec.Command("ip", "-6", "addr", "add", hand.String()+"/64", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if err := addrSet(lo.Index, outside, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	gua, ula := addrLive("2001:db8:1::/64"), addrLive("fd00:1::/64")
	ula.Source = sourceULA
	m := addrTestManager(sideLAN)
	m.ifname, m.ifi = "lo", lo
	m.snap = Snapshot{LAN: map[string][]Prefix{"lo": {gua, ula}}}
	m.pick = func(s Snapshot) []Prefix { return s.lanULA("lo") }
	m.iids = []iidPolicy{lanIID}
	m.applyPrefixAddrs()
	self := netip.MustParseAddr("fd00:1::1")
	for a, want := range map[netip.Addr]bool{oldGUA: false, oldULA: false, hand: true, outside: true, self: true} {
		if _, ok := addrFlags(t, lo.Index, a); ok != want {
			t.Errorf("%s on the LAN: %v, want %v", a, ok, want)
		}
	}
	if f, _ := addrFlags(t, lo.Index, self); f&(ifaFDeprecated|ifaFNoprefixroute) != ifaFDeprecated|ifaFNoprefixroute {
		t.Errorf("the ULA address has flags %#x, want deprecated without a prefix route", f)
	}
}
