package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
)

func newTestProxy(layout shared64Layout) *ndProxy {
	n := &ndProxy{
		mode:      "forward",
		ttl:       time.Minute,
		layout:    layout,
		wanIfi:    &net.Interface{Index: 2, Name: "wan0"},
		lanIfi:    &net.Interface{Index: 3, Name: "lan0"},
		prefixes:  []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
		sessions:  map[netip.Addr]*proxySession{},
		pending:   map[netip.Addr][]solicitor{},
		kernelSet: map[netip.Addr]int{},
		selfAddrs: map[netip.Addr]bool{netip.MustParseAddr("2001:db8::1"): true},
	}
	return n
}

// Upstream asks for a LAN host: probe the LAN side; after the NA the session settles on lan.
func TestProxyUpstreamAsksLANHost(t *testing.T) {
	n := newTestProxy("wan")
	host := netip.MustParseAddr("2001:db8::abcd")
	up := netip.MustParseAddr("fe80::1")
	n.mu.Lock()
	n.onSolicit(sideWAN, host, up)
	n.mu.Lock()
	s := n.sessions[host]
	if s == nil || s.State != "probing" || s.Side != sideLAN {
		t.Fatalf("should probe the LAN side, got %+v", s)
	}
	if len(n.pending[host]) != 1 || n.pending[host][0].side != sideWAN {
		t.Fatalf("solicitor should be recorded on the WAN side: %+v", n.pending[host])
	}
	n.onAdvert(sideLAN, host)
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.State != "valid" || s.Side != sideLAN {
		t.Fatalf("after NA should be valid/lan, got %+v", s)
	}
	if _, ok := n.pending[host]; ok {
		t.Fatal("askers should be cleared after answering")
	}
}

// LAN asks for an on-link host on the WAN side: probe that side (reverse proxy).
func TestProxyLANAsksUpstreamHost(t *testing.T) {
	n := newTestProxy("wan")
	hgw := netip.MustParseAddr("2001:db8::fffe")
	lanHost := netip.MustParseAddr("2001:db8::10")
	n.mu.Lock()
	n.onSolicit(sideLAN, hgw, lanHost)
	n.mu.Lock()
	s := n.sessions[hgw]
	if s == nil || s.State != "probing" || s.Side != sideWAN {
		t.Fatalf("should probe the WAN side, got %+v", s)
	}
	// The LAN host sending the NS should be learned as a side effect.
	if l := n.sessions[lanHost]; l == nil || l.State != "valid" || l.Side != sideLAN {
		t.Fatalf("LAN host %s should be learned passively: %+v", lanHost, l)
	}
	n.onAdvert(sideWAN, hgw)
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.State != "valid" || s.Side != sideWAN {
		t.Fatalf("should be valid/wan, got %+v", s)
	}
}

// A WAN host asking for a LAN host under the lan layout is learned with its /128 route, which
// the reply needs: the /64 is routed to the LAN.
func TestProxyLearnsTheWANAsker(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	n := newTestProxy("lan")
	asker := netip.MustParseAddr("2001:db8::20")
	n.mu.Lock()
	n.onSolicit(sideWAN, netip.MustParseAddr("2001:db8::abcd"), asker)
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[asker]; s == nil || s.State != "valid" || s.Side != sideWAN || n.kernelSet[asker] != n.wanIfi.Index {
		t.Fatalf("the asker is learned on the WAN: %+v %v", s, n.kernelSet)
	}
}

// No proxying between same-side hosts: a lan host asking for a known lan host gets no answer and no probe.
func TestProxySameSideNoReply(t *testing.T) {
	n := newTestProxy("wan")
	host := netip.MustParseAddr("2001:db8::abcd")
	n.mu.Lock()
	n.learn(sideLAN, host, time.Now())
	n.mu.Unlock()
	n.mu.Lock()
	n.onSolicit(sideLAN, host, netip.MustParseAddr("2001:db8::20"))
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.pending[host]) != 0 {
		t.Fatal("same side must not trigger a probe")
	}
	if n.sessions[host].State != "valid" {
		t.Fatal("session must not be changed to probing")
	}
}

// LAN DAD (source ::) must also probe upstream and answer on a hit so DAD fails.
func TestProxyLANDADProbesUpstream(t *testing.T) {
	n := newTestProxy("lan")
	addr := netip.MustParseAddr("2001:db8::77")
	n.mu.Lock()
	n.onSolicit(sideLAN, addr, netip.IPv6Unspecified())
	n.mu.Lock()
	defer n.mu.Unlock()
	s := n.sessions[addr]
	if s == nil || s.Side != sideWAN {
		t.Fatalf("DAD should probe wan: %+v", s)
	}
	if _, ok := n.sessions[netip.IPv6Unspecified()]; ok {
		t.Fatal(":: must not be learned as a host")
	}
}

// Router's own addresses and out-of-range addresses are not proxied.
func TestProxyCovered(t *testing.T) {
	n := newTestProxy("wan")
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.covered(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("own address must not be proxied")
	}
	if n.covered(netip.MustParseAddr("2001:db9::1")) {
		t.Fatal("out of range must not be proxied")
	}
	if !n.covered(netip.MustParseAddr("2001:db8::2")) {
		t.Fatal("in range should be proxied")
	}
}

// Expiring a session must remove its /128 route record.
func TestProxyRouteCleanup(t *testing.T) {
	n := newTestProxy("wan")
	host := netip.MustParseAddr("2001:db8::abcd")
	n.mu.Lock()
	n.kernelSet[host] = 3
	n.sessions[host] = &proxySession{State: "valid", Side: "lan", Expires: time.Now().Add(-time.Second)}
	n.sweep(time.Now())
	n.mu.Unlock()
	if _, ok := n.kernelSet[host]; ok {
		t.Fatal("route record should be removed after expiry")
	}
}

// Router itself (kernel) looks for a LAN host on WAN: probe lan, but record no solicitor and send no answer.
func TestProxySelfSolicitProbesOtherSide(t *testing.T) {
	n := newTestProxy("wan")
	host := netip.MustParseAddr("2001:db8::abcd")
	n.mu.Lock()
	n.onSolicit(sideWAN, host, netip.Addr{})
	n.mu.Lock()
	s := n.sessions[host]
	if s == nil || s.State != "probing" || s.Side != sideLAN {
		t.Fatalf("should probe the LAN side: %+v", s)
	}
	if len(n.pending[host]) != 0 {
		t.Fatal("own request must not record an solicitor")
	}
	n.onAdvert(sideLAN, host)
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.State != "valid" || s.Side != sideLAN {
		t.Fatalf("host should be learned on the LAN side: %+v", s)
	}
}

// lan layout: a LAN host or the router looks for an on-link host on the WAN side, probes it, and the learned /128 route goes on the WAN interface;
// wan layout: the /64 is already on-link on WAN, so no route is added.
func TestProxyLANLayoutRouteViaWAN(t *testing.T) {
	old := dryRun
	dryRun = true // stub routeSet succeeds in dry-run
	defer func() { dryRun = old }()

	hgw := netip.MustParseAddr("2001:db8::fffe")
	for _, tc := range []struct {
		layout  shared64Layout
		wantIdx int
	}{{"lan", 2}, {"split", 2}, {"wan", 0}} {
		n := newTestProxy(tc.layout)
		n.mu.Lock()
		n.onSolicit(sideLAN, hgw, netip.Addr{}) // router itself
		n.mu.Lock()
		if s := n.sessions[hgw]; s == nil || s.Side != sideWAN {
			t.Fatalf("%s: should probe wan: %+v", tc.layout, s)
		}
		n.onAdvert(sideWAN, hgw)
		n.mu.Lock()
		idx := n.kernelSet[hgw]
		n.mu.Unlock()
		if idx != tc.wantIdx {
			t.Fatalf("%s: /128 route interface should be %d, got %d", tc.layout, tc.wantIdx, idx)
		}
	}
}

// A host walking the prefix must not grow the session table past its cap, and the neighbours already
// confirmed must survive the flood.
func TestProxySessionTableCapped(t *testing.T) {
	n := newTestProxy("wan")
	known := netip.MustParseAddr("2001:db8::abcd")
	now := time.Now()
	n.mu.Lock()
	n.sessions[known] = &proxySession{State: "valid", Side: sideLAN, Expires: now.Add(n.ttl)}
	n.mu.Unlock()

	// Every scanned target arrives as a fresh NS from the WAN side, which is what a scan looks like.
	base := netip.MustParseAddr("2001:db8::").As16()
	for i := range maxProxySessions * 2 {
		b := base
		b[13], b[14], b[15] = byte(i>>16), byte(i>>8), byte(i)
		n.mu.Lock()
		n.onSolicit(sideWAN, netip.AddrFrom16(b), netip.MustParseAddr("fe80::2"))
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sessions) > maxProxySessions {
		t.Fatalf("session table grew past the cap: %d", len(n.sessions))
	}
	if s := n.sessions[known]; s == nil || s.State != "valid" {
		t.Fatalf("a confirmed neighbour was evicted by the scan: %+v", s)
	}
}

// One target asked for by many hosts must not grow the asker list without bound.
func TestProxyAskerListCapped(t *testing.T) {
	var list []solicitor
	base := netip.MustParseAddr("fe80::").As16()
	for i := range maxAskers * 4 {
		b := base
		b[14], b[15] = byte(i>>8), byte(i)
		list = appendAsker(list, solicitor{netip.AddrFrom16(b), sideWAN})
	}
	if len(list) != maxAskers {
		t.Fatalf("asker list should stop at %d, got %d", maxAskers, len(list))
	}
}

// Sessions an NA confirmed are not swept, so the table can fill with them; admit must then turn
// newcomers away rather than keep growing, and no /128 route may be added for them.
func TestProxyAdmitRefusesWhenFullOfValid(t *testing.T) {
	n := newTestProxy("wan")
	now := time.Now()
	base := netip.MustParseAddr("2001:db8::").As16()
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := range maxProxySessions {
		b := base
		b[13], b[14], b[15] = byte(i>>16), byte(i>>8), byte(i)
		n.sessions[netip.AddrFrom16(b)] = &proxySession{State: "valid", Side: sideLAN, Expires: now.Add(n.ttl)}
	}
	if n.admit(now) {
		t.Fatal("a table full of confirmed neighbours should refuse a newcomer")
	}
	newcomer := netip.MustParseAddr("2001:db8::ffff:ffff")
	n.learn(sideLAN, newcomer, now)
	if _, ok := n.sessions[newcomer]; ok {
		t.Fatal("learn should not have recorded a session past the cap")
	}
	if _, ok := n.kernelSet[newcomer]; ok {
		t.Fatal("learn should not have installed a /128 route past the cap")
	}
}

// auto mode proxies a shared /64 on a broadcast WAN, a delegated one equal to the on-link /64
// included, and never on a point-to-point WAN.
func TestProxyAutoMode(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/64")
	snap := Snapshot{
		WAN: []Prefix{{Prefix: p, Source: "ra"}, {Prefix: p, Source: "pd"}},
		LAN: map[string][]Prefix{"lan0": {{Prefix: p, Source: "pd"}}},
	}
	n := newTestProxy("lan")
	n.mode, n.lanIf = "auto", "lan0"
	n.setPrefixes(snap)
	if !n.autoOn || len(n.prefixes) != 1 {
		t.Fatalf("broadcast WAN: proxy should be on for %v", n.prefixes)
	}
	n.wanIfi = &net.Interface{Index: 2, Name: "ppp0", Flags: net.FlagUp | net.FlagPointToPoint}
	n.setPrefixes(snap)
	if n.autoOn || len(n.prefixes) != 0 {
		t.Fatalf("point-to-point WAN: proxy should be off, scope %v", n.prefixes)
	}
}

// With a delegation clear of the on-link /64 there is nothing to ask the ISP for, and auto mode
// then proxies like forward mode.
func TestProxyAutoModeWithClearDelegation(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/64")
	snap := Snapshot{
		WAN: []Prefix{{Prefix: p, Source: sourceRA}, {Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Source: sourcePD}},
		LAN: map[string][]Prefix{"lan0": {{Prefix: p, Source: sourceRA}}},
	}
	n := newTestProxy("wan")
	n.mode, n.lanIf, n.prefixes = proxyAuto, "lan0", nil
	n.setPrefixes(snap)
	if !n.autoOn || n.effectiveMode() != proxyForward {
		t.Fatalf("auto mode should be on and forward: %v %v", n.autoOn, n.effectiveMode())
	}
	host := netip.MustParseAddr("2001:db8::abcd")
	n.mu.Lock()
	n.onSolicit(sideWAN, host, netip.MustParseAddr("fe80::1"))
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[host]; s == nil || s.State != "probing" {
		t.Fatalf("auto mode probes like forward mode: %+v", s)
	}
}

// Excluded addresses are never proxied, and static ones always are.
func TestProxyExcludeAndStatic(t *testing.T) {
	n := newTestProxy("wan")
	n.exclude = []netip.Prefix{netip.MustParsePrefix("2001:db8::ff00/120")}
	n.static = []netip.Prefix{netip.MustParsePrefix("2001:db9::5/128")}
	if n.covered(netip.MustParseAddr("2001:db8::ff01")) {
		t.Fatal("excluded address proxied")
	}
	if !n.covered(netip.MustParseAddr("2001:db9::5")) {
		t.Fatal("static address not proxied")
	}
}

// A known neighbour on the other side is answered for, a known absent one is not, and a probe
// already under way is not repeated within a second: the asker only joins the list, once.
func TestProxyKnownSessionsAndDuplicateNS(t *testing.T) {
	n := newTestProxy("wan")
	valid, invalid, probing := netip.MustParseAddr("2001:db8::a"), netip.MustParseAddr("2001:db8::b"), netip.MustParseAddr("2001:db8::c")
	up, up2 := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	now := time.Now()
	n.sessions[valid] = &proxySession{State: "valid", Side: sideLAN, Expires: now.Add(time.Minute)}
	n.sessions[invalid] = &proxySession{State: "invalid", Side: sideLAN, Expires: now.Add(time.Minute)}
	for _, target := range []netip.Addr{valid, invalid, probing, probing, probing} {
		n.mu.Lock()
		n.onSolicit(sideWAN, target, up)
	}
	n.mu.Lock()
	n.onSolicit(sideWAN, probing, up2)
	n.mu.Lock()
	n.onSolicit(sideWAN, probing, netip.Addr{}) // the router's own NS joins no list
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.pending[valid]) != 0 || len(n.pending[invalid]) != 0 || n.sessions[invalid].State != "invalid" {
		t.Fatalf("known sessions start no probe: %+v", n.pending)
	}
	if got := n.pending[probing]; len(got) != 2 || got[0].addr != up || got[1].addr != up2 {
		t.Fatalf("askers: %+v", got)
	}
}

// A full table turns a new target away before any probe.
func TestProxyFullTableRefusesProbe(t *testing.T) {
	n := newTestProxy("wan")
	now := time.Now()
	base := netip.MustParseAddr("2001:db8::").As16()
	for i := range maxProxySessions {
		b := base
		b[13], b[14], b[15] = byte(i>>16), byte(i>>8), byte(i)
		n.sessions[netip.AddrFrom16(b)] = &proxySession{State: "valid", Side: sideLAN, Expires: now.Add(time.Minute)}
	}
	target := netip.MustParseAddr("2001:db8::1:0:0:1")
	n.mu.Lock()
	n.onSolicit(sideWAN, target, netip.MustParseAddr("fe80::1"))
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.sessions[target]; ok || len(n.pending) != 0 {
		t.Fatal("a full table must not take a new probe")
	}
}

// An unsolicited NA from a LAN host is learned, its /128 route added once; one from the WAN side
// for a target without a session is ignored.
func TestProxyUnsolicitedNA(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	n := newTestProxy("wan")
	host, far := netip.MustParseAddr("2001:db8::a"), netip.MustParseAddr("2001:db8::b")
	n.mu.Lock()
	n.onAdvert(sideLAN, host)
	n.mu.Lock()
	n.onAdvert(sideWAN, far)
	n.mu.Lock()
	n.learn(sideLAN, host, time.Now()) // the route is in place already
	defer n.mu.Unlock()
	if s := n.sessions[host]; s == nil || s.Side != sideLAN || n.kernelSet[host] != 3 {
		t.Fatalf("LAN host: %+v %v", s, n.kernelSet)
	}
	if _, ok := n.sessions[far]; ok {
		t.Fatal("a WAN NA without a session must be ignored")
	}
}

// prefix mode answers an NS from the WAN for any address in scope, and nothing else.
func TestProxyPrefixMode(t *testing.T) {
	n := newTestProxy("wan")
	n.mode = proxyPrefix
	host := netip.MustParseAddr("2001:db8::a")
	n.mu.Lock()
	n.onSolicit(sideLAN, host, netip.MustParseAddr("2001:db8::b"))
	n.mu.Lock()
	n.onSolicit(sideWAN, host, netip.Addr{})
	n.mu.Lock()
	if len(n.sessions) != 0 { // the LAN sender is not learned outside forward mode
		n.mu.Unlock()
		t.Fatalf("neither the LAN side nor the router itself is answered: %+v", n.sessions)
	}
	n.onSolicit(sideWAN, host, netip.MustParseAddr("fe80::1"))
	n.mu.Lock()
	defer n.mu.Unlock()
	if s := n.sessions[host]; s == nil || s.State != "valid" || s.Side != sideLAN {
		t.Fatalf("prefix mode: %+v", s)
	}
}

// static mode only installs kernel proxy entries for single addresses and waits.
func TestProxyStaticMode(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	n := newTestProxy("wan")
	n.mode = proxyStatic
	n.static = []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128"), netip.MustParsePrefix("2001:db8:1::/64")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.serve(ctx, nil)
}

// The router's own addresses are collected from both sides, skipping a side not known yet.
func TestProxyRefreshSelfAddrs(t *testing.T) {
	lo, err := net.InterfaceByIndex(1)
	if err != nil {
		t.Skip(err)
	}
	n := newTestProxy("wan")
	n.wanIfi, n.lanIfi = nil, lo
	n.refreshSelfAddrs()
	if !n.selfAddrs[netip.MustParseAddr("127.0.0.1")] {
		t.Fatalf("loopback addresses: %v", n.selfAddrs)
	}
}

// nsFrame builds an Ethernet frame carrying the ICMPv6 message m from src, with a correct checksum.
func nsFrame(src netip.Addr, hop byte, m []byte) []byte {
	f := make([]byte, 14+40, 14+40+len(m))
	f[12], f[13] = 0x86, 0xdd
	ip := f[14:]
	ip[0], ip[6], ip[7] = 0x60, 58, hop
	binary.BigEndian.PutUint16(ip[4:], uint16(len(m)))
	s, d := src.As16(), netip.MustParseAddr("ff02::1:ff00:10").As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	f = append(f, m...)
	binary.BigEndian.PutUint16(f[14+42:], icmpv6Checksum(f[14+8:14+40], f[14+40:]))
	return f
}

// A captured NS is taken only when it passes the checks the kernel makes: hop limit 255, a correct
// checksum, code 0, a well-formed Neighbor Solicitation in an IPv6 packet holding all of it.
func TestParseNS(t *testing.T) {
	src, target := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::10")
	ns, _ := ndp.MarshalMessage(&ndp.NeighborSolicitation{TargetAddress: target})
	na, _ := ndp.MarshalMessage(&ndp.NeighborAdvertisement{TargetAddress: target})
	good := nsFrame(src, 255, ns)
	tagged := append(append(append([]byte{}, good[:12]...), 0x81, 0x00, 0x00, 0x01), good[12:]...)
	padded := append(slices.Clone(good), 0, 0, 0, 0) // an Ethernet trailer
	for _, f := range [][]byte{good, tagged, padded} {
		if from, got, ok := parseNS(f); !ok || from != src || got != target {
			t.Fatalf("%x: %v %v %v", f, from, got, ok)
		}
	}

	badSum := slices.Clone(good)
	badSum[14+42]++
	code := slices.Clone(ns)
	code[1] = 1
	udp := slices.Clone(good)
	udp[14+6] = 17
	for name, f := range map[string][]byte{
		"hop limit 64":  nsFrame(src, 64, ns),
		"checksum":      badSum,
		"code 1":        nsFrame(src, 255, code),
		"NA":            nsFrame(src, 255, na),
		"odd length":    nsFrame(src, 255, append(slices.Clone(ns), 0)),
		"truncated":     good[:len(good)-1],
		"not ICMPv6":    udp,
		"no IPv6 frame": good[:14+39],
	} {
		if _, _, ok := parseNS(f); ok {
			t.Fatalf("%s: taken", name)
		}
	}
}
