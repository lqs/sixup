package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
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
	now := time.Now()
	for a, s := range n.sessions {
		if now.After(s.Expires) {
			delete(n.sessions, a)
			n.dropRoute(a)
		}
	}
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
