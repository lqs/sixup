package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
)

func newTestRA(snap Snapshot) *raServer {
	return &raServer{
		ifname: "lan0", ifi: &net.Interface{Index: 3, Name: "lan0", MTU: 1500, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
		minI: 200 * time.Second, maxI: 600 * time.Second, lifetime: 1800 * time.Second, snap: snap,
	}
}

func findOpt[T ndp.Option](opts []ndp.Option) (T, bool) {
	for _, o := range opts {
		if v, ok := o.(T); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func lanSnap(now time.Time) Snapshot {
	p := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	return Snapshot{
		WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}},
		LAN: map[string][]Prefix{"lan0": {p}},
		DNS: []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:4860:4860::8888")},
	}
}

func TestRABuildPrefixAndDNS(t *testing.T) {
	now := time.Now()
	r := newTestRA(lanSnap(now))
	ra := r.build()
	if ra.RouterLifetime != 1800*time.Second {
		t.Fatalf("router lifetime: %v", ra.RouterLifetime)
	}
	pi, ok := findOpt[*ndp.PrefixInformation](ra.Options)
	if !ok || pi.Prefix != netip.MustParseAddr("2001:db8:1::") || pi.PrefixLength != 64 || !pi.OnLink || !pi.AutonomousAddressConfiguration {
		t.Fatalf("PIO: %+v", pi)
	}
	if pi.PreferredLifetime > time.Hour || pi.ValidLifetime > 2*time.Hour || pi.PreferredLifetime < 59*time.Minute {
		t.Fatalf("PIO lifetimes must not exceed the upstream remainder: pref=%v valid=%v", pi.PreferredLifetime, pi.ValidLifetime)
	}
	rd, ok := findOpt[*ndp.RecursiveDNSServer](ra.Options)
	if !ok || len(rd.Servers) != 1 || rd.Servers[0] != netip.MustParseAddr("2001:4860:4860::8888") {
		t.Fatalf("link-local DNS must be filtered, got %+v", rd)
	}
	// RFC 8106: RDNSS lifetime between MaxRtrAdvInterval and twice that, capped by upstream valid.
	if rd.Lifetime != 2*r.maxI {
		t.Fatalf("RDNSS lifetime: %v", rd.Lifetime)
	}
	if _, ok := findOpt[*ndp.MTU](ra.Options); ok {
		t.Fatal("no MTU option when WAN MTU is unknown")
	}
}

func TestRABuildDeprecatedPrefix(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.LAN["lan0"][0].Deprecated = true
	snap.LAN["lan0"][0].Preferred = now
	ra := newTestRA(snap).build()
	pi, _ := findOpt[*ndp.PrefixInformation](ra.Options)
	if pi.PreferredLifetime != 0 {
		t.Fatalf("deprecated prefix must be advertised with preferred 0, got %v", pi.PreferredLifetime)
	}
	if ra.RouterLifetime == 0 {
		t.Fatal("router lifetime stays up while upstream still has a prefix")
	}
}

// No active prefix and nothing upstream: stop being a default router.
func TestRABuildNoPrefixNoUpstream(t *testing.T) {
	ra := newTestRA(Snapshot{LAN: map[string][]Prefix{}}).build()
	if ra.RouterLifetime != 0 {
		t.Fatalf("router lifetime should be 0, got %v", ra.RouterLifetime)
	}
	if _, ok := findOpt[*ndp.PrefixInformation](ra.Options); ok {
		t.Fatal("no PIO expected")
	}
}

func TestRABuildMTU(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.WANMTU = 1492
	ra := newTestRA(snap).build()
	m, ok := findOpt[*ndp.MTU](ra.Options)
	if !ok || m.MTU != 1492 {
		t.Fatalf("WAN path MTU below LAN MTU must be advertised, got %+v", m)
	}
	snap.WANMTU = 1500
	if _, ok := findOpt[*ndp.MTU](newTestRA(snap).build().Options); ok {
		t.Fatal("equal MTU needs no option")
	}
	r := newTestRA(snap)
	r.mtu = 1400
	if m, _ := findOpt[*ndp.MTU](r.build().Options); m.MTU != 1400 {
		t.Fatalf("configured MTU overrides, got %+v", m)
	}
}

func TestRABuildOverridesAndExtras(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.DNSSL = []string{"flets-east.jp"}
	snap.PREF64 = netip.MustParsePrefix("64:ff9b::/96")
	snap.WAN[0].Valid = now.Add(10 * time.Minute) // shorter than 2*maxI
	r := newTestRA(snap)
	r.dns = []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	r.pref64 = netip.MustParsePrefix("2001:db8:64::/96")
	r.routes = []netip.Prefix{netip.MustParsePrefix("2001:db8:ff::/48")}
	r.managed, r.other = false, true
	ra := r.build()
	if !ra.OtherConfiguration || ra.ManagedConfiguration {
		t.Fatal("M/O bits not carried")
	}
	rd, _ := findOpt[*ndp.RecursiveDNSServer](ra.Options)
	if len(rd.Servers) != 1 || rd.Servers[0] != netip.MustParseAddr("2001:db8::53") {
		t.Fatalf("-ra-dns must override upstream: %+v", rd)
	}
	if rd.Lifetime > 10*time.Minute {
		t.Fatalf("RDNSS lifetime must be capped by upstream valid: %v", rd.Lifetime)
	}
	sl, ok := findOpt[*ndp.DNSSearchList](ra.Options)
	if !ok || sl.DomainNames[0] != "flets-east.jp" {
		t.Fatalf("DNSSL: %+v", sl)
	}
	p64, _ := findOpt[*ndp.PREF64](ra.Options)
	if p64.Prefix != netip.MustParsePrefix("2001:db8:64::/96") {
		t.Fatalf("-ra-pref64 must override upstream: %+v", p64)
	}
	ri, ok := findOpt[*ndp.RouteInformation](ra.Options)
	if !ok || ri.PrefixLength != 48 || ri.RouteLifetime != r.lifetime {
		t.Fatalf("RIO: %+v", ri)
	}
}
