package main

import (
	"context"
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
		dns: lanDNS{list: []dnsEntry{{upstream: true}}},
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
	r.dns.list, _ = parseLANDNS("2001:db8::53")
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

func TestParseLANDNS(t *testing.T) {
	got, err := parseLANDNS("self, upstream, 2001:db8::53")
	if err != nil || len(got) != 3 || !got[0].self || !got[1].upstream || got[2].addr != netip.MustParseAddr("2001:db8::53") {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := parseLANDNS(" off "); err != nil || len(got) != 0 {
		t.Fatalf("off: %+v, %v", got, err)
	}
	for _, bad := range []string{"", "router", "192.0.2.1", "fe80::1%eth0", "self,", "off,self"} {
		if _, err := parseLANDNS(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// self is the router's own address on the LAN the RA goes out on, in the ULA when there is one,
// and follows the prefix; upstream passes the routable upstream servers through, in place.
func TestLANDNS(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	ifi := &net.Interface{Index: 3, Name: "lan0"}
	fixed, _ := parseIIDPolicy("::1")
	d := lanDNS{iid: fixed}
	resolve := func(spec string, s Snapshot) []netip.Addr {
		d.list, _ = parseLANDNS(spec)
		return d.resolve(s, ifi)
	}
	google := netip.MustParseAddr("2001:4860:4860::8888")
	if got := resolve("upstream", snap); len(got) != 1 || got[0] != google {
		t.Fatalf("upstream: want the routable upstream server, got %v", got)
	}
	if got := resolve("off", snap); len(got) != 0 {
		t.Fatalf("off: %v", got)
	}
	if got := resolve("self,upstream,2001:db8::53", snap); len(got) != 3 || got[0] != netip.MustParseAddr("2001:db8:1::1") || got[1] != google || got[2] != netip.MustParseAddr("2001:db8::53") {
		t.Fatalf("self in the global prefix, in order: %v", got)
	}
	snap.LAN["lan0"] = append(snap.LAN["lan0"], Prefix{Prefix: netip.MustParsePrefix("fd00:1::/64"), Source: "ula"})
	if got := resolve("self", snap); len(got) != 1 || got[0] != netip.MustParseAddr("fd00:1::1") {
		t.Fatalf("self prefers the ULA: %v", got)
	}
	if got := resolve("self", Snapshot{DNS: snap.DNS}); len(got) != 0 {
		t.Fatalf("self with no LAN prefix is left out: %v", got)
	}
}

// The prefix of this router's own NAT64 is announced only while Jool translates; -ra-pref64 wins
// over it, and without either the upstream's passes through. A prefix that stops being announced
// is withdrawn with lifetime 0 in the RAs sent right away, then left out.
func TestRAPref64FollowsNAT64(t *testing.T) {
	upstream := netip.MustParsePrefix("2001:db8:64::/96")
	pref64s := func(r *raServer) map[netip.Prefix]time.Duration {
		out := map[netip.Prefix]time.Duration{}
		for _, o := range r.build().Options {
			if p, ok := o.(*ndp.PREF64); ok {
				out[p.Prefix] = p.Lifetime
			}
		}
		return out
	}
	snap := lanSnap(time.Now())
	snap.PREF64 = upstream
	r := newTestRA(snap)
	if got := pref64s(r); len(got) != 1 || got[upstream] == 0 {
		t.Fatalf("Jool not translating: the upstream's prefix, got %v", got)
	}

	on := snap
	on.NAT64, on.Change = netip.MustParsePrefix("fd00:64::/96"), "renew"
	if !r.update(on) {
		t.Fatal("a new PREF64 calls for RAs right away")
	}
	if got := pref64s(r); got[on.NAT64] == 0 || got[upstream] != 0 || len(got) != 2 {
		t.Fatalf("Jool translating: the prefix it translates, and the upstream's withdrawn, got %v", got)
	}

	off := on
	off.NAT64 = netip.Prefix{}
	r.update(off)
	if got := pref64s(r); got[upstream] == 0 || got[on.NAT64] != 0 || len(got) != 2 {
		t.Fatalf("Jool stopped: its prefix withdrawn, got %v", got)
	}
	for range 3 {
		r.withdrawLeft-- // what send does after each RA
	}
	if got := pref64s(r); len(got) != 1 {
		t.Fatalf("after the burst the withdrawn prefix is left out, got %v", got)
	}
	if r.update(off) {
		t.Fatal("an unchanged snapshot needs no RA right away")
	}

	r.pref64 = netip.MustParsePrefix("2001:db8:ff64::/96")
	if got := pref64s(r); got[r.pref64] == 0 {
		t.Fatalf("-ra-pref64 names a NAT64 elsewhere, got %v", got)
	}
	r.pref64, r.pref64Off = netip.Prefix{}, true
	on.Change = "renew"
	r.update(on)
	if got := pref64s(r); len(got) != 0 {
		t.Fatalf("-ra-pref64 off announces nothing, even with Jool translating, got %v", got)
	}
}

func TestParsePref64(t *testing.T) {
	if p, off, err := parsePref64("auto"); err != nil || off || p.IsValid() {
		t.Fatalf("auto: %v %v %v", p, off, err)
	}
	if p, off, err := parsePref64("off"); err != nil || !off || p.IsValid() {
		t.Fatalf("off: %v %v %v", p, off, err)
	}
	if p, _, err := parsePref64("2001:db8:64::1/96"); err != nil || p != netip.MustParsePrefix("2001:db8:64::/96") {
		t.Fatalf("a prefix is masked: %v %v", p, err)
	}
	for _, bad := range []string{"", "on", "192.0.2.0/32", "::ffff:0:0/96", "2001:db8::/95", "2001:db8::/128"} {
		if _, _, err := parsePref64(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	if p, err := parseNAT64Prefix("fd00:64::/96"); err != nil || p.Bits() != 96 {
		t.Fatalf("a ULA network-specific prefix: %v %v", p, err)
	}
}

// Between the RAs of a burst, a snapshot is taken at once so the next RA carries it, and one that
// calls for RAs of its own restarts the burst.
func TestRABurstPauseTakesSnapshots(t *testing.T) {
	r := newTestRA(Snapshot{})
	ch := make(chan Snapshot, 1)

	renew := lanSnap(time.Now())
	renew.Change = "renew"
	ch <- renew
	if got := r.pause(context.Background(), ch, 50*time.Millisecond); got != pauseElapsed {
		t.Fatalf("a renewal waits out the pause, got %v", got)
	}
	if len(r.snap.LAN["lan0"]) != 1 {
		t.Fatal("the renewal must be taken all the same, or the next RA of the burst is stale")
	}

	add := lanSnap(time.Now())
	add.Change = "add"
	ch <- add
	if got := r.pause(context.Background(), ch, time.Hour); got != pauseRestart {
		t.Fatalf("a new prefix restarts the burst, got %v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := r.pause(ctx, ch, time.Hour); got != pauseCancelled {
		t.Fatalf("cancelled: got %v", got)
	}
}
