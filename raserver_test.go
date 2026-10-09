package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
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
	// the upstream's 1h and 2h, cut to ND_PREFERRED_LIMIT and ND_VALID_LIMIT (RFC 9096 L-16)
	if pi.PreferredLifetime != ndPreferredLimit || pi.ValidLifetime != ndValidLimit {
		t.Fatalf("PIO lifetimes must be capped: pref=%v valid=%v", pi.PreferredLifetime, pi.ValidLifetime)
	}
	rd, ok := findOpt[*ndp.RecursiveDNSServer](ra.Options)
	if !ok || len(rd.Servers) != 1 || rd.Servers[0] != netip.MustParseAddr("2001:4860:4860::8888") {
		t.Fatalf("link-local DNS must be filtered, got %+v", rd)
	}
	// RFC 8106: RDNSS lifetime at least 3 * MaxRtrAdvInterval by default, capped by upstream valid.
	if rd.Lifetime != 3*r.maxI {
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
	snap.WAN[0].Valid = now.Add(10 * time.Minute) // shorter than 3*maxI
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
	ri, ok := rio(ra, netip.MustParsePrefix("2001:db8:ff::/48"))
	if !ok || ri.RouteLifetime != r.lifetime {
		t.Fatalf("RIO: %+v", ri)
	}
}

func rio(ra *ndp.RouterAdvertisement, p netip.Prefix) (*ndp.RouteInformation, bool) {
	for _, o := range ra.Options {
		if ri, ok := o.(*ndp.RouteInformation); ok && netip.PrefixFrom(ri.Prefix, int(ri.PrefixLength)) == p {
			return ri, true
		}
	}
	return nil, false
}

// The delegation and the ULA are advertised as routes (RFC 7084 L-3), and a delegation gone with
// lifetime 0.
func TestRAAdvertisesTheDelegationAndULA(t *testing.T) {
	now := time.Now()
	r := newTestRA(lanSnap(now))
	ula := netip.MustParsePrefix("fd00:1:2::/48")
	r.snap.ULA = []Prefix{{Prefix: ula, Valid: now.Add(30 * 24 * time.Hour), Source: sourceULA}}
	ra := r.build()
	if ri, ok := rio(ra, netip.MustParsePrefix("2001:db8::/56")); !ok || ri.RouteLifetime != ndValidLimit {
		t.Fatalf("delegation RIO: %+v", ri)
	}
	if ri, ok := rio(ra, ula); !ok || ri.RouteLifetime != ndValidLimit {
		t.Fatalf("ULA RIO: %+v", ri)
	}
	r.snap.WAN[0].Stale, r.snap.WAN[0].Deprecated = true, true
	if ri, ok := rio(r.build(), netip.MustParsePrefix("2001:db8::/56")); !ok || ri.RouteLifetime != 0 {
		t.Fatalf("a delegation gone is withdrawn: %+v", ri)
	}

	// with a ULA of its own, the upstream's is not passed on
	site := netip.MustParsePrefix("fd00:1::/48")
	r.snap.UpstreamULA = []netip.Prefix{site, netip.MustParsePrefix("fd00:1::/64")}
	if _, ok := rio(r.build(), site); ok {
		t.Fatal("a site of its own keeps the upstream's out")
	}
	// A ULA delegated by the upstream lasts as long as the delegation, and the upstream's site
	// is reached through here too, as it is with no ULA at all, the upstream's /64 shared
	r.snap.ULA = []Prefix{{Prefix: netip.MustParsePrefix("fd00:1:0:10::/60"), Valid: now.Add(10 * time.Minute), Source: sourceULA, Delegated: true}}
	ra = r.build()
	if ri, ok := rio(ra, r.snap.ULA[0].Prefix); !ok || ri.RouteLifetime > 10*time.Minute || ri.RouteLifetime < 9*time.Minute {
		t.Fatalf("delegated ULA RIO: %+v", ri)
	}
	if ri, ok := rio(ra, site); !ok || ri.RouteLifetime != ndValidLimit {
		t.Fatalf("site RIO: %+v", ri)
	}
	r.snap.ULA = nil
	if ri, ok := rio(r.build(), site); !ok || ri.RouteLifetime != ndValidLimit {
		t.Fatalf("site RIO without a ULA: %+v", ri)
	}
	ra = r.build()
	if _, ok := rio(ra, netip.MustParsePrefix("fd00:1::/64")); ok {
		t.Fatal("the upstream's LAN is reached through its site prefix")
	}
	if _, ok := rio(ra, ula); ok {
		t.Fatal("the own ULA is gone")
	}
}

// A delegated /64 is advertised as a route too (IPv6 Ready CE Router 2.7.2).
func TestRAAdvertisesADelegated64(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.WAN[0].Prefix = netip.MustParsePrefix("2001:db8:1::/64")
	if _, ok := rio(newTestRA(snap).build(), netip.MustParsePrefix("2001:db8:1::/64")); !ok {
		t.Fatal("no RIO for the delegated /64")
	}
}

// With only withdrawn prefixes left on the LAN, the router is no default router (RFC 7084 L-4).
func TestRANoDefaultRouterOnStalePrefixes(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.LAN["lan0"][0].Stale, snap.LAN["lan0"][0].Deprecated = true, true
	if l := newTestRA(snap).build().RouterLifetime; l != 0 {
		t.Fatalf("lifetime %v", l)
	}
}

// A withdrawn prefix goes out with both lifetimes 0 (RFC 9096 section 3.5).
func TestRAWithdrawsStalePrefixes(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	snap.LAN["lan0"][0] = Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now, Valid: now.Add(time.Hour), Source: "pd", Deprecated: true, Stale: true}
	pi, ok := findOpt[*ndp.PrefixInformation](newTestRA(snap).build().Options)
	if !ok || pi.PreferredLifetime != 0 || pi.ValidLifetime != 0 {
		t.Fatalf("stale PIO: %+v", pi)
	}
}

// The router is no default router while the WAN has none (RFC 7084 G-4) or only the ULA is on the
// LAN (ULA-5), and losing the WAN router calls for RAs at once (G-5).
func TestRARouterLifetime(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	r := newTestRA(snap)
	snap.NoWANRouter = true
	if !r.update(snap) {
		t.Fatal("losing the WAN router must send RAs at once")
	}
	if l := r.build().RouterLifetime; l != 0 {
		t.Fatalf("no WAN router: lifetime %v", l)
	}
	ula := Snapshot{LAN: map[string][]Prefix{"lan0": {{Prefix: netip.MustParsePrefix("fd00:1:2::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourceULA}}}}
	if l := newTestRA(ula).build().RouterLifetime; l != 0 {
		t.Fatalf("ULA only: lifetime %v", l)
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

// self is the router's address in the LAN's ULA when there is one, else its global address on
// the WAN, since the LAN holds none; upstream passes the routable upstream servers through, in place.
func TestLANDNS(t *testing.T) {
	now := time.Now()
	snap := lanSnap(now)
	ifi := &net.Interface{Index: 3, Name: "lan0"}
	fixed, _ := parseIIDPolicy("::1")
	d := lanDNS{wanIID: fixed, wan: "sixup-none0"}
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
	if got := resolve("self,upstream,2001:db8::53", snap); !slices.Equal(got, []netip.Addr{google, netip.MustParseAddr("2001:db8::53")}) {
		t.Fatalf("self is left out while the router has no address the LAN reaches: %v", got)
	}
	// the WAN's /128 in the delegation, which the LAN reaches through the proxy entry
	snap.WANSubnet = Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd", OffLink: true}
	if got := resolve("self,upstream,2001:db8::53", snap); len(got) != 3 || got[0] != netip.MustParseAddr("2001:db8:1::1") || got[1] != google || got[2] != netip.MustParseAddr("2001:db8::53") {
		t.Fatalf("self on the WAN, in order: %v", got)
	}
	snap.WANAddr = netip.MustParseAddr("2001:db8::99")
	if got := resolve("self", snap); len(got) != 1 || got[0] != snap.WANAddr {
		t.Fatalf("self is the WAN address from IA_NA or configured by hand: %v", got)
	}
	snap.LAN["lan0"] = append(snap.LAN["lan0"], Prefix{Prefix: netip.MustParsePrefix("fd00:1::/64"), Source: "ula"})
	if got := resolve("self", snap); len(got) != 1 || got[0] != netip.MustParseAddr("fd00:1::1") {
		t.Fatalf("self prefers the ULA: %v", got)
	}
	snap.LAN["lan0"][1].Deprecated = true
	if got := resolve("self", snap); len(got) != 1 || got[0] != snap.WANAddr {
		t.Fatalf("a ULA being withdrawn is passed over: %v", got)
	}
	gone := Snapshot{DNS: snap.DNS, WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Source: "ra", SLAAC: true, Deprecated: true}}}
	if got := resolve("self", gone); len(got) != 0 {
		t.Fatalf("self with no LAN prefix and only a deprecated WAN prefix is left out: %v", got)
	}
}

// The WAN is looked up for the MAC an eui64 -wan-iid needs; a WAN that is not there yet still
// gives the stable address, by its name.
func TestLANDNSWANInterface(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no interface to look up")
	}
	if got := (lanDNS{wan: ifs[0].Name}).wanIfi(); got.Index != ifs[0].Index {
		t.Fatalf("%s: %+v", ifs[0].Name, got)
	}
	if got := (lanDNS{wan: "sixup-none0"}).wanIfi(); got.Name != "sixup-none0" || got.Index != 0 {
		t.Fatalf("missing WAN: %+v", got)
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

// The A and L flags follow -ra-slaac and -ra-onlink (RFC 7084 L-7).
func TestRAPIOFlags(t *testing.T) {
	r := newTestRA(lanSnap(time.Now()))
	r.noSLAAC, r.offLink = true, true
	pi, _ := findOpt[*ndp.PrefixInformation](r.build().Options)
	if pi.AutonomousAddressConfiguration || pi.OnLink {
		t.Fatalf("A and L must be clear: %+v", pi)
	}
}

// An ND message with an ICMP code other than 0 is invalid (RFC 4861 section 6.1), and an RS is
// taken only with hop limit 255, from a link-local source, or from :: without a link-layer address
// (IPv6 Ready CE Router 1.3.8 and 2.4.15).
func TestRSValidation(t *testing.T) {
	rs := &ndp.RouterSolicitation{}
	b, err := ndp.MarshalMessage(rs)
	if err != nil {
		t.Fatal(err)
	}
	if parseND(b) == nil {
		t.Fatal("a valid RS parses")
	}
	b[1] = 1
	if parseND(b) != nil {
		t.Fatal("code 1 is invalid")
	}
	ll := netip.MustParseAddr("fe80::1").WithZone("lan0")
	unspec := netip.IPv6Unspecified().WithZone("lan0") // as the reader gives it
	ok := &ipv6.ControlMessage{HopLimit: 255}
	withLL := &ndp.RouterSolicitation{Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}}}
	for _, c := range []struct {
		msg  ndp.Message
		cm   *ipv6.ControlMessage
		from netip.Addr
		want bool
	}{
		{rs, ok, ll, true},
		{withLL, ok, ll, true},
		{rs, ok, unspec, true},
		{withLL, ok, unspec, false},
		{rs, &ipv6.ControlMessage{HopLimit: 64}, ll, false},
		{rs, ok, netip.MustParseAddr("2001:db8::1"), false},
		{&ndp.RouterAdvertisement{}, ok, ll, false},
	} {
		if got := validRS(c.msg, c.cm, c.from); got != c.want {
			t.Errorf("%T from %s hop %d: got %v", c.msg, c.from, c.cm.HopLimit, got)
		}
	}
	if parseND([]byte{byte(ipv6.ICMPTypeRouterAdvertisement), 0}) != nil {
		t.Fatal("a truncated RA does not parse")
	}
}

// A fixed interval when the minimum is not below the maximum, and no PIO for a LAN prefix whose
// valid lifetime is over.
func TestRAIntervalAndExpiredPrefix(t *testing.T) {
	now := time.Now()
	s := lanSnap(now)
	s.LAN["lan0"] = append(s.LAN["lan0"], Prefix{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Valid: now.Add(-time.Second), Source: sourcePD})
	r := newTestRA(s)
	r.minI, r.maxI = 5*time.Second, 5*time.Second
	if got := r.interval(); got != 5*time.Second {
		t.Fatalf("interval: %v", got)
	}
	n := 0
	for _, o := range r.build().Options {
		if _, ok := o.(*ndp.PrefixInformation); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("only the live prefix is advertised, got %d PIOs", n)
	}
}
