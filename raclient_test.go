package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
)

func pio(p string, pref, valid time.Duration, onLink, auto bool) *ndp.PrefixInformation {
	pf := netip.MustParsePrefix(p)
	return &ndp.PrefixInformation{
		PrefixLength: uint8(pf.Bits()), OnLink: onLink, AutonomousAddressConfiguration: auto,
		ValidLifetime: valid, PreferredLifetime: pref, Prefix: pf.Addr(),
	}
}

func TestParseRAPrefixes(t *testing.T) {
	now := time.Now()
	ra := &ndp.RouterAdvertisement{RouterLifetime: 30 * time.Minute, Options: []ndp.Option{
		pio("2001:db8:1::/64", time.Hour, 2*time.Hour, true, true),
		pio("2001:db8:2::/64", time.Hour, 2*time.Hour, true, false), // no A bit: not SLAAC
		pio("2001:db8:3::/56", time.Hour, 2*time.Hour, true, true),  // not /64: never SLAAC
		pio("fe80::/64", time.Hour, 2*time.Hour, true, true),        // link-local: ignored
		pio("2001:db8:9::/64", 0, 0, true, true),                    // valid 0: revoked
	}}
	info := parseRA(ra, now, 1500, true, true)
	if len(info.prefixes) != 3 {
		t.Fatalf("want 3 prefixes, got %d", len(info.prefixes))
	}
	if !info.prefixes[0].SLAAC || info.prefixes[1].SLAAC || info.prefixes[2].SLAAC {
		t.Fatalf("SLAAC flags wrong: %+v", info.prefixes)
	}
	if len(info.revoked) != 1 || info.revoked[0] != netip.MustParsePrefix("2001:db8:9::/64") {
		t.Fatalf("revoked: %v", info.revoked)
	}
	if len(info.onLink) != 3 {
		t.Fatalf("all three L-bit prefixes should get on-link routes, got %v", info.onLink)
	}
	if p := info.prefixes[0]; p.validLeft(now) != 2*time.Hour || p.preferredLeft(now) != time.Hour {
		t.Fatalf("lifetimes: pref=%v valid=%v", p.preferredLeft(now), p.validLeft(now))
	}
}

// With the shared /64 on the LAN side the WAN must not get an on-link route for a /64,
// but longer prefixes still do.
func TestParseRAOnLinkLayout(t *testing.T) {
	ra := &ndp.RouterAdvertisement{RouterLifetime: time.Hour, Options: []ndp.Option{
		pio("2001:db8:1::/64", time.Hour, time.Hour, true, true),
		pio("2001:db8:3::/56", time.Hour, time.Hour, true, true),
	}}
	info := parseRA(ra, time.Now(), 1500, true, false)
	if _, ok := info.onLink[netip.MustParsePrefix("2001:db8:1::/64")]; ok {
		t.Fatal("/64 must not be on-link on WAN under lan layout")
	}
	if _, ok := info.onLink[netip.MustParsePrefix("2001:db8:3::/56")]; !ok {
		t.Fatal("/56 should still be on-link")
	}
}

// A router announcing lifetime 0 is going away: its prefixes are not adopted.
func TestParseRARouterLifetimeZero(t *testing.T) {
	ra := &ndp.RouterAdvertisement{RouterLifetime: 0, Options: []ndp.Option{
		pio("2001:db8:1::/64", time.Hour, time.Hour, true, true),
	}}
	if info := parseRA(ra, time.Now(), 1500, true, true); len(info.prefixes) != 0 {
		t.Fatalf("prefixes from a lifetime-0 router must be ignored: %v", info.prefixes)
	}
}

func TestParseRAOptions(t *testing.T) {
	dns := netip.MustParseAddr("2001:4860:4860::8888")
	ra := &ndp.RouterAdvertisement{RouterLifetime: time.Hour, Options: []ndp.Option{
		&ndp.RecursiveDNSServer{Lifetime: time.Hour, Servers: []netip.Addr{dns}},
		&ndp.RecursiveDNSServer{Lifetime: 0, Servers: []netip.Addr{netip.MustParseAddr("2001:db8::53")}}, // lifetime 0: dropped
		&ndp.DNSSearchList{Lifetime: time.Hour, DomainNames: []string{"example.net"}},
		&ndp.PREF64{Lifetime: time.Hour, Prefix: netip.MustParsePrefix("64:ff9b::/96")},
		&ndp.RouteInformation{PrefixLength: 48, Preference: ndp.High, RouteLifetime: time.Hour, Prefix: netip.MustParseAddr("2001:db8:aa::")},
		&ndp.RouteInformation{PrefixLength: 48, Preference: ndp.Medium, RouteLifetime: 0, Prefix: netip.MustParseAddr("2001:db8:bb::")},
		ndp.NewMTU(1492),
	}}
	info := parseRA(ra, time.Now(), 1500, true, true)
	if len(info.dns) != 1 || info.dns[0] != dns {
		t.Fatalf("dns: %v", info.dns)
	}
	if len(info.dnssl) != 1 || info.dnssl[0] != "example.net" {
		t.Fatalf("dnssl: %v", info.dnssl)
	}
	if info.pref64 != netip.MustParsePrefix("64:ff9b::/96") {
		t.Fatalf("pref64: %v", info.pref64)
	}
	if ri := info.routes[netip.MustParsePrefix("2001:db8:aa::/48")]; ri.lifetime != time.Hour || ri.pref != ndp.High {
		t.Fatalf("RIO: %+v", ri)
	}
	if ri, ok := info.routes[netip.MustParsePrefix("2001:db8:bb::/48")]; !ok || ri.lifetime != 0 {
		t.Fatalf("withdrawn RIO should be present with lifetime 0: %+v", ri)
	}
	if info.mtu != 1492 {
		t.Fatalf("mtu: %d", info.mtu)
	}
}

func TestParseRAMTUBounds(t *testing.T) {
	for _, tc := range []struct {
		mtu   uint32
		ifMTU int
		want  int
	}{
		{1492, 1500, 1492},
		{1500, 1500, 1500},
		{1279, 1500, 0}, // below IPv6 minimum
		{9000, 1500, 0}, // above the interface
		{9000, 0, 9000}, // unknown interface MTU: accept
	} {
		ra := &ndp.RouterAdvertisement{RouterLifetime: time.Hour, Options: []ndp.Option{ndp.NewMTU(tc.mtu)}}
		info := parseRA(ra, time.Now(), tc.ifMTU, true, true)
		if info.mtu != tc.want {
			t.Errorf("mtu %d ifMTU %d: got %d want %d", tc.mtu, tc.ifMTU, info.mtu, tc.want)
		}
		if tc.want == 0 && info.badMTU != int(tc.mtu) {
			t.Errorf("mtu %d: rejected value should be recorded, got %d", tc.mtu, info.badMTU)
		}
	}
}

func TestRouterMetricAndRank(t *testing.T) {
	if routerMetric(ndp.High) >= routerMetric(ndp.Medium) || routerMetric(ndp.Medium) >= routerMetric(ndp.Low) {
		t.Fatal("higher preference must map to a lower metric")
	}
	if prefRank(ndp.High) <= prefRank(ndp.Medium) || prefRank(ndp.Medium) <= prefRank(ndp.Low) {
		t.Fatal("prefRank order wrong")
	}
	a := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8::/64"): true}
	b := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8::/64"): true}
	c := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8:1::/64"): true}
	if !samePrefixSet(a, b) || samePrefixSet(a, c) || samePrefixSet(a, map[netip.Prefix]bool{}) {
		t.Fatal("samePrefixSet wrong")
	}
}

// The M and O bits of the upstream RA reach the store, which waits for PD only when they promise
// a DHCPv6 answer.
func TestRAClientPassesDHCPv6Flags(t *testing.T) {
	old := dryRun
	dryRun = true // routes and sysctls go through stubs
	defer func() { dryRun = old }()
	for _, other := range []bool{true, false} {
		st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, time.Minute, 0)
		ch := st.Subscribe()
		recv(t, ch)
		stable, _ := parseIIDPolicy("stable")
		c := &raClient{ifname: "wan0", ifi: &net.Interface{Index: 2, Name: "wan0", MTU: 1500}, store: st, slaac: true, iid: stable, routers: map[netip.Addr]*routerInfo{}}
		c.handle(&ndp.RouterAdvertisement{
			OtherConfiguration: other, RouterLifetime: 30 * time.Minute,
			Options: []ndp.Option{pio("2001:db8:0:1::/64", time.Hour, time.Hour, true, true)},
		}, netip.MustParseAddr("fe80::1"))
		c.publish()
		if s := recv(t, ch); s.PDPending != other {
			t.Fatalf("O=%v: want pd_pending=%v, got %v", other, other, s.PDPending)
		}
	}
}
