package main

import (
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// Every live prefix of the LAN is routed on-link until it expires, with the LAN's own usable
// address in it as the source; a /64 shared with the WAN is routed only where the layout puts it.
func TestLANRoutePlan(t *testing.T) {
	now := time.Now()
	gua := netip.MustParsePrefix("2001:db8:1::/64")
	ula := netip.MustParsePrefix("fd00:1::/64")
	shared := netip.MustParsePrefix("2001:db8:9::/64")
	s := Snapshot{
		WAN: []Prefix{{Prefix: shared, Source: sourceRA, Valid: now.Add(time.Hour)}},
		LAN: map[string][]Prefix{"lan0": {
			{Prefix: gua, Source: sourcePD, Valid: now.Add(time.Hour)},
			{Prefix: ula, Source: sourceULA, Valid: now.Add(2 * time.Hour)},
			{Prefix: shared, Source: sourceRA, Valid: now.Add(time.Hour)},
			{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Source: sourcePD, Valid: now.Add(-time.Second)},
		}},
	}
	addrs := []ifAddr{
		{Index: 3, Addr: netip.MustParseAddr("fd00:1::9")},
		{Index: 3, Addr: netip.MustParseAddr("fd00:1::5")},
		{Index: 3, Addr: netip.MustParseAddr("fd00:1::1"), Flags: ifaFTentative},
		{Index: 3, Addr: netip.MustParseAddr("fd00:1::2"), Flags: ifaFDadFailed},
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:1::1")}, // the WAN's /128: not on this LAN
	}
	got := lanRoutePlan(s, "lan0", "lan", addrs, 3, now)
	if len(got) != 3 || got[gua].src.IsValid() || got[ula].src != netip.MustParseAddr("fd00:1::5") || got[shared].src.IsValid() {
		t.Fatalf("lan layout: %+v", got)
	}
	if d := got[ula].expires; d <= time.Hour || d > 2*time.Hour {
		t.Fatalf("the route expires with the prefix: %v", d)
	}
	for _, layout := range []shared64Layout{"wan", "split"} {
		if got := lanRoutePlan(s, "lan0", layout, addrs, 3, now); len(got) != 2 || slices.Contains(slices.Collect(maps.Keys(got)), shared) {
			t.Fatalf("%s layout leaves the shared /64 to the proxy: %+v", layout, got)
		}
	}
	if got[gua].srcName() != "by address selection" || got[ula].srcName() != "fd00:1::5" {
		t.Fatalf("names: %q %q", got[gua].srcName(), got[ula].srcName())
	}
	if got := lanRoutePlan(s, "lan1", "lan", addrs, 4, now); len(got) != 0 {
		t.Fatalf("another LAN: %+v", got)
	}
}

// The addresses of this router on other interfaces that lie in a live prefix of the LAN are
// answered for there, once each and in order; its own, link-local and failed ones are not.
func TestLANProxyPlan(t *testing.T) {
	now := time.Now()
	prefixes := []Prefix{
		{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Valid: now.Add(time.Hour)},
		{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Valid: now.Add(-time.Second)},
	}
	addrs := []ifAddr{
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:1::9")},
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:1::1")},
		{Index: 5, Addr: netip.MustParseAddr("2001:db8:1::1")},
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:1::7"), Flags: ifaFDadFailed},
		{Index: 3, Addr: netip.MustParseAddr("2001:db8:1::3")},
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:2::1")},
		{Index: 2, Addr: netip.MustParseAddr("2001:db8:3::1")},
		{Index: 2, Addr: netip.MustParseAddr("fe80::1")},
	}
	got := lanProxyPlan(prefixes, addrs, 3, now)
	if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::9")}) {
		t.Fatalf("%v", got)
	}
}
