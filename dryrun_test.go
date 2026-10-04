package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// paramKey ignores lifetimes and deprecated prefixes, so only a real change is printed again.
func TestParamKey(t *testing.T) {
	now := time.Now()
	p := func(s string, dep bool) Prefix {
		return Prefix{Prefix: netip.MustParsePrefix(s), Preferred: now, Valid: now, Deprecated: dep}
	}
	s := Snapshot{
		WAN:     []Prefix{p("2001:db8::/56", false), p("2001:db8:9::/56", true)},
		LAN:     map[string][]Prefix{"eth2": {p("2001:db8:0:2::/64", false)}, "eth1": {p("2001:db8:0:1::/64", false), p("2001:db8:9:1::/64", true)}},
		WANAddr: netip.MustParseAddr("2001:db8::1"),
		Source:  sourcePD,
	}
	key := paramKey(s)
	if want := "2001:db8::/56|2001:db8::1|pd|eth1:2001:db8:0:1::/64|eth2:2001:db8:0:2::/64"; key != want {
		t.Errorf("got %q, want %q", key, want)
	}
	renewed := s
	renewed.WAN = []Prefix{s.WAN[0], s.WAN[1]}
	renewed.WAN[0].Valid = now.Add(time.Hour)
	if paramKey(renewed) != key {
		t.Error("a renewal changed the key")
	}
	s.Tunnel = &TunnelParams{Kind: tunnelDSLite, AFTRName: "aftr.example", Local: netip.MustParseAddr("2001:db8::1")}
	if k := paramKey(s); !strings.HasPrefix(k, key+"|ds-lite||aftr.example||2001:db8::1|") {
		t.Errorf("with a tunnel: %q", k)
	}
}

func TestDryReport(t *testing.T) {
	now := time.Now()
	s := Snapshot{
		Source:  sourcePD,
		WAN:     []Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/56"), Source: sourcePD, Preferred: now.Add(time.Hour + time.Second), Valid: now.Add(2*time.Hour + time.Second)}},
		LAN:     map[string][]Prefix{"eth1": {{Prefix: netip.MustParsePrefix("2001:db8::/64")}}},
		WANAddr: netip.MustParseAddr("2001:db8::1"),
		Tunnel:  &TunnelParams{Kind: tunnelDSLite, Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8:ff::1")},
	}
	rep := dryReport(s, dryOpts{wan: "sixup-none0", tunDev: "ip6tnl9", metric4: 100})
	if lan := rep["lan_split"].(map[string][]string); !slices.Equal(lan["eth1"], []string{"2001:db8::/64"}) {
		t.Errorf("lan_split = %v", lan)
	}
	if rep["wan_addr"] != "2001:db8::1" {
		t.Errorf("wan_addr = %v", rep["wan_addr"])
	}
	if _, ok := rep["tunnel_device"]; !ok {
		t.Errorf("no tunnel_device in %v", rep)
	}
	if _, ok := dryReport(Snapshot{}, dryOpts{wan: "sixup-none0", tunDev: "ip6tnl9"})["tunnel_device"]; ok {
		t.Error("tunnel_device without tunnel endpoints")
	}
}
