package main

import (
	"net/netip"
	"strings"
	"testing"
)

// The plan decides what the ruleset has to contain, so each line type is checked there rather than
// against a live kernel: MAP-E translates into its port set, DS-Lite does not translate at all, and
// a line with its own public IPv4 translates without a port restriction.
func TestNATPlanPerLineType(t *testing.T) {
	local, remote := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")

	dsl := Snapshot{Tunnel: &TunnelParams{
		Kind: "ds-lite", Local: local, Remote: remote, IPv4: netip.MustParseAddr("192.0.0.2"),
	}}
	p, ok := natPlanFor(dsl, 1460, 0)
	if !ok || p.ipv4.IsValid() || len(p.ports) != 0 {
		t.Fatalf("DS-Lite is translated by the AFTR, not here: %+v", p)
	}
	if p.mtu != 1460 {
		t.Fatalf("the MSS clamp still applies on DS-Lite: %+v", p)
	}

	ports := portSpans(4, 8, 0x56)
	mape := Snapshot{Tunnel: &TunnelParams{
		Kind: "map-e", Local: local, Remote: remote, IPv4: netip.MustParseAddr("203.0.113.9"),
		RuleMAPE: &mapeResult{IPv4: netip.MustParseAddr("203.0.113.9"), Ports: ports},
	}}
	p, _ = natPlanFor(mape, 1460, 0)
	if p.ipv4 != netip.MustParseAddr("203.0.113.9") || len(p.ports) != len(ports) {
		t.Fatalf("MAP-E must translate into its own port set: %+v", p)
	}

	fixed := Snapshot{Tunnel: &TunnelParams{
		Kind: "4in6", Local: local, Remote: remote, IPv4: netip.MustParseAddr("198.51.100.7"),
	}}
	p, _ = natPlanFor(fixed, 1460, 0)
	if p.ipv4 != netip.MustParseAddr("198.51.100.7") || len(p.ports) != 0 {
		t.Fatalf("a line with its own IPv4 translates without a port restriction: %+v", p)
	}

	// An unresolved tunnel has no endpoints to translate towards
	if _, ok := natPlanFor(Snapshot{Tunnel: &TunnelParams{Kind: "map-e"}}, 1460, 0); ok {
		t.Fatal("without endpoints there is nothing to install")
	}

	// The key is what decides whether the ruleset is rewritten; a renumbering must change it
	other := portSpans(4, 8, 0x57)
	p1, _ := natPlanFor(mape, 1460, 0)
	mape.Tunnel.RuleMAPE = &mapeResult{IPv4: netip.MustParseAddr("203.0.113.9"), Ports: other}
	p2, _ := natPlanFor(mape, 1460, 0)
	if p1.key() == p2.key() {
		t.Fatal("a different port set must produce a different key")
	}
}

// The log is the only place an operator sees what the translation ended up as, so it has to name
// the address, how much of it this subscriber owns, and the clamp.
func TestNATPlanDescribesItself(t *testing.T) {
	ports := portSpans(4, 8, 0x56)
	mape := natPlan{kind: "map-e", ipv4: netip.MustParseAddr("203.0.113.9"), ports: ports, mtu: 1460}
	got := mape.describe() + mssNote(mape.mtu)
	for _, want := range []string{"map-e", "203.0.113.9", "240 ports", "15 ranges", "MSS clamped to 1420"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q is missing from %q", want, got)
		}
	}
	if got := (natPlan{kind: "ds-lite", mtu: 1460}).describe(); !strings.Contains(got, "no source NAT") {
		t.Fatalf("DS-Lite should say why it translates nothing: %q", got)
	}
	if got := (natPlan{kind: "4in6", ipv4: netip.MustParseAddr("198.51.100.7")}).describe(); !strings.Contains(got, "every port") {
		t.Fatalf("a line that owns its address should say so: %q", got)
	}
	if mssNote(0) != "" {
		t.Fatal("an unknown MTU has no clamp to report")
	}
	if n := portCount(ports); n != 240 {
		t.Fatalf("a v6plus port set is 15 ranges of 16, got %d", n)
	}
}
