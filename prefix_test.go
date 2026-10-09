package main

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestSplitLAN(t *testing.T) {
	pd := netip.MustParsePrefix("2001:db8:1200::/56")
	got, ok := splitLAN(pd, 0x12)
	if !ok || got != netip.MustParsePrefix("2001:db8:1200:12::/64") {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := splitLAN(pd, 256); ok {
		t.Fatal("a /56 only yields 256 /64s")
	}
	p64 := netip.MustParsePrefix("2001:db8::/64")
	if got, ok := splitLAN(p64, 0); !ok || got != p64 {
		t.Fatalf("/64 index 0 should return unchanged, got %v", got)
	}
	if _, ok := splitLAN(p64, 1); ok {
		t.Fatal("a /64 cannot yield a second /64")
	}
	if _, ok := splitLAN(netip.MustParsePrefix("2001:db8::/80"), 0); ok {
		t.Fatal("prefixes longer than /64 are unusable")
	}
}

// noRecv asserts nothing is published within d.
func noRecv(t *testing.T, ch <-chan Snapshot, d time.Duration) {
	t.Helper()
	select {
	case s := <-ch:
		t.Fatalf("unexpected snapshot: change=%s %+v", s.Change, s.LAN)
	case <-time.After(d):
	}
}

func recv(t *testing.T, ch <-chan Snapshot) Snapshot {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for snapshot")
	}
	return Snapshot{}
}

func TestStoreLifecycle(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, 300*time.Millisecond, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch) // initial empty snapshot
	now := time.Now()
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	s := recv(t, ch)
	if s.Change != "add" || len(s.LAN["lan0"]) != 1 || len(s.LAN["lan1"]) != 1 {
		t.Fatalf("add: %+v", s)
	}
	if s.LAN["lan1"][0].Prefix != netip.MustParsePrefix("2001:db8:100:1::/64") {
		t.Fatalf("lan1 split wrong: %v", s.LAN["lan1"][0].Prefix)
	}
	// Renew: only lifetimes change.
	pd.Valid = now.Add(3 * time.Hour)
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	if s = recv(t, ch); s.Change != "renew" {
		t.Fatalf("renew: %s", s.Change)
	}
	// Revoke: prefix enters deprecation, preferred=0 but still in the snapshot.
	st.Set("pd", SourceUpdate{})
	s = recv(t, ch)
	if s.Change != "revoke" || len(s.LAN["lan0"]) != 1 || !s.LAN["lan0"][0].Deprecated {
		t.Fatalf("revoke: %+v", s)
	}
	if s.LAN["lan0"][0].preferredLeft(time.Now()) != 0 {
		t.Fatal("revoked prefix should have preferred 0")
	}
	if left := s.LAN["lan0"][0].validLeft(time.Now()); left > 300*time.Millisecond || left == 0 {
		t.Fatalf("deprecation period should be about hold: %v", left)
	}
	// After hold expires the prefix is gone.
	s = recv(t, ch)
	if len(s.LAN["lan0"]) != 0 {
		t.Fatalf("prefix still present after hold expired: %+v", s.LAN)
	}
}

func TestStorePreferRA(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:ffff::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "ra"}}})
	if s := recv(t, ch); s.Source != "ra" || s.Change != "add" {
		t.Fatalf("with RA only, RA should be used: %+v", s)
	}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:1::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "pd"}}})
	s := recv(t, ch)
	if s.Source != "pd" || s.Change != "revoke" {
		t.Fatalf("once PD arrives it should take over and revoke the RA prefix: %+v", s)
	}
}

func TestLifetimeClamp(t *testing.T) {
	now := time.Now()
	p := Prefix{Preferred: now.Add(-time.Second), Valid: now.Add(10 * time.Second)}
	if p.preferredLeft(now) != 0 || p.validLeft(now) != 10*time.Second {
		t.Fatal("expired preferred should be 0")
	}
	p.Deprecated = true
	p.Preferred = now.Add(time.Hour)
	if p.preferredLeft(now) != 0 {
		t.Fatal("deprecated prefix must have preferred 0")
	}
}

func TestSamePrefixSet(t *testing.T) {
	a := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8::/64"): true}
	b := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8::/64"): true}
	if !samePrefixSet(a, b) {
		t.Fatal("identical sets should be equal")
	}
	b[netip.MustParsePrefix("2001:db8:1::/64")] = true
	if samePrefixSet(a, b) {
		t.Fatal("added prefix should be detected")
	}
	if samePrefixSet(map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8:2::/64"): true}, a) {
		t.Fatal("replaced prefix should be detected")
	}
}

func TestIIDPolicy(t *testing.T) {
	pf := netip.MustParsePrefix("2001:db8:1:2::/64")
	ifi := &net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}
	p, err := parseIIDPolicy("::1")
	if err != nil || p.addr(nil, pf, ifi, 0) != netip.MustParseAddr("2001:db8:1:2::1") {
		t.Fatal(p, err)
	}
	p, _ = parseIIDPolicy("::1111:2222:3333:4444")
	if p.addr(nil, pf, ifi, 0) != netip.MustParseAddr("2001:db8:1:2:1111:2222:3333:4444") {
		t.Fatal(p.addr(nil, pf, ifi, 0))
	}
	p, _ = parseIIDPolicy("::")
	if p.addr(nil, pf, ifi, 0) != netip.MustParseAddr("2001:db8:1:2::") {
		t.Fatal("all-zero suffix should be used as is")
	}
	p, _ = parseIIDPolicy("eui64")
	if p.addr(nil, pf, ifi, 0) != netip.MustParseAddr("2001:db8:1:2:211:22ff:fe33:4455") {
		t.Fatal(p.addr(nil, pf, ifi, 0))
	}
	if _, err := parseIIDPolicy("2001:db8::1"); err == nil {
		t.Fatal("address with high bits set must fail")
	}
	p, _ = parseIIDPolicy("")
	a := p.addr([]byte("secret"), pf, ifi, 0)
	if !pf.Contains(a) || a == p.addr([]byte("other"), pf, ifi, 0) {
		t.Fatal("stable address must be inside the prefix and vary with the key")
	}
}

func TestIIDPolicies(t *testing.T) {
	ps, err := parseIIDPolicies("")
	if err != nil || len(ps) != 1 || ps[0].mode != iidStable {
		t.Fatal(ps, err)
	}
	ps, err = parseIIDPolicies("stable, ::1,eui64")
	if err != nil || len(ps) != 3 || ps[0].mode != iidStable || ps[1].mode != iidFixed || ps[2].mode != iidEUI64 {
		t.Fatal(ps, err)
	}
	for _, s := range []string{"::1,", "::1,::1", "::1,2001:db8::1"} {
		if _, err := parseIIDPolicies(s); err == nil {
			t.Fatalf("%q must fail", s)
		}
	}
}

func TestShared64Layout(t *testing.T) {
	cases := []struct {
		layout   shared64Layout
		side     side
		shared   bool
		wantPlen int
	}{
		{"wan", "wan", true, 64}, {"wan", "lan", true, 128},
		{"lan", "wan", true, 128}, {"lan", "lan", true, 64},
		{"split", "wan", true, 128}, {"split", "lan", true, 128},
		{"lan", "wan", false, 64}, {"split", "lan", false, 64},
	}
	for _, c := range cases {
		if got := c.layout.plen(c.side, c.shared); got != c.wantPlen {
			t.Errorf("%s/%s shared=%v: got %d want %d", c.layout, c.side, c.shared, got, c.wantPlen)
		}
	}
	snap := Snapshot{
		WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/64"), Source: "ra"}},
		LAN: map[string][]Prefix{"lan0": {{Prefix: netip.MustParsePrefix("2001:db8::/64"), Source: "ra"}}},
	}
	if !snap.sharedWith(netip.MustParsePrefix("2001:db8::/64")) || snap.sharedWith(netip.MustParsePrefix("2001:db8:1::/64")) {
		t.Fatal("sharedWith decision wrong")
	}
}

func TestStoreULA(t *testing.T) {
	ula := netip.MustParsePrefix("fd00:1234:5678::/48")
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, []netip.Prefix{ula}, false, 0, 0, "")
	ch := st.Subscribe()
	s := recv(t, ch)
	// ULA must be present even without a GUA.
	if len(s.LAN["lan1"]) != 1 || s.LAN["lan1"][0].Prefix != netip.MustParsePrefix("fd00:1234:5678:1::/64") || s.LAN["lan1"][0].Source != "ula" {
		t.Fatalf("%+v", s.LAN)
	}
	now := time.Now()
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}})
	s = recv(t, ch)
	if len(s.LAN["lan0"]) != 2 || s.Change != "add" {
		t.Fatalf("GUA and ULA should coexist: %+v", s.LAN["lan0"])
	}
	// Resubmitting the same prefix changes nothing, so nothing is published.
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}})
	noRecv(t, ch, 200*time.Millisecond)
	dir := t.TempDir()
	got, err := loadULA(dir, "auto")
	if err != nil || len(got) != 1 || got[0].Bits() != 48 || got[0].Addr().As16()[0] != 0xfd {
		t.Fatal(got, err)
	}
	again, _ := loadULA(dir, "auto")
	if again[0] != got[0] {
		t.Fatal("auto ULA should be persisted and reused")
	}
	if _, err := loadULA(dir, "2001:db8::/48"); err == nil {
		t.Fatal("non-ULA prefix must fail")
	}
}

func TestStoreMAPERules(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, true, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("240b:10:1234:5600::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "pd"}}})
	s := recv(t, ch)
	if s.Tunnel == nil || s.Tunnel.MAPESource != "rules" || s.Tunnel.MAPE == nil || s.Tunnel.RuleMAPE == nil {
		t.Fatalf("MAP-E should be filled in from the rule table: %+v", s.Tunnel)
	}
	// Provider is display text; match loosely so rewording it does not break the test.
	if !strings.Contains(s.Tunnel.RuleMAPE.Provider, "JPNE") || !s.Tunnel.hasDelivered() {
		t.Fatalf("%+v", s.Tunnel.RuleMAPE)
	}
	if got := s46Env(s.Tunnel.MAPE); !strings.HasPrefix(got, "ealen=25,") {
		t.Fatalf("rule-table MAP-E should fill the S46 container: %q", got)
	}
	// Option 94 delivered by DHCPv6 takes precedence.
	st.Set("pd", SourceUpdate{
		Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("240b:10:1234:5600::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "pd"}},
		Tunnel:   &TunnelParams{MAPE: &S46Cont{BR: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}},
	})
	if s = recv(t, ch); s.Tunnel.MAPESource != "dhcpv6" || s.Tunnel.RuleMAPE != nil {
		t.Fatalf("DHCPv6-delivered value should win: %+v", s.Tunnel)
	}
}

func TestStorePDGrace(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 300*time.Millisecond, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	ra := Prefix{Prefix: netip.MustParsePrefix("2001:db8:0:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "ra"}
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}, DNS: []netip.Addr{netip.MustParseAddr("fe80::1")}})
	s := recv(t, ch)
	if len(s.LAN["lan0"]) != 0 || len(s.DNS) != 1 {
		t.Fatalf("during grace the RA prefix must not be split to LAN, but DNS should be kept: %+v", s)
	}
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:0:2::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "pd"}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	s = recv(t, ch)
	if s.Change != "add" || len(s.LAN["lan0"]) != 1 || s.LAN["lan0"][0].Prefix != pd.Prefix {
		t.Fatalf("after PD arrives LAN should hold only the PD prefix, with no revoke phase: %+v", s.LAN)
	}

	// Fall back to RA when grace expires without a PD result.
	st2 := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 200*time.Millisecond, 0, "")
	ch2 := st2.Subscribe()
	recv(t, ch2)
	st2.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}})
	// During grace the RA prefix reaches the WAN only.
	if s = recv(t, ch2); len(s.WAN) != 1 || len(s.LAN["lan0"]) != 0 {
		t.Fatalf("during grace the RA prefix belongs to the WAN only: %+v", s)
	}
	if s = recv(t, ch2); s.Change != "add" || len(s.LAN["lan0"]) != 1 {
		t.Fatalf("after grace expires the RA prefix should be used: %+v", s)
	}
}

func TestRoutableDNS(t *testing.T) {
	got := routableDNS([]netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:4860:4860::8888")})
	if len(got) != 1 || got[0] != netip.MustParseAddr("2001:4860:4860::8888") {
		t.Fatalf("%v", got)
	}
}

func TestSharedWith(t *testing.T) {
	onLink := netip.MustParsePrefix("2409:8a00::/64")
	other := netip.MustParsePrefix("2409:8a00:0:4::/64")
	ra := Prefix{Prefix: onLink, Source: "ra"}
	cases := []struct {
		name   string
		wan    []Prefix
		lan    Prefix
		shared bool
	}{
		{"RA /64 on the LAN", []Prefix{ra}, ra, true},
		{"PD /64 equal to the on-link one", []Prefix{ra, {Prefix: onLink, Source: "pd"}}, Prefix{Prefix: onLink, Source: "pd"}, true},
		{"PD /64 other than the on-link one", []Prefix{ra, {Prefix: other, Source: "pd"}}, Prefix{Prefix: other, Source: "pd"}, false},
		{"PD /64 without an RA", []Prefix{{Prefix: onLink, Source: "pd"}}, Prefix{Prefix: onLink, Source: "pd"}, false},
	}
	for _, c := range cases {
		snap := Snapshot{WAN: c.wan, LAN: map[string][]Prefix{"lan0": {c.lan}}}
		if got := snap.sharedWith(c.lan.Prefix); got != c.shared {
			t.Errorf("%s: LAN prefix shared=%v, want %v", c.name, got, c.shared)
		}
		// The WAN side asks about the on-link prefix, which is shared only when the LAN uses it.
		if got := snap.sharedWith(onLink); got != (c.lan.Prefix == onLink && c.shared) {
			t.Errorf("%s: on-link prefix shared=%v", c.name, got)
		}
	}
}

// With PD in effect the RA prefixes stay in the WAN list, so the WAN keeps its SLAAC address and a
// delegated /64 equal to the on-link one is recognised as shared.
func TestStoreRAPrefixesUnderPD(t *testing.T) {
	now := time.Now()
	onLink := netip.MustParsePrefix("2001:db8:0:1::/64")
	ra := Prefix{Prefix: onLink, Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "ra", SLAAC: true}
	for _, c := range []struct {
		name   string
		pd     netip.Prefix
		shared bool
	}{
		{"different", netip.MustParsePrefix("2001:db8:0:2::/64"), false},
		{"same", onLink, true},
	} {
		st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
		ch := st.Subscribe()
		recv(t, ch)
		st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: c.pd, Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "pd"}}})
		recv(t, ch)
		st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}})
		s := recv(t, ch)
		if s.Source != "pd" || len(s.LAN["lan0"]) != 1 || s.LAN["lan0"][0].Prefix != c.pd {
			t.Fatalf("%s: the LAN should hold the PD prefix: %+v", c.name, s)
		}
		if w := s.wanSLAAC(); len(w) != 1 || w[0].Prefix != onLink {
			t.Fatalf("%s: the WAN should keep the RA prefix for SLAAC: %+v", c.name, s.WAN)
		}
		if got := s.sharedWith(c.pd); got != c.shared {
			t.Fatalf("%s: shared=%v, want %v", c.name, got, c.shared)
		}
	}
}

// Losing the WAN default router is published at once, not after the settle period (RFC 7084 G-5).
func TestStoreWANRouterLossSkipsSettle(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 300*time.Millisecond, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	ra := SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "ra"}}}
	st.Set("ra", ra)
	recv(t, ch)
	ra.NoRouter = true
	st.Set("ra", ra)
	select {
	case s := <-ch:
		if !s.NoWANRouter {
			t.Fatalf("want NoWANRouter: %+v", s)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("the loss waited for the settle period")
	}
}

// The LAN prefixes are recorded, and after a restart those the line does not hand out again are
// withdrawn once it hands out any (RFC 9096 section 3.5).
func TestStoreWithdrawsPrefixesFromBeforeRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "lan-prefixes.json")
	now := time.Now()
	pd := func(p string) SourceUpdate {
		return SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix(p), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}}
	}
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, file)
	ch := st.Subscribe()
	recv(t, ch)
	st.Set("pd", pd("2001:db8:a::/56"))
	recv(t, ch)

	st = newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, file)
	ch = st.Subscribe()
	if s := recv(t, ch); len(s.LAN["lan0"]) != 0 {
		t.Fatalf("nothing is withdrawn before the line answers: %+v", s.LAN)
	}
	st.Set("pd", pd("2001:db8:b::/56"))
	s := recv(t, ch)
	var stale, live []netip.Prefix
	for _, p := range s.LAN["lan0"] {
		if p.Stale {
			stale = append(stale, p.Prefix)
			if left := p.validLeft(time.Now()); left > time.Minute || left == 0 {
				t.Fatalf("withdrawn for the hold: %v", left)
			}
		} else {
			live = append(live, p.Prefix)
		}
	}
	if !slices.Equal(stale, []netip.Prefix{netip.MustParsePrefix("2001:db8:a::/64")}) || !slices.Equal(live, []netip.Prefix{netip.MustParsePrefix("2001:db8:b::/64")}) {
		t.Fatalf("stale %v, live %v", stale, live)
	}

	// A prefix that comes back is not withdrawn
	st = newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, file)
	ch = st.Subscribe()
	recv(t, ch)
	st.Set("pd", pd("2001:db8:b::/56"))
	for _, p := range recv(t, ch).LAN["lan0"] {
		if p.Prefix == netip.MustParsePrefix("2001:db8:b::/64") && p.Stale {
			t.Fatal("a prefix handed out again must not be withdrawn")
		}
	}
}

// The ULA prefixes are recorded too, without an expiry while given, and after a restart those -ula
// no longer gives are withdrawn at once, without waiting for the line (RFC 9096 section 3.5).
func TestStoreWithdrawsULAFromBeforeRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "lan-prefixes.json")
	lans := []lanDef{{"lan0", 0}}
	old, cur := netip.MustParsePrefix("fd00:1::/64"), netip.MustParsePrefix("fd00:2::/64")
	st := newStore("pd", lans, time.Minute, []netip.Prefix{netip.MustParsePrefix("fd00:1::/48")}, false, 0, 0, file)
	recv(t, st.Subscribe())
	b, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(b), `"fd00:1::/64"`) || strings.Contains(string(b), "valid_until") {
		t.Fatalf("a ULA given is recorded without an expiry: %s %v", b, err)
	}

	stale := func(s Snapshot) map[netip.Prefix]bool {
		out := map[netip.Prefix]bool{}
		for _, p := range s.LAN["lan0"] {
			out[p.Prefix] = p.Stale
			if p.Stale && (p.Source != sourceULA || p.validLeft(time.Now()) > time.Minute || p.validLeft(time.Now()) == 0) {
				t.Fatalf("withdrawn for the hold: %+v", p)
			}
		}
		return out
	}
	st = newStore("pd", lans, time.Minute, []netip.Prefix{netip.MustParsePrefix("fd00:2::/48")}, false, 0, 0, file)
	if st.previous != nil {
		t.Fatalf("nothing is left for the line to answer: %+v", st.previous)
	}
	if got := stale(recv(t, st.Subscribe())); len(got) != 2 || !got[old] || got[cur] {
		t.Fatalf("the old ULA is withdrawn before the line answers, the new one given: %v", got)
	}
	// both are recorded, the withdrawn one with the end of its hold, which a further restart keeps to
	b, _ = os.ReadFile(file)
	if strings.Count(string(b), "valid_until") != 1 {
		t.Fatalf("record: %s", b)
	}
	st = newStore("pd", lans, time.Minute, nil, false, 0, 0, file)
	if got := stale(recv(t, st.Subscribe())); len(got) != 2 || !got[old] || !got[cur] {
		t.Fatalf("with -ula gone, every ULA is withdrawn: %v", got)
	}

	// The line's prefixes stay for the line to answer; a ULA of a LAN no longer configured, or
	// whose hold is over, is left alone
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	// and so is a ULA the upstream delegated
	os.WriteFile(file, []byte(`[{"iface":"lan0","prefix":"2001:db8:a::/64","valid_until":"`+time.Now().Add(time.Hour).Format(time.RFC3339)+`"},
		{"iface":"lan9","prefix":"fd00:3::/64"},{"iface":"lan0","prefix":"fd00:4::/64","valid_until":"`+past+`"},
		{"iface":"lan0","prefix":"fd00:5::/64","valid_until":"`+time.Now().Add(time.Hour).Format(time.RFC3339)+`","delegated":true}]`), 0o600)
	st = newStore("pd", lans, time.Minute, nil, false, 0, 0, file)
	if len(st.previous) != 2 || st.previous[0].Prefix != netip.MustParsePrefix("2001:db8:a::/64") || !st.previous[1].Delegated || len(st.revoked) != 0 {
		t.Fatalf("previous %+v, revoked %+v", st.previous, st.revoked)
	}
	// the line answers without the ULA, which goes as one
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	st.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:a::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: sourcePD}}})
	s := recv(t, ch)
	if i := slices.IndexFunc(s.LAN["lan0"], func(p Prefix) bool { return p.Prefix == netip.MustParsePrefix("fd00:5::/64") }); i < 0 || !s.LAN["lan0"][i].Stale || s.LAN["lan0"][i].Source != sourceULA {
		t.Fatalf("the delegated ULA is withdrawn: %+v", s.LAN["lan0"])
	}
}

// The settle window must open on a real change only: a no-op update at startup used to consume it,
// pushing whatever arrived a moment later into the next batch.
func TestStoreSettleBatching(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 300*time.Millisecond, "")
	ch := st.Subscribe()
	recv(t, ch) // initial empty snapshot, delivered on subscribe

	st.Set("ra", SourceUpdate{}) // the RA client clears its source at startup: nothing changes
	noRecv(t, ch, 200*time.Millisecond)

	now := time.Now()
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	// The window opens here, so DNS arriving 100 ms later still lands in the same batch.
	time.Sleep(100 * time.Millisecond)
	dns := []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}, DNS: dns})

	s := recv(t, ch)
	if s.Change != "add" || len(s.LAN["lan0"]) != 1 || len(s.DNS) != 1 {
		t.Fatalf("prefix and DNS should arrive in one snapshot: %+v", s)
	}
	noRecv(t, ch, 200*time.Millisecond)
}

// DNS-only updates carry information the RA server and the DHCPv6 server need, so they must be
// classified as a change rather than swallowed as "none".
func TestStoreDNSOnlyChange(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	recv(t, ch)

	for _, tc := range []struct {
		name string
		upd  SourceUpdate
	}{
		{"DNS", SourceUpdate{Prefixes: []Prefix{pd}, DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}}},
		{"search list", SourceUpdate{Prefixes: []Prefix{pd}, DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}, DNSSL: []string{"flets-east.jp"}}},
		{"PREF64", SourceUpdate{Prefixes: []Prefix{pd}, DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}, DNSSL: []string{"flets-east.jp"}, PREF64: netip.MustParsePrefix("64:ff9b::/96")}},
		{"MTU", SourceUpdate{Prefixes: []Prefix{pd}, DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}, DNSSL: []string{"flets-east.jp"}, PREF64: netip.MustParsePrefix("64:ff9b::/96"), MTU: 1492}},
	} {
		st.Set("pd", tc.upd)
		if s := recv(t, ch); s.Change == "none" {
			t.Fatalf("a %s change must be published: %+v", tc.name, s)
		}
	}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}, DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}, DNSSL: []string{"flets-east.jp"}, PREF64: netip.MustParsePrefix("64:ff9b::/96"), MTU: 1492})
	noRecv(t, ch, 200*time.Millisecond)
}

// A line whose only DNS server is link-local leaves LAN clients with nothing, so say so.
func TestLinkLocalDNSOnly(t *testing.T) {
	snap := Snapshot{DNS: []netip.Addr{netip.MustParseAddr("fe80::1")}}
	hints := diagnoseSnapshot(snap, false)
	if len(hints) != 1 || !strings.Contains(hints[0], "fe80::1") {
		t.Fatalf("hints: %v", hints)
	}
	if len(diagnoseSnapshot(Snapshot{DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}}, false)) != 0 {
		t.Fatal("a routable DNS server is fine")
	}
}

// A single /64 holds one LAN segment. The others get nothing, and that is reported once rather than
// on every renewal.
func TestSingle64WithSeveralLANs(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	st := newStore("pd", []lanDef{{iface: "eth1", index: 0}, {iface: "eth2", index: 1}}, time.Minute, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	pd := netip.MustParsePrefix("2001:db8:1:2::/64")
	for i := range 3 {
		now := time.Now()
		st.Set("pd", SourceUpdate{Prefixes: []Prefix{{
			Prefix: pd, Preferred: now.Add(time.Duration(i+1) * time.Hour), Valid: now.Add(time.Duration(i+2) * time.Hour), Source: "pd",
		}}})
		s := recv(t, ch)
		if len(s.LAN["eth1"]) != 1 || s.LAN["eth1"][0].Prefix != pd {
			t.Fatalf("subnet 0 should take the whole /64: %v", s.LAN["eth1"])
		}
		if len(s.LAN["eth2"]) != 0 {
			t.Fatalf("subnet 1 cannot be carved out of a /64: %v", s.LAN["eth2"])
		}
	}
	if n := strings.Count(logged.String(), "too short to cover"); n != 1 {
		t.Fatalf("the shortage should be reported once, not %d times:\n%s", n, logged.String())
	}
	if !strings.Contains(logged.String(), "eth2(subnet 1)") {
		t.Fatalf("the report should name the segment left out:\n%s", logged.String())
	}
}

// The advice names what is wrong with the line and what to ask the ISP for, and is silent when a
// delegation clear of the on-link /64 exists.
func TestProxyAdvice(t *testing.T) {
	onLink := Prefix{Prefix: netip.MustParsePrefix("2001:db8::/64"), Source: "ra"}
	pd := func(p string) Prefix { return Prefix{Prefix: netip.MustParsePrefix(p), Source: "pd"} }
	cases := []struct {
		name   string
		wan    []Prefix
		reason string
		ask    string
	}{
		{"RA only", []Prefix{onLink}, "LAN shares the WAN link's on-link /64", "prefix delegation (IA_PD) with a /56"},
		{"PD equals on-link", []Prefix{onLink, pd("2001:db8::/64")}, "delegated /64 equals", "does not overlap"},
		{"PD contains on-link", []Prefix{onLink, pd("2001:db8::/56")}, "delegated /56 contains", "does not overlap"},
		{"PD apart", []Prefix{onLink, pd("2001:db8:100::/56")}, "", ""},
		{"PD without RA", []Prefix{pd("2001:db8::/64")}, "", ""},
	}
	for _, c := range cases {
		reason, ask := Snapshot{WAN: c.wan}.proxyAdvice()
		if (c.reason == "") != (reason == "") || !strings.Contains(reason, c.reason) || !strings.Contains(ask, c.ask) {
			t.Errorf("%s: got %q / %q", c.name, reason, ask)
		}
	}
	snap := Snapshot{WAN: []Prefix{onLink}}
	if hints := diagnoseSnapshot(snap, false); len(hints) != 1 || !strings.Contains(hints[0], "ask your ISP") {
		t.Fatalf("broadcast WAN: %v", hints)
	}
	if hints := diagnoseSnapshot(snap, true); len(hints) != 0 {
		t.Fatalf("a point-to-point WAN needs no proxy: %v", hints)
	}
}

// While PD is still out on a link whose RA announces DHCPv6, the WAN takes no address in the RA
// /64, since whether the LAN will share it decides the address's prefix length. An RA without M
// or O promises no DHCPv6 answer, so nothing waits for one.
func TestStorePDPending(t *testing.T) {
	now := time.Now()
	ra := Prefix{Prefix: netip.MustParsePrefix("2001:db8:0:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: "ra", SLAAC: true}

	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, time.Minute, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}, DHCPv6: true})
	s := recv(t, ch)
	if !s.PDPending || len(s.wanSLAAC()) != 0 {
		t.Fatalf("RA with M/O during grace: the WAN address waits for PD, got pending=%v %v", s.PDPending, s.wanSLAAC())
	}
	st.Set("pd", SourceUpdate{}) // refused
	s = recv(t, ch)
	if s.PDPending || len(s.wanSLAAC()) != 1 || !s.sharedWith(ra.Prefix) {
		t.Fatalf("once PD is refused the WAN address comes, already knowing the /64 is shared: %+v", s)
	}

	st = newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, time.Minute, 0, "")
	ch = st.Subscribe()
	recv(t, ch)
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}})
	if s = recv(t, ch); s.PDPending || len(s.wanSLAAC()) != 1 {
		t.Fatalf("RA without M/O: nothing to wait for: %+v", s)
	}

	st = newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 200*time.Millisecond, 0, "")
	ch = st.Subscribe()
	recv(t, ch)
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}, DHCPv6: true})
	recv(t, ch)
	if s = recv(t, ch); s.PDPending || len(s.wanSLAAC()) != 1 {
		t.Fatalf("the wait ends with the grace period even when DHCPv6 never answers: %+v", s)
	}
}

// Jool starting or stopping changes what the RA announces, so it has to be published.
func TestStoreNAT64(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	st.SetNAT64(nat64WKP)
	if s := recv(t, ch); s.NAT64 != nat64WKP {
		t.Fatal("NAT64 on is not published")
	}
	st.SetNAT64(netip.Prefix{})
	if s := recv(t, ch); s.NAT64.IsValid() {
		t.Fatal("NAT64 off is not published")
	}
}

// The part of a delegation the ISP keeps for the WAN link goes to no LAN (RFC 6603); a segment on
// it takes the highest subnet no other segment names instead.
func TestStoreSkipsTheExcludedSubnet(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Exclude: netip.MustParsePrefix("2001:db8:100::/64"),
		Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}})
	s := recv(t, ch)
	if len(s.LAN["lan0"]) != 1 || s.LAN["lan0"][0].Prefix != netip.MustParsePrefix("2001:db8:100:ff::/64") ||
		len(s.LAN["lan1"]) != 1 || s.LAN["lan1"][0].Prefix != netip.MustParsePrefix("2001:db8:100:1::/64") {
		t.Fatalf("subnet 0 is excluded and lan0 takes subnet ff, subnet 1 is not: %+v", s.LAN)
	}
	p := &pdPool{plen: 60, leases: map[string]*PDLease{}}
	if p.free(s, netip.MustParsePrefix("2001:db8:100::/60"), "k") {
		t.Fatal("a delegation over the excluded part is not free")
	}
}

func TestParseWANPrefix(t *testing.T) {
	got, err := parseWANPrefix("2001:db8:1:2::/64, 2001:db8:1:3::/64")
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64"), netip.MustParsePrefix("2001:db8:1:3::/64")}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := parseWANPrefix("2001:db8:100::/56"); err == nil {
		t.Error("an on-link prefix is a /64")
	}
	got, err = parsePrefixes("2001:db8:1:2::/64, 2001:db8:100::/56")
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64"), netip.MustParsePrefix("2001:db8:100::/56")}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"2001:db8::/96", "fd00::/48", "fe80::/64", "192.0.2.0/24", "nonsense"} {
		if _, err := parsePrefixes(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// The addresses configured by hand are those with both lifetimes infinite, of any length; one with
// a finite preferred lifetime, as sixup gives each of its own, is passed over.
func TestConfiguredAddrs(t *testing.T) {
	const inf = infiniteLft
	list := []ifAddr{
		{Addr: netip.MustParseAddr("fe80::1"), PrefixLen: 64, Preferred: inf, Valid: inf},
		{Addr: netip.MustParseAddr("2001:db8:9::5"), PrefixLen: 64, Preferred: 3600, Valid: 7200},
		{Addr: netip.MustParseAddr("2001:db8:1:2::5"), PrefixLen: 64, Flags: ifaFDeprecated, Valid: inf},
		{Addr: netip.MustParseAddr("2001:db8:1:2::6"), PrefixLen: 64, Preferred: 3600, Valid: inf},
		{Addr: netip.MustParseAddr("fd00::1"), PrefixLen: 64, Preferred: inf, Valid: inf},
		{Addr: netip.MustParseAddr("2:3:4:5:6:7:8:2"), PrefixLen: 126, Preferred: inf, Valid: inf},
		{Addr: netip.MustParseAddr("2001:db8:1:2::1"), PrefixLen: 64, Preferred: inf, Valid: inf},
		{Addr: netip.MustParseAddr("2001:db8:1:2::2"), PrefixLen: 64, Preferred: inf, Valid: inf},
	}
	got := configuredAddrs(list)
	want := []netip.Prefix{netip.MustParsePrefix("2:3:4:5:6:7:8:2/126"), netip.MustParsePrefix("2001:db8:1:2::1/64"), netip.MustParsePrefix("2001:db8:1:2::2/64")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := onLink64s(got); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64")}) {
		t.Fatalf("on-link /64s: %v", got)
	}
}

// With the WAN address configured by hand, sixup adds none of its own to the WAN, and reports
// that one.
func TestStoreConfiguredWAN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	vps := netip.MustParsePrefix("2001:db8:1:2::/64")
	wanAddr := netip.MustParseAddr("2001:db8:1:2::1")
	go keepStatic(ctx, st, []netip.Prefix{vps}, nil, false, wanAddr)
	s := recv(t, ch)
	if len(s.LAN["lan0"]) != 1 || !s.sharedWith(vps) || len(s.wanStatic()) != 0 || len(s.wanTemp()) != 0 || s.WANAddr != wanAddr {
		t.Fatalf("the WAN keeps only the address configured by hand: %+v", s)
	}
	if shared64Layout("wan").plen(sideLAN, true) != 128 {
		t.Fatal("the LAN takes a /128 in the shared /64")
	}
}

// The static prefixes go to the store again each day, on the fake clock of a synctest bubble, so
// their lifetimes never run out. The store's loop is left out, since it never ends.
func TestKeepStaticRenews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := &Store{in: make(chan storeMsg, 1)}
		ctx, cancel := context.WithCancel(context.Background())
		go keepStatic(ctx, st, nil, []netip.Prefix{netip.MustParsePrefix("2001:db8:100::/56")}, false, netip.Addr{})
		first := <-st.in
		time.Sleep(24 * time.Hour)
		again := <-st.in
		if d := again.upd.Prefixes[0].Valid.Sub(first.upd.Prefixes[0].Valid); d != 24*time.Hour {
			t.Fatalf("renewed %s later", d)
		}
		cancel()
	})
}

// A /64 given with -wan-prefix is the WAN link's, shared with the LAN (RFC 7278); one of -routed-prefix is
// split across the LANs as a delegation; and either stands before what DHCPv6-PD says.
func TestStoreStaticPrefix(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	vps := netip.MustParsePrefix("2001:db8:1:2::/64")
	go keepStatic(ctx, st, []netip.Prefix{vps}, nil, true, netip.Addr{})
	s := recv(t, ch)
	if len(s.LAN["lan0"]) != 1 || s.LAN["lan0"][0].Prefix != vps || !s.sharedWith(vps) || len(s.wanSLAAC()) != 1 {
		t.Fatalf("a /64 is the WAN link's, shared with the LAN: %+v", s)
	}
	now := time.Now()
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:9::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}}})
	select {
	case s := <-ch:
		if s.LAN["lan0"][0].Prefix != vps {
			t.Fatalf("-wan-prefix stands before DHCPv6-PD: %+v", s.LAN)
		}
	case <-time.After(500 * time.Millisecond):
	}

	st2 := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, nil, false, 0, 0, "")
	ch2 := st2.Subscribe()
	recv(t, ch2)
	go keepStatic(ctx, st2, nil, []netip.Prefix{netip.MustParsePrefix("2001:db8:100::/56")}, true, netip.Addr{})
	s = recv(t, ch2)
	if len(s.LAN["lan1"]) != 1 || s.LAN["lan1"][0].Prefix != netip.MustParsePrefix("2001:db8:100:1::/64") || s.WAN[0].Source != sourcePD {
		t.Fatalf("a /56 is split as a delegation: %+v", s)
	}
}

// The WAN subnet is the first LAN's delegated /64: always for temporary addresses, for static
// ones only without SLAAC and IA_NA.
func TestStoreWANSubnet(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 255}}, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Exclude: netip.MustParsePrefix("2001:db8:100::/64"),
		Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}})
	s := recv(t, ch)
	// subnet 0 is excluded, so lan0 takes fe
	w := s.WANSubnet
	if w.Prefix != netip.MustParsePrefix("2001:db8:100:fe::/64") || w.Prefix != s.LAN["lan0"][0].Prefix || !w.OffLink ||
		!slices.Equal(s.wanStatic(), []Prefix{w}) || !slices.Equal(s.wanTemp(), []Prefix{w}) {
		t.Fatalf("WAN subnet: %+v", w)
	}
	// with IA_NA, only temporary addresses
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{pd}, WANAddr: netip.MustParseAddr("2001:db8:1::5")})
	if s = recv(t, ch); len(s.wanStatic()) != 0 || !slices.Equal(s.wanTemp(), []Prefix{w}) {
		t.Fatalf("with IA_NA: static %v, temporary %v", s.wanStatic(), s.wanTemp())
	}
	// with SLAAC, static addresses in the SLAAC prefix
	ra := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "ra", SLAAC: true}
	st.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}})
	if s = recv(t, ch); len(s.wanStatic()) != 1 || s.wanStatic()[0].Prefix != ra.Prefix || !slices.Equal(s.wanTemp(), []Prefix{w}) {
		t.Fatalf("with SLAAC: static %v, temporary %v", s.wanStatic(), s.wanTemp())
	}
	st.Set("ra", SourceUpdate{})
	recv(t, ch)
	// a delegated /64
	st.Set("pd", SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:200::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}})
	if s = recv(t, ch); s.WANSubnet.Prefix != netip.MustParsePrefix("2001:db8:200::/64") {
		t.Fatalf("WAN subnet of a /64: %+v", s.WANSubnet)
	}
}

// An expired prefix has no time left; without a WAN subnet the temporary addresses come from the
// SLAAC prefix; and only a MAP-E CE is a tunnel endpoint to configure.
func TestSnapshotHelpers(t *testing.T) {
	now := time.Now()
	if left := (Prefix{Valid: now.Add(-time.Second)}).validLeft(now); left != 0 {
		t.Fatalf("expired prefix: %v left", left)
	}
	ra := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Source: sourceRA, SLAAC: true, Valid: now.Add(time.Hour)}
	s := Snapshot{WAN: []Prefix{ra}}
	if !slices.Equal(s.wanTemp(), []Prefix{ra}) {
		t.Fatalf("temporary addresses without a WAN subnet: %v", s.wanTemp())
	}
	if s.tunnelEndpoints() != nil {
		t.Fatal("no tunnel, no endpoint")
	}
	ce := netip.MustParseAddr("2001:db8:1::ce")
	s.Tunnel = &TunnelParams{RuleMAPE: &mapeResult{CE: ce}}
	if !slices.Equal(s.tunnelEndpoints(), []netip.Addr{ce}) {
		t.Fatalf("MAP-E endpoint: %v", s.tunnelEndpoints())
	}
}

// The resolved AFTR addresses, the capture and the DAD conflicts of the tunnel endpoint all reach
// the snapshot; a delegation already expired or deprecated derives no MAP-E.
func TestStoreTunnelInputs(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, true, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	expired := Prefix{Prefix: netip.MustParsePrefix("2001:db8:2::/56"), Preferred: now.Add(-time.Hour), Valid: now.Add(-time.Second), Source: sourcePD}
	deprecated := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/56"), Preferred: now.Add(-time.Second), Valid: now.Add(time.Hour), Source: sourcePD}
	live := Prefix{Prefix: netip.MustParsePrefix("240b:10:1234:5600::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}
	st.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{expired, deprecated, live}, Tunnel: &TunnelParams{AFTRName: "aftr.example"}})
	s := recv(t, ch)
	if s.Tunnel == nil || s.Tunnel.MAPESource != fromRules || s.Tunnel.AFTRName != "aftr.example" || len(s.WAN) != 2 {
		t.Fatalf("the rule table answers for the live delegation only: %+v %+v", s.Tunnel, s.WAN)
	}
	ce := s.Tunnel.RuleMAPE.CE

	aftr := []netip.Addr{netip.MustParseAddr("2001:db8::a")}
	st.SetAFTRAddrs("aftr.example", aftr)
	if s = recv(t, ch); !slices.Equal(s.Tunnel.AFTRAddrs, aftr) {
		t.Fatalf("AFTR addresses: %v", s.Tunnel.AFTRAddrs)
	}
	st.SetCaptured(&tunnelGuess{Type: tunnelMAPE, Remote: netip.MustParseAddr("2001:db8::b")})
	if s = recv(t, ch); s.Tunnel.Captured == nil || !strings.Contains(s.describe(now), "captured=") || !strings.Contains(s.describe(now), "AFTR=aftr.example") {
		t.Fatalf("capture: %+v", s.Tunnel)
	}
	st.SetEndpointConflict(ce, true)
	if s = recv(t, ch); !slices.Equal(s.Tunnel.Conflicts, []netip.Addr{ce}) {
		t.Fatalf("conflict: %v", s.Tunnel.Conflicts)
	}
	st.SetEndpointConflict(ce, false)
	if s = recv(t, ch); len(s.Tunnel.Conflicts) != 0 {
		t.Fatalf("conflict cleared: %v", s.Tunnel.Conflicts)
	}
	moved := netip.MustParseAddr("2001:db8:1::abcd")
	st.SetSelf(netip.MustParsePrefix("2001:db8:1::/64"), moved)
	if s = recv(t, ch); s.Change != changeRenew || s.Self[netip.MustParsePrefix("2001:db8:1::/64")] != moved {
		t.Fatalf("an address DAD moved is published: %s %v", s.Change, s.Self)
	}

	// MAP-E delivered by DHCPv6 is computed for the first delegation still preferred.
	r, ok := calcMAPE(live.Prefix)
	if !ok {
		t.Fatal("rule table")
	}
	st2 := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	ch2 := st2.Subscribe()
	recv(t, ch2)
	st2.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{deprecated, live}, Tunnel: &TunnelParams{MAPE: r.s46()}})
	if s = recv(t, ch2); s.Tunnel.MAPESource != fromDHCPv6 || s.Tunnel.RuleMAPE == nil {
		t.Fatalf("DHCPv6 MAP-E: %+v", s.Tunnel)
	}
}

// Segments a prefix cannot serve are reported: a ULA /64 has no second subnet, and an excluded /64
// leaves no spare one. Prefixes that go are held no longer than their valid lifetime, and the WAN
// prefix leaves the snapshot when its hold ends.
func TestStoreShortAndRevokedPrefixes(t *testing.T) {
	ula := netip.MustParsePrefix("fd00:1::/64")
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Minute, []netip.Prefix{ula}, false, 0, 0, "")
	ch := st.Subscribe()
	if s := recv(t, ch); len(s.LAN["lan0"]) != 1 || len(s.LAN["lan1"]) != 0 {
		t.Fatalf("the ULA /64 serves lan0 only: %+v", s.LAN)
	}
	now := time.Now()
	p := netip.MustParsePrefix("2001:db8:5::/64")
	st.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{{Prefix: p, Exclude: p, Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}}})
	if s := recv(t, ch); len(s.LAN["lan0"]) != 1 {
		t.Fatalf("the excluded /64 goes to no LAN: %+v", s.LAN)
	}

	st2 := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	ch2 := st2.Subscribe()
	recv(t, ch2)
	valid := time.Now().Add(300 * time.Millisecond)
	st2.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{{Prefix: p, Preferred: valid, Valid: valid, Source: sourcePD}}})
	recv(t, ch2)
	st2.Set(sourcePD, SourceUpdate{})
	s := recv(t, ch2)
	if s.Change != changeRevoke || len(s.LAN["lan0"]) != 1 || !s.LAN["lan0"][0].Valid.Equal(valid) || len(s.WAN) != 1 || !s.WAN[0].Valid.Equal(valid) {
		t.Fatalf("held until the valid lifetime: %+v", s)
	}
	if s = recv(t, ch2); s.Change != changeRevoke || len(s.LAN["lan0"]) != 0 || len(s.WAN) != 0 {
		t.Fatalf("gone after the hold: %+v", s)
	}
}

// A corrupt record is ignored, and one that cannot be written leaves the store running.
func TestStoreAdvertisedFileErrors(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt")
	if err := os.WriteFile(corrupt, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	busy := filepath.Join(dir, "busy") // a directory: written next to, but not renamed over
	if err := os.MkdirAll(filepath.Join(busy, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, file := range []string{corrupt, filepath.Join(dir, "missing", "file"), busy} {
		st := newStore("pd", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, file)
		if st.previous != nil {
			t.Fatalf("%s: a corrupt record is ignored", file)
		}
		ch := st.Subscribe()
		recv(t, ch)
		st.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:7::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}}})
		if s := recv(t, ch); len(s.LAN["lan0"]) != 1 {
			t.Fatalf("%s: %+v", file, s.LAN)
		}
	}
}

func TestLoadULASpecs(t *testing.T) {
	if got, err := loadULA("", ""); got != nil || err != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	got, err := loadULA("", "fd00:1::/48, fd00:2:0:1::/64")
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("fd00:1::/48"), netip.MustParsePrefix("fd00:2:0:1::/64")}) {
		t.Fatalf("list: %v %v", got, err)
	}
	if _, err := loadULA("", "fc00:aaaa::2/48"); err == nil || !strings.Contains(err.Error(), "give only the prefix such as fc00:aaaa::/48") {
		t.Fatalf("bits past the prefix must fail rather than be dropped: %v", err)
	}
	if _, err := loadULA("", "nonsense"); err == nil {
		t.Fatal("nonsense must fail")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadULA(file, "auto"); err == nil {
		t.Fatal("a state directory that is a file must fail")
	}
	if got, err := parsePrefixes("2001:db8:1::/48,,"); err != nil || len(got) != 1 {
		t.Fatalf("empty fields are skipped: %v %v", got, err)
	}
}

// A LAN takes addresses of this router only in its ULA prefixes.
func TestLANULA(t *testing.T) {
	ula := Prefix{Prefix: netip.MustParsePrefix("fd00:1::/64"), Source: sourceULA}
	s := Snapshot{LAN: map[string][]Prefix{"lan0": {{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Source: sourcePD}, ula}}}
	if got := s.lanULA("lan0"); len(got) != 1 || got[0] != ula {
		t.Fatalf("%+v", got)
	}
	if got := s.lanULA("lan1"); got != nil {
		t.Fatalf("another LAN: %+v", got)
	}
}
