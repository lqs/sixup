package main

import (
	"bytes"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
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
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, 300*time.Millisecond, nil, false, 0, 0)
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
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0)
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
	snap := Snapshot{WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/64"), Source: "ra"}}}
	if !snap.sharedWith(netip.MustParsePrefix("2001:db8::/64")) || snap.sharedWith(netip.MustParsePrefix("2001:db8:1::/64")) {
		t.Fatal("sharedWith decision wrong")
	}
}

func TestStoreULA(t *testing.T) {
	ula := netip.MustParsePrefix("fd00:1234:5678::/48")
	st := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, []netip.Prefix{ula}, false, 0, 0)
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
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, true, 0, 0)
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
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 300*time.Millisecond, 0)
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
	st2 := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 200*time.Millisecond, 0)
	ch2 := st2.Subscribe()
	recv(t, ch2)
	st2.Set("ra", SourceUpdate{Prefixes: []Prefix{ra}})
	// During grace the RA prefix is held back, so the snapshot is unchanged and nothing is published.
	noRecv(t, ch2, 100*time.Millisecond)
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

func TestSharedWithOnlyRA(t *testing.T) {
	snap := Snapshot{WAN: []Prefix{
		{Prefix: netip.MustParsePrefix("2409:8a00::/64"), Source: "ra"},
		{Prefix: netip.MustParsePrefix("2409:8a00:0:4::/64"), Source: "pd"},
	}}
	if snap.sharedWith(netip.MustParsePrefix("2409:8a00:0:4::/64")) {
		t.Fatal("a PD-delegated /64 does not count as shared")
	}
	if !snap.sharedWith(netip.MustParsePrefix("2409:8a00::/64")) {
		t.Fatal("only an RA on-link /64 counts as shared")
	}
}

// The settle window must open on a real change only: a no-op update at startup used to consume it,
// pushing whatever arrived a moment later into the next batch.
func TestStoreSettleBatching(t *testing.T) {
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 300*time.Millisecond)
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
	st := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0)
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
	hints := diagnoseSnapshot(snap)
	if len(hints) != 1 || !strings.Contains(hints[0], "fe80::1") {
		t.Fatalf("hints: %v", hints)
	}
	if len(diagnoseSnapshot(Snapshot{DNS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}})) != 0 {
		t.Fatal("a routable DNS server is fine")
	}
}

// A single /64 holds one LAN segment. The others get nothing, and that is reported once rather than
// on every renewal.
func TestSingle64WithSeveralLANs(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	st := newStore("pd", []lanDef{{iface: "eth1", index: 0}, {iface: "eth2", index: 1}}, time.Minute, nil, false, 0, 0)
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
