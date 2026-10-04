package main

import (
	"bytes"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStrayAddrs(t *testing.T) {
	pfx := netip.MustParsePrefix("2001:db8:1::/64")
	managed := []Prefix{{Prefix: pfx}}
	want := map[netip.Addr]Prefix{netip.MustParseAddr("2001:db8:1::1"): {Prefix: pfx}}
	temps := []*tempAddr{{addr: netip.MustParseAddr("2001:db8:1::aa")}}
	endpoints := map[netip.Addr]string{netip.MustParseAddr("2001:db8:1::1111:1111:1111:1111"): "ok"}
	list := []ifAddr{
		{Addr: netip.MustParseAddr("2001:db8:1::1"), PrefixLen: 64},                    // computed this round
		{Addr: netip.MustParseAddr("2001:db8:1::aa"), PrefixLen: 64},                   // already in the temp address table
		{Addr: netip.MustParseAddr("2001:db8:1::1111:1111:1111:1111"), PrefixLen: 128}, // tunnel endpoint
		{Addr: netip.MustParseAddr("2001:db8:1::dead"), PrefixLen: 64},                 // stray, must be taken over
		{Addr: netip.MustParseAddr("2001:db8:2::1"), PrefixLen: 64},                    // outside managed prefixes
		{Addr: netip.MustParseAddr("fe80::1"), PrefixLen: 64},                          // link-local
		{Addr: netip.MustParseAddr("fd00::1"), PrefixLen: 64},                          // different prefix
	}
	got := strayAddrs(list, want, managed, temps, endpoints)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("2001:db8:1::dead") {
		t.Fatalf("only the stray address should be picked, got %+v", got)
	}
}

// A WAN prefix with the L flag clear takes a /128, so no on-link route comes with the address
// (RFC 5942 section 4, IPv6 Ready CE Router 1.6.2).
func TestWANAddressOffLink(t *testing.T) {
	m := &addrManager{side: sideWAN, layout: "lan"}
	p := Prefix{Prefix: netip.MustParsePrefix("2001:db8::/64"), Source: sourceRA}
	if got := m.plen(p); got != 64 {
		t.Fatalf("on-link: /%d", got)
	}
	p.OffLink = true
	if got := m.plen(p); got != 128 {
		t.Fatalf("off-link: /%d", got)
	}
}

// addrDryRun turns on dry-run mode for the test, so address changes go nowhere.
func addrDryRun(t *testing.T) {
	old := dryRun
	dryRun = true
	t.Cleanup(func() { dryRun = old })
}

// addrTestManager returns a manager on an interface that does not exist, for dry-run tests and
// for failing kernel calls.
func addrTestManager(s side, prefixes ...Prefix) *addrManager {
	pick := func(Snapshot) []Prefix { return prefixes }
	return &addrManager{
		ifname: "none0", ifi: &net.Interface{Index: 9999, Name: "none0"}, secret: make([]byte, 32),
		iids: []iidPolicy{{mode: iidStable}}, pick: pick, tempPick: pick, side: s, layout: "lan",
		cfg:     tempConfig{preferredLft: time.Hour},
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{},
		announce: map[netip.Addr]int{}, endpoints: map[netip.Addr]string{},
	}
}

// addrLive returns a prefix with an hour of preferred and two of valid lifetime left.
func addrLive(s string) Prefix {
	now := time.Now()
	return Prefix{Prefix: netip.MustParsePrefix(s), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: sourcePD}
}

func TestAddressLoadSecret(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := loadSecret(dir)
	if len(s) != 32 {
		t.Fatalf("secret of %d bytes", len(s))
	}
	if again := loadSecret(dir); !bytes.Equal(again, s) {
		t.Fatal("the persisted secret was not read back")
	}
	// a damaged file is replaced
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := loadSecret(dir)
	if len(s2) != 32 || bytes.Equal(s2, s) {
		t.Fatal("a damaged secret file was not replaced by a new secret")
	}
	if again := loadSecret(dir); !bytes.Equal(again, s2) {
		t.Fatal("the replacement secret was not persisted")
	}

	addrDryRun(t)
	dry := filepath.Join(t.TempDir(), "dry")
	if s := loadSecret(dry); len(s) != 32 {
		t.Fatalf("dry-run secret of %d bytes", len(s))
	}
	if _, err := os.Stat(dry); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote the state directory: %v", err)
	}
}

func TestAddressWatchWANAddr(t *testing.T) {
	w := netip.MustParseAddr("2001:db8::5")
	lan := addrTestManager(sideLAN)
	lan.snap.WANAddr = w
	lan.watchWANAddr()
	if lan.wanAddr.IsValid() || len(lan.announce) != 0 {
		t.Fatal("a LAN manager watches no IA_NA address")
	}
	m := addrTestManager(sideWAN)
	m.snap.WANAddr = w
	m.watchWANAddr()
	if m.wanAddr != w || m.announce[w] != 3 || !m.dadDue {
		t.Fatalf("a new IA_NA address is not queued for announcement: %v %v", m.wanAddr, m.announce)
	}
	m.announce[w] = 1
	m.watchWANAddr()
	if m.announce[w] != 1 {
		t.Fatal("the same IA_NA address is queued again")
	}
}

func TestAddressTimers(t *testing.T) {
	for _, c := range []struct {
		regen, grace, want time.Duration
	}{
		{time.Hour, 0, 15 * time.Minute},
		{time.Hour, 30 * time.Minute, 30 * time.Minute},
		{10 * time.Millisecond, 5 * time.Millisecond, time.Second},
	} {
		m := &addrManager{cfg: tempConfig{regenInterval: c.regen, grace: c.grace}}
		if got := m.drainInterval(); got != c.want {
			t.Errorf("drainInterval(regen %s, grace %s) = %s, want %s", c.regen, c.grace, got, c.want)
		}
	}
	m := &addrManager{cfg: tempConfig{regenInterval: time.Hour}}
	for range 20 {
		if d := m.nextRegen(); d <= 36*time.Minute || d > time.Hour {
			t.Fatalf("nextRegen = %s, outside (36m, 1h]", d)
		}
	}
	for _, regen := range []time.Duration{0, 10 * time.Millisecond} {
		m := &addrManager{cfg: tempConfig{regenInterval: regen}}
		if d := m.nextRegen(); d != time.Second {
			t.Fatalf("nextRegen with interval %s = %s, want the 1s floor", regen, d)
		}
	}
}

// No address goes in a prefix past its valid lifetime, nor in one being withdrawn from the LAN.
func TestAddressSkipsDeadPrefixes(t *testing.T) {
	addrDryRun(t)
	expired := addrLive("2001:db8:1::/64")
	expired.Valid = time.Now().Add(-time.Second)
	stale := addrLive("2001:db8:2::/64")
	stale.Stale = true
	live := addrLive("2001:db8:3::/64")
	m := addrTestManager(sideLAN, expired, stale, live)
	m.applyPrefixAddrs()
	if len(m.applied) != 1 {
		t.Fatalf("want one address, got %v", m.applied)
	}
	for a := range m.applied {
		if !live.Prefix.Contains(a) {
			t.Fatalf("%s is not in the live prefix", a)
		}
	}
	// a stale prefix still takes an address on the WAN, so that it can be retired there
	m = addrTestManager(sideWAN, stale)
	m.applyPrefixAddrs()
	if len(m.applied) != 1 {
		t.Fatalf("want the WAN address in the stale prefix, got %v", m.applied)
	}
}

func TestAddressSlotOf(t *testing.T) {
	m := addrTestManager(sideLAN)
	fixed, _ := parseIIDPolicy("::1")
	m.iids = []iidPolicy{{mode: iidStable}, fixed}
	p := netip.MustParsePrefix("2001:db8:1::/64")
	if got := m.slotOf(netip.MustParseAddr("2001:db8:1::1"), p); got != (iidSlot{p, 1}) {
		t.Fatalf("the fixed suffix is policy 1, got %+v", got)
	}
	if got := m.slotOf(netip.MustParseAddr("2001:db8:1::99"), p); got != (iidSlot{p, 0}) {
		t.Fatalf("an unknown address falls back to policy 0, got %+v", got)
	}
}

func TestAddressTempLimits(t *testing.T) {
	addrDryRun(t)
	p := addrLive("2001:db8:1::/64")
	gone := netip.MustParsePrefix("2001:db8:2::/64")
	m := addrTestManager(sideLAN, p)
	m.cfg.maxConcurrent = 2
	now := time.Now()
	old := &tempAddr{addr: netip.MustParseAddr("2001:db8:2::1"), prefix: gone, plen: 64, created: now.Add(-2 * time.Hour), state: "preferred"}
	mid := &tempAddr{addr: netip.MustParseAddr("2001:db8:2::2"), prefix: gone, plen: 64, created: now.Add(-time.Hour), state: "deprecated"}
	m.temps = []*tempAddr{mid, old}
	if !m.rotate() {
		t.Fatal("no temporary address was made")
	}
	if old.state != "deprecated" {
		t.Fatal("a temporary address in a prefix no longer active stays preferred")
	}
	if len(m.temps) != 2 || m.tempOf(old.addr) != nil || m.tempOf(mid.addr) == nil {
		t.Fatalf("the oldest temporary address should be reclaimed at the cap, left %v", m.temps)
	}
	if m.tempOf(netip.MustParseAddr("2001:db8:9::1")) != nil {
		t.Fatal("an unknown address is a temporary one")
	}
}

func TestAddressIIDInvalid(t *testing.T) {
	for _, s := range []string{"2001:db8::1", "bogus", "192.0.2.1", "::ffff:192.0.2.1"} {
		if _, err := parseIIDPolicy(s); err == nil {
			t.Errorf("%q is accepted as a suffix", s)
		}
	}
}

func TestAddressEndpoints(t *testing.T) {
	addrDryRun(t)
	m := addrTestManager(sideWAN)
	m.applyEndpoints() // without a tunnel, nothing to do
	if len(m.endpoints) != 0 {
		t.Fatal("endpoints without an extra function")
	}
	m.store = newStore("pd", nil, time.Minute, nil, false, 0, 0, "")
	e1 := netip.MustParseAddr("2001:db8:4::e1")
	w := netip.MustParseAddr("2001:db8:3::5")
	var want []netip.Addr
	m.extra = func(Snapshot) []netip.Addr { return want }
	check := func(step string, exp map[netip.Addr]string) {
		t.Helper()
		if !maps.Equal(m.endpoints, exp) {
			t.Fatalf("%s: endpoints %v, want %v", step, m.endpoints, exp)
		}
	}

	want = []netip.Addr{e1, w}
	m.snap.WANAddr = w
	m.applyEndpoints()
	check("first", map[netip.Addr]string{e1: "tentative", w: "external"})
	m.applyEndpoints()
	check("unchanged", map[netip.Addr]string{e1: "tentative", w: "external"})

	// e1 failed DAD and then becomes the IA_NA address: used as is, and the conflict is cleared;
	// w is no longer owned elsewhere and becomes an endpoint of its own
	m.endpoints[e1] = "conflict"
	m.snap.WANAddr = e1
	m.applyEndpoints()
	check("owner changed", map[netip.Addr]string{e1: "external", w: "tentative"})

	e3 := netip.MustParseAddr("2001:db8:4::e3")
	m.endpoints[e3] = "conflict"
	want = nil
	m.applyEndpoints()
	check("none wanted", map[netip.Addr]string{})
	if !m.ownedElsewhere(e1) || m.ownedElsewhere(w) {
		t.Fatal("ownedElsewhere follows the IA_NA address")
	}
}
