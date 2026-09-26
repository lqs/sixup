package main

import (
	"encoding/hex"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// pdSnap is a line delegating up, with subnet 0 of it on lan0.
func pdSnap(up string) Snapshot {
	now := time.Now()
	u := netip.MustParsePrefix(up)
	lan, _ := splitLAN(u, 0)
	return Snapshot{
		WAN: []Prefix{{Prefix: u, Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}},
		LAN: map[string][]Prefix{"lan0": {{Prefix: lan, Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}},
	}
}

func hint(bits int) netip.Prefix { return netip.PrefixFrom(netip.IPv6Unspecified(), bits) }

func TestPDPick(t *testing.T) {
	cases := []struct {
		name string
		up   string
		want []string // lengths granted to successive routers hinting /56; "" when none is left
	}{
		{"/56 upstream", "2001:db8:100::/56", []string{"/60", "/60"}},
		{"/60 upstream gives the half the LAN does not use", "2001:db8:100::/60", []string{"/61", "/62", "/63", "/64", ""}},
		{"/64 upstream has nothing to delegate", "2001:db8:100::/64", []string{""}},
	}
	for _, c := range cases {
		s := pdSnap(c.up)
		p := &pdPool{plen: 60, leases: map[string]*PDLease{}}
		for i, w := range c.want {
			key := leaseKey("router", uint32(i))
			pf, up, ok := p.pick(s, key, hint(56))
			if w == "" {
				if ok {
					t.Errorf("%s: router %d got %s, want none", c.name, i, pf)
				}
				continue
			}
			if !ok || "/"+strconv.Itoa(pf.Bits()) != w {
				t.Fatalf("%s: router %d got %s ok=%v, want a %s", c.name, i, pf, ok, w)
			}
			if !up.Prefix.Contains(pf.Addr()) || pf.Overlaps(s.LAN["lan0"][0].Prefix) {
				t.Fatalf("%s: %s must lie in %s and clear of the LAN", c.name, pf, up.Prefix)
			}
			for _, l := range p.leases {
				if l.Prefix.Overlaps(pf) {
					t.Fatalf("%s: %s overlaps %s", c.name, pf, l.Prefix)
				}
			}
			p.leases[key] = &PDLease{Prefix: pf, Expires: time.Now().Add(time.Hour)}
		}
	}
}

func TestPDPickHints(t *testing.T) {
	s := pdSnap("2001:db8:100::/56")
	p := &pdPool{plen: 60, leases: map[string]*PDLease{}}
	if pf, _, _ := p.pick(s, "a", hint(64)); pf.Bits() != 64 {
		t.Fatalf("a /64 hint asks for less and gets it: %s", pf)
	}
	if pf, _, _ := p.pick(s, "a", netip.Prefix{}); pf.Bits() != 60 {
		t.Fatalf("no hint gets the default length: %s", pf)
	}
	asked := netip.MustParsePrefix("2001:db8:100:f0::/60")
	if pf, _, _ := p.pick(s, "a", asked); pf != asked {
		t.Fatalf("a free prefix the router asks for is kept: %s", pf)
	}
	if pf, _, _ := p.pick(s, "a", netip.MustParsePrefix("2001:db8:100::/60")); pf.Overlaps(s.LAN["lan0"][0].Prefix) {
		t.Fatalf("a prefix overlapping the LAN is not handed out: %s", pf)
	}
	if pf, _, ok := p.pick(s, "a", hint(80)); !ok || pf.Bits() != 64 {
		t.Fatalf("a hint longer than /64 still gets a /64: %s", pf)
	}
	first, _, _ := p.pick(s, "b", hint(56))
	if again, _, _ := p.pick(s, "b", hint(56)); again != first {
		t.Fatalf("the same router gets the same block: %s then %s", first, again)
	}
}

func newPDServer(stateful bool, snap Snapshot) *dhcpServer {
	s := newTestServer(stateful)
	s.snap = snap
	s.pd = &pdPool{plen: 60, leases: map[string]*PDLease{}}
	return s
}

func iapd(prefixes ...netip.Prefix) *dhcpv6.OptIAPD {
	ia := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 7}}
	for _, p := range prefixes {
		ia.Options.Add(&dhcpv6.OptIAPrefix{Prefix: prefixToIPNet(p)})
	}
	return ia
}

// granted returns the prefixes in the only IA_PD of resp with a non-zero valid lifetime, and the
// ones returned with lifetime 0.
func granted(t *testing.T, resp *dhcpv6.Message) (live, stale []netip.Prefix, ia *dhcpv6.OptIAPD) {
	t.Helper()
	ias := resp.Options.IAPD()
	if len(ias) != 1 {
		t.Fatalf("want one IA_PD, got %d", len(ias))
	}
	for _, p := range ias[0].Options.Prefixes() {
		a, _ := netip.AddrFromSlice(p.Prefix.IP)
		ones, _ := p.Prefix.Mask.Size()
		pf := netip.PrefixFrom(a.Unmap(), ones)
		if p.ValidLifetime > 0 {
			live = append(live, pf)
		} else {
			stale = append(stale, pf)
		}
	}
	return live, stale, ias[0]
}

func TestServerDelegates(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		s := newPDServer(stateful, pdSnap("2001:db8:100::/56"))
		adv := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL)
		if adv.MessageType != dhcpv6.MessageTypeAdvertise {
			t.Fatalf("stateful=%v: want ADVERTISE, got %v", stateful, adv.MessageType)
		}
		live, _, ia := granted(t, adv)
		if len(live) != 1 || live[0].Bits() != 60 {
			t.Fatalf("stateful=%v: a /56 hint gets a /60: %v", stateful, live)
		}
		if p := ia.Options.Prefixes()[0]; p.PreferredLifetime > s.preferred || p.ValidLifetime > s.valid {
			t.Fatalf("lifetimes above the configured ones: %v", p)
		}
		if len(s.pd.leases) != 0 {
			t.Fatal("an ADVERTISE commits nothing")
		}
		reply := s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iapd(hint(56))), peerLL)
		if got, _, _ := granted(t, reply); len(got) != 1 || got[0] != live[0] {
			t.Fatalf("REQUEST should commit the advertised %s: %v", live[0], got)
		}
		l := s.pd.leases[leaseKey(duidOf(cliDUID), 7)]
		if l == nil || l.Prefix != live[0] || l.Peer != peerLL || l.Iface != "lan0" {
			t.Fatalf("lease not recorded: %+v", l)
		}
		renew := s.handle(cliMsg(dhcpv6.MessageTypeRenew, dhcpv6.OptServerID(srvDUID), iapd(live[0])), peerLL)
		if got, stale, _ := granted(t, renew); len(got) != 1 || got[0] != live[0] || len(stale) != 0 {
			t.Fatalf("RENEW keeps the prefix: %v, stale %v", got, stale)
		}
		s.handle(cliMsg(dhcpv6.MessageTypeRelease, dhcpv6.OptServerID(srvDUID), iapd(live[0])), peerLL)
		if len(s.pd.leases) != 0 {
			t.Fatal("RELEASE ends the delegation")
		}
	}
}

// When the upstream delegation moves, the router gets a prefix from the new one and its old
// prefix back with lifetime 0.
func TestServerDelegationAfterPrefixChange(t *testing.T) {
	s := newPDServer(false, pdSnap("2001:db8:100::/56"))
	reply := s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iapd(hint(56))), peerLL)
	old, _, _ := granted(t, reply)
	old0 := s.snap
	s.snap = pdSnap("2001:db8:200::/56")
	s.onPrefixChange(old0)
	if len(s.pd.leases) != 0 {
		t.Fatal("a delegation outside the new upstream prefix is dropped")
	}
	renew := s.handle(cliMsg(dhcpv6.MessageTypeRenew, dhcpv6.OptServerID(srvDUID), iapd(old[0])), peerLL)
	live, stale, _ := granted(t, renew)
	if len(live) != 1 || !netip.MustParsePrefix("2001:db8:200::/56").Contains(live[0].Addr()) {
		t.Fatalf("new prefix should come from the new upstream: %v", live)
	}
	if len(stale) != 1 || stale[0] != old[0] {
		t.Fatalf("the old prefix should come back with lifetime 0: %v", stale)
	}
}

func TestServerDelegationLifetimeCap(t *testing.T) {
	snap := pdSnap("2001:db8:100::/56")
	now := time.Now()
	snap.WAN[0].Preferred, snap.WAN[0].Valid = now.Add(10*time.Minute), now.Add(20*time.Minute)
	s := newPDServer(false, snap)
	_, _, ia := granted(t, s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL))
	p := ia.Options.Prefixes()[0]
	if p.PreferredLifetime > 10*time.Minute || p.ValidLifetime > 20*time.Minute {
		t.Fatalf("lifetimes must not outlast the upstream prefix (RFC 9096 L-15): %v", p)
	}
}

func TestServerDelegationDisabledOrEmpty(t *testing.T) {
	s := newTestServer(true) // no pool
	_, _, ia := granted(t, s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL))
	if st := ia.Options.Status(); st == nil || st.StatusCode != iana.StatusNoPrefixAvail {
		t.Fatalf("disabled: want NoPrefixAvail, got %v", st)
	}
	s = newPDServer(true, pdSnap("2001:db8:100::/64"))
	_, _, ia = granted(t, s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL))
	if st := ia.Options.Status(); st == nil || st.StatusCode != iana.StatusNoPrefixAvail {
		t.Fatalf("a /64 upstream: want NoPrefixAvail, got %v", st)
	}
}

func TestPDLeaseFileRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pd-leases.json")
	p := newPDPool(60, file)
	l := &PDLease{DUID: "00030001aabbcc000001", IAID: 7, Prefix: netip.MustParsePrefix("2001:db8:100:10::/60"), Iface: "lan0", Peer: peerLL, Expires: time.Now().Add(time.Hour).Round(time.Second)}
	p.leases[leaseKey(l.DUID, l.IAID)] = l
	p.save()
	got := newPDPool(60, file).leases[leaseKey(l.DUID, l.IAID)]
	if got == nil || got.Prefix != l.Prefix || got.Peer != l.Peer || !got.Expires.Equal(l.Expires) {
		t.Fatalf("round trip lost the lease: %+v", got)
	}
}

func duidOf(d dhcpv6.DUID) string { return hex.EncodeToString(d.ToBytes()) }

// A downstream sixup asking with its default /56 hint gets a /60 from an upstream sixup, and its
// store splits that across its own LANs: sixup behind sixup works without configuration.
func TestSixupBehindSixup(t *testing.T) {
	old := dryRun
	dryRun = true // the downstream's address and route changes go through stubs
	defer func() { dryRun = old }()
	up := newPDServer(false, pdSnap("2001:db8:100::/56"))

	store := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, nil, false, 0, 0)
	ch := store.Subscribe()
	recv(t, ch)
	down := &dhcpClient{ifi: &net.Interface{Index: 2}, store: store, pdLen: 56, duid: cliDUID, iaid: [4]byte{0, 0, 0, 7}}
	msg := func(mt dhcpv6.MessageType, mods ...dhcpv6.Modifier) *dhcpv6.Message {
		m, _ := dhcpv6.NewMessage(append(append(down.baseOptions(0), mods...), down.iaOptions(nil)...)...)
		m.MessageType = mt
		return m
	}
	adv := up.handle(msg(dhcpv6.MessageTypeSolicit), peerLL)
	req := msg(dhcpv6.MessageTypeRequest, dhcpv6.WithServerID(adv.Options.ServerID()))
	for _, ia := range adv.Options.IAPD() {
		req.Options.Update(ia) // as request() echoes the advertised IAs
	}
	l := down.apply(up.handle(req, peerLL))
	if l == nil || len(l.prefixes) != 1 || l.prefixes[0].Prefix.Bits() != 60 {
		t.Fatalf("the downstream should hold a /60: %+v", l)
	}
	s := recv(t, ch)
	if len(s.LAN["lan0"]) != 1 || len(s.LAN["lan1"]) != 1 || !l.prefixes[0].Prefix.Contains(s.LAN["lan1"][0].Prefix.Addr()) {
		t.Fatalf("the downstream LANs should be carved from its /60: %+v", s.LAN)
	}
}

// Neither an expired delegation nor the WAN link's on-link prefix blocks a block.
func TestPDFree(t *testing.T) {
	s := pdSnap("2001:db8:100::/62")
	onLink := netip.MustParsePrefix("2001:db8:100:3::/64")
	s.WAN = append(s.WAN, Prefix{Prefix: onLink, Source: "ra"})
	p := &pdPool{plen: 60, leases: map[string]*PDLease{
		"gone": {Prefix: netip.MustParsePrefix("2001:db8:100:2::/64"), Iface: "eth9", Expires: time.Now().Add(-time.Minute)},
	}}
	got := map[netip.Prefix]bool{}
	for i := range 3 {
		key := leaseKey("router", uint32(i))
		if pf, _, ok := p.pick(s, key, hint(64)); ok {
			got[pf] = true
			p.leases[key] = &PDLease{Prefix: pf, Expires: time.Now().Add(time.Hour)}
		}
	}
	want := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8:100:1::/64"): true, netip.MustParsePrefix("2001:db8:100:2::/64"): true}
	if len(got) != len(want) || !got[netip.MustParsePrefix("2001:db8:100:1::/64")] || !got[netip.MustParsePrefix("2001:db8:100:2::/64")] {
		t.Fatalf("want %v, got %v", want, got)
	}
}
