package main

import (
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
			pf, up, ok := p.pick(s, key, hint(56), false)
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

// auto delegates the next of /48, /56, /60 and /64 longer than the upstream delegation, cutting a
// hint for more down to it, and takes back a delegation longer than that.
func TestPDPickAuto(t *testing.T) {
	p := &pdPool{leases: map[string]*PDLease{}}
	for up, want := range map[string]int{
		"2001:db8::/32": 48, "2001:db8::/47": 48, "2001:db8:100::/48": 56, "2001:db8:100::/52": 56,
		"2001:db8:100::/56": 60, "2001:db8:100::/58": 60, "2001:db8:100::/60": 64, "2001:db8:100::/62": 64,
	} {
		if pf, _, ok := p.pick(pdSnap(up), "a", hint(40), false); !ok || pf.Bits() != want {
			t.Errorf("out of %s: %s, want a /%d", up, pf, want)
		}
	}
	s := pdSnap("2001:db8:100::/48")
	if pf, _, _ := p.pick(s, "a", netip.MustParsePrefix("2001:db8:100:1000::/52"), false); pf.Bits() != 56 {
		t.Fatalf("a /52 asked for out of a /48 is cut down: %s", pf)
	}
}

func TestPDPickHints(t *testing.T) {
	s := pdSnap("2001:db8:100::/56")
	p := &pdPool{plen: 60, leases: map[string]*PDLease{}}
	if pf, _, _ := p.pick(s, "a", hint(64), false); pf.Bits() != 64 {
		t.Fatalf("a /64 hint asks for less and gets it: %s", pf)
	}
	if pf, _, _ := p.pick(s, "a", netip.Prefix{}, false); pf.Bits() != 60 {
		t.Fatalf("no hint gets the default length: %s", pf)
	}
	asked := netip.MustParsePrefix("2001:db8:100:f0::/60")
	if pf, _, _ := p.pick(s, "a", asked, false); pf != asked {
		t.Fatalf("a free prefix the router asks for is kept: %s", pf)
	}
	if pf, _, _ := p.pick(s, "a", netip.MustParsePrefix("2001:db8:100::/60"), false); pf.Overlaps(s.LAN["lan0"][0].Prefix) {
		t.Fatalf("a prefix overlapping the LAN is not handed out: %s", pf)
	}
	if pf, _, ok := p.pick(s, "a", hint(80), false); !ok || pf.Bits() != 64 {
		t.Fatalf("a hint longer than /64 still gets a /64: %s", pf)
	}
	first, _, _ := p.pick(s, "b", hint(56), false)
	if again, _, _ := p.pick(s, "b", hint(56), false); again != first {
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

// T1 and T2 follow the shorter of the two prefixes in the IA_PD, even when that one has no
// preferred lifetime left.
func TestServerDelegationTimersFollowTheShorter(t *testing.T) {
	snap := pdSnap("2001:db8:100::/56")
	now := time.Now()
	snap.WAN[0].Preferred = now.Add(-time.Second)
	snap.ULA = []Prefix{{Prefix: netip.MustParsePrefix("fd00:9::/48"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: sourceULA}}
	s := newPDServer(false, snap)
	live, _, ia := granted(t, s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL))
	if len(live) != 2 || ia.T1 != 0 || ia.T2 != 0 {
		t.Fatalf("want both prefixes with T1 and T2 of 0: %v %v %v", live, ia.T1, ia.T2)
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
	p := newPDPool(60, file, nil)
	l := &PDLease{DUID: "00030001aabbcc000001", IAID: 7, Prefix: netip.MustParsePrefix("2001:db8:100:10::/60"), Iface: "lan0", Peer: peerLL, Expires: time.Now().Add(time.Hour).Round(time.Second)}
	p.leases[leaseKey(l.DUID, l.IAID)] = l
	p.save()
	got := newPDPool(60, file, nil).leases[leaseKey(l.DUID, l.IAID)]
	if got == nil || got.Prefix != l.Prefix || got.Peer != l.Peer || !got.Expires.Equal(l.Expires) {
		t.Fatalf("round trip lost the lease: %+v", got)
	}
}

// The firewall learns the live delegations, on startup and on every change.
func TestPDTellsTheFirewall(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pd-leases.json")
	fw := &firewall{delegIn: make(chan []netip.Prefix, 1)}
	p := newPDPool(60, file, fw)
	if ps := <-fw.delegIn; len(ps) != 0 {
		t.Fatalf("no delegations yet, got %v", ps)
	}
	live := netip.MustParsePrefix("2001:db8:100:10::/60")
	p.leases["a"] = &PDLease{Prefix: live, Expires: time.Now().Add(time.Hour)}
	p.leases["b"] = &PDLease{Prefix: netip.MustParsePrefix("2001:db8:100:20::/60"), Expires: time.Now().Add(-time.Second)}
	p.save()
	if ps := <-fw.delegIn; !slices.Equal(ps, []netip.Prefix{live}) {
		t.Fatalf("want only the live delegation, got %v", ps)
	}
	newPDPool(60, file, fw)
	if ps := <-fw.delegIn; !slices.Equal(ps, []netip.Prefix{live}) {
		t.Fatalf("reloaded: want %v, got %v", live, ps)
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

	store := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Second, nil, false, 0, 0, "")
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
		if pf, _, ok := p.pick(s, key, hint(64), false); ok {
			got[pf] = true
			p.leases[key] = &PDLease{Prefix: pf, Expires: time.Now().Add(time.Hour)}
		}
	}
	want := map[netip.Prefix]bool{netip.MustParsePrefix("2001:db8:100:1::/64"): true, netip.MustParsePrefix("2001:db8:100:2::/64"): true}
	if len(got) != len(want) || !got[netip.MustParsePrefix("2001:db8:100:1::/64")] || !got[netip.MustParsePrefix("2001:db8:100:2::/64")] {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// A router that accepts Reconfigure gets a key with its delegation, the same one as for its
// addresses, so it can be told to renew when the delegation goes (RFC 9096 section 3.5).
func TestDelegationCarriesTheReconfigureKey(t *testing.T) {
	s := newPDServer(true, pdSnap("2001:db8:100::/56"))
	accept := &dhcpv6.OptionGeneric{OptionCode: optionReconfAccept}
	reply := s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iana1(), iapd(hint(56)), accept), peerLL)
	if reply.Options.GetOne(dhcpv6.OptionAuth) == nil {
		t.Fatal("no Reconfigure key in the Reply")
	}
	var na, pd string
	for _, l := range s.leases {
		na = l.ReconfKey
	}
	for _, l := range s.pd.leases {
		pd = l.ReconfKey
	}
	if na == "" || na != pd {
		t.Fatalf("one key for addresses and delegations: %q %q", na, pd)
	}

	st := newPDServer(false, pdSnap("2001:db8:100::/56"))
	reply = st.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iapd(hint(56)), accept), peerLL)
	if reply.Options.GetOne(dhcpv6.OptionAuth) == nil {
		t.Fatal("a stateless server gives a delegating router its key too")
	}
}

func TestPDLeaseFileErrors(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	os.WriteFile(corrupt, []byte("["), 0o600)
	if p := newPDPool(60, corrupt, nil); len(p.leases) != 0 {
		t.Fatalf("a corrupt file is ignored: %v", p.leases)
	}
	p := newPDPool(60, filepath.Join(dir, "no-such-dir", "pd.json"), nil)
	p.leases["a"] = &PDLease{Prefix: netip.MustParsePrefix("2001:db8:100:10::/60"), Expires: time.Now().Add(time.Hour)}
	p.save()
	if _, err := os.Stat(p.file); err == nil {
		t.Fatal("a file in a missing directory cannot be written")
	}
}

// An upstream with a ULA delegates a part of it in the same IA_PD; the downstream without -ula
// splits that among its LANs as its own ULA, keeps it off the WAN, renews it with the
// delegation, and gives it up with it. With -ula it keeps its own.
func TestSixupBehindSixupULA(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	now := time.Now()
	site := netip.MustParsePrefix("fd00:1::/48")
	snap := pdSnap("2001:db8:100::/56")
	snap.ULA = []Prefix{{Prefix: site, Preferred: now.Add(7 * 24 * time.Hour), Valid: now.Add(30 * 24 * time.Hour), Source: sourceULA}}
	ownLAN, _ := splitLAN(site, 0)
	snap.LAN["lan0"] = append(snap.LAN["lan0"], Prefix{Prefix: ownLAN, Source: sourceULA})
	up := newPDServer(false, snap)

	for _, own := range []bool{false, true} {
		up.snap.ULA = slices.Clone(snap.ULA)
		var ula []netip.Prefix
		if own {
			ula = []netip.Prefix{netip.MustParsePrefix("fd00:9::/48")}
		}
		store := newStore("pd", []lanDef{{"lan0", 0}, {"lan1", 1}}, time.Minute, ula, false, 0, 0, "")
		ch := store.Subscribe()
		recv(t, ch)
		down := &dhcpClient{ifi: &net.Interface{Index: 2}, store: store, pdLen: 56, duid: cliDUID, iaid: [4]byte{0, 0, 0, 7}}
		exchange := func(mt dhcpv6.MessageType, l *lease) *lease {
			m, _ := dhcpv6.NewMessage(append(append(down.baseOptions(0), dhcpv6.WithServerID(srvDUID)), down.iaOptions(l)...)...)
			m.MessageType = mt
			return down.apply(up.handle(m, peerLL))
		}
		l := exchange(dhcpv6.MessageTypeRequest, nil)
		var gua, deleg netip.Prefix
		for _, p := range l.prefixes {
			if p.Prefix.Addr().IsPrivate() {
				deleg = p.Prefix
			} else {
				gua = p.Prefix
			}
		}
		if gua.Bits() != 60 || !site.Contains(deleg.Addr()) || deleg.Bits() != 60 || deleg.Overlaps(ownLAN) {
			t.Fatalf("own=%v: want a /60 of each, the ULA one clear of the upstream's LAN: %+v", own, l.prefixes)
		}
		s := recv(t, ch)
		if len(s.WAN) != 1 || s.WAN[0].Prefix != gua {
			t.Fatalf("own=%v: the ULA stays off the WAN: %+v", own, s.WAN)
		}
		lanULA := s.lanULA("lan1")
		if own {
			if len(s.ULA) != 1 || s.ULA[0].Delegated || len(lanULA) != 1 || lanULA[0].Prefix != netip.MustParsePrefix("fd00:9:0:1::/64") {
				t.Fatalf("-ula keeps its own: %+v %+v", s.ULA, lanULA)
			}
			continue
		}
		want, _ := splitLAN(deleg, 1)
		if len(s.ULA) != 1 || !s.ULA[0].Delegated || s.ULA[0].Prefix != deleg || len(lanULA) != 1 || lanULA[0].Prefix != want || !lanULA[0].Delegated {
			t.Fatalf("the delegated ULA is split among the LANs: %+v %+v", s.ULA, lanULA)
		}

		// a renewal moves the lifetimes, which goes out
		up.snap.ULA[0].Preferred = up.snap.ULA[0].Preferred.Add(time.Hour)
		up.preferred += time.Minute
		l = exchange(dhcpv6.MessageTypeRenew, l)
		if s = recv(t, ch); s.Change != changeRenew || !s.ULA[0].Delegated {
			t.Fatalf("the renewed ULA is published: %s %+v", s.Change, s.ULA)
		}

		// the upstream's ULA goes, and with it the downstream's, withdrawn from the LANs
		up.snap.ULA = nil
		exchange(dhcpv6.MessageTypeRenew, l)
		s = recv(t, ch)
		stale := slices.IndexFunc(s.LAN["lan1"], func(p Prefix) bool { return p.Prefix == want })
		if len(s.ULA) != 0 || s.Change != changeRevoke || stale < 0 || !s.LAN["lan1"][stale].Stale {
			t.Fatalf("the ULA gone is withdrawn: %s %+v %+v", s.Change, s.ULA, s.LAN["lan1"])
		}
	}

	up.snap.ULA = slices.Clone(snap.ULA)
	reply := up.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iapd(hint(56))), peerLL)
	if live, _, _ := granted(t, reply); len(live) != 2 || len(up.pd.leases) < 2 {
		t.Fatalf("one prefix of each: %v", live)
	}
	up.handle(cliMsg(dhcpv6.MessageTypeRelease, dhcpv6.OptServerID(srvDUID), iapd(hint(56))), peerLL)
	if len(up.pd.leases) != 0 {
		t.Fatalf("RELEASE ends both: %+v", up.pd.leases)
	}
	// only a ULA to delegate: it goes alone; nothing at all: NoPrefixAvail
	up.snap.WAN = nil
	if live, _, _ := granted(t, up.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL)); len(live) != 1 || !live[0].Addr().IsPrivate() {
		t.Fatalf("the ULA alone: %v", live)
	}
	up.snap.ULA = nil
	if _, _, ia := granted(t, up.handle(cliMsg(dhcpv6.MessageTypeSolicit, iapd(hint(56))), peerLL)); ia.Options.Status() == nil || ia.Options.Status().StatusCode != iana.StatusNoPrefixAvail {
		t.Fatalf("nothing to delegate: %+v", ia)
	}
}
