package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

var (
	srvDUID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}
	cliDUID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0, 0, 1}}
	cliMAC  = "aa:bb:cc:00:00:01"
	peerLL  = netip.MustParseAddr("fe80::a8bb:ccff:fe00:1")
)

func newTestServer(stateful bool) *dhcpServer {
	now := time.Now()
	return &dhcpServer{
		ifname: "lan0", ifi: &net.Interface{Index: 3, Name: "lan0"}, stateful: stateful, duid: srvDUID,
		poolStart: 0x1000, poolEnd: 0x1003, preferred: time.Hour, valid: 2 * time.Hour,
		dns:    lanDNS{list: []dnsEntry{{upstream: true}}},
		leases: map[string]*Lease{},
		snap: Snapshot{
			LAN:   map[string][]Prefix{"lan0": {{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}}},
			DNS:   []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::53")},
			DNSSL: []string{"example.net"},
		},
	}
}

func cliMsg(mt dhcpv6.MessageType, opts ...dhcpv6.Option) *dhcpv6.Message {
	m, _ := dhcpv6.NewMessage()
	m.MessageType = mt
	m.AddOption(dhcpv6.OptClientID(cliDUID))
	for _, o := range opts {
		m.AddOption(o)
	}
	return m
}

func iana1() *dhcpv6.OptIANA { return &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}} }

func firstAddr(t *testing.T, resp *dhcpv6.Message) (netip.Addr, *dhcpv6.OptIANA) {
	t.Helper()
	ias := resp.Options.IANA()
	if len(ias) != 1 {
		t.Fatalf("want one IA_NA, got %d", len(ias))
	}
	addrs := ias[0].Options.Addresses()
	if len(addrs) != 1 {
		t.Fatalf("want one address, got %+v", ias[0].Options)
	}
	a, _ := netip.AddrFromSlice(addrs[0].IPv6Addr)
	return a.Unmap(), ias[0]
}

func TestServerInformationRequest(t *testing.T) {
	s := newTestServer(false)
	resp := s.handle(cliMsg(dhcpv6.MessageTypeInformationRequest), peerLL)
	if resp == nil || resp.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("want REPLY, got %v", resp)
	}
	dns := resp.Options.DNS()
	if len(dns) != 1 || !dns[0].Equal(net.ParseIP("2001:db8::53")) {
		t.Fatalf("link-local DNS must be filtered: %v", dns)
	}
	if dl := resp.Options.DomainSearchList(); dl == nil || dl.Labels[0] != "example.net" {
		t.Fatalf("DNSSL missing: %v", dl)
	}
	if resp.Options.ServerID() == nil || !resp.Options.ServerID().Equal(srvDUID) {
		t.Fatal("server ID missing")
	}
}

func TestServerStatelessRefusesAddresses(t *testing.T) {
	s := newTestServer(false)
	resp := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1()), peerLL)
	if resp.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("want ADVERTISE, got %v", resp.MessageType)
	}
	st := resp.Options.IANA()[0].Options.Status()
	if st == nil || st.StatusCode != iana.StatusNoAddrsAvail {
		t.Fatalf("want NoAddrsAvail, got %v", st)
	}
	adv := s.handle(cliMsg(dhcpv6.MessageTypeSolicit), peerLL)
	if adv == nil || adv.MessageType != dhcpv6.MessageTypeAdvertise || adv.Options.Status().StatusCode != iana.StatusNoAddrsAvail {
		t.Fatalf("a SOLICIT without IA gets an ADVERTISE with NoAddrsAvail, got %v", adv)
	}
}

// The validation of RFC 8415 section 16 and the answers of section 18.3 (IPv6 Ready CE Router 2.1
// and 2.2).
func TestServerValidation(t *testing.T) {
	s := newTestServer(true)
	withSID := func(mt dhcpv6.MessageType, sid dhcpv6.DUID, opts ...dhcpv6.Option) *dhcpv6.Message {
		m := cliMsg(mt, opts...)
		m.AddOption(dhcpv6.OptServerID(sid))
		return m
	}
	for _, mt := range []dhcpv6.MessageType{dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRebind} {
		if s.handle(withSID(mt, s.duid, iana1()), peerLL) != nil {
			t.Errorf("%s with a Server ID, even this server's, is dropped", mt)
		}
	}
	if s.handle(cliMsg(dhcpv6.MessageTypeInformationRequest, iana1()), peerLL) != nil {
		t.Error("an Information-Request with an IA is dropped")
	}
	anon, _ := dhcpv6.NewMessage()
	anon.MessageType = dhcpv6.MessageTypeInformationRequest
	if s.handle(anon, peerLL) == nil {
		t.Error("an Information-Request without a Client ID is answered")
	}
	if s.handle(cliMsg(dhcpv6.MessageTypeConfirm, iana1()), peerLL) != nil {
		t.Error("a Confirm with no address gets no Reply")
	}
	rel := s.handle(withSID(dhcpv6.MessageTypeRelease, s.duid, iana1()), peerLL)
	if rel == nil || len(rel.Options.IANA()) != 1 || rel.Options.IANA()[0].Options.Status().StatusCode != iana.StatusNoBinding {
		t.Errorf("releasing an unknown IA answers NoBinding for it: %v", rel)
	}
	if s.unicast(withSID(dhcpv6.MessageTypeSolicit, s.duid)) != nil {
		t.Error("a unicast Solicit is dropped")
	}
	req := s.unicast(withSID(dhcpv6.MessageTypeRequest, s.duid, iana1()))
	if req == nil || req.Options.Status().StatusCode != iana.StatusUseMulticast || len(req.Options.IANA()) != 0 {
		t.Errorf("a unicast Request is told UseMulticast and nothing else: %v", req)
	}
}

func TestServerSolicitRequestCommit(t *testing.T) {
	s := newTestServer(true)
	adv := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1()), peerLL)
	if adv.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("want ADVERTISE, got %v", adv.MessageType)
	}
	offered, ia := firstAddr(t, adv)
	if !netip.MustParsePrefix("2001:db8:1::/64").Contains(offered) {
		t.Fatalf("offered address outside prefix: %s", offered)
	}
	// Preferred is capped by the upstream remainder, which has ticked down slightly.
	if ia.T1 < 29*time.Minute || ia.T1 > 30*time.Minute || ia.T2 < 47*time.Minute || ia.T2 > 48*time.Minute {
		t.Fatalf("T1/T2 should be 0.5 and 0.8 of preferred: %v %v", ia.T1, ia.T2)
	}
	if len(s.leases) != 0 {
		t.Fatal("ADVERTISE must not commit a lease")
	}

	req := cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iana1(),
		&dhcpv6.OptFQDN{DomainName: &rfc1035label.Labels{Labels: []string{"nas", "lan"}}})
	rep := s.handle(req, peerLL)
	if rep.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("want REPLY, got %v", rep.MessageType)
	}
	got, _ := firstAddr(t, rep)
	if got != offered {
		t.Fatalf("REQUEST must confirm the offered address: %s vs %s", got, offered)
	}
	l := s.leases[leaseKey(hex.EncodeToString(cliDUID.ToBytes()), 1)]
	if l == nil || l.Addr != offered || l.Hostname != "nas" || l.MAC != cliMAC || l.Peer != peerLL {
		t.Fatalf("lease not committed correctly: %+v", l)
	}
}

func TestServerRapidCommit(t *testing.T) {
	s := newTestServer(true)
	rep := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1(), &dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit}), peerLL)
	if rep.MessageType != dhcpv6.MessageTypeReply || rep.Options.GetOne(dhcpv6.OptionRapidCommit) == nil {
		t.Fatalf("rapid commit should yield REPLY with the option echoed: %v", rep)
	}
	if len(s.leases) != 1 {
		t.Fatal("rapid commit must commit the lease")
	}
}

func TestServerRenewWithoutBinding(t *testing.T) {
	s := newTestServer(true)
	rep := s.handle(cliMsg(dhcpv6.MessageTypeRenew, dhcpv6.OptServerID(srvDUID), iana1()), peerLL)
	st := rep.Options.IANA()[0].Options.Status()
	if st == nil || st.StatusCode != iana.StatusNoBinding {
		t.Fatalf("RENEW of unknown binding must return NoBinding, got %v", st)
	}
}

// After the prefix changes, the client's old address is returned with lifetime 0 and a new one assigned.
func TestServerRebindAfterPrefixChange(t *testing.T) {
	s := newTestServer(true)
	old := netip.MustParseAddr("2001:db8:9::1000")
	s.leases[leaseKey(hex.EncodeToString(cliDUID.ToBytes()), 1)] = &Lease{DUID: hex.EncodeToString(cliDUID.ToBytes()), IAID: 1, Addr: old}
	ia := iana1()
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: old.AsSlice(), PreferredLifetime: time.Hour, ValidLifetime: time.Hour})
	rep := s.handle(cliMsg(dhcpv6.MessageTypeRebind, ia), peerLL)
	addrs := rep.Options.IANA()[0].Options.Addresses()
	var zeroed, fresh bool
	for _, a := range addrs {
		ip, _ := netip.AddrFromSlice(a.IPv6Addr)
		if ip.Unmap() == old && a.ValidLifetime == 0 {
			zeroed = true
		}
		if netip.MustParsePrefix("2001:db8:1::/64").Contains(ip.Unmap()) && a.ValidLifetime > 0 {
			fresh = true
		}
	}
	if !zeroed || !fresh {
		t.Fatalf("want old address zeroed and a new one assigned, got %+v", addrs)
	}
}

func TestServerConfirm(t *testing.T) {
	s := newTestServer(true)
	on := iana1()
	on.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8:1::1000")})
	if st := s.handle(cliMsg(dhcpv6.MessageTypeConfirm, on), peerLL).Options.Status(); st.StatusCode != iana.StatusSuccess {
		t.Fatalf("on-link address should confirm: %v", st)
	}
	off := iana1()
	off.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8:9::1000")})
	if st := s.handle(cliMsg(dhcpv6.MessageTypeConfirm, off), peerLL).Options.Status(); st.StatusCode != iana.StatusNotOnLink {
		t.Fatalf("off-link address should get NotOnLink: %v", st)
	}
}

func TestServerReleaseAndServerIDCheck(t *testing.T) {
	s := newTestServer(true)
	s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1(), &dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit}), peerLL)
	other := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{9, 9, 9, 9, 9, 9}}
	if s.handle(cliMsg(dhcpv6.MessageTypeRelease, dhcpv6.OptServerID(other), iana1()), peerLL) != nil {
		t.Fatal("messages for another server must be ignored")
	}
	if len(s.leases) != 1 {
		t.Fatal("lease must survive a foreign RELEASE")
	}
	rep := s.handle(cliMsg(dhcpv6.MessageTypeRelease, dhcpv6.OptServerID(srvDUID), iana1()), peerLL)
	if rep.Options.Status().StatusCode != iana.StatusSuccess || len(s.leases) != 0 {
		t.Fatal("RELEASE must drop the lease")
	}
}

func TestServerStaticBindingAndPool(t *testing.T) {
	s := newTestServer(true)
	// IID-only static entry: high 64 bits are filled from the active prefix.
	s.statics = []staticBind{{mac: cliMAC, addr: netip.MustParseAddr("::beef")}}
	rep := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1(), &dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit}), peerLL)
	if a, _ := firstAddr(t, rep); a != netip.MustParseAddr("2001:db8:1::beef") {
		t.Fatalf("static binding by MAC: got %s", a)
	}

	// Pool of 4: the 5th distinct client is refused.
	s = newTestServer(true)
	for i := range 4 {
		d := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{1, 2, 3, 4, 5, byte(i)}}
		m, _ := dhcpv6.NewMessage()
		m.MessageType = dhcpv6.MessageTypeSolicit
		m.AddOption(dhcpv6.OptClientID(d))
		m.AddOption(iana1())
		m.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit})
		if st := s.handle(m, peerLL).Options.IANA()[0].Options.Status(); st != nil {
			t.Fatalf("client %d should get an address, got %v", i, st)
		}
	}
	rep = s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1()), peerLL)
	if st := rep.Options.IANA()[0].Options.Status(); st == nil || st.StatusCode != iana.StatusNoAddrsAvail {
		t.Fatalf("exhausted pool must return NoAddrsAvail, got %v", st)
	}
}

func TestServerLeaseFileRoundTrip(t *testing.T) {
	s := newTestServer(true)
	s.leaseFile = filepath.Join(t.TempDir(), "leases.json")
	s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iana1(),
		&dhcpv6.OptionGeneric{OptionCode: optionReconfAccept}), peerLL)
	if _, err := os.Stat(s.leaseFile); err != nil {
		t.Fatalf("lease file not written: %v", err)
	}
	s2 := newTestServer(true)
	s2.leaseFile = s.leaseFile
	s2.loadLeases()
	if len(s2.leases) != 1 {
		t.Fatalf("want 1 lease after reload, got %d", len(s2.leases))
	}
	var a, b *Lease
	for _, l := range s.leases {
		a = l
	}
	for _, l := range s2.leases {
		b = l
	}
	if a.Addr != b.Addr || a.DUID != b.DUID || a.ReconfKey == "" || a.ReconfKey != b.ReconfKey || !a.Expires.Equal(b.Expires) {
		t.Fatalf("lease changed across save/load: %+v vs %+v", a, b)
	}
}

// The Reconfigure the server signs must pass the client's verification with the same key.
func TestReconfigureRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	l := &Lease{DUID: hex.EncodeToString(cliDUID.ToBytes()), IAID: 1, ReconfKey: hex.EncodeToString(key), Peer: peerLL}
	raw, ok := buildReconfigure(srvDUID, l, time.Now())
	if !ok {
		t.Fatal("buildReconfigure failed")
	}
	msg, err := dhcpv6.MessageFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := &dhcpClient{duid: cliDUID, serverID: srvDUID, reconfKey: key}
	if !c.verifyReconfigure(msg) {
		t.Fatal("client rejected a correctly signed Reconfigure")
	}
	c.reconfKey = []byte("wrong-key-wrong-")
	if c.verifyReconfigure(msg) {
		t.Fatal("wrong key must fail")
	}
	if _, ok := buildReconfigure(srvDUID, &Lease{DUID: l.DUID}, time.Now()); ok {
		t.Fatal("no key: nothing to sign")
	}
}

// A declined address stays out of the pool (RFC 8415 section 18.3.8, IPv6 Ready CE Router 2.1.15).
func TestServerKeepsDeclinedAddressOut(t *testing.T) {
	s := newTestServer(true)
	req := cliMsg(dhcpv6.MessageTypeRequest, iana1())
	req.AddOption(dhcpv6.OptServerID(srvDUID))
	first, _ := firstAddr(t, s.handle(req, peerLL))
	na := iana1()
	na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: first.AsSlice(), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
	// another client declining it locks nothing away
	other, _ := dhcpv6.NewMessage()
	other.MessageType = dhcpv6.MessageTypeDecline
	other.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: net.HardwareAddr{2, 9, 9, 9, 9, 9}}))
	other.AddOption(dhcpv6.OptServerID(srvDUID))
	other.AddOption(na)
	s.handle(other, peerLL)
	if len(s.declined) != 0 {
		t.Fatalf("another client's Decline kept %v out", s.declined)
	}
	dec := cliMsg(dhcpv6.MessageTypeDecline, na)
	dec.AddOption(dhcpv6.OptServerID(srvDUID))
	if s.handle(dec, peerLL) == nil {
		t.Fatal("a Decline is answered")
	}
	if again, _ := firstAddr(t, s.handle(req, peerLL)); again == first {
		t.Fatalf("%s was declined and handed out again", first)
	}
}

// The upstream's time servers are passed on to the LAN (RFC 7084 L-12).
func TestServerPassesNTPOn(t *testing.T) {
	s := newTestServer(false)
	s.snap.NTP = []netip.Addr{netip.MustParseAddr("2001:db8::123")}
	resp := s.handle(cliMsg(dhcpv6.MessageTypeInformationRequest), peerLL)
	if got := resp.Options.NTPServers(); len(got) != 1 || !got[0].Equal(net.ParseIP("2001:db8::123")) {
		t.Fatalf("NTP: %v", got)
	}
	if got := resp.Options.SNTP(); len(got) != 1 {
		t.Fatalf("SNTP: %v", got)
	}
}

// The SIP servers of the upstream reach the hosts that ask for them (RFC 7084 L-12)
func TestServerPassesSIPOn(t *testing.T) {
	s := newTestServer(false)
	sip := net.ParseIP("2001:db8::5060")
	s.snap.Options = []dhcpOption{{dhcpv6.OptionSIPServersIPv6AddressList, sip}}
	resp := s.handle(cliMsg(dhcpv6.MessageTypeInformationRequest), peerLL)
	if resp.Options.GetOne(dhcpv6.OptionSIPServersIPv6AddressList) != nil {
		t.Fatal("SIP servers sent unasked")
	}
	resp = s.handle(cliMsg(dhcpv6.MessageTypeInformationRequest, dhcpv6.OptRequestedOption(dhcpv6.OptionSIPServersIPv6AddressList)), peerLL)
	o := resp.Options.GetOne(dhcpv6.OptionSIPServersIPv6AddressList)
	if o == nil || !bytes.Equal(o.ToBytes(), sip) {
		t.Fatalf("SIP servers: %v", o)
	}
}

// dhcp6sDryRun turns route changes into no-ops for the test.
func dhcp6sDryRun(t *testing.T) {
	old := dryRun
	dryRun = true
	t.Cleanup(func() { dryRun = old })
}

// A GUA wins over a ULA, a deprecated prefix is skipped, and with nothing left no address is offered.
func TestDHCP6sActivePrefix(t *testing.T) {
	s := newTestServer(true)
	ula1, ula2 := netip.MustParsePrefix("fd00:1::/64"), netip.MustParsePrefix("fd00:2::/64")
	gua := s.snap.LAN["lan0"][0]
	dep := gua
	dep.Deprecated = true
	s.snap.LAN["lan0"] = []Prefix{dep, {Prefix: ula1, Source: "ula"}, {Prefix: ula2, Source: "ula"}}
	if p, ok := s.activePrefix(); !ok || p.Prefix != ula1 {
		t.Fatalf("the first ULA when no GUA is usable: %v %v", p, ok)
	}
	s.snap.LAN["lan0"] = []Prefix{{Prefix: ula1, Source: "ula"}, gua}
	if p, ok := s.activePrefix(); !ok || p.Prefix != gua.Prefix {
		t.Fatalf("a GUA over a ULA: %v %v", p, ok)
	}
	s.snap.LAN["lan0"] = []Prefix{dep}
	rep := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1(), &dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit}), peerLL)
	if st := rep.Options.IANA()[0].Options.Status(); st == nil || st.StatusCode != iana.StatusNoAddrsAvail {
		t.Fatalf("no active prefix: want NoAddrsAvail, got %v", st)
	}
}

// Messages the server does not act on, and odd contents of those it does.
func TestDHCP6sOddMessages(t *testing.T) {
	s := newTestServer(true)
	if s.unicast(cliMsg(dhcpv6.MessageTypeRequest, iana1())) != nil {
		t.Error("a unicast Request without a Server ID is dropped")
	}
	if s.handle(cliMsg(dhcpv6.MessageTypeReply, dhcpv6.OptServerID(srvDUID)), peerLL) != nil {
		t.Error("a Reply sent to the server is dropped")
	}
	bad := iana1()
	bad.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.IP{1, 2, 3}})
	if st := s.handle(cliMsg(dhcpv6.MessageTypeConfirm, bad), peerLL).Options.Status(); st == nil || st.StatusCode != iana.StatusSuccess {
		t.Errorf("an address that does not parse is skipped in a Confirm: %v", st)
	}
	rel := s.handle(cliMsg(dhcpv6.MessageTypeRelease, dhcpv6.OptServerID(srvDUID), iapd()), peerLL)
	if ias := rel.Options.IAPD(); len(ias) != 1 || ias[0].Options.Status().StatusCode != iana.StatusNoBinding {
		t.Errorf("releasing an IA_PD without a pool answers NoBinding: %v", rel)
	}
}

// A client that accepts Reconfigure but is given nothing to hold gets no key.
func TestDHCP6sNoKeyWithoutBinding(t *testing.T) {
	s := newTestServer(false)
	rep := s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iana1(),
		&dhcpv6.OptionGeneric{OptionCode: optionReconfAccept}), peerLL)
	if rep.Options.GetOne(dhcpv6.OptionAuth) != nil {
		t.Fatal("a stateless server holding no binding hands out no key")
	}
}

// An empty prefix entry is skipped, and a router that moves to another link-local address gets its
// route moved too.
func TestDHCP6sDelegationMoves(t *testing.T) {
	dhcp6sDryRun(t)
	s := newPDServer(false, pdSnap("2001:db8:100::/56"))
	ia := iapd(hint(56))
	ia.Options.Add(&dhcpv6.OptIAPrefix{})
	live, _, _ := granted(t, s.handle(cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), ia), peerLL))
	other := netip.MustParseAddr("fe80::99")
	again, _, _ := granted(t, s.handle(cliMsg(dhcpv6.MessageTypeRenew, dhcpv6.OptServerID(srvDUID), iapd(live[0])), other))
	if len(again) != 1 || again[0] != live[0] {
		t.Fatalf("the prefix stays: %v then %v", live, again)
	}
	if l := s.pd.leases[leaseKey(duidOf(cliDUID), 7)]; l.Peer != other {
		t.Fatalf("the lease follows the router: %+v", l)
	}
}

func TestDHCP6sRoutesOfOtherInterfaces(t *testing.T) {
	dhcp6sDryRun(t)
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no interfaces")
	}
	s := newPDServer(false, pdSnap("2001:db8:100::/56"))
	pf := netip.MustParsePrefix("2001:db8:100:10::/60")
	// a missing interface is skipped, an existing one is used
	s.pdRoute(&PDLease{Prefix: pf, Iface: "nope-dhcp6s0", Peer: peerLL}, true)
	s.pdRoute(&PDLease{Prefix: pf, Iface: ifs[0].Name, Peer: peerLL}, true)

	now := time.Now()
	s.pd.leases["live"] = &PDLease{Prefix: pf, Iface: "lan0", Peer: peerLL, Expires: now.Add(time.Hour)}
	s.pd.leases["gone"] = &PDLease{Prefix: pf, Iface: "lan0", Peer: peerLL, Expires: now.Add(-time.Hour)}
	s.pd.leases["other"] = &PDLease{Prefix: pf, Iface: "lan9", Peer: peerLL, Expires: now.Add(time.Hour)}
	s.restoreRoutes()

	s.pd = nil
	s.restoreRoutes()
	s.dropDelegations(func(*PDLease) bool { return true })
}

func TestDHCP6sAllocateSkipsStaticsAndOldDeclines(t *testing.T) {
	s := newTestServer(true)
	s.poolEnd = s.poolStart // a pool of one
	only := netip.MustParseAddr("2001:db8:1::1000")
	s.statics = []staticBind{{mac: "02:00:00:00:00:99", addr: only}}
	rep := s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1()), peerLL)
	if st := rep.Options.IANA()[0].Options.Status(); st == nil || st.StatusCode != iana.StatusNoAddrsAvail {
		t.Fatalf("another host's static address is not handed out: %v", rep.Options.IANA()[0].Options)
	}
	s.statics = nil
	s.declined = map[netip.Addr]time.Time{only: time.Now().Add(-time.Second)}
	if a, _ := firstAddr(t, s.handle(cliMsg(dhcpv6.MessageTypeSolicit, iana1()), peerLL)); a != only {
		t.Fatalf("a decline that ran out frees the address: %s", a)
	}
	if len(s.declined) != 0 {
		t.Fatalf("the old decline is forgotten: %v", s.declined)
	}
}

func TestDHCP6sMACFromDUID(t *testing.T) {
	m := cliMsg(dhcpv6.MessageTypeSolicit)
	llt := &dhcpv6.DUIDLLT{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}
	if got := macFromDUID(llt, m); got != "02:00:00:00:00:07" {
		t.Errorf("DUID-LLT: %q", got)
	}
	en := &dhcpv6.DUIDEN{EnterpriseNumber: 1, EnterpriseIdentifier: []byte{1}}
	if got := macFromDUID(en, m); got != "" {
		t.Errorf("DUID-EN without the relay's option: %q", got)
	}
	m.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionClientLinkLayerAddr, OptionData: []byte{0, 1, 2, 0, 0, 0, 0, 8}})
	if got := macFromDUID(en, m); got != "02:00:00:00:00:08" {
		t.Errorf("the relay's client link-layer address: %q", got)
	}
	short := cliMsg(dhcpv6.MessageTypeSolicit, &dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionClientLinkLayerAddr, OptionData: []byte{0, 1}})
	if got := macFromDUID(en, short); got != "" {
		t.Errorf("a truncated link-layer address: %q", got)
	}
}

// Leases off the new prefix go when their client cannot be told to renew.
func TestDHCP6sPrefixChangeDropsUnreachableLeases(t *testing.T) {
	s := newTestServer(true)
	on := netip.MustParseAddr("2001:db8:1::1000")
	s.leases["on"] = &Lease{DUID: "aa", Addr: on}
	s.leases["off"] = &Lease{DUID: "bb", Addr: netip.MustParseAddr("2001:db8:9::1000"), ReconfKey: "00"}
	s.onPrefixChange(Snapshot{})
	if len(s.leases) != 1 || s.leases["on"] == nil {
		t.Fatalf("only the lease on the prefix stays: %v", s.leases)
	}
}

func TestDHCP6sBuildReconfigureRefusesBadLeases(t *testing.T) {
	for _, duid := range []string{"zz", "00"} {
		if _, ok := buildReconfigure(srvDUID, &Lease{DUID: duid, ReconfKey: "0011"}, time.Now()); ok {
			t.Errorf("DUID %q: nothing to send", duid)
		}
	}
}

func TestDHCP6sExpireLeases(t *testing.T) {
	dhcp6sDryRun(t)
	s := newPDServer(true, pdSnap("2001:db8:100::/56"))
	s.leaseFile = filepath.Join(t.TempDir(), "leases.json")
	now := time.Now()
	s.leases["old"] = &Lease{DUID: "aa", Addr: netip.MustParseAddr("2001:db8:1::1"), Expires: now.Add(-time.Second)}
	s.leases["new"] = &Lease{DUID: "bb", Addr: netip.MustParseAddr("2001:db8:1::2"), Expires: now.Add(time.Hour)}
	s.pd.leases["old"] = &PDLease{Prefix: netip.MustParsePrefix("2001:db8:100:10::/60"), Iface: "lan0", Expires: now.Add(-time.Second)}
	s.expireLeases()
	if len(s.leases) != 1 || s.leases["new"] == nil || len(s.pd.leases) != 0 {
		t.Fatalf("expired leases and delegations go: %v %v", s.leases, s.pd.leases)
	}
	if _, err := os.Stat(s.leaseFile); err != nil {
		t.Fatalf("the change is saved: %v", err)
	}
	os.Remove(s.leaseFile)
	s.expireLeases()
	if _, err := os.Stat(s.leaseFile); err == nil {
		t.Fatal("nothing changed, nothing saved")
	}
}

func TestDHCP6sLeaseFileErrors(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer(true)
	s.leaseFile = filepath.Join(dir, "missing.json")
	s.loadLeases()
	if len(s.leases) != 0 {
		t.Fatal("no file, no leases")
	}
	s.leaseFile = filepath.Join(dir, "corrupt.json")
	os.WriteFile(s.leaseFile, []byte("{"), 0o600)
	s.loadLeases()
	if len(s.leases) != 0 {
		t.Fatal("a corrupt file is ignored")
	}
	s.leaseFile = filepath.Join(dir, "no-such-dir", "leases.json")
	s.leases["a"] = &Lease{Addr: netip.MustParseAddr("2001:db8:1::2")}
	s.leases["b"] = &Lease{Addr: netip.MustParseAddr("2001:db8:1::1")}
	s.saveLeases()
	if _, err := os.Stat(s.leaseFile); err == nil {
		t.Fatal("a lease file in a missing directory cannot be written")
	}
	if l := s.leaseList(); l[0].Addr != netip.MustParseAddr("2001:db8:1::1") {
		t.Fatalf("leases are listed by address: %v", l)
	}
}

func TestDHCP6sServerDUID(t *testing.T) {
	if d := serverDUID(context.Background(), &dhcpClient{duid: cliDUID}, "", ""); d != cliDUID {
		t.Fatalf("the client's DUID: %v", d)
	}
	// the client's DUID is waited for, until the context ends
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if d := serverDUID(ctx, &dhcpClient{}, "", ""); d != nil {
		t.Fatalf("no DUID yet: %v", d)
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if d := serverDUID(done, nil, t.TempDir(), "nope-dhcp6s0"); d != nil {
		t.Fatalf("no WAN interface: %v", d)
	}

	var up string
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp != 0 {
			up = ifi.Name
			break
		}
	}
	if up == "" {
		t.Skip("no interface is up")
	}
	dir := t.TempDir()
	if d := serverDUID(context.Background(), nil, dir, up); d == nil {
		t.Fatal("a DUID is made and kept for the WAN")
	}
	if _, err := os.Stat(filepath.Join(dir, "duid")); err != nil {
		t.Fatalf("the DUID is saved: %v", err)
	}
	// a state directory that is a file cannot keep it
	if d := serverDUID(context.Background(), nil, filepath.Join(dir, "duid"), up); d != nil {
		t.Fatalf("an unwritable state directory: %v", d)
	}
}
