package main

import (
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
	if s.handle(cliMsg(dhcpv6.MessageTypeSolicit), peerLL) != nil {
		t.Fatal("a SOLICIT without IA_NA gets no answer in stateless mode")
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
