package main

import (
	"crypto/hmac"
	"crypto/md5"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

func TestNextRT(t *testing.T) {
	rt := time.Second
	for range 20 {
		rt = nextRT(rt, 30*time.Second)
	}
	if rt < 27*time.Second || rt > 33*time.Second {
		t.Fatalf("RT should converge near MRT: %v", rt)
	}
	j := jitter(time.Second, true)
	if j < time.Second || j > 1100*time.Millisecond {
		t.Fatalf("first SOLICIT allows only positive jitter: %v", j)
	}
}

// Server signs as sendReconfigure does; client verifies with verifyReconfigure.
func TestReconfigureAuth(t *testing.T) {
	key := []byte("0123456789abcdef")
	serverID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{1, 2, 3, 4, 5, 6}}
	clientID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{6, 5, 4, 3, 2, 1}}
	msg, _ := dhcpv6.NewMessage()
	msg.MessageType = dhcpv6.MessageTypeReconfigure
	msg.AddOption(dhcpv6.OptServerID(serverID))
	msg.AddOption(dhcpv6.OptClientID(clientID))
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionReconfMessage, OptionData: []byte{byte(dhcpv6.MessageTypeRenew)}})
	a := make([]byte, 28)
	a[0], a[1], a[11] = 3, 1, 2
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: a})
	raw := msg.ToBytes()
	mac := hmac.New(md5.New, key)
	mac.Write(raw)
	idx := findAuthValue(raw)
	if idx < 0 {
		t.Fatal("AUTH option not found")
	}
	copy(raw[idx:], mac.Sum(nil))
	signed, err := dhcpv6.MessageFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := &dhcpClient{duid: clientID, serverID: serverID, reconfKey: key}
	if !c.verifyReconfigure(signed) {
		t.Fatal("valid Reconfigure failed verification")
	}
	raw[len(raw)-1] ^= 0xff
	tampered, _ := dhcpv6.MessageFromBytes(raw)
	if c.verifyReconfigure(tampered) {
		t.Fatal("tampered Reconfigure must not pass")
	}
	c.reconfKey = nil
	if c.verifyReconfigure(signed) {
		t.Fatal("must not pass without a key")
	}
}

func be32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func TestParseCommon(t *testing.T) {
	c := &dhcpClient{solMaxRT: solParams.mrt, infMaxRT: infParams.mrt}
	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	rep.AddOption(dhcpv6.OptDNS(net.ParseIP("2001:db8::53"), net.ParseIP("2001:db8::54")))
	rep.AddOption(dhcpv6.OptDomainSearchList(&rfc1035label.Labels{Labels: []string{"flets-east.jp"}}))
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionSolMaxRT, OptionData: be32(7200)})
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionInfMaxRT, OptionData: be32(10)}) // below 60 s: ignored
	key := make([]byte, 28)
	key[0], key[11] = 3, 1
	for i := 12; i < 28; i++ {
		key[i] = byte(i)
	}
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: key})
	upd := c.parseCommon(rep)
	if len(upd.DNS) != 2 || upd.DNS[0] != netip.MustParseAddr("2001:db8::53") {
		t.Fatalf("dns: %v", upd.DNS)
	}
	if len(upd.DNSSL) != 1 || upd.DNSSL[0] != "flets-east.jp" {
		t.Fatalf("dnssl: %v", upd.DNSSL)
	}
	if c.solMaxRT != 7200*time.Second {
		t.Fatalf("SOL_MAX_RT not applied: %v", c.solMaxRT)
	}
	if c.infMaxRT != infParams.mrt {
		t.Fatalf("out-of-range INF_MAX_RT must be ignored: %v", c.infMaxRT)
	}
	if len(c.reconfKey) != 16 || c.reconfKey[0] != 12 {
		t.Fatalf("reconfigure key not captured: %x", c.reconfKey)
	}
}

func TestApplyReply(t *testing.T) {
	old := dryRun
	dryRun = true // address configuration goes through stubs
	defer func() { dryRun = old }()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0)
	ch := store.Subscribe()
	recv(t, ch) // initial empty snapshot
	c := &dhcpClient{ifi: &net.Interface{Index: 2}, store: store}

	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	_, pd, _ := net.ParseCIDR("2001:db8:100::/56")
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{1}, T1: 1800 * time.Second, T2: 2880 * time.Second}
	iapd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: pd, PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
	_, gone, _ := net.ParseCIDR("2001:db8:200::/56")
	iapd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: gone, PreferredLifetime: 0, ValidLifetime: 0}) // withdrawn
	rep.AddOption(iapd)
	na := &dhcpv6.OptIANA{IaId: [4]byte{2}}
	na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8::1234"), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
	rep.AddOption(na)
	refused := &dhcpv6.OptIANA{IaId: [4]byte{3}}
	refused.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail})
	rep.AddOption(refused)

	l := c.apply(rep)
	if l == nil {
		t.Fatal("a REPLY with a prefix must produce a binding")
	}
	if len(l.prefixes) != 1 || l.prefixes[0].Prefix != netip.MustParsePrefix("2001:db8:100::/56") {
		t.Fatalf("prefixes: %+v", l.prefixes)
	}
	if len(l.addrs) != 1 || l.addrs[0] != netip.MustParseAddr("2001:db8::1234") {
		t.Fatalf("addrs: %v", l.addrs)
	}
	now := time.Now()
	if d := l.t1.Sub(now); d < 1799*time.Second || d > 1801*time.Second {
		t.Fatalf("T1 from server should be used: %v", d)
	}
	s := recv(t, ch)
	if s.Source != "pd" || len(s.LAN["lan0"]) != 1 || s.LAN["lan0"][0].Prefix != netip.MustParsePrefix("2001:db8:100::/64") || s.WANAddr != l.addrs[0] {
		t.Fatalf("store not updated from REPLY: %+v", s)
	}

	// T1/T2 absent: derive from the shortest preferred lifetime.
	rep2, _ := dhcpv6.NewMessage()
	rep2.MessageType = dhcpv6.MessageTypeReply
	iapd2 := &dhcpv6.OptIAPD{IaId: [4]byte{1}}
	iapd2.Options.Add(&dhcpv6.OptIAPrefix{Prefix: pd, PreferredLifetime: 1000 * time.Second, ValidLifetime: 2000 * time.Second})
	rep2.AddOption(iapd2)
	l2 := c.apply(rep2)
	if d := time.Until(l2.t1); d < 499*time.Second || d > 501*time.Second {
		t.Fatalf("default T1 should be half the preferred lifetime: %v", d)
	}
	if d := time.Until(l2.t2); d < 799*time.Second || d > 801*time.Second {
		t.Fatalf("default T2 should be 0.8 of the preferred lifetime: %v", d)
	}

	// Nothing usable: no binding.
	rep3, _ := dhcpv6.NewMessage()
	rep3.MessageType = dhcpv6.MessageTypeReply
	rep3.AddOption(refused)
	if c.apply(rep3) != nil {
		t.Fatal("a REPLY without prefixes or addresses yields no binding")
	}
}

func TestRefusesEverything(t *testing.T) {
	mk := func(opts ...dhcpv6.Option) *dhcpv6.Message {
		m, _ := dhcpv6.NewMessage()
		for _, o := range opts {
			m.AddOption(o)
		}
		return m
	}
	noPD := &dhcpv6.OptIAPD{IaId: [4]byte{1}}
	noPD.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail})
	okPD := &dhcpv6.OptIAPD{IaId: [4]byte{2}}
	_, pd, _ := net.ParseCIDR("2001:db8::/56")
	okPD.Options.Add(&dhcpv6.OptIAPrefix{Prefix: pd, ValidLifetime: time.Hour})
	noNA := &dhcpv6.OptIANA{IaId: [4]byte{3}}
	noNA.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail})

	if !refusesEverything(mk(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail})) {
		t.Fatal("top-level NoPrefixAvail is a refusal")
	}
	if !refusesEverything(mk(noPD, noNA)) {
		t.Fatal("all IAs refused is a refusal")
	}
	if refusesEverything(mk(noPD, okPD)) {
		t.Fatal("one granted IA means not refused")
	}
	if refusesEverything(mk()) {
		t.Fatal("no IA at all is not a refusal")
	}
}
