package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
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
	sip := net.ParseIP("2001:db8::5060")
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionSIPServersIPv6AddressList, OptionData: sip})
	upd := c.parseCommon(rep)
	if want := []dhcpOption{{dhcpv6.OptionSIPServersIPv6AddressList, sip}}; !slices.EqualFunc(upd.Options, want, dhcpOption.equal) {
		t.Fatalf("options passed on: %v", upd.Options)
	}
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
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
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

// A refused hint is retried once with an empty IA_PD, leaving the length to the server.
func TestPDHintRetry(t *testing.T) {
	c := &dhcpClient{pdLen: 56}
	hint := func() int {
		m, _ := dhcpv6.NewMessage(c.iaOptions(nil)...)
		pds := m.Options.IAPD()
		if len(pds) != 1 {
			t.Fatalf("want one IA_PD, got %d", len(pds))
		}
		ps := pds[0].Options.Prefixes()
		if len(ps) == 0 {
			return 0
		}
		ones, _ := ps[0].Prefix.Mask.Size()
		return ones
	}
	if got := hint(); got != 56 {
		t.Fatalf("first SOLICIT should hint /56, got /%d", got)
	}
	if !c.retryUnhinted() {
		t.Fatal("the first refusal should be retried")
	}
	if got := hint(); got != 0 {
		t.Fatalf("the retry should carry no hint, got /%d", got)
	}
	if c.retryUnhinted() {
		t.Fatal("a refusal without the hint goes to the backoff")
	}
	if (&dhcpClient{}).retryUnhinted() {
		t.Fatal("no PD requested, nothing to retry")
	}
}

// An IA with T1 past T2, and a lease preferred longer than valid, are invalid, and a message that
// does not name a server and this client is not for it (IPv6 Ready CE Router 1.1.18, 1.1.19 and
// 1.2.10).
func TestClientValidation(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	recv(t, store.Subscribe())
	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 9}}
	c := &dhcpClient{ifi: &net.Interface{Index: 2}, store: store, duid: duid}

	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	_, a, _ := net.ParseCIDR("2001:db8:100::/56")
	_, b, _ := net.ParseCIDR("2001:db8:200::/56")
	badT := &dhcpv6.OptIAPD{IaId: [4]byte{1}, T1: 3000 * time.Second, T2: 1000 * time.Second}
	badT.Options.Add(&dhcpv6.OptIAPrefix{Prefix: a, PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour})
	badLife := &dhcpv6.OptIAPD{IaId: [4]byte{2}}
	badLife.Options.Add(&dhcpv6.OptIAPrefix{Prefix: b, PreferredLifetime: 2 * time.Hour, ValidLifetime: time.Hour})
	rep.AddOption(badT)
	rep.AddOption(badLife)
	if l := c.apply(rep); l != nil {
		t.Fatalf("nothing valid to bind: %+v", l)
	}

	if c.forUs(rep) {
		t.Fatal("no Server ID and no Client ID")
	}
	rep.AddOption(dhcpv6.OptServerID(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}))
	rep.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 8}}))
	if c.forUs(rep) {
		t.Fatal("another client's")
	}
	rep.UpdateOption(dhcpv6.OptClientID(duid))
	if !c.forUs(rep) {
		t.Fatal("this client's")
	}
}

// Without a MAC the IAID comes from the name, as in OpenWrt's odhcp6c, so a redial that gives ppp0
// a new index keeps it (RFC 9096 WPD-10).
func TestIAIDWithoutMAC(t *testing.T) {
	a := iaidFor(&net.Interface{Index: 7, Name: "ppp0"})
	b := iaidFor(&net.Interface{Index: 12, Name: "ppp0"})
	if a != b || a != [4]byte{0xe9, 0x93, 0xa0, 0x63} {
		t.Fatalf("got %x and %x", a, b)
	}
	if got := iaidFor(&net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{2, 0, 0x11, 0x22, 0x33, 0x44}}); got != [4]byte{0x11, 0x22, 0x33, 0x44} {
		t.Fatalf("with a MAC: %x", got)
	}
}

// OPTION_PD_EXCLUDE carries the bits after the delegated prefix, left-aligned (RFC 6603 section 4.2).
func TestParsePDExclude(t *testing.T) {
	pd := netip.MustParsePrefix("2001:db8:100::/56")
	// a /64 with subnet ID 0x12: 8 bits after the /56
	if got, ok := parsePDExclude(pd, []byte{64, 0x12}); !ok || got != netip.MustParsePrefix("2001:db8:100:12::/64") {
		t.Fatalf("got %v %v", got, ok)
	}
	// a /60 with subnet ID 0xa: 4 bits, left-aligned in one byte
	if got, ok := parsePDExclude(pd, []byte{60, 0xa0}); !ok || got != netip.MustParsePrefix("2001:db8:100:a0::/60") {
		t.Fatalf("got %v %v", got, ok)
	}
	for _, bad := range [][]byte{{56, 0}, {64}, {129, 0, 0}} {
		if _, ok := parsePDExclude(pd, bad); ok {
			t.Errorf("%x must be refused", bad)
		}
	}
}

// The DUID is made once and kept in the state directory, so the ISP knows the router again after a
// restart (RFC 7084 W-5).
func TestDUIDPersists(t *testing.T) {
	old := dryRun
	dryRun = false
	defer func() { dryRun = old }()
	dir := t.TempDir()
	ifi := &net.Interface{Name: "wan0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}
	a := &dhcpClient{stateDir: dir, ifi: ifi}
	if err := a.loadDUID(); err != nil {
		t.Fatal(err)
	}
	b := &dhcpClient{stateDir: dir, ifi: ifi}
	if err := b.loadDUID(); err != nil {
		t.Fatal(err)
	}
	if a.duid == nil || !a.duid.Equal(b.duid) {
		t.Fatalf("the DUID changed across a restart: %v, %v", a.duid, b.duid)
	}
	if _, err := os.Stat(filepath.Join(dir, "duid")); err != nil {
		t.Fatal(err)
	}
}

// dhcp6cOffline is a client on an interface that does not exist: every send fails, so only what a
// test puts on its channels reaches it.
func dhcp6cOffline(t *testing.T) *dhcpClient {
	t.Helper()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	c := newDHCPClient("dhcp6c-none", store, t.TempDir(), 56, true)
	c.ifi = &net.Interface{Index: 1 << 20, Name: "dhcp6c-none"}
	c.duid = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0x0c}}
	return c
}

// dhcp6cLoopback names the loopback interface, which is up.
func dhcp6cLoopback(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagUp != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface up")
	return ""
}

// dhcp6cCanceled is a context that has already ended.
func dhcp6cCanceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// dhcp6cReconfigure is a Reconfigure from server to client, signed with key as sendReconfigure
// signs it; msgType, if any, is its Reconfigure Message option.
func dhcp6cReconfigure(t *testing.T, key []byte, server, client dhcpv6.DUID, msgType []byte) *dhcpv6.Message {
	t.Helper()
	msg, _ := dhcpv6.NewMessage()
	msg.MessageType = dhcpv6.MessageTypeReconfigure
	msg.AddOption(dhcpv6.OptServerID(server))
	msg.AddOption(dhcpv6.OptClientID(client))
	if msgType != nil {
		msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionReconfMessage, OptionData: msgType})
	}
	a := make([]byte, 28)
	a[0], a[1], a[11] = 3, 1, 2
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: a})
	raw := msg.ToBytes()
	mac := hmac.New(md5.New, key)
	mac.Write(raw)
	copy(raw[findAuthValue(raw):], mac.Sum(nil))
	signed, err := dhcpv6.MessageFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A Reconfigure is acted on only when it comes from the server of the binding, names this client
// and carries the right key (RFC 8415 section 20.4); it asks for the message its option names, a
// Renew without one.
func TestDHCP6cHandleReconfigure(t *testing.T) {
	key := []byte("0123456789abcdef")
	server := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{1, 2, 3, 4, 5, 6}}
	other := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{1, 2, 3, 4, 5, 7}}
	client := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{6, 5, 4, 3, 2, 1}}
	c := &dhcpClient{duid: client, serverID: server, reconfKey: key, reconfig: make(chan dhcpv6.MessageType, 1)}
	none := func() {
		t.Helper()
		select {
		case mt := <-c.reconfig:
			t.Fatalf("unexpected %s", mt)
		default:
		}
	}

	reply, _ := dhcpv6.NewMessage()
	reply.MessageType = dhcpv6.MessageTypeReply
	c.handleUnsolicited(reply)
	none()

	if c.verifyReconfigure(dhcp6cReconfigure(t, key, other, client, nil)) {
		t.Fatal("another server's Reconfigure passed")
	}
	if c.verifyReconfigure(dhcp6cReconfigure(t, key, server, other, nil)) {
		t.Fatal("another client's Reconfigure passed")
	}
	noAuth, _ := dhcpv6.NewMessage()
	noAuth.MessageType = dhcpv6.MessageTypeReconfigure
	noAuth.AddOption(dhcpv6.OptServerID(server))
	noAuth.AddOption(dhcpv6.OptClientID(client))
	if c.verifyReconfigure(noAuth) {
		t.Fatal("a Reconfigure without authentication passed")
	}
	badAuth := make([]byte, 28)
	badAuth[0], badAuth[1], badAuth[11] = 3, 2, 2 // not HMAC-MD5
	noAuth.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAuth, OptionData: badAuth})
	if c.verifyReconfigure(noAuth) {
		t.Fatal("a Reconfigure with another algorithm passed")
	}

	c.handleUnsolicited(dhcp6cReconfigure(t, []byte("fedcba9876543210"), server, client, nil))
	none()

	c.handleUnsolicited(dhcp6cReconfigure(t, key, server, client, []byte{byte(dhcpv6.MessageTypeRebind)}))
	if mt := <-c.reconfig; mt != dhcpv6.MessageTypeRebind {
		t.Fatalf("got %s, want REBIND", mt)
	}
	c.handleUnsolicited(dhcp6cReconfigure(t, key, server, client, nil))
	c.handleUnsolicited(dhcp6cReconfigure(t, key, server, client, nil)) // queue full: dropped
	if mt := <-c.reconfig; mt != dhcpv6.MessageTypeRenew {
		t.Fatalf("got %s, want RENEW", mt)
	}
	none()
}

func TestDHCP6cWalkOptions(t *testing.T) {
	if findAuthValue([]byte{7, 0}) != -1 {
		t.Fatal("a message shorter than its header has no AUTH")
	}
	walkOptionsOffset([]byte{0, 11, 0, 9, 1}, func(code uint16, _, _ int) {
		t.Fatalf("option %d runs past the end", code)
	})
}

// A corrupt state file gets a new DUID; an interface without a MAC gets a random locally
// administered one; a dry run keeps nothing; and an unwritable state directory is an error.
func TestDHCP6cLoadDUID(t *testing.T) {
	old := dryRun
	defer func() { dryRun = old }()
	dryRun = false
	ifi := &net.Interface{Name: "wan0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}

	dir := t.TempDir()
	p := filepath.Join(dir, "duid")
	if err := os.WriteFile(p, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &dhcpClient{stateDir: dir, ifi: ifi}
	if err := c.loadDUID(); err != nil || c.duid == nil {
		t.Fatalf("regenerating: %v %v", c.duid, err)
	}
	if b, _ := os.ReadFile(p); string(b) == "not hex\n" {
		t.Fatal("the corrupt state file was kept")
	}

	dryRun = true
	c = &dhcpClient{stateDir: t.TempDir(), ifi: &net.Interface{Name: "ppp0"}}
	if err := c.loadDUID(); err != nil {
		t.Fatal(err)
	}
	ll, ok := c.duid.(*dhcpv6.DUIDLL)
	if !ok || len(ll.LinkLayerAddr) != 6 || ll.LinkLayerAddr[0]&0x03 != 0x02 {
		t.Fatalf("want a DUID-LL from a random local unicast address, got %v", c.duid)
	}
	if _, err := os.Stat(filepath.Join(c.stateDir, "duid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run wrote the DUID: %v", err)
	}

	dryRun = false
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = &dhcpClient{stateDir: filepath.Join(file, "state"), ifi: ifi}
	if err := c.loadDUID(); err == nil {
		t.Fatal("a state directory under a file must fail")
	}
}

// NTP servers come once each, from either option, and an INF_MAX_RT in range is taken.
func TestDHCP6cParseCommonTimeServers(t *testing.T) {
	c := &dhcpClient{solMaxRT: solParams.mrt, infMaxRT: infParams.mrt}
	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	ntp := net.ParseIP("2001:db8::123")
	rep.AddOption(dhcpv6.OptSNTP(ntp, ntp))
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionInfMaxRT, OptionData: be32(120)})
	upd := c.parseCommon(rep)
	if len(upd.NTP) != 1 || upd.NTP[0] != netip.MustParseAddr("2001:db8::123") {
		t.Fatalf("ntp: %v", upd.NTP)
	}
	if c.infMaxRT != 120*time.Second {
		t.Fatalf("INF_MAX_RT not applied: %v", c.infMaxRT)
	}
}

// What apply skips or derives besides TestApplyReply: refused and malformed IAs, the Prefix
// Exclude option, addresses no longer given, and a T2 below T1.
func TestDHCP6cApplyEdges(t *testing.T) {
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	gone := netip.MustParseAddr("2001:db8::dead")
	c := &dhcpClient{ifi: &net.Interface{Index: 2}, store: store, naAddrs: []netip.Addr{gone}}

	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	refused := &dhcpv6.OptIAPD{IaId: [4]byte{1}}
	refused.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail})
	rep.AddOption(refused)
	pd := &dhcpv6.OptIAPD{IaId: [4]byte{2}, T1: 1000 * time.Second}
	pd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(56, 128)}, PreferredLifetime: time.Hour, ValidLifetime: time.Hour})
	ex := &dhcpv6.OptIAPrefix{Prefix: prefixToIPNet(netip.MustParsePrefix("2001:db8:100::/56")), PreferredLifetime: 1000 * time.Second, ValidLifetime: time.Hour}
	ex.Options.Add(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionPDExclude, OptionData: []byte{64, 0x12}})
	pd.Options.Add(ex)
	rep.AddOption(pd)
	badT := &dhcpv6.OptIANA{IaId: [4]byte{3}, T1: 20 * time.Second, T2: 10 * time.Second}
	badT.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8::1"), PreferredLifetime: time.Hour, ValidLifetime: time.Hour})
	rep.AddOption(badT)
	na := &dhcpv6.OptIANA{IaId: [4]byte{4}}
	na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8::2"), PreferredLifetime: time.Hour}) // valid 0
	na.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8::3"), PreferredLifetime: time.Hour, ValidLifetime: 3 * time.Hour})
	rep.AddOption(na)

	l := c.apply(rep)
	if l == nil || len(l.prefixes) != 1 || len(l.addrs) != 1 || l.addrs[0] != netip.MustParseAddr("2001:db8::3") {
		t.Fatalf("binding: %+v", l)
	}
	if l.prefixes[0].Exclude != netip.MustParsePrefix("2001:db8:100:12::/64") {
		t.Fatalf("Prefix Exclude: %v", l.prefixes[0].Exclude)
	}
	if !l.t2.Equal(l.t1) || time.Until(l.t1) < 999*time.Second {
		t.Fatalf("T2 below T1 must be raised to it: T1 in %s, T2 in %s", time.Until(l.t1), time.Until(l.t2))
	}
	if d := time.Until(l.valid); d < 3*time.Hour-time.Second {
		t.Fatalf("the binding lasts as long as its longest lifetime: %s", d)
	}
	if slices.Contains(c.naAddrs, gone) || len(c.fresh) != 1 {
		t.Fatalf("addresses: %v, fresh %v", c.naAddrs, c.fresh)
	}
}

// A Renew or Rebind names the addresses of the binding.
func TestDHCP6cIAOptionsFromLease(t *testing.T) {
	c := &dhcpClient{pdLen: 56, wantNA: true, iaid: [4]byte{9}}
	a := netip.MustParseAddr("2001:db8::5")
	l := &lease{
		prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: time.Now().Add(time.Hour), Valid: time.Now().Add(time.Hour)}},
		addrs:    []netip.Addr{a},
	}
	m, _ := dhcpv6.NewMessage(c.iaOptions(l)...)
	nas := m.Options.IANA()
	if len(nas) != 1 || len(nas[0].Options.Addresses()) != 1 || !nas[0].Options.Addresses()[0].IPv6Addr.Equal(a.AsSlice()) {
		t.Fatalf("IA_NA: %v", nas)
	}
	if pds := m.Options.IAPD(); len(pds) != 1 || len(pds[0].Options.Prefixes()) != 1 {
		t.Fatalf("IA_PD: %v", pds)
	}
}

// waitBound ends on whatever comes first, and handles messages that come meanwhile.
func TestDHCP6cWaitBound(t *testing.T) {
	c := dhcp6cOffline(t)
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	if got := c.waitBound(dhcp6cCanceled(), later); got != "ctx" {
		t.Fatalf("canceled: %s", got)
	}
	if got := c.waitBound(ctx, time.Now()); got != "t1" {
		t.Fatalf("at T1: %s", got)
	}
	c.Reconfirm("test")
	c.Reconfirm("test again") // one is enough
	if got := c.waitBound(ctx, later); got != "reconfirm" {
		t.Fatalf("reconfirm: %s", got)
	}
	c.reconfig <- dhcpv6.MessageTypeRenew
	if got := c.waitBound(ctx, later); got != "reconf" {
		t.Fatalf("reconfigure: %s", got)
	}
	c.link <- linkEvent{Up: true}
	c.link <- linkEvent{Up: false}
	if got := c.waitBound(ctx, later); got != "down" || c.linkUp {
		t.Fatalf("link down: %s", got)
	}
	reply, _ := dhcpv6.NewMessage()
	reply.MessageType = dhcpv6.MessageTypeReply
	c.recv <- reply
	if got := c.waitBound(ctx, time.Now().Add(20*time.Millisecond)); got != "t1" || len(c.recv) != 0 {
		t.Fatalf("a stray Reply: %s", got)
	}
}

func TestDHCP6cOnExchangeErr(t *testing.T) {
	c := &dhcpClient{}
	for _, err := range []error{context.Canceled, errLinkDown, errTimeout} {
		c.onExchangeErr(err)
	}
}

// Only an O-only line falls back to Information-Request, and only once.
func TestDHCP6cFallbackInfo(t *testing.T) {
	c := &dhcpClient{}
	if c.fallbackInfo() || c.infoOnly {
		t.Fatal("no O-only RA, no fallback")
	}
	c.raOther = true
	if !c.fallbackInfo() || !c.infoOnly {
		t.Fatal("O-only RA: fall back")
	}
	if c.fallbackInfo() {
		t.Fatal("already in Information-Request mode")
	}
}

// The backoff after a refusal starts at 5 minutes and doubles up to an hour.
func TestDHCP6cRefusedWait(t *testing.T) {
	c := dhcp6cOffline(t)
	c.unhinted = true
	ctx := dhcp6cCanceled()
	for _, want := range []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour} {
		c.refusedWait(ctx, "test")
		if c.refuseBackoff != want {
			t.Fatalf("backoff %s, want %s", c.refuseBackoff, want)
		}
	}
	if c.unhinted {
		t.Fatal("after the backoff the hint is tried again")
	}
}

// Nothing is released without a binding or a server, and a Release no server acknowledges keeps
// the addresses.
func TestDHCP6cReleaseUnacknowledged(t *testing.T) {
	c := dhcp6cOffline(t)
	c.release(nil)
	l := &lease{prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:100::/56")}}}
	c.release(l) // no server
	c.serverID = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: []byte{1, 2, 3, 4, 5, 6}}
	a := netip.MustParseAddr("2001:db8::5")
	c.naAddrs = []netip.Addr{a}
	c.link <- linkEvent{Up: false}
	c.release(l)
	if len(c.naAddrs) != 1 {
		t.Fatal("an unacknowledged Release cleared the binding")
	}
}

func TestDHCP6cWaitDone(t *testing.T) {
	c := &dhcpClient{done: make(chan struct{})}
	close(c.done)
	c.WaitDone()
}

// The waits of seconds to hours, on the fake clock of a synctest bubble: the backoff after a
// refusal, the wait for a RELEASE that never finishes, and the retries of a DUID that cannot be
// written yet and of a socket that cannot be opened yet. The store stays outside the bubble,
// whose goroutines must all end.
func TestDHCP6cTimers(t *testing.T) {
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	lo := dhcp6cLoopback(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		c := newDHCPClient("dhcp6c-none", store, t.TempDir(), 56, false)
		start := time.Now()
		c.refusedWait(context.Background(), "test")
		if d := time.Since(start); d != 5*time.Minute {
			t.Fatalf("the first backoff took %s", d)
		}
		start = time.Now()
		c.WaitDone()
		if d := time.Since(start); d != 4*time.Second {
			t.Fatalf("waiting for a client that never finishes took %s", d)
		}

		// the state directory is under a file until that goes
		ctx, cancel := context.WithCancel(context.Background())
		c = newDHCPClient(lo, store, filepath.Join(file, "state"), 56, false)
		go c.run(ctx, true)
		synctest.Wait()
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if _, err := os.Stat(filepath.Join(file, "state")); err != nil {
			t.Fatalf("the DUID is not written once it can be: %v", err)
		}
		cancel()
		<-c.done

		// Linux gives the loopback no link-local address, so the socket is retried until ctx ends
		ctx, cancel = context.WithCancel(context.Background())
		c = newDHCPClient(lo, store, t.TempDir(), 56, false)
		c.linkUp = true
		done := make(chan struct{})
		go func() {
			c.waitLinkUp(ctx)
			close(done)
		}()
		time.Sleep(3 * time.Second)
		cancel()
		<-done
		if c.conn != nil {
			c.conn.Close()
		}
	})
}

// A link that stays down until the binding expires loses it.
func TestDHCP6cRejoinExpires(t *testing.T) {
	c := dhcp6cOffline(t)
	c.linkUp = false
	if l := c.rejoin(context.Background(), &lease{valid: time.Now().Add(30 * time.Millisecond)}); l != nil {
		t.Fatal("the binding outlived its valid lifetime")
	}
}

func TestDHCP6cAwaitDADCanceled(t *testing.T) {
	c := dhcp6cOffline(t)
	if failed := c.awaitDAD(dhcp6cCanceled(), []netip.Addr{netip.MustParseAddr("2001:db8::5")}); failed != nil {
		t.Fatalf("canceled: %v", failed)
	}
}

// waitLinkUp gives up when ctx ends, whether waiting for the link, the interface or the socket.
func TestDHCP6cWaitLinkUpCanceled(t *testing.T) {
	ctx := dhcp6cCanceled()
	c := dhcp6cOffline(t)
	c.linkUp = false
	c.waitLinkUp(ctx)
	c.cycle(ctx) // ends right after waitLinkUp

	c.linkUp = true
	c.waitLinkUp(ctx) // the interface is missing

	// Linux gives the loopback no link-local address, so the socket cannot be opened
	c.ifname = dhcp6cLoopback(t)
	c.waitLinkUp(ctx)
	if c.conn != nil {
		c.conn.Close()
	}
}

// exchange's retransmission and its ways out, with sends that fail and answers put straight into
// the client's queue from build, which alone sees the transaction ID.
func TestDHCP6cExchange(t *testing.T) {
	ctx := context.Background()
	msg := func(mt dhcpv6.MessageType, tid dhcpv6.TransactionID) *dhcpv6.Message {
		m, _ := dhcpv6.NewMessage()
		m.MessageType = mt
		m.TransactionID = tid
		return m
	}
	build := func(sent *int, answer func(int, dhcpv6.TransactionID)) func(time.Duration, dhcpv6.TransactionID) *dhcpv6.Message {
		return func(_ time.Duration, tid dhcpv6.TransactionID) *dhcpv6.Message {
			if answer != nil {
				answer(*sent, tid)
			}
			*sent++
			return msg(dhcpv6.MessageTypeRequest, tid)
		}
	}
	isReply := func(m *dhcpv6.Message) (bool, bool) {
		ok := m.MessageType == dhcpv6.MessageTypeReply
		return ok, ok
	}

	c := dhcp6cOffline(t)
	var sent int
	if err := c.exchange(dhcp6cCanceled(), dhcpv6.MessageTypeSolicit, solParams, build(&sent, nil), isReply); !errors.Is(err, context.Canceled) || sent != 0 {
		t.Fatalf("canceled before the first Solicit: %v, %d sent", err, sent)
	}

	if err := c.exchange(ctx, dhcpv6.MessageTypeRequest, retransParams{irt: 5 * time.Millisecond, mrc: 2}, build(&sent, nil), isReply); !errors.Is(err, errTimeout) || sent != 2 {
		t.Fatalf("MRC 2: %v, %d sent", err, sent)
	}

	sent = 0
	if err := c.exchange(ctx, dhcpv6.MessageTypeRequest, retransParams{irt: time.Hour, mrd: time.Nanosecond}, build(&sent, nil), isReply); !errors.Is(err, errTimeout) || sent != 1 {
		t.Fatalf("MRD past at once: %v, %d sent", err, sent)
	}

	sent = 0
	if err := c.exchange(ctx, dhcpv6.MessageTypeRequest, retransParams{irt: time.Hour, mrd: 20 * time.Millisecond}, build(&sent, nil), isReply); !errors.Is(err, errTimeout) || sent != 1 {
		t.Fatalf("MRD: %v, %d sent", err, sent)
	}

	c.link <- linkEvent{Up: true}
	c.link <- linkEvent{Up: false}
	if err := c.exchange(ctx, dhcpv6.MessageTypeRequest, reqParams, build(&sent, nil), isReply); !errors.Is(err, errLinkDown) || c.linkUp {
		t.Fatalf("link down: %v", err)
	}

	// another transaction's message, one of this transaction's that accept refuses, and the Reply
	sent = 0
	err := c.exchange(ctx, dhcpv6.MessageTypeRequest, reqParams, build(&sent, func(_ int, tid dhcpv6.TransactionID) {
		other := tid
		other[0]++
		c.recv <- msg(dhcpv6.MessageTypeReply, other)
		c.recv <- msg(dhcpv6.MessageTypeAdvertise, tid)
		c.recv <- msg(dhcpv6.MessageTypeReply, tid)
	}), isReply)
	if err != nil || sent != 1 || len(c.recv) != 0 {
		t.Fatalf("Reply: %v, %d sent", err, sent)
	}

	// a message matched but not done ends the exchange when the RT runs out
	sent = 0
	err = c.exchange(ctx, dhcpv6.MessageTypeRequest, retransParams{irt: 5 * time.Millisecond}, build(&sent, func(_ int, tid dhcpv6.TransactionID) {
		c.recv <- msg(dhcpv6.MessageTypeAdvertise, tid)
	}), func(*dhcpv6.Message) (bool, bool) { return true, false })
	if err != nil || sent != 1 {
		t.Fatalf("matched: %v, %d sent", err, sent)
	}

	// past the first RT, the first Advertise ends a Solicit at once
	sent = 0
	err = c.exchange(ctx, dhcpv6.MessageTypeSolicit, retransParams{irt: 5 * time.Millisecond}, build(&sent, func(n int, tid dhcpv6.TransactionID) {
		if n == 1 {
			c.recv <- msg(dhcpv6.MessageTypeAdvertise, tid)
		}
	}), func(*dhcpv6.Message) (bool, bool) { return true, false })
	if err != nil || sent != 2 {
		t.Fatalf("second Solicit: %v, %d sent", err, sent)
	}
}

// send reports a socket it cannot open, and drops one it cannot write to.
func TestDHCP6cSendFails(t *testing.T) {
	c := dhcp6cOffline(t)
	m, _ := dhcpv6.NewMessage()
	if err := c.send(m); err == nil {
		t.Fatal("no link-local address, no socket")
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	c.conn = conn
	if err := c.send(m); err == nil || c.conn != nil {
		t.Fatalf("a closed socket: %v, %v", err, c.conn)
	}
}

// The reader skips what does not parse, dumps the rest when debugging, and reports the link down
// when its socket fails.
func TestDHCP6cReader(t *testing.T) {
	old := logLevel.Level()
	setDebug()
	defer logLevel.Set(old)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := &dhcpClient{conn: conn, recv: make(chan *dhcpv6.Message, 1), link: make(chan linkEvent, 1)}
	go c.reader(conn)

	out, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	rep, _ := dhcpv6.NewMessage()
	rep.MessageType = dhcpv6.MessageTypeReply
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAFTRName, OptionData: []byte("\x04aftr\x07example\x00")})
	rep.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionS46ContMapE})
	for _, b := range [][]byte{{0xff}, rep.ToBytes()} {
		if _, err := out.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case m := <-c.recv:
		if m.MessageType != dhcpv6.MessageTypeReply {
			t.Fatalf("got %s", m.MessageType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the Reply never came")
	}
	conn.Close()
	select {
	case ev := <-c.link:
		if ev.Up {
			t.Fatal("want link down")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a failed socket must report the link down")
	}
}

// run gives up when ctx ends before the interface or the DUID is there, or before the RA; and
// starts on the M and O flags of the RA.
func TestDHCP6cRun(t *testing.T) {
	old := dryRun
	dryRun = false
	defer func() { dryRun = old }()
	lo := dhcp6cLoopback(t)
	ctx := dhcp6cCanceled()
	store := newStore("pd", []lanDef{{"lan0", 0}}, time.Second, nil, false, 0, 0, "")
	finished := func(c *dhcpClient) {
		t.Helper()
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
			t.Fatal("run did not return")
		}
	}

	c := newDHCPClient("dhcp6c-none", store, t.TempDir(), 56, false)
	c.run(ctx, false)
	finished(c)

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = newDHCPClient(lo, store, filepath.Join(file, "state"), 56, false)
	c.run(ctx, false)
	finished(c)

	c = newDHCPClient(lo, store, t.TempDir(), 56, false)
	c.run(ctx, true)
	finished(c)

	for _, f := range []raFlags{{managed: true}, {other: true}, {}} {
		ctx, cancel := context.WithCancel(context.Background())
		c := newDHCPClient(lo, store, t.TempDir(), 56, false)
		c.linkUp = false // the cycle waits for the link, so the test sees only the start
		c.start <- f
		go c.run(ctx, true)
		for deadline := time.Now().Add(2 * time.Second); len(c.start) > 0; {
			if time.Now().After(deadline) {
				t.Fatal("the RA flags were never taken")
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		finished(c)
		if c.raOther != (f.other && !f.managed) {
			t.Fatalf("%+v: raOther %v", f, c.raOther)
		}
	}
}
