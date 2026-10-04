package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

func tlv(code uint16, v []byte) []byte {
	b := make([]byte, 4+len(v))
	binary.BigEndian.PutUint16(b, code)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	copy(b[4:], v)
	return b
}

// Build a transix-style MAP-E container: one rule, port params and a BR.
func sampleMAPE() []byte {
	rule := []byte{0x01, 16, 16, 203, 0, 0, 0, 40}
	rule = append(rule, []byte{0x24, 0x04, 0x92, 0x00, 0x00}...) // 2404:9200::/40
	rule = append(rule, tlv(93, []byte{6, 8, 0x12, 0x00})...)    // offset 6, psid-len 8, psid 0x12
	br := netip.MustParseAddr("2404:9200::8").As16()
	return append(tlv(89, rule), tlv(90, br[:])...)
}

func TestParseS46MAPE(t *testing.T) {
	c, err := parseS46Cont(sampleMAPE())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 1 || len(c.BR) != 1 {
		t.Fatalf("%+v", c)
	}
	r := c.Rules[0]
	if !r.FMR || r.EALen != 16 || r.IPv4Prefix != netip.MustParsePrefix("203.0.0.0/16") || r.IPv6Prefix != netip.MustParsePrefix("2404:9200::/40") {
		t.Fatalf("%+v", r)
	}
	if r.PSIDOffset == nil || *r.PSIDOffset != 6 || *r.PSIDLen != 8 || *r.PSID != 0x12 {
		t.Fatalf("port params: %+v", r)
	}
	if c.BR[0] != netip.MustParseAddr("2404:9200::8") {
		t.Fatal(c.BR)
	}
	env := s46Env(c)
	if env != "ealen=16,prefix4len=16,ipv4prefix=203.0.0.0,prefix6len=40,ipv6prefix=2404:9200::,fmr=1,offset=6,psidlen=8,psid=18,br=2404:9200::8" {
		t.Fatal(env)
	}
}

func TestParseFQDN(t *testing.T) {
	name, err := parseFQDN([]byte{2, 'g', 'w', 7, 't', 'r', 'a', 'n', 's', 'i', 'x', 2, 'j', 'p', 0})
	if err != nil || name != "gw.transix.jp" {
		t.Fatal(name, err)
	}
	if _, err := parseFQDN([]byte{9, 'a'}); err == nil {
		t.Fatal("out-of-range length must fail")
	}
}

func TestParseTunnelIsolatesErrors(t *testing.T) {
	msg, _ := dhcpv6.NewMessage()
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAFTRName, OptionData: []byte{9, 'a'}})
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionS46ContMapE, OptionData: sampleMAPE()})
	tp := parseTunnel(msg)
	if tp == nil || tp.MAPE == nil || tp.Errors["64"] == "" {
		t.Fatalf("%+v", tp)
	}
}

func FuzzParseS46Cont(f *testing.F) {
	f.Add(sampleMAPE())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		parseS46Cont(b)
	})
}

func FuzzParseFQDN(f *testing.F) {
	f.Add([]byte{2, 'j', 'p', 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		parseFQDN(b)
	})
}

func FuzzDHCPv6Message(f *testing.F) {
	f.Add(sampleMAPE())
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, err := dhcpv6.MessageFromBytes(b)
		if err != nil {
			return
		}
		parseTunnel(msg)
		findAuthValue(msg.ToBytes())
	})
}

func TestTunnelMTU(t *testing.T) {
	for _, tc := range []struct{ override, ifMTU, pathMTU, want int }{
		{0, 1500, 0, 1460},       // no upstream MTU option: interface MTU less the IPv6 header
		{0, 1500, 1492, 1452},    // PPPoE path MTU wins because it is smaller
		{0, 1492, 1500, 1452},    // a larger path MTU never raises it above the interface
		{1400, 1500, 1492, 1400}, // -tunnel-mtu overrides everything
		{0, 1280, 0, 1240},       // never below the IPv6 minimum less the header
		{0, 600, 0, 1240},
	} {
		if got := tunnelMTU(tc.override, tc.ifMTU, tc.pathMTU); got != tc.want {
			t.Errorf("tunnelMTU(%d,%d,%d) = %d, want %d", tc.override, tc.ifMTU, tc.pathMTU, got, tc.want)
		}
	}
}

// dry-run has to show the exact device it would build, including the case where -tunnel-dev is absent.
func TestPlanTunnel(t *testing.T) {
	tp := &TunnelParams{Captured: &tunnelGuess{
		Type:   "4in6",
		Local:  netip.MustParseAddr("2400:2410::8"),
		Remote: netip.MustParseAddr("2400:2000::8"),
		IPv4:   netip.MustParseAddr("126.0.0.8"),
	}}
	tp.resolve(netip.Addr{})
	s := Snapshot{Tunnel: tp, WANMTU: 1500}

	p, ok := planTunnel(s, "ipip6-wan", "eth0", 0, 1500, 4096)
	if !ok || p.Dev != "ipip6-wan" || p.Kind != "4in6" || p.Source != "capture" || p.MTU != 1460 || p.Note != "" {
		t.Fatalf("%+v", p)
	}
	if len(p.Commands) != 4 || !strings.Contains(p.Commands[0], "mode ipip6 local 2400:2410::8") {
		t.Fatalf("commands: %v", p.Commands)
	}
	if !strings.Contains(p.Commands[2], "126.0.0.8/32") {
		t.Fatalf("the public IPv4 should be assigned: %v", p.Commands)
	}
	if p.Route4Metric != 4096 || !strings.Contains(p.Commands[3], "ip route add default dev ipip6-wan metric 4096") {
		t.Fatalf("the IPv4 default route should be planned: %+v", p)
	}
	if noRoute, _ := planTunnel(s, "ipip6-wan", "eth0", 0, 1500, 0); noRoute.Route4Metric != 0 || len(noRoute.Commands) != 3 {
		t.Fatalf("metric 0 adds no route: %+v", noRoute)
	}

	// Without -tunnel-dev the plan still shows, under a placeholder name, and says nothing is created.
	p, _ = planTunnel(s, "", "eth0", 0, 1500, 4096)
	if p.Dev == "" || !strings.Contains(p.Note, "-tunnel-dev") {
		t.Fatalf("%+v", p)
	}

	// A DAD conflict on the local endpoint defers creation, and the plan says so.
	s.Tunnel.Conflicts = []netip.Addr{s.Tunnel.Local}
	if p, _ = planTunnel(s, "ipip6-wan", "eth0", 0, 1500, 4096); !strings.Contains(p.Note, "DAD") {
		t.Fatalf("%+v", p)
	}

	if _, ok := planTunnel(Snapshot{}, "ipip6-wan", "eth0", 0, 1500, 4096); ok {
		t.Fatal("no tunnel, no plan")
	}
}

// The public IPv4 must not be configured twice on this host, so a duplicate anywhere else is found.
func TestAddr4Holder(t *testing.T) {
	lo := ""
	ifis, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagLoopback != 0 {
			lo = ifi.Name
		}
	}
	if lo == "" {
		t.Skip("no loopback interface")
	}
	if got := addr4Holder("sixup-ipv4", netip.MustParseAddr("127.0.0.1")); got != lo {
		t.Fatalf("127.0.0.1 sits on %s, got %q", lo, got)
	}
	// The device being configured is not its own duplicate.
	if got := addr4Holder(lo, netip.MustParseAddr("127.0.0.1")); got != "" {
		t.Fatalf("the device itself should not count: %q", got)
	}
	if got := addr4Holder("sixup-ipv4", netip.MustParseAddr("192.0.2.1")); got != "" {
		t.Fatalf("no interface has that address, got %q", got)
	}
}

// tunnelLW4o6 is a Lightweight 4over6 container: a binding with port parameters and a BR.
func tunnelLW4o6() []byte {
	bind := []byte{192, 0, 2, 1, 56, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00} // 2001:db8:1::/56
	bind = append(bind, tlv(94, []byte{1})...)                                 // not port parameters
	bind = append(bind, tlv(93, []byte{1, 2, 3})...)                           // too short to be
	bind = append(bind, tlv(93, []byte{6, 8, 0x34, 0x00})...)
	br := netip.MustParseAddr("2001:db8::8").As16()
	return append(tlv(92, bind), tlv(90, br[:])...)
}

// Each container is kept, and each one that fails is reported under its option number.
func TestParseTunnelContainers(t *testing.T) {
	msg, _ := dhcpv6.NewMessage()
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionAFTRName, OptionData: []byte{4, 'a', 'f', 't', 'r', 0}})
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionS46ContMapE, OptionData: sampleMAPE()})
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionS46ContMapT, OptionData: sampleMAPE()})
	msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionS46ContLW, OptionData: tunnelLW4o6()})
	tp := parseTunnel(msg)
	if tp == nil || tp.AFTRName != "aftr" || tp.MAPE == nil || tp.MAPT == nil || tp.LW4o6 == nil || tp.Errors != nil || tp.RawMAPT == "" || tp.RawLW4o6 == "" {
		t.Fatalf("%+v", tp)
	}
	b := tp.LW4o6.Bind
	if b == nil || b.IPv4Addr != netip.MustParseAddr("192.0.2.1") || b.IPv6Prefix != netip.MustParsePrefix("2001:db8:1::/56") || *b.PSID != 0x34 || *b.PSIDLen != 8 || *b.PSIDOffset != 6 {
		t.Fatalf("%+v", b)
	}
	if !tp.hasDelivered() {
		t.Fatal("DHCPv6 delivered a tunnel")
	}

	msg, _ = dhcpv6.NewMessage()
	for _, code := range []dhcpv6.OptionCode{dhcpv6.OptionS46ContMapE, dhcpv6.OptionS46ContMapT, dhcpv6.OptionS46ContLW} {
		msg.AddOption(&dhcpv6.OptionGeneric{OptionCode: code, OptionData: []byte{0, 90, 0}})
	}
	if tp := parseTunnel(msg); tp == nil || len(tp.Errors) != 3 || tp.MAPE != nil || tp.MAPT != nil || tp.LW4o6 != nil {
		t.Fatalf("%+v", tp)
	}

	msg, _ = dhcpv6.NewMessage()
	if tp := parseTunnel(msg); tp != nil {
		t.Fatalf("no tunnel options, no parameters: %+v", tp)
	}
}

// Lengths come off the wire, so every one of them is checked.
func TestParseS46Malformed(t *testing.T) {
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00} // the first 40 bits of 2001:db8::
	rule := func(tail ...byte) []byte {
		return tlv(89, append([]byte{0, 16, 24, 192, 0, 2, 0, 40}, tail...))
	}
	for name, b := range map[string][]byte{
		"too large":              make([]byte, 4097),
		"truncated header":       {0, 90, 0},
		"length out of bounds":   {0, 90, 0, 20, 1, 2},
		"short rule":             tlv(89, []byte{1, 2, 3}),
		"IPv4 prefix over 32":    tlv(89, []byte{0, 16, 33, 192, 0, 2, 0, 40, 0x20, 0x01, 0x0d, 0xb8, 0x00}),
		"IPv6 prefix cut short":  rule(0x20),
		"IPv6 prefix over 128":   tlv(89, append([]byte{0, 16, 24, 192, 0, 2, 0, 200}, make([]byte, 25)...)),
		"short port params":      rule(append(append(append([]byte{}, v6...), tlv(1, nil)...), tlv(93, []byte{1, 2, 3})...)...),
		"BR length":              tlv(90, []byte{192, 0, 2, 1}),
		"empty DMR":              tlv(91, nil),
		"long DMR":               tlv(91, make([]byte, 18)),
		"DMR over 128":           tlv(91, []byte{200, 0x20}),
		"short bind":             tlv(92, []byte{1, 2, 3}),
		"bind prefix cut short":  tlv(92, []byte{192, 0, 2, 1, 56, 0x20}),
		"bind prefix over 128":   tlv(92, append([]byte{192, 0, 2, 1, 200}, make([]byte, 25)...)),
		"bind options cut short": tlv(92, []byte{192, 0, 2, 1, 0, 0, 93}),
	} {
		if c, err := parseS46Cont(b); err == nil {
			t.Errorf("%s: parsed as %+v", name, c)
		}
	}

	// Port parameters with a PSID length of 0, a DMR and an unknown sub-option are all fine.
	c, err := parseS46Cont(slices.Concat(rule(append(append([]byte{}, v6...), tlv(93, []byte{0, 0, 0, 0})...)...),
		tlv(91, []byte{64, 0x20, 0x01, 0x0d, 0xb8, 0, 0xff, 0, 0}), tlv(95, []byte{1})))
	if err != nil || len(c.Rules) != 1 || *c.Rules[0].PSID != 0 || c.Rules[0].FMR || *c.DMR != netip.MustParsePrefix("2001:db8:ff::/64") {
		t.Fatalf("%+v %v", c, err)
	}

	if _, err := parseFQDN(make([]byte, 256)); err == nil {
		t.Fatal("a name over 255 bytes must fail")
	}
	if _, err := parseFQDN([]byte{0}); err == nil {
		t.Fatal("the root alone is no AFTR name")
	}
}

// The odhcp6c-style variables carry a DMR and a lw4o6 binding, and leave out what is unknown.
func TestS46Env(t *testing.T) {
	dmr := netip.MustParsePrefix("2001:db8:ff::/64")
	c, err := parseS46Cont(tunnelLW4o6())
	if err != nil {
		t.Fatal(err)
	}
	c.DMR = &dmr
	c.Rules = []S46Rule{{IPv4Prefix: netip.MustParsePrefix("192.0.2.0/24"), IPv6Prefix: netip.MustParsePrefix("2001:db8::/32")}}
	want := "ealen=0,prefix4len=24,ipv4prefix=192.0.2.0,prefix6len=32,ipv6prefix=2001:db8::,br=2001:db8::8,dmr=2001:db8:ff::/64" +
		" ipv4addr=192.0.2.1,prefix6len=56,ipv6prefix=2001:db8:1::,offset=6,psidlen=8,psid=52,br=2001:db8::8"
	if got := s46Env(c); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	bare := &S46Cont{Bind: &S46Bind{IPv4Addr: c.Bind.IPv4Addr, IPv6Prefix: c.Bind.IPv6Prefix}}
	if got := s46Env(bare); got != "ipv4addr=192.0.2.1,prefix6len=56,ipv6prefix=2001:db8:1::" {
		t.Fatal(got)
	}
}

// Only the CE address the rule table computed has to be configured on the WAN.
func TestTunnelEndpoints(t *testing.T) {
	if e := (&TunnelParams{Captured: &tunnelGuess{Local: netip.MustParseAddr("2001:db8::1")}}).endpoints(); e != nil {
		t.Fatalf("a captured local endpoint is already ours: %v", e)
	}
	ce := netip.MustParseAddr("2001:db8::c0a8:1:1234:0")
	if e := (&TunnelParams{RuleMAPE: &mapeResult{CE: ce}}).endpoints(); len(e) != 1 || e[0] != ce {
		t.Fatal(e)
	}
}

// No name means no lookup, and a lookup that cannot finish returns nothing, a link-local server
// included.
func TestResolveAFTRFails(t *testing.T) {
	if got := resolveAFTR(context.Background(), "", nil, "lo"); got != nil {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := resolveAFTR(ctx, "aftr.example", []netip.Addr{netip.MustParseAddr("fe80::53")}, "lo"); got != nil {
		t.Fatal(got)
	}
}

// tunnelAFTRSend hands the resolver a snapshot while draining what it stores meanwhile.
func tunnelAFTRSend(ch chan<- Snapshot, st *Store, s Snapshot) {
	for {
		select {
		case ch <- s:
			return
		case <-st.aftrIn:
		}
	}
}

// A name that does not resolve is retried; a new name is looked up at once and stored with its
// addresses, after which nothing is retried.
func TestAFTRResolverRetries(t *testing.T) {
	r := &aftrResolver{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.run(ctx, nil)
	if r.retry != 30*time.Second {
		t.Fatalf("default retry %s", r.retry)
	}

	st := &Store{aftrIn: make(chan aftrUpdate)}
	r = &aftrResolver{store: st, retry: 10 * time.Millisecond}
	ctx, cancel = context.WithCancel(context.Background())
	ch := make(chan Snapshot)
	done := make(chan struct{})
	go func() { r.run(ctx, ch); close(done) }()
	bad := Snapshot{Tunnel: &TunnelParams{AFTRName: "bad!name.invalid"}}
	tunnelAFTRSend(ch, st, Snapshot{})
	tunnelAFTRSend(ch, st, bad)
	for range 2 { // the first lookup and a retry
		if u := <-st.aftrIn; u.name != "bad!name.invalid" || u.addrs != nil {
			t.Fatalf("%+v", u)
		}
	}
	tunnelAFTRSend(ch, st, bad) // the same name again starts nothing new
	tunnelAFTRSend(ch, st, Snapshot{Tunnel: &TunnelParams{AFTRName: "localhost"}})
	for deadline := time.Now().Add(5 * time.Second); ; {
		u := <-st.aftrIn
		if u.name == "localhost" && slices.ContainsFunc(u.addrs, netip.Addr.IsLoopback) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("localhost never resolved: %+v", u)
		}
	}
	cancel()
	<-done
}
