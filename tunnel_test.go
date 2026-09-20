package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

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
