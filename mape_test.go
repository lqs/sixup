package main

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Cross-check against a reference Lua implementation of the same rule tables, pointed at by
// SIXUP_MAPE_LUA; without lua or that script, only check internal consistency.
func TestCalcMAPEAgainstLua(t *testing.T) {
	cases := []string{
		"240b:10:1234:5600::/56",  // JPNE /31 rule
		"240b:253:abcd:ef00::/56", // another JPNE rule
		"2404:7a82:400:1200::/56", // BIGLOBE east /38 rule
		"2404:7a86:800:3400::/56", // BIGLOBE west
		"240d:10:1000:3400::/56",  // NURO
		"2400:4050:400:5600::/56", // OCN /38 x /20, 6-bit PSID
		"2400:4152:9c00:c100::/56",
	}
	lua, luaErr := exec.LookPath("lua")
	script := os.Getenv("SIXUP_MAPE_LUA")
	if script == "" {
		luaErr = errors.New("SIXUP_MAPE_LUA is not set")
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c)
		r, ok := calcMAPE(p)
		if !ok {
			t.Fatalf("%s should resolve to a rule", c)
		}
		if !r.Rule6.Contains(p.Addr()) || !r.Rule4.Contains(r.IPv4) || !p.Contains(r.CE) {
			t.Fatalf("%s result is self-contradictory: %+v", c, r)
		}
		if len(r.Ports) != 1<<uint(r.Offset)-1 {
			t.Fatalf("%s wrong number of port ranges: %d", c, len(r.Ports))
		}
		if luaErr != nil {
			continue
		}
		out, err := exec.Command(lua, script, "calc", p.Addr().String()).Output()
		if err != nil {
			t.Skipf("cannot run Lua cross-check: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) < 12 {
			t.Fatalf("%s unexpected Lua output: %q", c, out)
		}
		want := map[string]string{
			"ipv4": lines[1], "br": lines[2], "rule4": lines[3] + "/" + lines[4],
			"rule6": lines[5] + "/" + lines[6], "ealen": lines[7], "psidlen": lines[8], "offset": lines[9],
			"ce": lines[11],
		}
		got := map[string]string{
			"ipv4": r.IPv4.String(), "br": r.BR.String(), "rule4": r.Rule4.String(),
			"rule6": r.Rule6.String(), "ealen": itoa(int(r.EALen)), "psidlen": itoa(int(r.PSIDLen)), "offset": itoa(int(r.Offset)),
			"ce": r.CE.String(),
		}
		for k := range want {
			if wantV, gotV := normPrefix(want[k]), normPrefix(got[k]); wantV != gotV {
				t.Errorf("%s %s: lua=%s go=%s", c, k, want[k], got[k])
			}
		}
		luaPorts := strings.Fields(lines[10])
		goPorts := 0
		for _, ps := range r.Ports {
			goPorts += int(ps.End-ps.Start) + 1
		}
		if len(luaPorts) != goPorts || luaPorts[0] != itoa(int(r.Ports[0].Start)) {
			t.Errorf("%s ports: lua %d starting at %s, go %d starting at %d", c, len(luaPorts), luaPorts[0], goPorts, r.Ports[0].Start)
		}
	}
	if _, ok := calcMAPE(netip.MustParsePrefix("2001:db8::/56")); ok {
		t.Fatal("non-Japanese IPoE prefix must not match")
	}
	if _, ok := calcMAPE(netip.MustParsePrefix("240b:10::/48")); ok {
		t.Fatal("prefix shorter than /56 carries too little information")
	}
}

func normPrefix(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

func itoa(i int) string { return strconv.Itoa(i) }

// An ISP that really sends option 94 must end up with the same kind of answer as the rule table
// produces, otherwise no tunnel device can be built from it. The numbers are the RFC 7597 Appendix A
// example: rule 2001:db8::/40 to 192.0.2.0/24, EA-len 16, so a /56 delegation carries 8 IPv4 bits
// and an 8-bit PSID.
func TestMAPEFromOption94(t *testing.T) {
	off, plen := uint8(6), uint8(8)
	c := &S46Cont{
		BR: []netip.Addr{netip.MustParseAddr("2001:db8:ffff::1")},
		Rules: []S46Rule{{
			EALen: 16, IPv6Prefix: netip.MustParsePrefix("2001:db8::/40"),
			IPv4Prefix: netip.MustParsePrefix("192.0.2.0/24"), PSIDOffset: &off, PSIDLen: &plen,
		}},
	}
	pd := netip.MustParsePrefix("2001:db8:0034:5600::/56")
	r, ok := mapeFromS46(c, pd)
	if !ok {
		t.Fatal("the rule covers the delegated prefix and should resolve")
	}
	// EA bits are 0x3456: the high 8 are the IPv4 suffix, the low 8 are the PSID
	if r.IPv4 != netip.MustParseAddr("192.0.2.52") {
		t.Fatalf("IPv4 should come from the rule prefix plus the EA bits: %v", r.IPv4)
	}
	if r.PSID != 0x56 {
		t.Fatalf("PSID should be the low EA bits: %#x", r.PSID)
	}
	if want := netip.MustParseAddr("2001:db8:34:5600:0:c000:234:56"); r.CE != want {
		t.Fatalf("CE address should follow RFC 7597 section 6: got %v, want %v", r.CE, want)
	}
	if !pd.Contains(r.CE) || !r.Rule4.Contains(r.IPv4) {
		t.Fatalf("result is self-contradictory: %+v", r)
	}
	if len(r.Ports) != 1<<uint(off)-1 {
		t.Fatalf("wrong number of port ranges: %d", len(r.Ports))
	}

	// A prefix outside the rule has no mapping, and a container without a BR cannot build a tunnel
	if _, ok := mapeFromS46(c, netip.MustParsePrefix("2001:db9::/56")); ok {
		t.Fatal("a prefix outside the rule must not resolve")
	}
	if _, ok := mapeFromS46(&S46Cont{Rules: c.Rules}, pd); ok {
		t.Fatal("without a BR address there is no tunnel remote endpoint")
	}
}
