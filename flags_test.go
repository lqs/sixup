package main

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseLans(t *testing.T) {
	got := parseLans([]string{"eth1", "eth2:5", "eth3"})
	want := []lanDef{{iface: "eth1", index: 0}, {iface: "eth2", index: 5}, {iface: "eth3", index: 2}}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseStatics(t *testing.T) {
	got := parseStatics([]string{"mac=02:00:00:00:00:01, addr=::100", "duid=0001AB,addr=2001:db8::5,note=x"})
	want := []staticBind{
		{mac: "02:00:00:00:00:01", addr: netip.MustParseAddr("::100")},
		{duid: "0001ab", addr: netip.MustParseAddr("2001:db8::5")},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParsePool(t *testing.T) {
	if a, b := parsePool("1000-ffff"); a != 0x1000 || b != 0xffff {
		t.Errorf("got %x-%x", a, b)
	}
}

func TestParsePrefixOrAddr(t *testing.T) {
	for in, want := range map[string]string{"2001:db8::/64": "2001:db8::/64", "2001:db8::1": "2001:db8::1/128"} {
		if got := parsePrefixOrAddr(in); got != netip.MustParsePrefix(want) {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
