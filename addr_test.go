package main

import (
	"net/netip"
	"testing"
)

func TestStrayAddrs(t *testing.T) {
	pfx := netip.MustParsePrefix("2001:db8:1::/64")
	managed := []Prefix{{Prefix: pfx}}
	want := map[netip.Addr]Prefix{netip.MustParseAddr("2001:db8:1::1"): {Prefix: pfx}}
	temps := []*tempAddr{{addr: netip.MustParseAddr("2001:db8:1::aa")}}
	endpoints := map[netip.Addr]string{netip.MustParseAddr("2001:db8:1::1111:1111:1111:1111"): "ok"}
	list := []ifAddr{
		{Addr: netip.MustParseAddr("2001:db8:1::1"), PrefixLen: 64},                    // computed this round
		{Addr: netip.MustParseAddr("2001:db8:1::aa"), PrefixLen: 64},                   // already in the temp address table
		{Addr: netip.MustParseAddr("2001:db8:1::1111:1111:1111:1111"), PrefixLen: 128}, // tunnel endpoint
		{Addr: netip.MustParseAddr("2001:db8:1::dead"), PrefixLen: 64},                 // stray, must be taken over
		{Addr: netip.MustParseAddr("2001:db8:2::1"), PrefixLen: 64},                    // outside managed prefixes
		{Addr: netip.MustParseAddr("fe80::1"), PrefixLen: 64},                          // link-local
		{Addr: netip.MustParseAddr("fd00::1"), PrefixLen: 64},                          // different prefix
	}
	got := strayAddrs(list, want, managed, temps, endpoints)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("2001:db8:1::dead") {
		t.Fatalf("only the stray address should be picked, got %+v", got)
	}
}
