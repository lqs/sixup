//go:build linux && integration

package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// A WAN address goes in as /64 while the RA prefix is the WAN's alone, and has to become /128
// once the LAN shares that /64. The kernel keeps the old length across a replace, so without a
// delete the /64 on-link route stays on the WAN next to the LAN's.
func TestAddressLengthChangeAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	fixed, _ := parseIIDPolicy("::1")
	m := &addrManager{
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanSLAAC, side: sideWAN, layout: "lan",
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, announce: map[netip.Addr]int{},
	}
	now := time.Now()
	onLink := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "ra", SLAAC: true}
	addr := netip.MustParseAddr("2001:db8:1::1")
	plenOf := func() int {
		list, err := addrList(ifi.Index)
		if err != nil {
			t.Fatal(err)
		}
		for _, ia := range list {
			if ia.Addr == addr {
				return ia.PrefixLen
			}
		}
		return 0
	}

	m.snap = Snapshot{WAN: []Prefix{onLink}}
	m.applyPrefixAddrs()
	if got := plenOf(); got != 64 {
		t.Fatalf("not shared yet: want /64, got /%d", got)
	}
	m.snap = Snapshot{WAN: []Prefix{onLink}, LAN: map[string][]Prefix{"lan0": {onLink}}}
	m.applyPrefixAddrs()
	if got := plenOf(); got != 128 {
		t.Fatalf("shared with the LAN: want /128, got /%d", got)
	}
	if len(routeTypes(t, onLink.Prefix)) != 0 {
		t.Fatal("the /64 on-link route is still on the WAN")
	}
	m.snap = Snapshot{}
	m.applyPrefixAddrs()
	if got := plenOf(); got != 0 {
		t.Fatalf("the address outlived its prefix as /%d", got)
	}
}

// An address an earlier run left with the other length is corrected too, although this run has
// not configured it yet.
func TestAddressLengthLeftByEarlierRunAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("2001:db8:1::1")
	if err := addrSet(ifi.Index, addr, 64, time.Hour, time.Hour, false, 0); err != nil {
		t.Fatal(err)
	}
	fixed, _ := parseIIDPolicy("::1")
	now := time.Now()
	onLink := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "ra", SLAAC: true}
	m := &addrManager{
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanSLAAC, side: sideWAN, layout: "lan",
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{addr: 64}, dadCnt: map[iidSlot]uint8{}, announce: map[netip.Addr]int{},
		snap: Snapshot{WAN: []Prefix{onLink}, LAN: map[string][]Prefix{"lan0": {onLink}}},
	}
	m.applyPrefixAddrs()
	list, err := addrList(ifi.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, ia := range list {
		if ia.Addr == addr && ia.PrefixLen != 128 {
			t.Fatalf("want /128, got /%d", ia.PrefixLen)
		}
	}
}
