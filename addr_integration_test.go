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

// Without SLAAC or IA_NA the WAN takes /128s in the WAN subnet, with no on-link route.
func TestAddressInWANSubnetAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	fixed, _ := parseIIDPolicy("::1")
	now := time.Now()
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	lan := pd
	lan.Prefix = netip.MustParsePrefix("2001:db8:100::/64")
	snap := Snapshot{WAN: []Prefix{pd}, LAN: map[string][]Prefix{"lan0": {lan}}}
	snap.WANSubnet = snap.wanSubnet([]lanDef{{"lan0", 0}})
	m := &addrManager{
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanStatic, side: sideWAN, layout: "lan",
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, announce: map[netip.Addr]int{},
		snap: snap,
	}
	m.applyPrefixAddrs()
	addr := netip.MustParseAddr("2001:db8:100::1")
	list, err := addrList(ifi.Index)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ia := range list {
		if ia.Addr == addr {
			found = true
			if ia.PrefixLen != 128 {
				t.Fatalf("want /128, got /%d", ia.PrefixLen)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not on the WAN: %v", addr, list)
	}
	if len(routeTypes(t, netip.MustParsePrefix("2001:db8:100::/64"))) != 0 {
		t.Fatal("the WAN subnet brought an on-link route")
	}
}

// A static address added after the temporary ones does not become the source.
func TestAddressTemporaryStaysSourceAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	// no DAD, so that a static address is a usable source at once
	if err := sysctlSet(ifi.Name, "accept_dad", "0"); err != nil {
		t.Fatal(err)
	}
	if err := routeSet(ifi.Index, netip.MustParsePrefix("::/0"), netip.Addr{}, 1024, 0); err != nil {
		t.Fatal(err)
	}
	fixed, _ := parseIIDPolicy("::1")
	m := &addrManager{
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanSLAAC, side: sideWAN, layout: "lan",
		cfg:     tempConfig{enabled: true, preferredLft: time.Hour, maxConcurrent: 8, skipDAD: true},
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, announce: map[netip.Addr]int{},
	}
	now := time.Now()
	ra := func(s string) Prefix {
		return Prefix{Prefix: netip.MustParsePrefix(s), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "ra", SLAAC: true}
	}
	source := func() netip.Addr {
		c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("2001:4860::1"), Port: 53})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	}
	isTemp := func(a netip.Addr) bool {
		t := m.tempOf(a)
		return t != nil && t.state == "preferred"
	}

	m.snap = Snapshot{WAN: []Prefix{ra("2001:db8:1::/64")}}
	m.applyPrefixAddrs()
	m.ensureTemps()
	if a := source(); !isTemp(a) {
		t.Fatalf("source %s is not the temporary address", a)
	}
	// sharing the /64 with the LAN re-adds the static address as /128
	p := ra("2001:db8:1::/64")
	m.snap = Snapshot{WAN: []Prefix{p}, LAN: map[string][]Prefix{"lan0": {p}}}
	m.applyPrefixAddrs()
	m.ensureTemps()
	if a := source(); !isTemp(a) {
		t.Fatalf("after a static address was added the source is %s, not a temporary address", a)
	}
}

// With SLAAC and a delegation, the static address stays in the SLAAC prefix and the temporary
// ones go in the WAN subnet, and are the source.
func TestAddressTemporaryInWANSubnetAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	if err := sysctlSet(ifi.Name, "accept_dad", "0"); err != nil {
		t.Fatal(err)
	}
	if err := routeSet(ifi.Index, netip.MustParsePrefix("::/0"), netip.Addr{}, 1024, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	onLink := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "ra", SLAAC: true}
	pd := Prefix{Prefix: netip.MustParsePrefix("2001:db8:100::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(2 * time.Hour), Source: "pd"}
	lan := pd
	lan.Prefix = netip.MustParsePrefix("2001:db8:100::/64")
	snap := Snapshot{WAN: []Prefix{onLink, pd}, LAN: map[string][]Prefix{"lan0": {lan}}}
	snap.WANSubnet = snap.wanSubnet([]lanDef{{"lan0", 0}})
	fixed, _ := parseIIDPolicy("::1")
	m := &addrManager{
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanStatic, tempPick: Snapshot.wanTemp, side: sideWAN, layout: "lan",
		cfg:     tempConfig{enabled: true, preferredLft: time.Hour, maxConcurrent: 8, skipDAD: true},
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, announce: map[netip.Addr]int{},
		snap: snap,
	}
	m.applyPrefixAddrs()
	m.ensureTemps()
	list, err := addrList(ifi.Index)
	if err != nil {
		t.Fatal(err)
	}
	var temps []netip.Addr
	for _, ia := range list {
		switch {
		case ia.Addr == netip.MustParseAddr("2001:db8:1::1"):
		case onLink.Prefix.Contains(ia.Addr):
			t.Fatalf("%s is a second address in the on-link prefix", ia.Addr)
		case snap.WANSubnet.Prefix.Contains(ia.Addr):
			if ia.PrefixLen != 128 {
				t.Fatalf("%s/%d is not a /128", ia.Addr, ia.PrefixLen)
			}
			temps = append(temps, ia.Addr)
		}
	}
	if len(temps) != 1 {
		t.Fatalf("want one temporary address in %s, got %v", snap.WANSubnet.Prefix, temps)
	}
	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("2001:4860::1"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(); a != temps[0] {
		t.Fatalf("source %s is not the temporary address %s", a, temps[0])
	}
}
