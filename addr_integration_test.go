//go:build linux && integration

package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// addrDADPair enters a fresh namespace and creates the veth pair dad0 (ours) and dad1 (the rest
// of the link), with DAD quick to wait for: no initial delay, one probe and 300ms for an answer.
// It returns once dad0's link-local address is usable.
func addrDADPair(t *testing.T) (ours, peer *net.Interface) {
	t.Helper()
	enterNetNS(t)
	for path, val := range map[string]string{
		"/proc/sys/net/ipv6/conf/default/router_solicitation_delay": "0",
		"/proc/sys/net/ipv6/conf/default/dad_transmits":             "1",
	} {
		if err := sysctlWrite(path, val); err != nil {
			t.Fatal(err)
		}
	}
	idx, pidx := linkVeth(t, "dad0", "dad1")
	for _, dev := range []string{"dad0", "dad1"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/neigh/"+dev+"/retrans_time_ms", "300"); err != nil {
			t.Fatal(err)
		}
	}
	linkUp(t, idx)
	linkUp(t, pidx)
	netlinkWaitFor(t, "a usable link-local address on dad0", func() bool {
		list, _ := addrList(idx)
		for _, ia := range list {
			if ia.Addr.IsLinkLocalUnicast() && ia.Flags&ifaFTentative == 0 {
				return true
			}
		}
		return false
	})
	ours, err := net.InterfaceByName("dad0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err = net.InterfaceByName("dad1")
	if err != nil {
		t.Fatal(err)
	}
	return ours, peer
}

// addrFlags returns the flags of a on the interface, and whether it is there.
func addrFlags(t *testing.T, index int, a netip.Addr) (uint32, bool) {
	t.Helper()
	list, err := addrList(index)
	if err != nil {
		t.Fatal(err)
	}
	for _, ia := range list {
		if ia.Addr == a {
			return ia.Flags, true
		}
	}
	return 0, false
}

// addrMust configures an address, without DAD unless dad is set.
func addrMust(t *testing.T, index int, a netip.Addr, plen int, dad bool) {
	t.Helper()
	flags := uint32(ifaFNodad)
	if dad {
		flags = 0
	}
	if err := addrSet(index, a, plen, time.Hour, 0, true, flags); err != nil {
		t.Fatalf("adding %s: %v", a, err)
	}
}

// DAD results on a real link: the WAN announces each new address to the routers, a conflicting
// prefix address moves to the next DAD_Counter, a conflicting temporary address is replaced, and
// a conflicting tunnel endpoint is reported.
func TestAddressDADAgainstKernel(t *testing.T) {
	ours, peer := addrDADPair(t)
	p := addrLive("2001:db8:1::/64")
	fixed1, _ := parseIIDPolicy("::1")
	fixed2, _ := parseIIDPolicy("::2")
	m := addrTestManager(sideWAN, p)
	m.ifname, m.ifi = ours.Name, ours
	m.iids = []iidPolicy{fixed1, fixed2}
	m.store = newStore("pd", nil, time.Minute, nil, false, 0, 0, "")
	a1, a2 := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:1::2")
	temp := netip.MustParseAddr("2001:db8:1::7")
	e1 := netip.MustParseAddr("2001:db8:4::e1")
	e2 := netip.MustParseAddr("2001:db8:4::e2")
	w := netip.MustParseAddr("2001:db8:3::5") // the IA_NA address
	foreign := netip.MustParseAddr("2001:db8:2::f")
	flags := func(a netip.Addr) uint32 {
		f, _ := addrFlags(t, ours.Index, a)
		return f
	}

	// A temporary address that fails DAD is replaced by a new one in the same prefix. The kernel
	// deletes a failed address with a finite valid lifetime, so it keeps only a permanent one.
	addrMust(t, peer.Index, temp, 64, false)
	addrMust(t, ours.Index, temp, 64, true)
	m.temps = []*tempAddr{{addr: temp, prefix: p.Prefix, plen: 64, created: time.Now(), state: "preferred"}}
	netlinkWaitFor(t, "the temporary address to fail DAD", func() bool { return flags(temp)&ifaFDadFailed != 0 })
	m.checkDAD()
	if m.tempOf(temp) != nil || len(m.temps) != 1 || m.temps[0].state != "preferred" || !p.Prefix.Contains(m.temps[0].addr) {
		t.Fatalf("the failed temporary address was not replaced: %+v", m.temps)
	}

	// right after they are added the new addresses are still tentative
	addrMust(t, ours.Index, w, 64, false)
	addrMust(t, ours.Index, foreign, 64, true)
	m.snap.WANAddr = w
	endpoints := []netip.Addr{e2, w}
	m.extra = func(Snapshot) []netip.Addr { return endpoints }
	gone := netip.MustParseAddr("2001:db8:9::9")
	m.announce[gone] = 3
	m.applyPrefixAddrs()
	m.applyEndpoints()
	m.watchWANAddr()
	m.checkDAD()
	if !m.dadDue || m.endpoints[e2] != "tentative" || m.announce[a1] != 3 {
		t.Fatalf("tentative addresses are not waited for: dadDue %v endpoints %v announce %v", m.dadDue, m.endpoints, m.announce)
	}
	if m.announce[w] != 2 {
		t.Fatalf("the IA_NA address should have been announced once, %d left", m.announce[w])
	}
	if _, ok := m.announce[gone]; ok {
		t.Fatal("an address no longer on the interface is still to be announced")
	}
	netlinkWaitFor(t, "DAD to pass", func() bool {
		return flags(a1)&ifaFTentative == 0 && flags(a2)&ifaFTentative == 0 && flags(e2)&ifaFTentative == 0
	})

	// a1 and e1 now conflict with the peer, as permanent addresses that stay listed once failed
	addrDel(ours.Index, a1, 64)
	addrMust(t, peer.Index, a1, 64, false)
	addrMust(t, peer.Index, e1, 128, false)
	addrMust(t, ours.Index, a1, 64, true)
	endpoints = []netip.Addr{e1, e2, w}
	m.applyEndpoints()
	netlinkWaitFor(t, "a1 and e1 to fail DAD", func() bool {
		return flags(a1)&ifaFDadFailed != 0 && flags(e1)&ifaFDadFailed != 0
	})
	m.checkDAD()
	if m.dadCnt[iidSlot{p.Prefix, 0}] != 1 {
		t.Fatalf("DAD_Counter %v", m.dadCnt)
	}
	if _, ok := m.applied[a1]; ok {
		t.Fatal("the conflicting address is still applied")
	}
	if _, ok := m.announce[a1]; ok {
		t.Fatal("the conflicting address is still to be announced")
	}
	stable := stableIID(m.secret, p.Prefix, ours.Name, 1)
	if _, ok := m.applied[stable]; !ok {
		t.Fatalf("the next address %s is not applied: %v", stable, m.applied)
	}
	if got := m.store.Current().Self[p.Prefix]; got != stable {
		t.Fatalf("the store is not told of the next address: %v", got)
	}
	if m.endpoints[e1] != "conflict" || m.endpoints[e2] != "ok" || m.endpoints[w] != "external" {
		t.Fatalf("endpoints %v", m.endpoints)
	}
	if _, ok := addrFlags(t, ours.Index, e1); ok {
		t.Fatal("the conflicting endpoint is still configured")
	}
	m.checkDAD()
	if _, ok := m.announce[w]; ok {
		t.Fatalf("the IA_NA address is announced more than three times: %v", m.announce)
	}
}

// announceAddr gives up quietly when it cannot open the socket or build the advertisement.
func TestAddressAnnounceFailsAgainstKernel(t *testing.T) {
	ours, _ := addrDADPair(t)
	a := netip.MustParseAddr("2001:db8:1::1")
	announceAddr(&net.Interface{Index: 9999, Name: "none0"}, a)
	noMAC := *ours
	noMAC.HardwareAddr = nil
	announceAddr(&noMAC, a)
}

// run takes over a recreated interface and serves until cancelled: snapshots, temporary address
// rotation, draining and DAD polling.
func TestAddressRunAgainstKernel(t *testing.T) {
	enterNetNS(t)
	openTun(t, "wan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	ifi, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	left := netip.MustParseAddr("2001:db8:5::1")
	addrMust(t, ifi.Index, left, 64, false)
	p := addrLive("2001:db8:1::/64")
	m := addrTestManager(sideWAN, p)
	m.ifname, m.ifi = ifi.Name, nil
	// the snapshot sent below brings a second prefix for temporary addresses
	q := addrLive("2001:db8:2::/64")
	m.tempPick = func(s Snapshot) []Prefix {
		if s.WANMTU != 0 {
			return []Prefix{p, q}
		}
		return []Prefix{p}
	}
	m.cfg = tempConfig{enabled: true, regenInterval: 10 * time.Millisecond, grace: 5 * time.Millisecond, preferredLft: time.Hour, maxConcurrent: 8}
	store := newStore("pd", nil, time.Minute, nil, false, 0, 0, "")
	hub := &linkHub{subs: map[string][]chan linkEvent{}}
	ch := make(chan Snapshot, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch <- Snapshot{WANMTU: 1500}
		time.Sleep(2200 * time.Millisecond) // past the 1s floor of every timer in serve
		cancel()
	}()
	m.run(ctx, hub, store, ch)
	if m.plens[left] != 64 {
		t.Fatalf("the address an earlier run left is not known: %v", m.plens)
	}
	inQ := 0
	for _, ta := range m.temps {
		if ta.prefix == q.Prefix {
			inQ++
		}
	}
	if inQ < 2 {
		t.Fatalf("no temporary address was added in the new prefix and rotated: %+v", m.temps)
	}
}

// drain keeps a retired address while a socket uses it and reclaims it after two empty checks.
func TestAddressDrainAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	busy, idle, pref := netip.MustParseAddr("2001:db8::b"), netip.MustParseAddr("2001:db8::a1"), netip.MustParseAddr("2001:db8::f")
	for _, a := range []netip.Addr{busy, idle, pref} {
		addrMust(t, lo.Index, a, 128, false)
	}
	netlinkTCPListen(t, unix.AF_INET6, busy)
	m := addrTestManager(sideWAN)
	m.ifname, m.ifi, m.ctAvail = "lo", lo, true
	m.temps = []*tempAddr{
		{addr: pref, plen: 128, state: "preferred"},
		{addr: busy, plen: 128, state: "deprecated"},
		{addr: idle, plen: 128, state: "deprecated"},
	}
	m.drain()
	m.drain()
	if m.tempOf(idle) != nil {
		t.Fatal("the idle address was not reclaimed")
	}
	if _, ok := addrFlags(t, lo.Index, idle); ok {
		t.Fatal("the idle address is still configured")
	}
	if b := m.tempOf(busy); b == nil || b.state != "draining" || b.emptyCnt != 0 {
		t.Fatalf("the busy address: %+v", b)
	}
	if m.tempOf(pref).state != "preferred" {
		t.Fatal("drain touched a preferred address")
	}
}

// An address inside a managed prefix of the WAN left by someone else is deprecated and drained,
// and gives up its prefix route, which the layout may give to the LAN.
func TestAddressAdoptStrayAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	stray := netip.MustParseAddr("2001:db8:1::dead")
	addrMust(t, lo.Index, stray, 64, false)
	m := addrTestManager(sideWAN, addrLive("2001:db8:1::/64"))
	m.ifname, m.ifi = "lo", lo
	m.applyPrefixAddrs()
	tm := m.tempOf(stray)
	if tm == nil || tm.state != "deprecated" || tm.prefix != netip.MustParsePrefix("2001:db8:1::/64") {
		t.Fatalf("the stray address was not adopted: %+v", m.temps)
	}
	list, err := addrList(lo.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, ia := range list {
		if ia.Addr == stray && (ia.Preferred != 0 || ia.Flags&ifaFNoprefixroute == 0) {
			t.Fatalf("the stray address is still preferred for %ds, or keeps its prefix route: %#x", ia.Preferred, ia.Flags)
		}
	}
}

// Failing kernel calls are reported and skipped, without corrupting the manager's state.
func TestAddressKernelErrorsAgainstKernel(t *testing.T) {
	enterNetNS(t)
	p := addrLive("2001:db8:1::/64")
	p.Source = sourceRA
	p.OffLink = true // a /128 on the WAN
	m := addrTestManager(sideWAN, p)
	fixed, _ := parseIIDPolicy("::1")
	m.iids = []iidPolicy{fixed}
	a := netip.MustParseAddr("2001:db8:1::1")
	old := netip.MustParseAddr("2001:db8:1::99")
	m.plens[a] = 64 // went in as /64 with its on-link route
	m.applied[old] = p
	m.applyPrefixAddrs()
	if len(m.applied) != 1 {
		t.Fatalf("applied %v", m.applied)
	}
	m.cfg.maxConcurrent = 1
	if m.rotate() {
		t.Fatal("a temporary address was made on a missing interface")
	}
	ta := &tempAddr{addr: netip.MustParseAddr("2001:db8:1::7"), prefix: p.Prefix, plen: 64, state: "preferred"}
	m.temps = []*tempAddr{ta}
	m.deprecate(ta)
	if ta.state != "preferred" {
		t.Fatal("deprecated although the kernel refused")
	}
	m.remove(ta)
	if len(m.temps) != 0 {
		t.Fatal("remove keeps the address after a failed delete")
	}
	m.extra = func(Snapshot) []netip.Addr { return []netip.Addr{netip.MustParseAddr("2001:db8:4::e1")} }
	m.applyEndpoints()
	if len(m.endpoints) != 0 {
		t.Fatalf("an endpoint the kernel refused is recorded: %v", m.endpoints)
	}
}

// Without sockets the manager keeps its state and degrades: DAD is polled again later, and
// retirement goes on without conntrack.
func TestAddressWithoutFDsAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	p := addrLive("2001:db8:1::/64")
	p.Source, p.OffLink = sourceRA, true // a /128 on the WAN
	m := addrTestManager(sideWAN, p)
	fixed, _ := parseIIDPolicy("::1")
	m.iids = []iidPolicy{fixed}
	m.ifi = &net.Interface{Index: 1, Name: "lo"}
	m.dadDue, m.ctAvail = true, true
	m.plens[netip.MustParseAddr("2001:db8:1::1")] = 64 // went in as /64 with its on-link route
	netlinkWithoutFDs(t, func() {
		m.checkDAD()
		m.applyPrefixAddrs()
		if n := m.inUse(netip.MustParseAddr("2001:db8::1")); n != 0 {
			t.Errorf("inUse = %d", n)
		}
	})
	if len(m.temps) != 0 {
		t.Fatalf("temporary addresses from nowhere: %+v", m.temps)
	}
	if !m.dadDue {
		t.Fatal("a failed DAD poll is not retried")
	}
	if m.ctAvail || !m.ctWarn {
		t.Fatal("conntrack failing does not switch to sock_diag alone")
	}
}

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
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{}, announce: map[netip.Addr]int{},
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
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{addr: 64}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{}, announce: map[netip.Addr]int{},
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
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{}, announce: map[netip.Addr]int{},
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
		ifname: ifi.Name, ifi: ifi, iids: []iidPolicy{fixed}, pick: Snapshot.wanSLAAC, tempPick: Snapshot.wanSLAAC, side: sideWAN, layout: "lan",
		cfg:     tempConfig{enabled: true, preferredLft: time.Hour, maxConcurrent: 8, skipDAD: true},
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{}, announce: map[netip.Addr]int{},
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
		applied: map[netip.Addr]Prefix{}, plens: map[netip.Addr]int{}, dadCnt: map[iidSlot]uint8{}, dadWait: map[netip.Addr]bool{}, announce: map[netip.Addr]int{},
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

// A prefix address goes in with a finite valid lifetime, so when it fails DAD the kernel deletes
// it instead of keeping it with IFA_F_DADFAILED. Its disappearance still has to count as the
// failure: the next DAD_Counter is used instead of the same address over and over.
func TestAddressDADFiniteLifetimeAgainstKernel(t *testing.T) {
	ours, peer := addrDADPair(t)
	p := addrLive("2001:db8:1::/64")
	fixed, _ := parseIIDPolicy("::1")
	m := addrTestManager(sideLAN, p)
	m.ifname, m.ifi = ours.Name, ours
	m.iids = []iidPolicy{fixed}
	a := netip.MustParseAddr("2001:db8:1::1")
	addrMust(t, peer.Index, a, 64, false)

	m.applyPrefixAddrs()
	if _, ok := m.applied[a]; !ok {
		t.Fatalf("%s is not applied: %v", a, m.applied)
	}
	netlinkWaitFor(t, "the kernel to delete the address that failed DAD", func() bool {
		m.checkDAD()
		_, ok := addrFlags(t, ours.Index, a)
		return !ok
	})
	m.checkDAD()
	if m.dadCnt[iidSlot{p.Prefix, 0}] != 1 {
		t.Fatalf("DAD_Counter did not advance after the deleted address: %v, applied %v", m.dadCnt, m.applied)
	}
	if _, ok := m.applied[a]; ok {
		t.Fatal("the conflicting address is still applied")
	}
	next := stableIID(m.secret, p.Prefix, ours.Name, 1)
	if _, ok := m.applied[next]; !ok {
		t.Fatalf("the next address %s is not applied: %v", next, m.applied)
	}
	netlinkWaitFor(t, "the next address to pass DAD", func() bool {
		f, ok := addrFlags(t, ours.Index, next)
		return ok && f&ifaFTentative == 0
	})
	m.checkDAD()
	if m.dadDue || m.dadCnt[iidSlot{p.Prefix, 0}] != 1 {
		t.Fatalf("a passed address is still watched: dadDue %v DAD_Counter %v", m.dadDue, m.dadCnt)
	}
}
