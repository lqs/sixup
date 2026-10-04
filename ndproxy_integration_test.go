//go:build linux && integration

package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// snmOf is the solicited-node group of a.
func snmOf(a netip.Addr) netip.Addr {
	snm, _ := ndp.SolicitedNodeMulticast(a)
	return snm
}

// ndproxyNS sends an NS for target from c to the target's solicited-node group, as a host
// resolving it does.
func ndproxyNS(t *testing.T, c *ndp.Conn, ifi *net.Interface, target netip.Addr, cm *ipv6.ControlMessage) {
	t.Helper()
	ns := &ndp.NeighborSolicitation{TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: ifi.HardwareAddr}}}
	if err := c.WriteTo(ns, cm, snmOf(target)); err != nil {
		t.Fatal(err)
	}
}

// ndproxyNA sends an NA for target from c to dst.
func ndproxyNA(t *testing.T, c *ndp.Conn, ifi *net.Interface, target, dst netip.Addr) {
	t.Helper()
	na := &ndp.NeighborAdvertisement{Solicited: true, Override: true, TargetAddress: target, Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: ifi.HardwareAddr}}}
	if err := c.WriteTo(na, nil, dst); err != nil {
		t.Fatal(err)
	}
}

// ndproxyFor matches an NS or NA for target.
func ndproxyFor[T *ndp.NeighborSolicitation | *ndp.NeighborAdvertisement](target netip.Addr) func(ndp.Message, *ipv6.ControlMessage) bool {
	return func(m ndp.Message, _ *ipv6.ControlMessage) bool {
		switch m := m.(type) {
		case *ndp.NeighborSolicitation:
			_, want := any(m).(T)
			return want && m.TargetAddress == target
		case *ndp.NeighborAdvertisement:
			_, want := any(m).(T)
			return want && m.TargetAddress == target
		}
		return false
	}
}

// ndproxyStart creates the WAN pair wan-ndp0/up-ndp0 and the LAN pair lan-ndp0/dn-ndp0, and runs
// a proxy on them whose LAN holds 2001:db8:1::/64; it returns once the proxy's sockets are open.
func ndproxyStart(t *testing.T, ctx context.Context, n *ndProxy) (wan, up, lan, dn *net.Interface, done <-chan struct{}) {
	t.Helper()
	wan, up = raVethPair(t, "wan-ndp0", "up-ndp0")
	lan, dn = raVethPair(t, "lan-ndp0", "dn-ndp0")
	st := newStore("pd", []lanDef{{"lan-ndp0", 0}}, time.Minute, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	now := time.Now()
	st.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:1::/56"), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}}})
	recv(t, ch)
	n.wanIf, n.lanIf = "wan-ndp0", "lan-ndp0"
	n.wanPkts = newPacketHub(ctx, "wan-ndp0")
	c := make(chan struct{})
	go func() {
		n.run(ctx, newLinkHub(ctx), st, st.Subscribe())
		close(c)
	}()
	time.Sleep(300 * time.Millisecond)
	return wan, up, lan, dn, c
}

// The proxy in forward mode against the kernel. The upstream's NS for a LAN host goes to the
// host's solicited-node group, which nothing on the router joins; it is heard all the same, probed
// on the LAN, and the host's NA adds its /128 route and is answered for on the WAN, also to a
// device checking the address before taking it. A LAN host's NS for a host on the WAN is heard and
// answered the same way. Packets with a hop limit other than 255 are ignored; a socket that cannot
// open ends the round.
func TestNDProxyAgainstKernel(t *testing.T) {
	t.Parallel()
	if !ownNetns(t) {
		return
	}
	raNetns(t)
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &ndProxy{mode: proxyForward, ttl: 2 * time.Second, layout: "wan"}
	pctx, pcancel := context.WithCancel(ctx)
	start := time.Now()
	wan, up, _, dn, done := ndproxyStart(t, pctx, n)

	// lo has no link-local address, so neither side opens on it
	lo, _ := net.InterfaceByName("lo")
	(&ndProxy{mode: proxyForward, wanIf: "lo", wanIfi: lo, ttl: time.Second}).serve(ctx, nil)
	(&ndProxy{mode: proxyForward, wanIf: "wan-ndp0", wanIfi: wan, lanIf: "lo", lanIfi: lo, ttl: time.Second}).serve(ctx, nil)
	// a kernel proxy entry on an interface that does not exist fails
	(&ndProxy{wanIf: "nope0", wanIfi: &net.Interface{Index: 1 << 30, Name: "nope0"}, static: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}}).applyStatic()
	// the LAN interface never comes, and run ends with its context
	wctx, wcancel := context.WithCancel(ctx)
	wdone := make(chan struct{})
	go func() {
		(&ndProxy{wanIf: "wan-ndp0", lanIf: "missing0", ttl: time.Second}).run(wctx, newLinkHub(ctx), nil, nil)
		close(wdone)
	}()
	time.Sleep(100 * time.Millisecond)
	wcancel()
	<-wdone

	upC, upLL := raHost(t, up)
	dnC, dnLL := raHost(t, dn)
	host, far := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::40")
	// each host listens to its own group, where the probes for it go
	if err := dnC.JoinGroup(snmOf(host)); err != nil {
		t.Fatal(err)
	}
	if err := upC.JoinGroup(snmOf(far)); err != nil {
		t.Fatal(err)
	}

	// hop limit 64: ignored
	early := netip.MustParseAddr("2001:db8:1::30")
	ndproxyNS(t, upC, up, early, &ipv6.ControlMessage{HopLimit: 64})
	raSendRaw(t, dn, dnLL, allNodes, 64, &ndp.NeighborAdvertisement{TargetAddress: early})

	ndproxyNS(t, upC, up, host, nil)
	proxyLL := raExpect(t, dnC, 2*time.Second, ndproxyFor[*ndp.NeighborSolicitation](host))
	ndproxyNA(t, dnC, dn, host, proxyLL)
	raExpect(t, upC, 2*time.Second, ndproxyFor[*ndp.NeighborAdvertisement](host))
	if !slices.Contains(routeTypes(t, netip.PrefixFrom(host, 128)), unix.RTN_UNICAST) {
		t.Fatal("no /128 route to the LAN host")
	}
	// a device on the WAN checking the LAN host's address before taking it is told to all nodes
	raSendRaw(t, up, netip.IPv6Unspecified(), snmOf(host), 255, &ndp.NeighborSolicitation{TargetAddress: host})
	raExpect(t, upC, 2*time.Second, func(m ndp.Message, cm *ipv6.ControlMessage) bool {
		return ndproxyFor[*ndp.NeighborAdvertisement](host)(m, cm) && cm.Dst.Equal(net.IPv6linklocalallnodes)
	})

	// the LAN asks for a host on the WAN
	ndproxyNS(t, dnC, dn, far, nil)
	wanLL := raExpect(t, upC, 2*time.Second, ndproxyFor[*ndp.NeighborSolicitation](far))
	ndproxyNA(t, upC, up, far, wanLL)
	raExpect(t, dnC, 2*time.Second, ndproxyFor[*ndp.NeighborAdvertisement](far))

	n.mu.Lock()
	earlySession := n.sessions[early]
	n.mu.Unlock()
	if earlySession != nil {
		t.Fatalf("hop limit 64: %+v", earlySession)
	}

	time.Sleep(time.Until(start.Add(1200 * time.Millisecond))) // a sweep
	pcancel()
	<-done
	// the sockets are closed now: nothing goes out, and an IPv4 target has no group to go to
	n.probe(sideWAN, netip.MustParseAddr("192.0.2.1"))
	n.probe(sideWAN, host)
	n.reply(sideWAN, host, upLL)
}

// The router's own packets that come back over a link, as a Wi-Fi access point reflects a
// station's multicast, are told apart although the kernel hands their source over with the
// interface as its zone. The kernel itself drops a frame from an address of the interface it
// arrives on, so these carry the router's address on the other side, which it may pick as the
// source when no address of the outgoing interface fits better. The router's NS starts a probe and
// joins no list, on the side probed it is not probed again, and its NA is not taken for a
// neighbour's.
func TestNDProxyIgnoresOwnPackets(t *testing.T) {
	t.Parallel()
	if !ownNetns(t) {
		return
	}
	raNetns(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &ndProxy{mode: proxyForward, ttl: time.Minute, layout: "wan"}
	wan, up, lan, dn, _ := ndproxyStart(t, ctx, n)
	dnC, _ := raHost(t, dn)
	wanAddr, lanAddr := netip.MustParseAddr("2001:db8:1::2"), netip.MustParseAddr("2001:db8:1::1")
	for ifi, a := range map[*net.Interface]netip.Addr{wan: wanAddr, lan: lanAddr} {
		if err := addrSet(ifi.Index, a, 128, time.Hour, time.Hour, false, ifaFNodad); err != nil {
			t.Fatal(err)
		}
	}
	n.mu.Lock()
	n.refreshSelfAddrs()
	n.mu.Unlock()
	host, own := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::20")
	if err := dnC.JoinGroup(snmOf(own)); err != nil { // where the probe for own goes
		t.Fatal(err)
	}
	ns := &ndp.NeighborSolicitation{TargetAddress: own}
	na := func(target netip.Addr) *ndp.NeighborAdvertisement {
		return &ndp.NeighborAdvertisement{Override: true, TargetAddress: target}
	}

	ndproxyNA(t, dnC, dn, host, allNodes) // the LAN host announces itself
	raSendRaw(t, up, lanAddr, allNodes, 255, ns)
	raExpect(t, dnC, 2*time.Second, ndproxyFor[*ndp.NeighborSolicitation](own))
	raSendRaw(t, dn, wanAddr, allNodes, 255, ns)
	raSendRaw(t, dn, wanAddr, allNodes, 255, na(own))
	raSendRaw(t, up, lanAddr, allNodes, 255, na(host))
	time.Sleep(200 * time.Millisecond)
	n.mu.Lock()
	s, hs := n.sessions[own], n.sessions[host]
	pending := len(n.pending[own])
	n.mu.Unlock()
	if s == nil || s.State != "probing" || pending != 0 {
		t.Fatalf("own packets: %+v, %d askers", s, pending)
	}
	if hs == nil || hs.Side != sideLAN {
		t.Fatalf("the router's own NA moved the LAN host: %+v", hs)
	}
}

// prefix mode answers the upstream's NS for any address in the LAN prefix, sent to that
// address's solicited-node group, without probing the LAN.
func TestNDProxyPrefixModeAgainstKernel(t *testing.T) {
	t.Parallel()
	if !ownNetns(t) {
		return
	}
	raNetns(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &ndProxy{mode: proxyPrefix, ttl: time.Minute, layout: "lan"}
	_, up, _, dn, _ := ndproxyStart(t, ctx, n)
	upC, _ := raHost(t, up)
	dnC, _ := raHost(t, dn)
	host := netip.MustParseAddr("2001:db8:1::10")
	if err := dnC.JoinGroup(snmOf(host)); err != nil {
		t.Fatal(err)
	}

	ndproxyNS(t, upC, up, host, nil)
	raExpect(t, upC, 2*time.Second, ndproxyFor[*ndp.NeighborAdvertisement](host))
	// nothing is probed on the LAN
	dnC.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		m, _, _, err := dnC.ReadFrom()
		if err != nil {
			break
		}
		if ns, ok := m.(*ndp.NeighborSolicitation); ok && ns.TargetAddress == host {
			t.Fatal("prefix mode probed the LAN")
		}
	}
}
