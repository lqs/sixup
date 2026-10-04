//go:build linux && integration

package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// raNetns prepares a fresh namespace for Neighbor Discovery: the loopback up, and no DAD, so that
// link-local addresses are usable at once.
func raNetns(t *testing.T) {
	t.Helper()
	loUp(t)
	for _, k := range []string{"all", "default"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/"+k+"/accept_dad", "0"); err != nil {
			t.Fatal(err)
		}
	}
}

// raVethPair creates a veth pair in this namespace, brings both ends up and waits for their
// link-local addresses.
func raVethPair(t *testing.T, name, peer string) (*net.Interface, *net.Interface) {
	t.Helper()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd(name, peer, int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	var out [2]*net.Interface
	linkUp(t, mustIface(t, name))
	linkUp(t, mustIface(t, peer)) // the carrier, and with it the link-local addresses, needs both
	for i, n := range []string{name, peer} {
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			ifi, err := net.InterfaceByName(n)
			if err != nil {
				t.Fatal(err)
			}
			if c, _, err := ndp.Listen(ifi, ndp.LinkLocal); err == nil {
				c.Close()
				out[i] = ifi
				break
			} else if time.Now().After(deadline) {
				t.Fatalf("%s: no link-local address: %v", n, err)
			}
		}
	}
	return out[0], out[1]
}

// raSendRaw sends an ND message out of ifi with any source and hop limit, which a socket would not
// allow, to a multicast destination.
func raSendRaw(t *testing.T, ifi *net.Interface, src, dst netip.Addr, hop byte, m ndp.Message) {
	t.Helper()
	icmp, err := ndp.MarshalMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, 40, 40+len(icmp))
	pkt[0], pkt[6], pkt[7] = 0x60, unix.IPPROTO_ICMPV6, hop
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(icmp)))
	s, d := src.As16(), dst.As16()
	copy(pkt[8:], s[:])
	copy(pkt[24:], d[:])
	pkt = append(pkt, icmp...)
	// the checksum over the pseudo-header and the message
	var sum uint32
	for _, b := range [][]byte{pkt[8:40], {0, 0, byte(len(icmp) >> 8), byte(len(icmp)), 0, 0, 0, unix.IPPROTO_ICMPV6}, icmp} {
		for i := 0; i < len(b); i += 2 {
			sum += uint32(b[i]) << 8
			if i+1 < len(b) {
				sum += uint32(b[i+1])
			}
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(pkt[42:], ^uint16(sum))

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Protocol: nativeEndian.Uint16(binary.BigEndian.AppendUint16(nil, unix.ETH_P_IPV6)), Ifindex: ifi.Index, Halen: 6}
	copy(sa.Addr[:], []byte{0x33, 0x33, d[12], d[13], d[14], d[15]})
	if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
		t.Fatal(err)
	}
}

// raHost listens for Neighbor Discovery on the host end of a pair, with the destination of each
// message reported.
func raHost(t *testing.T, ifi *net.Interface) (*ndp.Conn, netip.Addr) {
	t.Helper()
	c, addr, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetControlMessage(ipv6.FlagDst, true)
	return c, addr
}

// raExpect reads until a message matches, and fails after d.
func raExpect(t *testing.T, c *ndp.Conn, d time.Duration, match func(ndp.Message, *ipv6.ControlMessage) bool) netip.Addr {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	for {
		m, cm, from, err := c.ReadFrom()
		if err != nil {
			t.Fatalf("no matching message: %v", err)
		}
		if cm != nil && match(m, cm) {
			return from
		}
	}
}

// raMulticastRA matches a multicast RA with n PIOs, or with any number for n < 0.
func raMulticastRA(n int) func(ndp.Message, *ipv6.ControlMessage) bool {
	return func(m ndp.Message, cm *ipv6.ControlMessage) bool {
		ra, ok := m.(*ndp.RouterAdvertisement)
		if !ok || !cm.Dst.IsMulticast() {
			return false
		}
		pios := 0
		for _, o := range ra.Options {
			if _, ok := o.(*ndp.PrefixInformation); ok {
				pios++
			}
		}
		return n < 0 || pios == n
	}
}

// An RS from a host with an address is answered by unicast within 0.5 s, the second one of two
// sent a second apart included, which MIN_DELAY_BETWEEN_RAS would hold back for a multicast answer
// (RFC 4861 section 6.2.6, IPv6 Ready CE Router 2.4.17). One from :: is answered by multicast, and
// within 3 s of the last multicast RA only after the rest of them. A new prefix starts a burst,
// another one during it starts it over, and on exit an RA withdraws the router.
func TestRAServerAnswersRSAgainstKernel(t *testing.T) {
	t.Parallel()
	if !ownNetns(t) {
		return
	}
	raNetns(t)
	_, hostA := raVethPair(t, "lan-test0", "host-test0")
	lanB, hostB := raVethPair(t, "lan-test1", "host-test1")
	a, addrA := raHost(t, hostA)
	b, _ := raHost(t, hostB)

	// without a link-local address the socket does not open, and supervise tries again later
	lo, _ := net.InterfaceByName("lo")
	(&raServer{ifname: "lo", ifi: lo}).serve(context.Background(), nil, nil)

	hub := newLinkHub(context.Background())
	run := func(r *raServer) (*Store, context.CancelFunc, chan struct{}) {
		ctx, cancel := context.WithCancel(context.Background())
		st := newStore("pd", []lanDef{{r.ifname, 0}}, time.Minute, nil, false, 0, 0, "")
		ch := st.Subscribe()
		done := make(chan struct{})
		go func() {
			r.run(ctx, hub, st, ch)
			close(done)
		}()
		return st, cancel, done
	}
	stA, cancelA, doneA := run(&raServer{ifname: "lan-test0", minI: 200 * time.Second, maxI: 600 * time.Second, lifetime: ndPreferredLimit})
	_, cancelB, doneB := run(&raServer{ifname: "lan-test1", minI: time.Second, maxI: time.Second, lifetime: ndPreferredLimit})
	defer cancelA()
	defer cancelB()

	// the initial burst; B then goes on every second
	for range 3 {
		raExpect(t, a, 6*time.Second, raMulticastRA(-1))
	}
	for range 4 {
		raExpect(t, b, 3*time.Second, raMulticastRA(-1))
	}
	// B has just sent one, so an RS from :: waits; the exit takes it in the wait
	raSendRaw(t, hostB, netip.IPv6Unspecified(), allRouters2, 255, &ndp.RouterSolicitation{})
	time.Sleep(300 * time.Millisecond)
	cancelB()
	<-doneB

	for i := range 2 {
		if err := a.WriteTo(&ndp.RouterSolicitation{}, nil, allRouters2.WithZone("host-test0")); err != nil {
			t.Fatal(err)
		}
		sent := time.Now()
		raExpect(t, a, time.Second, func(m ndp.Message, cm *ipv6.ControlMessage) bool {
			_, ok := m.(*ndp.RouterAdvertisement)
			return ok && cm.Dst.Equal(addrA.AsSlice())
		})
		if d := time.Since(sent); d > 600*time.Millisecond {
			t.Fatalf("RS %d answered after %s", i+1, d)
		}
		time.Sleep(time.Second)
	}

	// from :: with a link-layer address the RS is invalid; without, it is answered by multicast
	raSendRaw(t, hostA, netip.IPv6Unspecified(), allRouters2, 255, &ndp.RouterSolicitation{Options: []ndp.Option{
		&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: hostA.HardwareAddr}}})
	raSendRaw(t, hostA, netip.IPv6Unspecified(), allRouters2, 255, &ndp.RouterSolicitation{})
	raExpect(t, a, 4*time.Second, raMulticastRA(0))

	now := time.Now()
	pd := func(p string) Prefix {
		return Prefix{Prefix: netip.MustParsePrefix(p), Preferred: now.Add(time.Hour), Valid: now.Add(time.Hour), Source: sourcePD}
	}
	stA.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{pd("2001:db8:1::/56")}})
	raExpect(t, a, 2*time.Second, raMulticastRA(1))
	stA.Set(sourcePD, SourceUpdate{Prefixes: []Prefix{pd("2001:db8:1::/56"), pd("2001:db8:2::/56")}})
	raExpect(t, a, 2*time.Second, raMulticastRA(2))
	cancelA()
	raExpect(t, a, 2*time.Second, func(m ndp.Message, cm *ipv6.ControlMessage) bool {
		ra, ok := m.(*ndp.RouterAdvertisement)
		return ok && ra.RouterLifetime == 0 && raMulticastRA(0)(m, cm)
	})
	<-doneA

	// a PREF64 withdrawal counts down with each multicast RA, and a closed socket sends nothing
	r := &raServer{ifname: "lan-test1", ifi: lanB, maxI: time.Minute, withdraw: nat64WKP, withdrawLeft: 1}
	if err := r.open(); err != nil {
		t.Fatal(err)
	}
	r.send("test")
	if r.withdrawLeft != 0 {
		t.Fatalf("withdrawals left: %d", r.withdrawLeft)
	}
	r.conn.Close()
	r.send("closed")
}

// The WAN side against the kernel: the RS go out 4 s apart, an RA with hop limit 64 is ignored and
// a valid one taken, the prefix is deprecated when its preferred lifetime ends, and the link going
// down ends the default router. A default route set by hand counts as one too.
func TestRAClientAgainstKernel(t *testing.T) {
	t.Parallel()
	if !ownNetns(t) {
		return
	}
	raNetns(t)
	wan, up := raVethPair(t, "wan-test0", "up-test0")
	stable, _ := parseIIDPolicy("stable")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// no link-local address on lo: the error is reported once, and a second round on the same
	// interface keeps the prefixes
	lo, _ := net.InterfaceByName("lo")
	c0 := &raClient{ifname: "lo", store: newStore("ra", nil, time.Minute, nil, false, 0, 0, "")}
	c0.serve(ctx, lo)
	msg := c0.lastOpenErr
	c0.serve(ctx, lo)
	if msg == "" || c0.lastOpenErr != msg {
		t.Fatalf("open errors: %q then %q", msg, c0.lastOpenErr)
	}

	// a default route set otherwise counts as a default router; the neighbour settings of an RA
	// fail for an interface name the kernel does not know
	st1 := newStore("ra", nil, time.Minute, nil, false, 0, 0, "")
	ch1 := st1.Subscribe()
	recv(t, ch1)
	c1 := &raClient{ifname: "nope0", ifi: wan, store: st1, routers: map[netip.Addr]*routerInfo{}}
	c1.publish()
	if s := recv(t, ch1); !s.NoWANRouter {
		t.Fatal("no default route yet")
	}
	gw := netip.MustParseAddr("fe80::99")
	c1.handle(&ndp.RouterAdvertisement{RouterLifetime: time.Minute, ReachableTime: time.Second}, gw)
	r := c1.routers[gw]
	c1.routers = map[netip.Addr]*routerInfo{}
	c1.publish()
	if s := recv(t, ch1); s.NoWANRouter {
		t.Fatal("the default route counts")
	}
	c1.dropDefault(gw, r)
	// and no default route through an interface that does not exist
	(&raClient{ifname: "nope0", ifi: &net.Interface{Index: 1 << 30, Name: "nope0"}, routers: map[netip.Addr]*routerInfo{}}).handle(&ndp.RouterAdvertisement{RouterLifetime: time.Minute}, gw)

	host, hostAddr, err := ndp.Listen(up, ndp.LinkLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if err := host.JoinGroup(allRouters2); err != nil { // where the RS go
		t.Fatal(err)
	}
	st := newStore("ra", []lanDef{{"lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	c := &raClient{ifname: "wan-test0", store: st, slaac: true, iid: stable, secret: []byte("secret")}
	done := make(chan struct{})
	go func() {
		c.run(ctx, newLinkHub(ctx))
		close(done)
	}()
	var first time.Time
	host.SetReadDeadline(time.Now().Add(10 * time.Second))
	for n := 0; n < 3; {
		m, _, _, err := host.ReadFrom()
		if err != nil {
			t.Fatalf("RS %d: %v", n+1, err)
		}
		if _, ok := m.(*ndp.RouterSolicitation); ok {
			if n == 0 {
				first = time.Now()
			}
			n++
		}
	}
	if d := time.Since(first); d < 7*time.Second {
		t.Fatalf("three RS within %s", d)
	}
	// after the third RS has had no answer either, the default route is looked for elsewhere
	time.Sleep(time.Until(first.Add(12*time.Second + 300*time.Millisecond)))

	ignored := netip.MustParsePrefix("2001:db8:0:9::/64")
	raSendRaw(t, up, hostAddr, allNodes, 64, &ndp.RouterAdvertisement{RouterLifetime: 30 * time.Minute, Options: []ndp.Option{
		pio(ignored.String(), time.Hour, time.Hour, true, true)}})
	if err := host.WriteTo(&ndp.RouterAdvertisement{CurrentHopLimit: 64, RouterLifetime: 30 * time.Minute, ReachableTime: 30 * time.Second, Options: []ndp.Option{
		pio("2001:db8:0:1::/64", time.Second, time.Hour, true, true)}}, nil, allNodes); err != nil {
		t.Fatal(err)
	}
	s := recv(t, ch)
	for s.NoWANRouter || len(s.WAN) == 0 {
		s = recv(t, ch)
	}
	if len(s.WAN) != 1 || s.WAN[0].Prefix == ignored || !s.WANAddr.IsValid() {
		t.Fatalf("RA: %+v", s)
	}
	// the preferred lifetime ends, and with it the WAN address
	if s = recv(t, ch); s.WANAddr.IsValid() {
		t.Fatalf("deprecated: %+v", s)
	}
	linkDown(t, wan.Index)
	for s = recv(t, ch); !s.NoWANRouter; s = recv(t, ch) {
	}
	cancel()
	<-done
}
