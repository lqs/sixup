//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ip6 builds an IPv6 packet carrying an L4 header and payload in l4, the checksum of UDP, TCP or ICMPv6 filled in.
func ip6(src, dst netip.Addr, proto byte, l4 []byte) []byte {
	p := make([]byte, 40, 40+len(l4))
	p[0], p[6], p[7] = 0x60, proto, 64
	binary.BigEndian.PutUint16(p[4:], uint16(len(l4)))
	s, d := src.As16(), dst.As16()
	copy(p[8:], s[:])
	copy(p[24:], d[:])
	p = append(p, l4...)
	sumAt, ok := map[byte]int{unix.IPPROTO_UDP: 6, unix.IPPROTO_TCP: 16, unix.IPPROTO_ICMPV6: 2}[proto]
	if !ok {
		return p
	}
	pseudo := append(append(append([]byte{}, s[:]...), d[:]...), 0, 0, byte(len(l4)>>8), byte(len(l4)), 0, 0, 0, proto)
	binary.BigEndian.PutUint16(p[40+sumAt:], ^checksum(append(pseudo, p[40:]...)))
	return p
}

func udp6(from, to netip.AddrPort) []byte {
	u := make([]byte, 12)
	binary.BigEndian.PutUint16(u[0:], from.Port())
	binary.BigEndian.PutUint16(u[2:], to.Port())
	binary.BigEndian.PutUint16(u[4:], 12)
	copy(u[8:], "ping")
	return ip6(from.Addr(), to.Addr(), unix.IPPROTO_UDP, u)
}

func syn6(from, to netip.AddrPort) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], from.Port())
	binary.BigEndian.PutUint16(tcp[2:], to.Port())
	tcp[12], tcp[13] = 5<<4, 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	return ip6(from.Addr(), to.Addr(), unix.IPPROTO_TCP, tcp)
}

// ah6 puts an AH between the IPv6 header of pkt and its payload.
func ah6(pkt []byte) []byte {
	ah := make([]byte, 24) // 12 fixed bytes and a 12-byte ICV
	ah[0], ah[1] = pkt[6], 24/4-2
	binary.BigEndian.PutUint32(ah[4:], 0x100) // SPI
	p := append(append(append([]byte{}, pkt[:40]...), ah...), pkt[40:]...)
	p[6] = unix.IPPROTO_AH
	binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	return p
}

func echo6(from, to netip.Addr) []byte {
	return ip6(from, to, unix.IPPROTO_ICMPV6, []byte{128, 0, 0, 0, 0, 1, 0, 1})
}

// passes sends pkt in through in and reports whether it came out of out towards its destination.
func passes(t *testing.T, in, out *os.File, pkt []byte) bool {
	t.Helper()
	return forwarded(t, in, out, pkt, netip.AddrFrom16([16]byte(pkt[24:40])))
}

// forwarded sends pkt in through in and reports whether it came out of out towards to, where
// destination NAT may have sent it.
func forwarded(t *testing.T, in, out *os.File, pkt []byte, to netip.Addr) bool {
	t.Helper()
	if _, err := in.Write(pkt); err != nil {
		t.Fatalf("inject: %v", err)
	}
	dst := to.As16()
	out.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		n, err := out.Read(buf)
		if err != nil {
			return false
		}
		// the kernel's own traffic on the device aside, such as MLD reports
		if n >= 40 && buf[0]>>4 == 6 && string(buf[24:40]) == string(dst[:]) && buf[6] == pkt[6] {
			return true
		}
	}
}

// The filter drops what the Internet starts, except for flows the LAN started, endpoints that
// recently sent out, what PCP opened, downstream delegations, and what RFC 6092 says has to pass.
func TestFirewallAgainstKernel(t *testing.T) {
	enterNetNS(t)
	host := netip.MustParseAddr("2001:db8:1::10")
	far, other := netip.MustParseAddr("2001:db8:f::1"), netip.MustParseAddr("2001:db8:f::2")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/56"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, inbound: true, source: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()

	if passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(host, 5000))) {
		t.Fatal("unsolicited UDP from the WAN must be dropped")
	}
	if !passes(t, lanDev, wanDev, udp6(netip.AddrPortFrom(host, 5000), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("the LAN sends out freely")
	}
	if !passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(other, 9999), netip.AddrPortFrom(host, 5000))) {
		t.Fatal("an endpoint that sent out is reachable by anyone for a while (endpoint-independent filtering)")
	}
	if passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(other, 9999), netip.AddrPortFrom(host, 5001))) {
		t.Fatal("only that endpoint, not the host's other ports")
	}

	syn := syn6(netip.AddrPortFrom(far, 40000), netip.AddrPortFrom(host, 8080))
	if passes(t, wanDev, lanDev, syn) {
		t.Fatal("an unsolicited SYN must be dropped")
	}
	f.replace(f.holes, pinholeElements([]portMapping{{proto: unix.IPPROTO_TCP, internal: netip.AddrPortFrom(host, 8080), external: 8080}}))
	if !passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40001), netip.AddrPortFrom(host, 8080))) {
		t.Fatal("a port PCP opened lets the SYN through")
	}
	f.replace(f.holes, nil)
	if passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40002), netip.AddrPortFrom(host, 8080))) {
		t.Fatal("a closed pinhole drops again")
	}

	if !passes(t, wanDev, lanDev, echo6(far, host)) {
		t.Fatal("echo request is let through (RFC 4890)")
	}

	// RFC 6092 REC-21, REC-22, REC-24 and REC-26
	if !passes(t, wanDev, lanDev, ah6(udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(host, 6000)))) {
		t.Fatal("AH is let through")
	}
	if !passes(t, wanDev, lanDev, ip6(far, host, unix.IPPROTO_ESP, []byte{0, 0, 1, 0, 0, 0, 0, 1})) {
		t.Fatal("ESP is let through")
	}
	if !passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(far, 500), netip.AddrPortFrom(host, 500))) {
		t.Fatal("IKE is let through")
	}
	if !passes(t, wanDev, lanDev, ip6(far, host, ipprotoHIP, []byte{59, 0, 0, 0, 0, 0, 0, 0})) {
		t.Fatal("HIP is let through")
	}

	// A downstream router's delegation is left to that router
	behind := netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1:12::5"), 80)
	if passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40003), behind)) {
		t.Fatal("undelegated, the SYN is dropped")
	}
	f.delegs = []netip.Prefix{netip.MustParsePrefix("2001:db8:1:10::/60"), netip.MustParsePrefix("2001:db8:1:20::/60")}
	f.replace(f.deleg, delegationElements(f.delegs))
	f.applyOurs()
	if !passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40004), behind)) {
		t.Fatal("a SYN into a delegation is let through")
	}
	for _, a := range []string{"2001:db8:1::10", "2001:db8:1:30::1", "2001:db8:1:f::1"} {
		if passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40005), netip.AddrPortFrom(netip.MustParseAddr(a), 80))) {
			t.Fatalf("%s is outside the delegations", a)
		}
	}
	if !passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 40006), netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1:2f:ffff:ffff:ffff:ffff"), 80))) {
		t.Fatal("the last address of a delegation is inside it")
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"forward", "wan_in"} {
		rules, err := c.GetRules(f.table(), &nftables.Chain{Name: chain})
		if err != nil {
			t.Fatal(err)
		}
		countedAndCommented(t, rules)
	}
}

// unreachable reports whether dev put out an ICMPv6 Destination Unreachable of the code to addr.
func unreachable(t *testing.T, dev *os.File, to netip.Addr, code byte) bool {
	t.Helper()
	dev.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	want := to.As16()
	for {
		n, err := dev.Read(buf)
		if err != nil {
			return false
		}
		if n >= 48 && buf[6] == unix.IPPROTO_ICMPV6 && string(buf[24:40]) == string(want[:]) && buf[40] == 1 && buf[41] == code {
			return true
		}
	}
}

// The border of RFC 7084 holds in every mode, -unsolicited allow included.
func TestFirewallBorderAgainstKernel(t *testing.T) {
	enterNetNS(t)
	host, stray := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1:99::1")
	far := netip.MustParseAddr("2001:db8:f::1")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/56"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, source: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)

	out := udp6(netip.AddrPortFrom(host, 5000), netip.AddrPortFrom(far, 4000))
	if passes(t, lanDev, wanDev, out) {
		t.Fatal("nothing is forwarded before the line hands out a prefix (G-3)")
	}
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()
	if !passes(t, lanDev, wanDev, out) {
		t.Fatal("the LAN sends out from its prefix")
	}
	if !passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(host, 5001))) {
		t.Fatal("allow lets unsolicited traffic in")
	}
	if passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(stray, 5000))) {
		t.Fatal("the WAN reaches only the LAN prefixes")
	}
	if passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::99"), 4000), netip.AddrPortFrom(host, 5001))) {
		t.Fatal("a source in the LAN prefixes arriving from the WAN is spoofed (REC-6)")
	}
	// On a /64 shared with the WAN link, hosts on the WAN side are in it too (RFC 7278)
	f.replace(f.shared, delegationElements([]netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}))
	if !passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::99"), 4000), netip.AddrPortFrom(host, 5002))) {
		t.Fatal("a host on the WAN side of a shared /64 reaches the LAN")
	}
	if _, err := lanDev.Write(udp6(netip.AddrPortFrom(stray, 5000), netip.AddrPortFrom(far, 4000))); err != nil {
		t.Fatal(err)
	}
	if !unreachable(t, lanDev, stray, 5) {
		t.Fatal("a source outside the LAN prefixes is refused with code 5 (S-2, L-14)")
	}
	ula := netip.MustParseAddr("fd00:1::10")
	lanIf, err := net.InterfaceByName("lan-test0")
	if err != nil {
		t.Fatal(err)
	}
	if err := routeSet(lanIf.Index, netip.MustParsePrefix("fd00:1::/64"), netip.Addr{}, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := lanDev.Write(udp6(netip.AddrPortFrom(ula, 5000), netip.AddrPortFrom(far, 4000))); err != nil {
		t.Fatal(err)
	}
	if !unreachable(t, lanDev, ula, 1) {
		t.Fatal("nothing from a ULA of another site leaves by the WAN, and its sender is told (ULA-4)")
	}
	// A ULA the upstream advertises, shared with the LAN, is of the same site (RFC 4193 section 4.3)
	up := netip.MustParsePrefix("fd00:1::/64")
	f.lan = append(f.lan, up)
	f.applyOurs()
	f.replace(f.upULA, delegationElements([]netip.Prefix{up}))
	if !passes(t, lanDev, wanDev, udp6(netip.AddrPortFrom(ula, 5001), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("the upstream's ULA crosses the WAN")
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := c.GetRules(f.table(), &nftables.Chain{Name: "forward"})
	if err != nil {
		t.Fatal(err)
	}
	countedAndCommented(t, rules)
}

// An interface sixup does not serve, such as a container bridge, sends out what the operator's
// source NAT translated, and nothing else, and is reached through the operator's destination NAT;
// the router's own traffic is not looked at.
func TestFirewallOtherInterfaceAgainstKernel(t *testing.T) {
	enterNetNS(t)
	far := netip.MustParseAddr("2001:db8:f::1")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/64"))
	dockDev := openTun(t, "dock-test0", netip.MustParsePrefix("fd00:2::/64"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, inbound: true, source: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()

	container := netip.MustParseAddr("fd00:2::10")
	if passes(t, dockDev, wanDev, udp6(netip.AddrPortFrom(container, 5000), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("a ULA leaves untranslated (ULA-4)")
	}
	if passes(t, dockDev, wanDev, udp6(netip.AddrPortFrom(netip.MustParseAddr("fd00:2::11"), 5000), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("a source outside our prefixes leaves untranslated (S-2)")
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "operator-nat"})
	post := c.AddChain(&nftables.Chain{Name: "post", Table: tbl, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
	to := netip.MustParseAddr("2001:db8:f::99").As16()
	c.AddRule(&nftables.Rule{Table: tbl, Chain: post, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("wan-test0")},
		&expr.Immediate{Register: 1, Data: to[:]},
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: 1},
	}})
	// A published port: what comes for the address to goes to the container
	pre := c.AddChain(&nftables.Chain{Name: "pre", Table: tbl, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	ctr := container.As16()
	c.AddRule(&nftables.Rule{Table: tbl, Chain: pre, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: to[:]},
		&expr.Immediate{Register: 1, Data: ctr[:]},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: 1},
	}})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.DelTable(tbl)
		c.Flush()
	})
	if !passes(t, dockDev, wanDev, udp6(netip.AddrPortFrom(container, 5001), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("what the operator's NAT translated goes out")
	}
	if !forwarded(t, wanDev, dockDev, udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(netip.AddrFrom16(to), 5001)), container) {
		t.Fatal("the reply to what the operator's source NAT translated reaches the container")
	}
	if !forwarded(t, wanDev, dockDev, udp6(netip.AddrPortFrom(far, 4001), netip.AddrPortFrom(netip.AddrFrom16(to), 80)), container) {
		t.Fatal("what the operator's destination NAT forwards in reaches the container")
	}
	if passes(t, wanDev, dockDev, udp6(netip.AddrPortFrom(far, 4002), netip.AddrPortFrom(container, 80))) {
		t.Fatal("the container's ULA is not reachable without the NAT (ULA-4)")
	}

	// The router's own address in a ULA, outside our prefixes
	own := netip.MustParseAddr("fd00:2::1")
	dockIf, err := net.InterfaceByName("dock-test0")
	if err != nil {
		t.Fatal(err)
	}
	if err := addrSet(dockIf.Index, own, 64, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	c.DelTable(tbl)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(own, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(far, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	wanDev.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	for {
		n, err := wanDev.Read(buf)
		if err != nil {
			t.Fatal("the router's own traffic goes out")
		}
		if n >= 40 && buf[0]>>4 == 6 && netip.AddrFrom16([16]byte(buf[8:24])) == own {
			break
		}
	}

	rules, err := c.GetRules(f.table(), &nftables.Chain{Name: "postrouting"})
	if err != nil {
		t.Fatal(err)
	}
	countedAndCommented(t, rules)
}

// With -source-filter off, a LAN source outside the prefixes goes out, as one routed into the LAN
// by other means has to.
func TestFirewallSourceFilterOffAgainstKernel(t *testing.T) {
	enterNetNS(t)
	stray, far := netip.MustParseAddr("2001:db8:1:99::1"), netip.MustParseAddr("2001:db8:f::1")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/56"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()
	if !passes(t, lanDev, wanDev, udp6(netip.AddrPortFrom(stray, 5000), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("a source outside the LAN prefixes goes out")
	}
	if !passes(t, wanDev, lanDev, udp6(netip.AddrPortFrom(far, 4000), netip.AddrPortFrom(stray, 5000))) {
		t.Fatal("and the WAN reaches it")
	}
	if passes(t, lanDev, wanDev, udp6(netip.AddrPortFrom(netip.MustParseAddr("fd00:1::10"), 5000), netip.AddrPortFrom(far, 4000))) {
		t.Fatal("the ULA border still holds")
	}
}

// icmp6 builds an ICMPv6 message of the type and code, with body after the 4-byte field that
// follows the checksum.
func icmp6(from, to netip.Addr, typ, code byte, field [4]byte, body []byte) []byte {
	return ip6(from, to, unix.IPPROTO_ICMPV6, append([]byte{typ, code, 0, 0, field[0], field[1], field[2], field[3]}, body...))
}

// The ICMPv6 of RFC 4890 section 4.3 from the WAN to the LAN under -unsolicited request, and the
// state of RFC 6092: errors about a flow the LAN started pass and others do not (REC-10, REC-18,
// REC-36), a TCP endpoint that sent out is reachable (REC-33), and a simultaneous open works
// An unsolicited SYN is told it is prohibited, though only after 6 seconds; one the LAN host
// answers with a SYN of its own in that time, a TCP simultaneous open, is not (RFC 6092 REC-34).
func TestFirewallRejectsSYNAgainstKernel(t *testing.T) {
	if !ownNetns(t) { // the goroutines of rejectSYNs too
		return
	}
	loUp(t)
	host := netip.MustParseAddr("2001:db8:1::10")
	far := netip.MustParseAddr("2001:db8:f::1")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/56"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	// the router's own address, the source of its ICMPv6 errors
	if err := addrSet(mustIface(t, "wan-test0"), netip.MustParseAddr("2001:db8:e::1"), 128, time.Hour, time.Hour, false, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, inbound: true, source: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.rejectSYNs(ctx)
	time.Sleep(200 * time.Millisecond) // bound to the NFLOG group

	alone, answered := netip.AddrPortFrom(far, 40010), netip.AddrPortFrom(far, 40011)
	start := time.Now()
	for _, from := range []netip.AddrPort{alone, answered} {
		if passes(t, wanDev, lanDev, syn6(from, netip.AddrPortFrom(host, 8090))) {
			t.Fatal("an unsolicited SYN must be dropped")
		}
	}
	time.Sleep(time.Second)
	if !passes(t, lanDev, wanDev, syn6(netip.AddrPortFrom(host, 8090), answered)) {
		t.Fatal("the LAN host's own SYN goes out")
	}

	var got []uint16 // the source ports of the SYNs reported
	buf := make([]byte, 2048)
	for time.Since(start) < synWait+2*time.Second {
		wanDev.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := wanDev.Read(buf)
		if err != nil {
			continue
		}
		p := buf[:n]
		if n < 48+60 || p[6] != unix.IPPROTO_ICMPV6 || p[40] != 1 || netip.AddrFrom16([16]byte(p[24:40])) != far {
			continue
		}
		if p[41] != 1 {
			t.Fatalf("ICMPv6 destination unreachable with code %d, not 1", p[41])
		}
		if e := time.Since(start); e < synWait-100*time.Millisecond {
			t.Fatalf("reported after %s, before the 6 s", e)
		}
		got = append(got, binary.BigEndian.Uint16(p[48+40:]))
	}
	if len(got) != 1 || got[0] != alone.Port() {
		t.Fatalf("SYNs reported from ports %v, want only %d", got, alone.Port())
	}
}

// (REC-31).
func TestFirewallICMPv6AgainstKernel(t *testing.T) {
	enterNetNS(t)
	host := netip.MustParseAddr("2001:db8:1::10")
	far, other := netip.MustParseAddr("2001:db8:f::1"), netip.MustParseAddr("2001:db8:f::2")
	wanDev := openTun(t, "wan-test0", netip.MustParsePrefix("2001:db8:f::/48"))
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/64"))
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, inbound: true, source: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	f.lan = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	f.applyOurs()

	// Errors about a flow the LAN started pass, whatever their code (4.3.1, 4.3.2); others do not
	out := udp6(netip.AddrPortFrom(host, 5000), netip.AddrPortFrom(far, 4000))
	if !passes(t, lanDev, wanDev, out) {
		t.Fatal("the LAN sends out")
	}
	for _, e := range []struct{ typ, code byte }{{1, 4}, {2, 0}, {3, 0}, {3, 1}, {4, 0}, {4, 1}, {4, 2}} {
		if !passes(t, wanDev, lanDev, icmp6(far, host, e.typ, e.code, [4]byte{0, 0, 5, 0}, out)) {
			t.Errorf("type %d code %d about the LAN's flow is let through", e.typ, e.code)
		}
	}
	stray := udp6(netip.AddrPortFrom(host, 6000), netip.AddrPortFrom(far, 7000))
	if passes(t, wanDev, lanDev, icmp6(far, host, 1, 4, [4]byte{}, stray)) {
		t.Error("an error about no flow is dropped (REC-10)")
	}

	// Echo: a request from the WAN passes, a reply only as the answer to the LAN's request
	echo := func(from, to netip.Addr, typ byte, id byte) []byte {
		return icmp6(from, to, typ, 0, [4]byte{0, id, 0, 1}, nil)
	}
	if !passes(t, wanDev, lanDev, echo(far, host, 128, 1)) {
		t.Error("an Echo Request from the WAN is let through")
	}
	if passes(t, wanDev, lanDev, echo(far, host, 129, 2)) {
		t.Error("an Echo Reply nobody asked for is dropped")
	}
	if !passes(t, lanDev, wanDev, echo(host, far, 128, 3)) || !passes(t, wanDev, lanDev, echo(far, host, 129, 3)) {
		t.Error("the Echo Reply to the LAN's request is let through")
	}

	// Node Information: a query from the WAN is dropped, the answer to the LAN's passes
	if passes(t, wanDev, lanDev, icmp6(far, host, 139, 0, [4]byte{0, 3, 0, 0}, make([]byte, 8))) {
		t.Error("a Node Information query from the WAN is dropped")
	}
	if !passes(t, lanDev, wanDev, icmp6(host, far, 139, 0, [4]byte{0, 3, 0, 0}, make([]byte, 8))) ||
		!passes(t, wanDev, lanDev, icmp6(far, host, 140, 0, [4]byte{0, 3, 0, 0}, make([]byte, 8))) {
		t.Error("the Node Information answer to the LAN's query is let through")
	}

	// Mobile IPv6 answers are dropped too, as conntrack does not pair them (4.3.2, not done)
	if !passes(t, lanDev, wanDev, icmp6(host, far, 144, 0, [4]byte{0, 9, 0, 0}, nil)) {
		t.Fatal("the LAN sends out")
	}
	if passes(t, wanDev, lanDev, icmp6(far, host, 145, 0, [4]byte{0, 9, 0, 0}, make([]byte, 16))) {
		t.Error("a Home Agent Address Discovery Reply is dropped, as the table says")
	}

	// What RFC 4890 leaves to a policy, or says to drop (4.3.4, 4.3.5)
	for _, typ := range []byte{150, 5, 99, 102, 126, 154, 199, 202, 254, 138, 100, 101, 200, 201, 127, 255} {
		if passes(t, wanDev, lanDev, icmp6(far, host, typ, 0, [4]byte{}, make([]byte, 8))) {
			t.Errorf("type %d from the WAN is dropped", typ)
		}
	}

	// TCP: an endpoint that sent out is reachable by anyone (REC-33), and a simultaneous open
	// works (REC-31)
	if !passes(t, lanDev, wanDev, syn6(netip.AddrPortFrom(host, 7000), netip.AddrPortFrom(far, 80))) ||
		!passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(other, 9000), netip.AddrPortFrom(host, 7000))) {
		t.Error("a TCP endpoint that sent out is reachable by anyone for a while")
	}
	if passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(other, 9000), netip.AddrPortFrom(host, 7001))) {
		t.Error("but not the host's other ports")
	}
	if !passes(t, lanDev, wanDev, syn6(netip.AddrPortFrom(host, 7100), netip.AddrPortFrom(far, 7200))) ||
		!passes(t, wanDev, lanDev, syn6(netip.AddrPortFrom(far, 7200), netip.AddrPortFrom(host, 7100))) {
		t.Error("the SYN of a simultaneous open is let through")
	}
}

// firewallSetStarts lists the addresses that begin the elements of a set in the filter table, and
// counts its elements.
func firewallSetStarts(t *testing.T, name string) (starts []netip.Addr, n int) {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Error(err)
		return nil, 0
	}
	elems, err := c.GetSetElements(&nftables.Set{Table: (&firewall{}).table(), Name: name})
	if err != nil {
		t.Errorf("reading the set %s: %v", name, err)
		return nil, 0
	}
	for _, e := range elems {
		if a, ok := netip.AddrFromSlice(e.Key); ok && len(e.Key) == 16 && !e.IntervalEnd {
			starts = append(starts, a)
		}
	}
	return starts, len(elems)
}

// run installs the table, follows the snapshots, the pinholes and the delegations into the sets,
// and takes the table away when it is stopped.
func TestFirewallRunAgainstKernel(t *testing.T) {
	enterNetNS(t)
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ns)
	shared, pd := netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::/64")
	stale, ula := netip.MustParsePrefix("2001:db8:3::/64"), netip.MustParsePrefix("fd00:1::/64")
	upULA, deleg := netip.MustParsePrefix("fd01::/48"), netip.MustParsePrefix("2001:db8:9::/48")
	snap := Snapshot{
		WAN: []Prefix{{Prefix: shared, Source: sourceRA}},
		LAN: map[string][]Prefix{"lan-run0": {
			{Prefix: shared, Source: sourceRA},
			{Prefix: pd, Source: sourcePD},
			{Prefix: stale, Source: sourcePD, Stale: true},
			{Prefix: ula, Source: sourceULA},
		}},
		UpstreamULA: []netip.Prefix{upULA},
	}
	f := &firewall{wan: "wan-run0", lans: []string{"lan-run0"}, inbound: true, source: true,
		holeIn: make(chan []portMapping), delegIn: make(chan []netip.Prefix)}
	ch := make(chan Snapshot)
	ctx, cancel := context.WithCancel(t.Context())
	sets := map[string][]netip.Addr{}
	holes := 0
	go func() {
		defer cancel()
		ch <- snap
		f.holeIn <- []portMapping{{proto: unix.IPPROTO_UDP, internal: netip.MustParseAddrPort("[2001:db8:1::10]:5000")}}
		f.delegIn <- []netip.Prefix{deleg}
		ch <- snap // unchanged, and the delegation above is in by the time run takes it
		if err := inNetns(ns, func() error {
			for _, name := range []string{"ours", "wan_link", "upstream_ula", "delegated"} {
				sets[name], _ = firewallSetStarts(t, name)
			}
			_, holes = firewallSetStarts(t, "pinholes")
			return nil
		}); err != nil {
			t.Error(err)
		}
	}()
	f.run(ctx, ch)

	for name, want := range map[string][]netip.Prefix{
		"ours":         {shared, pd, deleg, ula}, // the ULA too, which the ULA border keeps in when it is this router's own
		"wan_link":     {shared},
		"upstream_ula": {upULA},
		"delegated":    {deleg},
	} {
		got := sets[name]
		if len(got) != len(want) {
			t.Errorf("the set %s should hold %v, got %v", name, want, got)
			continue
		}
		for _, p := range want {
			if !slices.Contains(got, p.Addr()) {
				t.Errorf("the set %s should hold %v, got %v", name, want, got)
			}
		}
	}
	if holes != 1 {
		t.Errorf("the pinhole should be in its set, got %d elements", holes)
	}
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, tbl := range tables {
		if tbl.Name == filterTable {
			t.Fatal("stopping must remove the table")
		}
	}
}

// Without CAP_NET_ADMIN the table cannot go in, which run reports and gives up on.
func TestFirewallRunWithoutNetAdmin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("dropping a capability needs one to begin with")
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // should the table go in after all, run returns at once and removes it
	done := make(chan error)
	go func() {
		// The thread keeps its reduced capabilities, so it is never handed back to the runtime
		runtime.LockOSThread()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			done <- err
			return
		}
		data[0].Effective &^= 1 << unix.CAP_NET_ADMIN
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			done <- err
			return
		}
		(&firewall{wan: "wan-run0", lans: []string{"lan-run0"}}).run(ctx, nil)
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatalf("dropping CAP_NET_ADMIN: %v", err)
	}
	if !bytes.Contains(logged.Bytes(), []byte("cannot install table inet "+filterTable)) {
		t.Fatalf("the failure should be reported:\n%s", logged.String())
	}
}

// A set or a table the kernel does not have is reported, not fatal: the next update tries again.
func TestFirewallReportsNftablesFailures(t *testing.T) {
	enterNetNS(t)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	f := &firewall{}
	f.replace(&nftables.Set{Table: f.table(), Name: "ours", KeyType: nftables.TypeIP6Addr, Interval: true}, nil)
	if !bytes.Contains(logged.Bytes(), []byte("failed to update the set ours")) {
		t.Fatalf("a set outside any table should be reported:\n%s", logged.String())
	}
	f.remove()
	if !bytes.Contains(logged.Bytes(), []byte("failed to remove table inet "+filterTable)) {
		t.Fatalf("a table that is not there should be reported:\n%s", logged.String())
	}
}

// syn6MSS is syn6 with an MSS option.
func syn6MSS(from, to netip.AddrPort, mss uint16) []byte {
	tcp := make([]byte, 24)
	binary.BigEndian.PutUint16(tcp[0:], from.Port())
	binary.BigEndian.PutUint16(tcp[2:], to.Port())
	tcp[12], tcp[13] = 6<<4, 0x02
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	tcp[20], tcp[21] = 2, 4
	binary.BigEndian.PutUint16(tcp[22:], mss)
	return ip6(from.Addr(), to.Addr(), unix.IPPROTO_TCP, tcp)
}

// Through the NAT64 every SYN goes with an MSS of at most 1220, either way, so nothing Jool
// translates exceeds 1280 bytes.
func TestFirewallNAT64MSSAgainstKernel(t *testing.T) {
	enterNetNS(t)
	host := netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::10"), 40000)
	far := netip.AddrPortFrom(netip.MustParseAddr("64:ff9b::c000:201"), 443)
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("2001:db8:1::/56"))
	natDev := openTun(t, joolOutside, nat64WKP)
	if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	f := &firewall{wan: "wan-test0", lans: []string{"lan-test0"}, nat64: true}
	if err := f.install(); err != nil {
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(f.remove)
	mss := func(in, out *os.File, pkt []byte) uint16 {
		t.Helper()
		if _, err := in.Write(pkt); err != nil {
			t.Fatal(err)
		}
		out.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				t.Fatalf("the SYN was not forwarded: %v", err)
			}
			if n >= 64 && buf[0]>>4 == 6 && buf[6] == unix.IPPROTO_TCP {
				return binary.BigEndian.Uint16(buf[40+22:])
			}
		}
	}
	for _, c := range []struct {
		name      string
		in, out   *os.File
		from, to  netip.AddrPort
		mss, want uint16
	}{
		{"to the NAT64", lanDev, natDev, host, far, 1440, 1220},
		{"to the NAT64, already small", lanDev, natDev, host, far, 1000, 1000},
		{"from the NAT64", natDev, lanDev, far, host, 1440, 1220},
	} {
		if got := mss(c.in, c.out, syn6MSS(c.from, c.to, c.mss)); got != c.want {
			t.Errorf("%s: MSS %d came out as %d, want %d", c.name, c.mss, got, c.want)
		}
	}
}
