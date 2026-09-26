//go:build linux && integration

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// These tests need a kernel that accepts what the rule builder produces, which the unit tests
// cannot tell: an expression can marshal cleanly and still be rejected. They run as root in a
// network namespace of their own, so nothing on the host is touched:
//
//	docker run --rm --privileged -v "$PWD:/src" -w /src golang:1.27-alpine \
//	  go test -tags integration -run TestNATAgainstKernel ./...
func enterNetNS(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("writing nftables needs root")
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("cannot enter a network namespace of my own: %v", err)
	}
}

func mapeSnapshot(psid uint16) Snapshot {
	return Snapshot{Tunnel: &TunnelParams{
		Kind: "map-e", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		RuleMAPE: &mapeResult{IPv4: netip.MustParseAddr("203.0.113.9"), Ports: portSpans(4, 8, psid)},
	}}
}

func rulesIn(t *testing.T, c *nftables.Conn, chain string) []*nftables.Rule {
	t.Helper()
	r, err := c.GetRules(&nftables.Table{Family: nftables.TableFamilyINet, Name: natTable},
		&nftables.Chain{Name: chain})
	if err != nil {
		t.Fatalf("reading chain %s back: %v", chain, err)
	}
	return r
}

func TestNATAgainstKernel(t *testing.T) {
	enterNetNS(t)
	m := &natManager{dev: "sixup-test0", mtu: 1460, warned: true}
	t.Cleanup(m.remove)

	ports := portSpans(4, 8, 0x56)
	m.apply(mapeSnapshot(0x56))

	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	post := rulesIn(t, c, "postrouting")
	if len(post) != len(ports) {
		t.Fatalf("the kernel holds %d source NAT rules, one per port range would be %d", len(post), len(ports))
	}
	// The order rules come back in is the order they went in, so the ranges can be compared directly
	for i, r := range post {
		im := map[uint32][]byte{}
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Immediate); ok {
				im[v.Register] = v.Data
			}
		}
		start, end := binary.BigEndian.Uint16(im[3]), binary.BigEndian.Uint16(im[4])
		if start != ports[i].Start || end != ports[i].End {
			t.Fatalf("rule %d came back as %d-%d, want %s", i, start, end, ports[i])
		}
	}
	if n := len(rulesIn(t, c, "forward")); n != 2 {
		t.Fatalf("the MSS clamp should be one rule per direction, got %d", n)
	}

	// A renumbering rewrites the set; the old ranges must not survive it
	m.apply(mapeSnapshot(0x57))
	post = rulesIn(t, c, "postrouting")
	if len(post) == 0 {
		t.Fatal("the table is empty after a renumbering")
	}
	for _, r := range post {
		for _, e := range r.Exprs {
			v, ok := e.(*expr.Immediate)
			if !ok || v.Register != 3 {
				continue
			}
			if got := binary.BigEndian.Uint16(v.Data); got == ports[0].Start {
				t.Fatalf("a port range from the previous prefix is still installed: %d", got)
			}
		}
	}

	m.remove()
	if tables, err := c.ListTables(); err == nil {
		for _, tb := range tables {
			if tb.Name == natTable {
				t.Fatal("the table outlived the daemon")
			}
		}
	}
}

// DS-Lite is translated by the AFTR, so the kernel should end up with the clamp and no source NAT.
func TestNATAgainstKernelDSLite(t *testing.T) {
	enterNetNS(t)
	m := &natManager{dev: "sixup-test0", mtu: 1460, warned: true}
	t.Cleanup(m.remove)
	m.apply(Snapshot{Tunnel: &TunnelParams{
		Kind: "ds-lite", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		IPv4: netip.MustParseAddr("192.0.0.2"),
	}})
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		t.Fatalf("listing chains: %v", err)
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == natTable && ch.Name == "postrouting" {
			t.Fatal("DS-Lite must not translate here, the AFTR does")
		}
	}
	if n := len(rulesIn(t, c, "forward")); n != 2 {
		t.Fatalf("the clamp applies on DS-Lite too, one rule per direction, got %d rules", n)
	}
}

// Another source NAT chain on the same hook decides the translation for whichever flow it sees
// first, which on a MAP-E line means a port the border relay does not route back. The operator has
// to be told; sixup neither removes it nor quietly outruns it.
func TestNATReportsAForeignSourceNATChain(t *testing.T) {
	enterNetNS(t)
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	foreign := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "someone-else"})
	c.AddChain(&nftables.Chain{
		Name: "srcnat", Table: foreign, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	// An IPv6 table cannot translate the tunnel's IPv4, so it is not worth a warning
	foreign6 := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "someone-else6"})
	c.AddChain(&nftables.Chain{
		Name: "srcnat", Table: foreign6, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	if err := c.Flush(); err != nil {
		t.Fatalf("installing the other table: %v", err)
	}
	t.Cleanup(func() {
		c.DelTable(foreign)
		c.DelTable(foreign6)
		c.Flush()
	})

	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	m := &natManager{dev: "sixup-test0", mtu: 1460}
	t.Cleanup(m.remove)
	m.apply(mapeSnapshot(0x56))

	if !bytes.Contains(logged.Bytes(), []byte("ip someone-else/srcnat")) {
		t.Fatalf("the other chain should be named in the warning, with its family:\n%s", logged.String())
	}
	if bytes.Contains(logged.Bytes(), []byte("someone-else6")) {
		t.Fatalf("an IPv6 NAT chain cannot touch the tunnel's IPv4:\n%s", logged.String())
	}
}

// openTun creates a TUN device carrying bare IPv4 packets, up and with a route to dst through it.
func openTun(t *testing.T, name string, dst netip.Prefix) *os.File {
	t.Helper()
	// Attach first and hand the fd to the poller after, as wireguard-go does: registered while
	// still unattached, the fd is not reliably pollable and the read deadline cannot work.
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no TUN device: %v", err)
	}
	ifr, _ := unix.NewIfreq(name)
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		t.Fatalf("TUNSETIFF %s: %v", name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), name)
	t.Cleanup(func() { f.Close() })
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	linkUp(t, ifi.Index)
	if err := routeSet(ifi.Index, dst, netip.Addr{}, 0, 0); err != nil {
		t.Fatalf("route %s via %s: %v", dst, name, err)
	}
	if err := sysctlWrite("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", "0"); err != nil {
		t.Fatal(err)
	}
	if err := sysctlWrite("/proc/sys/net/ipv4/conf/"+name+"/forwarding", "1"); err != nil {
		t.Fatal(err)
	}
	return f
}

// syn builds an IPv4 TCP SYN from src to dst, with an MSS option unless mss is 0.
func syn(src, dst netip.Addr, mss uint16) []byte {
	opts := 0
	if mss > 0 {
		opts = 4
	}
	p := make([]byte, 20+20+opts)
	p[0], p[8], p[9] = 0x45, 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	s4, d4 := src.As4(), dst.As4()
	copy(p[12:], s4[:])
	copy(p[16:], d4[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	tcp := p[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	tcp[12], tcp[13] = byte((20+opts)/4)<<4, 0x02
	if mss > 0 {
		tcp[20], tcp[21] = 2, 4
		binary.BigEndian.PutUint16(tcp[22:], mss)
	}
	return p
}

// forwardedMSS sends a SYN in through in and returns the MSS option of what comes out of out, or
// 0 when the SYN carries none.
func forwardedMSS(t *testing.T, in, out *os.File, pkt []byte) uint16 {
	t.Helper()
	if _, err := in.Write(pkt); err != nil {
		t.Fatalf("inject: %v", err)
	}
	out.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	for {
		n, err := out.Read(buf)
		if err != nil {
			t.Fatalf("the SYN was not forwarded: %v", err)
		}
		p := buf[:n]
		if n < 40 || p[0]>>4 != 4 || p[9] != unix.IPPROTO_TCP {
			continue // the kernel's own traffic on the device
		}
		tcp := p[20:]
		if tcp[12]>>4 == 5 {
			return 0
		}
		return binary.BigEndian.Uint16(tcp[22:])
	}
}

// The clamp lowers the MSS of a SYN leaving through the tunnel and of one arriving from it. The
// kernel never raises an MSS it writes, so a smaller one and a SYN without the option pass as they are.
func TestMSSClampAgainstKernel(t *testing.T) {
	enterNetNS(t)
	lan, far := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	lanDev := openTun(t, "lan-test0", netip.MustParsePrefix("192.0.2.0/24"))
	tunDev := openTun(t, "sixup-test0", netip.MustParsePrefix("198.51.100.0/24"))
	m := &natManager{dev: "sixup-test0", mtu: 1460, warned: true}
	t.Cleanup(m.remove)
	m.apply(Snapshot{Tunnel: &TunnelParams{
		Kind: "ds-lite", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		IPv4: netip.MustParseAddr("192.0.0.2"),
	}})
	cases := []struct {
		name    string
		in, out *os.File
		src     netip.Addr
		dst     netip.Addr
		mss     uint16
		want    uint16
	}{
		{"leaving, too large", lanDev, tunDev, lan, far, 1460, 1420},
		{"leaving, already small", lanDev, tunDev, lan, far, 1200, 1200},
		{"leaving, no option", lanDev, tunDev, lan, far, 0, 0},
		{"arriving, too large", tunDev, lanDev, far, lan, 1460, 1420},
	}
	for _, c := range cases {
		if got := forwardedMSS(t, c.in, c.out, syn(c.src, c.dst, c.mss)); got != c.want {
			t.Errorf("%s: MSS %d came out as %d, want %d", c.name, c.mss, got, c.want)
		}
	}
}
