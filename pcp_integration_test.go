//go:build linux && integration

package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// pcpTestLinks enters a namespace of its own with lo up and a veth pair whose end pcp-lan0 is up
// and pcp-down0 down, and returns the namespace.
func pcpTestLinks(t *testing.T) int {
	t.Helper()
	enterNetNS(t)
	loUp(t)
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(ns) })
	if err := vethAdd("pcp-lan0", "pcp-down0", ns); err != nil {
		t.Fatal(err)
	}
	linkUp(t, mustIface(t, "pcp-lan0"))
	return ns
}

// pcpTestConns opens the sockets the announcements go out on, in the namespace of the caller.
func pcpTestConns(t *testing.T) (*ipv4.PacketConn, *ipv6.PacketConn) {
	t.Helper()
	c4, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c4.Close() })
	c6, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c6.Close() })
	return ipv4.NewPacketConn(c4), ipv6.NewPacketConn(c6)
}

// pcpSendFromPort0 sends payload to dst over UDP from source port 0, which no reply can go to.
func pcpSendFromPort0(t *testing.T, dst *net.UDPAddr, payload []byte) {
	t.Helper()
	network, laddr := "ip4:udp", "0.0.0.0" // an IPv4 checksum of 0 means none
	if dst.IP.To4() == nil {
		network, laddr = "ip6:udp", "::"
	}
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if dst.IP.To4() == nil {
		// IPv6 requires the checksum, which the kernel fills in at offset 6
		raw, err := c.(*net.IPConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6) })
		if err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(b[2:], uint16(dst.Port))
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	if _, err := c.WriteTo(append(b, payload...), &net.IPAddr{IP: dst.IP, Zone: dst.Zone}); err != nil {
		t.Fatal(err)
	}
}

// pcpCancelAfter cancels the context it returns after d.
func pcpCancelAfter(d time.Duration) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(d, cancel)
	return ctx
}

// The server gives up when it can listen on neither family, ignores requests from interfaces that
// are not LANs, and follows the tunnel's IPv4.
func TestPCPServerRunAgainstKernel(t *testing.T) {
	ns := pcpTestLinks(t)
	h6, err := net.ListenPacket("udp6", "[::]:5351")
	if err != nil {
		t.Fatal(err)
	}
	h4, err := net.ListenPacket("udp4", "0.0.0.0:5351")
	if err != nil {
		t.Fatal(err)
	}
	(&pcpServer{}).run(t.Context(), nil)
	h6.Close()
	h4.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan Snapshot)
	done := make(chan struct{})
	p := &pcpServer{lans: []string{"pcp-lan0"}, nat: &natManager{mapIn: make(chan []portMapping, 1)}}
	go func() {
		defer close(done)
		inNetns(ns, func() error { p.run(ctx, ch); return nil })
	}()
	time.Sleep(200 * time.Millisecond) // let it bind

	for network, ip := range map[string]net.IP{"udp6": net.IPv6loopback, "udp4": net.IPv4(127, 0, 0, 1)} {
		dst := &net.UDPAddr{IP: ip, Port: pcpServerPort}
		c, err := net.DialUDP(network, nil, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte{0, natpmpOpAddress}); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, err := c.Read(make([]byte, 64)); err == nil {
			t.Fatalf("%s: a request over lo, not a LAN, is answered with %d bytes", dst, n)
		}
	}

	tunnel := Snapshot{Tunnel: &TunnelParams{Local: netip.MustParseAddr("2001:db8::2"), Remote: netip.MustParseAddr("2001:db8::1"), IPv4: netip.MustParseAddr("203.0.113.9")}}
	ch <- tunnel     // gained
	ch <- Snapshot{} // lost
	ch <- Snapshot{} // unchanged
	cancel()
	<-done
}

// The PCP announcement skips a missing LAN, goes on when sending on one fails, and repeats after a
// growing gap until stopped.
func TestPCPAnnounceAgainstKernel(t *testing.T) {
	pcpTestLinks(t)
	c4, c6 := pcpTestConns(t)
	p := &pcpServer{lans: []string{"nope0", "pcp-down0", "lo"}, c4: c4, c6: c6, start: time.Now()}
	p.announce(pcpCancelAfter(700 * time.Millisecond))
}

// The server answers on the interface a request came in on and from the address it was sent to,
// and ignores interfaces that are not LANs.
func TestPCPServerAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A goroutine may run on any thread, and only this one is in the test's namespace
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ns)
	go inNetns(ns, func() error { (&pcpServer{lans: []string{"lo"}}).run(ctx, nil); return nil })
	time.Sleep(200 * time.Millisecond) // let it bind

	// A request from port 0 cannot be answered; the replies below show it was dealt with first
	pcpSendFromPort0(t, &net.UDPAddr{IP: net.IPv6loopback, Port: pcpServerPort}, []byte{0, natpmpOpAddress})
	pcpSendFromPort0(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pcpServerPort}, []byte{0, natpmpOpAddress})

	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IPv6loopback, Port: pcpServerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := pcpReq(pcpOpMap, 60, mapData(6, 8080))
	lo := netip.IPv6Loopback().As16()
	copy(req[8:24], lo[:])
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1100)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	// ::1 is not a global address, so the mapping is refused, which proves the whole path
	if n != len(req) || buf[1] != 0x80|pcpOpMap || buf[3] != pcpNotAuthorized {
		t.Fatalf("reply: %x", buf[:min(n, 8)])
	}

	// NAT-PMP over IPv4 is answered in its own format; with no tunnel, Network Failure (RFC 6886)
	c4, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pcpServerPort})
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	if _, err := c4.Write([]byte{0, natpmpOpAddress}); err != nil {
		t.Fatal(err)
	}
	c4.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err = c4.Read(buf); err != nil {
		t.Fatalf("no NAT-PMP reply: %v", err)
	}
	if n != 12 || buf[0] != 0 || buf[1] != 128 || buf[3] != natpmpNetworkFailure {
		t.Fatalf("NAT-PMP reply: %x", buf[:n])
	}
}

// The router's own listeners are found: UDP bound to the IPv4 wildcard and TCP listening on the
// IPv6 one, which takes IPv4 too; a UDP socket connected to a peer is outbound traffic and is not.
func TestPCPLocalListenersAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 40001})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", "[::]:40002")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: 40003}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tunnel := netip.MustParseAddr("203.0.113.9")
	u, err := localListeners(pcpProtoUDP, tunnel)
	if err != nil || !u[40001] || u[40003] {
		t.Fatalf("UDP: %v %v", u, err)
	}
	if tc, err := localListeners(pcpProtoTCP, tunnel); err != nil || !tc[40002] {
		t.Fatalf("TCP: %v %v", tc, err)
	}
}
