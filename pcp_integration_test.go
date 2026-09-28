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
