//go:build linux && integration

package main

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The namespace Jool runs in: without the module no translation happens, but the plumbing around
// it can be checked. 64:ff9b::/96 and the pool4 address are routed into it, IPv4 reaches the
// namespace and comes back, and closing the descriptor takes the namespace and the veth away.
func TestJoolNamespaceAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	link := netip.MustParsePrefix("192.168.255.254/31")
	if err := checkJoolIPv4(link); err != nil {
		t.Fatalf("an empty namespace has nothing to overlap: %v", err)
	}
	m := &joolManager{prefix: nat64WKP, link: link}
	if err := m.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(routeTypes(t, nat64WKP)) != 1 {
		t.Fatalf("%s is not routed into the namespace", nat64WKP)
	}
	outside, inside := joolAddrs(link)

	// A UDP socket opened inside stays there; a datagram from outside has to reach it and the
	// answer has to find its way back
	var srv *net.UDPConn
	if err := inNetns(m.ns, func() error {
		var err error
		srv, err = net.ListenUDP("udp4", &net.UDPAddr{IP: inside.AsSlice(), Port: 9999})
		return err
	}); err != nil {
		t.Fatalf("listening inside: %v", err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: inside.AsSlice(), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.Write([]byte("ping"))
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, from, err := srv.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("nothing reached the namespace: %v", err)
	}
	if got, _ := netip.AddrFromSlice(from.IP.To4()); got != outside {
		t.Fatalf("the host's side should talk from %s, got %s", outside, got)
	}
	srv.WriteToUDP([]byte("pong"), from)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := cli.Read(buf); err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("the answer did not come back: %v", err)
	}

	// Jool's output is forwarded inside, and untranslated packets for the prefix are refused there
	if err := inNetns(m.ns, func() error {
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			t.Errorf("IPv4 forwarding is off inside: %q %v", b, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A second run may start while the kernel still tears down the first one's namespace: its veth
	// is no conflict, and building a new pair replaces it
	if err := checkJoolIPv4(link); err != nil {
		t.Fatalf("the veth of an earlier run must not count as a conflict: %v", err)
	}
	srv.Close()
	cli.Close()
	st := newStore("pd", nil, time.Second, nil, false, 0, 0)
	ch := st.Subscribe()
	recv(t, ch)
	again := &joolManager{prefix: nat64WKP, link: link, store: st}
	if err := again.setup(); err != nil {
		t.Fatalf("setup over an earlier run's veth: %v", err)
	}
	// start would get here once Jool had its instance; without the module the test stands in for it
	again.active = true
	st.SetNAT64(nat64WKP)
	recv(t, ch)
	unix.Close(m.ns)

	// Anything else routing into the /31 is
	if err := routeSet(1, netip.MustParsePrefix("192.168.255.0/24"), netip.Addr{}, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := checkJoolIPv4(link); err == nil {
		t.Fatal("a /31 inside another route must be refused")
	}
	routeDel(1, netip.MustParsePrefix("192.168.255.0/24"), netip.Addr{}, 0)

	again.stop()
	if s := recv(t, ch); s.NAT64.IsValid() {
		t.Fatal("stopping must withdraw the prefix from the RA")
	}
	// The kernel tears a namespace down in the background, which takes seconds
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := net.InterfaceByName(joolOutside); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the veth outlived the namespace")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
