//go:build linux && integration

package main

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// dhcp6sLinkLocal waits for the link-local address of the interface name.
func dhcp6sLinkLocal(t *testing.T, name string) netip.Addr {
	t.Helper()
	for range 50 {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().IsLinkLocalUnicast() {
				return p.Addr()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s has no link-local address", name)
	return netip.Addr{}
}

// dhcp6sRead reads one DHCPv6 message from c, failing the test after a second.
func dhcp6sRead(t *testing.T, c *net.UDPConn) *dhcpv6.Message {
	t.Helper()
	buf := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	m, err := dhcpv6.MessageFromBytes(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The server answers on its LAN only, tells a unicast Request to use multicast, and sends a
// Reconfigure to a client whose address left with the prefix.
func TestDHCP6ServerAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	for _, k := range []string{"all", "default"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/"+k+"/accept_dad", "0"); err != nil {
			t.Fatal(err)
		}
	}
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ns)
	if err := vethAdd("d6s-lan0", "d6s-host0", ns); err != nil {
		t.Fatal(err)
	}
	linkUp(t, mustIface(t, "d6s-host0"))
	linkUp(t, mustIface(t, "d6s-lan0"))
	hostLL := dhcp6sLinkLocal(t, "d6s-host0")
	srvLL := dhcp6sLinkLocal(t, "d6s-lan0")

	s := newTestServer(true)
	s.ifname = "d6s-lan0"
	s.leaseFile = filepath.Join(t.TempDir(), "leases.json")

	// A port taken by a socket that does not share it, and a group that cannot be joined
	held, err := net.ListenPacket("udp6", "[::]:547")
	if err != nil {
		t.Fatal(err)
	}
	s.serve(t.Context(), nil)
	held.Close()
	s.ifi = &net.Interface{Index: 9999}
	s.serve(t.Context(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"d6s-lan0", 0}}, time.Minute, nil, false, 0, 0, "")
	ch := make(chan Snapshot)
	done := make(chan struct{})
	// The server's goroutine opens its sockets on a thread in this namespace
	go func() {
		defer close(done)
		inNetns(ns, func() error { s.run(ctx, newLinkHub(ctx), store, ch); return nil })
	}()
	for {
		s.mu.Lock()
		ready := s.pc != nil
		s.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cli, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 546})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	send := func(b []byte, to *net.UDPAddr) {
		t.Helper()
		if _, err := cli.WriteTo(b, to); err != nil {
			t.Fatal(err)
		}
	}
	multicast := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547, Zone: "d6s-host0"}
	// one from port 0 cannot be answered; the Reply below shows it was dealt with first
	pcpSendFromPort0(t, multicast, cliMsg(dhcpv6.MessageTypeInformationRequest).ToBytes())
	send(cliMsg(dhcpv6.MessageTypeInformationRequest).ToBytes(), multicast)
	if m := dhcp6sRead(t, cli); m.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("Information-Request: %v", m)
	}
	// Neither garbage nor a message that comes in on another interface is answered
	send([]byte{1}, multicast)
	send(cliMsg(dhcpv6.MessageTypeInformationRequest).ToBytes(), &net.UDPAddr{IP: net.IPv6loopback, Port: 547})
	req := cliMsg(dhcpv6.MessageTypeRequest, dhcpv6.OptServerID(srvDUID), iana1())
	send(req.ToBytes(), &net.UDPAddr{IP: srvLL.AsSlice(), Port: 547, Zone: "d6s-host0"})
	if m := dhcp6sRead(t, cli); m.Options.Status() == nil || m.Options.Status().StatusCode != iana.StatusUseMulticast {
		t.Fatalf("a unicast Request: %v", m)
	}

	// A lease the new prefix leaves behind is told to renew
	s.mu.Lock()
	s.leases["moved"] = &Lease{DUID: hex.EncodeToString(cliDUID.ToBytes()), IAID: 1, Addr: netip.MustParseAddr("2001:db8:9::1000"),
		Peer: hostLL, ReconfKey: "000102030405060708090a0b0c0d0e0f", Expires: time.Now().Add(time.Hour)}
	s.mu.Unlock()
	ch <- Snapshot{Change: "remove"}
	ch <- Snapshot{Change: "add"}
	if m := dhcp6sRead(t, cli); m.MessageType != dhcpv6.MessageTypeReconfigure {
		t.Fatalf("want a Reconfigure, got %v", m)
	}
	cancel()
	<-done
}

// Reconfigure to a router whose delegation goes, and the sends that fail.
func TestDHCP6ServerReconfigureAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	c, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := newPDServer(false, pdSnap("2001:db8:100::/56"))
	s.ifname, s.ifi, s.pc = "lo", &net.Interface{Index: 1, Name: "lo"}, ipv6.NewPacketConn(c)
	s.pd.leases["r"] = &PDLease{DUID: hex.EncodeToString(cliDUID.ToBytes()), IAID: 7, Prefix: netip.MustParsePrefix("2001:db8:100:10::/60"),
		Iface: "lo", Peer: netip.IPv6Loopback(), Expires: time.Now().Add(time.Hour), ReconfKey: "000102030405060708090a0b0c0d0e0f"}
	s.dropDelegations(func(*PDLease) bool { return true })
	if len(s.pd.leases) != 0 {
		t.Fatal("the delegation is dropped")
	}
	s.sendReconfigure(&Lease{DUID: "zz"}) // nothing to sign
	s.ifi = &net.Interface{Index: 9999}
	s.sendReconfigure(&Lease{DUID: hex.EncodeToString(cliDUID.ToBytes()), Peer: netip.IPv6Loopback(), ReconfKey: "00"})
}
