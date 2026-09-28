//go:build linux && integration

package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// An RS from a host with an address is answered by unicast within 0.5 s, the second one of two
// sent a second apart included, which MIN_DELAY_BETWEEN_RAS would hold back for a multicast answer
// (RFC 4861 section 6.2.6, IPv6 Ready CE Router 2.4.17).
func TestRAServerAnswersRSAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	loUp(t)
	for _, k := range []string{"all", "default"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/"+k+"/accept_dad", "0"); err != nil {
			t.Fatal(err)
		}
	}
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd("lan-test0", "host-test0", int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	linkUp(t, mustIface(t, "host-test0"))
	linkUp(t, mustIface(t, "lan-test0"))
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newStore("pd", []lanDef{{"lan-test0", 0}}, time.Minute, nil, false, 0, 0, "")
	r := &raServer{ifname: "lan-test0", minI: 200 * time.Second, maxI: 600 * time.Second, lifetime: ndPreferredLimit}
	go r.run(ctx, newLinkHub(ctx), store, store.Subscribe())

	hostIfi, _ := net.InterfaceByName("host-test0")
	host, addr, err := ndp.Listen(hostIfi, ndp.LinkLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	host.SetControlMessage(ipv6.FlagDst, true)
	time.Sleep(6 * time.Second) // past the initial burst

	for i := range 2 {
		if err := host.WriteTo(&ndp.RouterSolicitation{}, nil, allRouters2.WithZone("host-test0")); err != nil {
			t.Fatal(err)
		}
		sent := time.Now()
		host.SetReadDeadline(sent.Add(time.Second))
		for {
			m, cm, _, err := host.ReadFrom()
			if err != nil {
				t.Fatalf("RS %d: no unicast RA within a second: %v", i+1, err)
			}
			if _, ok := m.(*ndp.RouterAdvertisement); ok && cm != nil && cm.Dst.Equal(addr.AsSlice()) {
				if d := time.Since(sent); d > 600*time.Millisecond {
					t.Fatalf("RS %d answered after %s", i+1, d)
				}
				break
			}
		}
		time.Sleep(time.Second)
	}
}
