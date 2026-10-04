//go:build linux && integration

package main

import (
	"net"
	"testing"
)

// The tunnel device is built, given its IPv4 and route, and modified in place on the next apply;
// what the kernel refuses leaves the manager unapplied.
func TestTunnelDeviceAgainstKernel(t *testing.T) {
	enterNetNS(t)
	// lo is still down, so an IPv4 default route through it is refused
	(&tunnelManager{dev: "lo", metric4: 300}).route4()
	loUp(t)

	m := &tunnelManager{dev: "sixup-tt0", wan: "lo", metric4: 300}
	m.apply(tundevSpec)
	if !m.applied {
		t.Fatal("the tunnel should have been built")
	}
	ifi, err := net.InterfaceByName("sixup-tt0")
	if err != nil {
		t.Fatal(err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if want := tunnelMTU(0, lo.MTU, 0); ifi.MTU != want || ifi.Flags&net.FlagUp == 0 {
		t.Fatalf("%+v, want mtu %d and up", ifi, want)
	}
	if addr4Holder("lo", tundevSpec.IPv4) != "sixup-tt0" {
		t.Fatalf("%s should sit on the tunnel", tundevSpec.IPv4)
	}
	m.applied = false
	m.apply(tundevSpec) // modified in place
	if !m.applied {
		t.Fatal("modifying the tunnel should succeed")
	}

	bad := &tunnelManager{dev: "sixup-name-too-long", wan: "lo"}
	bad.apply(tundevSpec)
	if bad.applied {
		t.Fatal("the kernel refuses a name over 15 bytes")
	}
}
