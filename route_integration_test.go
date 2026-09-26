//go:build linux && integration

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// loUp brings up the loopback of the fresh namespace, which starts down and takes no routes.
func loUp(t *testing.T) {
	t.Helper()
	c, err := rtDial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[4:8], 1)
	nativeEndian.PutUint32(hdr[8:12], unix.IFF_UP)
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_UP)
	if _, err := c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Request | netlink.Acknowledge}, Data: hdr}); err != nil {
		t.Fatalf("lo up: %v", err)
	}
}

// routeTypes dumps the main IPv6 table and returns the route types (RTN_*) with destination dst.
func routeTypes(t *testing.T, dst netip.Prefix) []byte {
	t.Helper()
	c, err := rtDial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msgs, err := c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_GETROUTE, Flags: netlink.Request | netlink.Dump}, Data: []byte{unix.AF_INET6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}})
	if err != nil {
		t.Fatalf("route dump: %v", err)
	}
	var out []byte
	for _, m := range msgs {
		if len(m.Data) < 12 || int(m.Data[1]) != dst.Bits() {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[12:])
		if err != nil {
			continue
		}
		for ad.Next() {
			if ad.Type() == unix.RTA_DST {
				if a, ok := netip.AddrFromSlice(ad.Bytes()); ok && a == dst.Addr() {
					out = append(out, m.Data[7])
				}
			}
		}
	}
	return out
}

// An IPv6 route is added with the RA protocol, and deleting it has to find it again.
func TestRouteDeleteAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	dst := netip.MustParsePrefix("2001:db8:1::/64")
	if err := routeSet(1, dst, netip.Addr{}, 0, 0); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(routeTypes(t, dst)) == 0 {
		t.Fatal("the route was not added")
	}
	if err := routeDel(1, dst, netip.Addr{}, 0); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(routeTypes(t, dst)) != 0 {
		t.Fatal("the route is still there after routeDel")
	}
}

// The unreachable route for a delegation is accepted without a device, sits under the more
// specific LAN route, and goes on delete.
func TestRouteUnreachableAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	up := netip.MustParsePrefix("2001:db8:100::/56")
	lan := netip.MustParsePrefix("2001:db8:100::/64")
	if err := routeUnreachable(up, time.Hour, false); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := routeSet(1, lan, netip.Addr{}, 0, 0); err != nil {
		t.Fatalf("LAN route: %v", err)
	}
	if got := routeTypes(t, up); len(got) != 1 || got[0] != unix.RTN_UNREACHABLE {
		t.Fatalf("want one unreachable route, got types %v", got)
	}
	if err := routeUnreachable(up, 0, true); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := routeTypes(t, up); len(got) != 0 {
		t.Fatalf("still there after delete: %v", got)
	}
	if len(routeTypes(t, lan)) != 1 {
		t.Fatal("deleting the unreachable route must leave the LAN route alone")
	}
}
