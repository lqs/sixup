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
func loUp(t *testing.T) { linkUp(t, 1) }

func linkUp(t *testing.T, index int) {
	t.Helper()
	c, err := rtDial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[4:8], uint32(index))
	nativeEndian.PutUint32(hdr[8:12], unix.IFF_UP)
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_UP)
	if _, err := c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: netlink.Request | netlink.Acknowledge}, Data: hdr}); err != nil {
		t.Fatalf("link %d up: %v", index, err)
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

// The on-link route the kernel adds for an address's prefix is found and removed by its protocol,
// on kernels that leave it behind when the address goes. A route of ours to the same prefix on
// another device stays.
func TestRoutePrefixDeleteAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	dst := netip.MustParsePrefix("2001:db8:1::/64")
	if err := routeOp(unix.RTM_NEWROUTE, netlink.Request|netlink.Acknowledge|netlink.Create, unix.RTN_UNICAST, unix.RTPROT_KERNEL, 1, dst, netip.Addr{}, 256, time.Hour); err != nil {
		t.Fatalf("adding a kernel route: %v", err)
	}
	if err := routeUnreachable(dst, time.Hour, false); err != nil {
		t.Fatalf("adding a route of ours: %v", err)
	}
	if err := prefixRouteDel(1, dst); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := routeTypes(t, dst); len(got) != 1 || got[0] != unix.RTN_UNREACHABLE {
		t.Fatalf("only the kernel's route should be gone, left %v", got)
	}
	if err := prefixRouteDel(1, dst); err != nil {
		t.Fatalf("deleting a route already gone is no error: %v", err)
	}
}
