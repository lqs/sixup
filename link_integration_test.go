//go:build linux && integration

package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// linkVeth creates the veth pair name/peer, both down, in the namespace of the calling thread.
func linkVeth(t *testing.T, name, peer string) (int, int) {
	t.Helper()
	ns, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := vethAdd(name, peer, int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	return mustIface(t, name), mustIface(t, peer)
}

// A VLAN on a lower device that is down cannot come up, which bringUp reports and moves past.
func TestLinkBringUpFailsAgainstKernel(t *testing.T) {
	enterNetNS(t)
	lower, _ := linkVeth(t, "low0", "low1")
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, "vlan0")
	ae.Uint32(unix.IFLA_LINK, uint32(lower))
	ae.Nested(unix.IFLA_LINKINFO, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.IFLA_INFO_KIND, "vlan")
		ae.Nested(unix.IFLA_INFO_DATA, func(ae *netlink.AttributeEncoder) error {
			ae.Uint16(unix.IFLA_VLAN_ID, 7)
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := linkRequest(unix.RTM_NEWLINK, netlink.Create|netlink.Excl, make([]byte, 16), attrs); err != nil {
		t.Skipf("no VLAN support: %v", err)
	}
	bringUp("vlan0", nil)
	ifi, err := net.InterfaceByName("vlan0")
	if err != nil {
		t.Fatal(err)
	}
	if ifi.Flags&net.FlagUp != 0 {
		t.Fatal("a VLAN came up on a lower device that is down")
	}
}

// supervise waits for the interface to come up and cancels the body when it goes down; the hub
// passes link events on, drops them for a subscriber that does not keep up, and reports an
// interface removed.
func TestLinkSuperviseAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	idx, peer := linkVeth(t, "sup0", "sup1")
	linkUp(t, peer)
	hubCtx, stopHub := context.WithCancel(context.Background())
	defer stopHub()
	h := newLinkHub(hubCtx)
	stalled := h.Subscribe("sup0") // never read

	// The interface is down at first, so waitIface retries after 2s. The body returns at once;
	// the cancellation arrives during the second supervise waits before the next round.
	ctx, cancel := context.WithCancel(context.Background())
	rounds := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.supervise(ctx, "sup0", func(_ context.Context, ifi *net.Interface) {
			if ifi.Index != idx {
				t.Errorf("body got index %d, want %d", ifi.Index, idx)
			}
			rounds <- struct{}{}
		})
	}()
	time.Sleep(100 * time.Millisecond)
	linkUp(t, idx)
	select {
	case <-rounds:
	case <-time.After(5 * time.Second):
		t.Fatal("the body did not start once the interface came up")
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervise did not return after cancel")
	}

	// a round ended by the link going down
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done = make(chan struct{})
	go func() {
		defer close(done)
		h.supervise(ctx, "sup0", func(cctx context.Context, _ *net.Interface) {
			rounds <- struct{}{}
			<-cctx.Done()
			rounds <- struct{}{}
		})
	}()
	select {
	case <-rounds:
	case <-time.After(3 * time.Second):
		t.Fatal("the body did not start")
	}
	linkDown(t, idx)
	select {
	case <-rounds:
	case <-time.After(3 * time.Second):
		t.Fatal("the body was not cancelled when the link went down")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervise did not return after cancel")
	}

	// flood the stalled subscriber
	for len(stalled) < cap(stalled) {
		linkUp(t, idx)
		linkDown(t, idx)
		time.Sleep(10 * time.Millisecond)
	}
	linkUp(t, idx)
	linkDown(t, idx)
	time.Sleep(100 * time.Millisecond)

	gone := h.Subscribe("sup1")
	if err := linkDel(idx); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-gone:
			if ev.Gone {
				if ev.Up {
					t.Fatal("a removed interface is up")
				}
				return
			}
		case <-deadline:
			t.Fatal("no removal event")
		}
	}
}

func TestLinkHubWithoutFDsAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	netlinkWithoutFDs(t, func() {
		h := newLinkHub(context.Background())
		if h == nil || h.subs == nil {
			t.Fatal("no inert hub without link events")
		}
	})
}
