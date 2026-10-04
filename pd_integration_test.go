//go:build linux && integration

package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Every upstream delegation shorter than /64 gets an unreachable route for as long as it lasts,
// which goes with it and when holding stops.
func TestPDHoldDelegationsAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ns)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan Snapshot)
	done := make(chan struct{})
	go func() {
		defer close(done)
		inNetns(ns, func() error { holdDelegations(ctx, ch); return nil })
	}()

	now := time.Now()
	up := netip.MustParsePrefix("2001:db8:100::/56")
	held := Snapshot{WAN: []Prefix{
		{Prefix: up, Valid: now.Add(time.Hour), Source: sourcePD},
		{Prefix: up, Valid: now.Add(time.Minute), Source: sourcePD}, // the longer lifetime wins
		{Prefix: netip.MustParsePrefix("2001:db8:200::/64"), Valid: now.Add(time.Hour), Source: sourcePD},
		{Prefix: netip.MustParsePrefix("2001:db8:300::/56"), Valid: now.Add(time.Hour), Source: sourceRA},
		{Valid: now.Add(time.Hour), Source: sourcePD}, // no prefix: the kernel refuses its route
	}}
	unreachable := func() bool { return slices.Contains(routeTypes(t, up), unix.RTN_UNREACHABLE) }
	ch <- held
	ch <- held // taken once the first is done
	if !unreachable() {
		t.Fatalf("no unreachable route for %s", up)
	}
	ch <- Snapshot{}
	ch <- Snapshot{}
	if unreachable() {
		t.Fatalf("the route for %s outlives the delegation", up)
	}
	ch <- held
	cancel()
	<-done
	if unreachable() {
		t.Fatalf("the route for %s outlives holding", up)
	}
}
