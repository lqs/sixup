package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestLinkState(t *testing.T) {
	for ev, want := range map[linkEvent]string{
		{Gone: true}: "removed",
		{Up: true}:   "UP",
		{}:           "DOWN",
	} {
		if got := linkState(ev); got != want {
			t.Errorf("linkState(%+v) = %q, want %q", ev, got, want)
		}
	}
}

// Waiting for an interface that never appears ends with the context, and so does supervising it.
func TestLinkWaitMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if ifi := waitIface(ctx, "sixup-none0"); ifi != nil {
		t.Fatalf("got %v for a missing interface", ifi)
	}
	h := &linkHub{subs: map[string][]chan linkEvent{}}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	h.supervise(ctx, "sixup-none0", func(context.Context, *net.Interface) {
		t.Error("body ran for a missing interface")
	})
}
