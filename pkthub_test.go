package main

import (
	"context"
	"testing"
)

func TestClassifyFrameMalformed(t *testing.T) {
	tunnel := frame(4, 0, 0)
	for _, f := range [][]byte{
		tunnel[:13],
		append(append([]byte{}, tunnel[:12]...), 0x88, 0xa8, 0x00), // tag cut short
		tunnel[:14+39],
		frame(58, 135<<8, 0)[:14+40], // no ICMPv6 type
		append(append([]byte{}, tunnel[:12]...), 0x08, 0x00),
	} {
		if k := classifyFrame(f); k != 0 {
			t.Fatalf("%x classified as %d", f, k)
		}
	}
}

// dispatch hands each frame only to the listeners that want its kind, drops what a full listener
// cannot take, and stops once the socket it reads from has been replaced.
func TestPacketHubDispatch(t *testing.T) {
	h := newPacketHub(context.Background(), "sixup-none0")
	want := &packetSub{hub: h, kinds: kindTunnel, C: make(chan []byte, 1)}
	other := &packetSub{hub: h, kinds: 0, C: make(chan []byte, 1)}
	h.subs[want], h.subs[other] = struct{}{}, struct{}{}
	h.gen = 2
	frames := make(chan []byte, 3)
	frames <- frame(17, 547, 546)
	frames <- frame(4, 0, 0)
	frames <- frame(4, 0x100, 1) // want is full by now
	close(frames)
	h.dispatch(2, frames)
	if len(want.C) != 1 || (<-want.C)[54] != 0 || len(other.C) != 0 {
		t.Fatal("only the first tunnel frame should have reached the tunnel listener")
	}

	stale := make(chan []byte, 2)
	stale <- frame(4, 0, 0)
	stale <- frame(4, 0, 0)
	h.dispatch(1, stale) // returns on the first frame, leaving the second
	if len(want.C) != 0 || len(stale) != 1 {
		t.Fatal("a reader of an old socket must not deliver")
	}
}

// Without the interface the socket cannot open; the last listener leaving stops the retries.
func TestPacketHubWithoutInterface(t *testing.T) {
	h := newPacketHub(context.Background(), "sixup-none0")
	s := h.Subscribe(kindTunnel)
	if h.stop != nil || h.lastErr == "" {
		t.Fatalf("open should have failed: %+v", h)
	}
	s.Close()
	if len(h.subs) != 0 || h.stop != nil {
		t.Fatalf("%+v", h)
	}
}

// A reader exiting is ignored when the hub replaced or closed its socket, or nobody listens any more.
func TestPacketHubReaderExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := newPacketHub(ctx, "sixup-none0")
	h.gen = 3
	h.onReaderExit(2) // an older socket
	h.stop = func() {}
	h.onReaderExit(3) // nobody listens
	if h.stop != nil || h.gen != 3 {
		t.Fatalf("%+v", h)
	}
	h.subs[&packetSub{hub: h, kinds: kindTunnel}] = struct{}{}
	h.stop = func() {}
	cancel()
	h.onReaderExit(3) // shutting down
	if h.stop != nil || h.gen != 3 {
		t.Fatalf("%+v", h)
	}
}
