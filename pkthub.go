package main

import (
	"context"
	"encoding/binary"
	"log"
	"sync"
	"time"
)

// frameKind selects which frames a listener wants; the union also drives the kernel BPF.
type frameKind uint8

const (
	kindTunnel frameKind = 1 << iota // IPv6 next-header 4, IPv4-in-IPv6
)

// packetHub is the single capture socket per interface, shared so listeners do not each pay for a raw socket.
// It opens on the first Subscribe, closes on the last Close, and reopens after read errors (interface re-created).
type packetHub struct {
	ifname  string
	ctx     context.Context
	mu      sync.Mutex
	subs    map[*packetSub]struct{}
	stop    func()
	kinds   frameKind // filter kinds attached to the current socket
	gen     int
	lastErr string
}

type packetSub struct {
	hub   *packetHub
	kinds frameKind
	C     chan []byte
}

func newPacketHub(ctx context.Context, ifname string) *packetHub {
	return &packetHub{ifname: ifname, ctx: ctx, subs: map[*packetSub]struct{}{}}
}

// Subscribe registers a listener whose C receives only frames in kinds. Callers must Close it.
func (h *packetHub) Subscribe(kinds frameKind) *packetSub {
	s := &packetSub{hub: h, kinds: kinds, C: make(chan []byte, 256)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.reconcile()
	h.mu.Unlock()
	return s
}

func (s *packetSub) Close() {
	h := s.hub
	h.mu.Lock()
	delete(h.subs, s)
	h.reconcile()
	h.mu.Unlock()
}

// reconcile opens, closes or reopens with a new filter to match the listener set. Caller holds the lock.
func (h *packetHub) reconcile() {
	var want frameKind
	for s := range h.subs {
		want |= s.kinds
	}
	if want == 0 {
		if h.stop != nil {
			h.stop()
			h.stop = nil
			log.Printf("[tunnel-capture %s] no listeners, stopping capture", h.ifname)
		}
		return
	}
	if h.stop != nil && want == h.kinds {
		return
	}
	if h.stop != nil {
		h.stop()
		h.stop = nil
	}
	h.kinds = want
	h.gen++
	h.open(h.gen)
}

// open retries every 2s until it succeeds or no listeners remain. Caller holds the lock.
func (h *packetHub) open(gen int) {
	ifi, err := ifaceByName(h.ifname)
	if err == nil {
		frames := make(chan []byte, 256)
		stop, err2 := packetCapture(ifi.Index, frames, h.kinds, func() { h.onReaderExit(gen) })
		if err2 == nil {
			h.stop = stop
			h.lastErr = ""
			go h.dispatch(gen, frames)
			log.Printf("[tunnel-capture %s] capture started (kinds %d)", h.ifname, h.kinds)
			return
		}
		err = err2
	}
	if msg := err.Error(); msg != h.lastErr {
		h.lastErr = msg
		log.Printf("[tunnel-capture %s] capture open failed: %v, retrying every 2s (same error not repeated)", h.ifname, err)
	}
	time.AfterFunc(2*time.Second, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.gen == gen && h.stop == nil && len(h.subs) > 0 {
			h.open(gen)
		}
	})
}

// onReaderExit reopens after a read error, since the interface may have been re-created.
func (h *packetHub) onReaderExit(gen int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gen != gen || h.stop == nil {
		return // closed by us
	}
	h.stop = nil
	if len(h.subs) == 0 || h.ctx.Err() != nil {
		return
	}
	log.Printf("[tunnel-capture %s] socket lost, reopening once the interface returns", h.ifname)
	h.gen++
	g := h.gen
	time.AfterFunc(2*time.Second, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.gen == g && h.stop == nil && len(h.subs) > 0 {
			h.open(g)
		}
	})
}

// dispatch routes frames by kind; slow listeners drop frames rather than block the reader.
func (h *packetHub) dispatch(gen int, frames <-chan []byte) {
	for f := range frames {
		k := classifyFrame(f)
		if k == 0 {
			continue
		}
		h.mu.Lock()
		if h.gen != gen {
			h.mu.Unlock()
			return
		}
		for s := range h.subs {
			if s.kinds&k == 0 {
				continue
			}
			select {
			case s.C <- f:
			default:
			}
		}
		h.mu.Unlock()
	}
}

// classifyFrame mirrors captureFilter for userspace dispatch and covers the case where BPF attach failed.
func classifyFrame(f []byte) frameKind {
	if len(f) < 14 {
		return 0
	}
	et := binary.BigEndian.Uint16(f[12:14])
	off := 14
	for et == 0x8100 || et == 0x88a8 {
		if len(f) < off+4 {
			return 0
		}
		et = binary.BigEndian.Uint16(f[off+2 : off+4])
		off += 4
	}
	if et != 0x86dd || len(f) < off+40 {
		return 0
	}
	if f[off+6] == 4 {
		return kindTunnel
	}
	return 0
}
