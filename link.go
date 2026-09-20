package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// waitIface polls every 2s until the interface exists and is UP; returns nil on ctx cancel.
func waitIface(ctx context.Context, name string) *net.Interface {
	warned := false
	for {
		ifi, err := ifaceByName(name)
		if err == nil && ifi.Flags&net.FlagUp != 0 {
			if warned {
				log.Printf("[link-watch] interface %s ready (index %d)", name, ifi.Index)
			}
			return ifi
		}
		if !warned {
			if err != nil {
				log.Printf("[link-watch] interface %s missing, retrying every 2s", name)
			} else {
				log.Printf("[link-watch] interface %s not UP, retrying every 2s", name)
			}
			warned = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

// linkHub fans out netlink link events by interface name.
// Without netlink (non-Linux) it is inert and components fall back to retry-on-error.
type linkHub struct {
	mu   sync.Mutex
	subs map[string][]chan linkEvent
}

func newLinkHub(ctx context.Context) *linkHub {
	h := &linkHub{subs: map[string][]chan linkEvent{}}
	ch := make(chan linkEvent, 32)
	if err := linkWatch(ch); err != nil {
		log2("[link-watch] cannot subscribe to link events: %v", err)
		return h
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-ch:
				h.mu.Lock()
				for _, s := range h.subs[ev.Name] {
					select {
					case s <- ev:
					default:
					}
				}
				h.mu.Unlock()
			}
		}
	}()
	return h
}

func (h *linkHub) Subscribe(name string) chan linkEvent {
	ch := make(chan linkEvent, 8)
	h.mu.Lock()
	h.subs[name] = append(h.subs[name], ch)
	h.mu.Unlock()
	return ch
}

// supervise runs body once the interface is ready and cancels it when the link goes down or away.
// Sockets bound to the old interface are unusable after re-creation, so each round reopens them.
func (h *linkHub) supervise(ctx context.Context, name string, body func(ctx context.Context, ifi *net.Interface)) {
	events := h.Subscribe(name)
	for ctx.Err() == nil {
		ifi := waitIface(ctx, name)
		if ifi == nil {
			return
		}
		cctx, cancel := context.WithCancel(ctx)
		go func() {
			for {
				select {
				case <-cctx.Done():
					return
				case ev := <-events:
					if !ev.Up || ev.Gone {
						log.Printf("[link-watch] interface %s %s, closing its sockets until it returns", name, linkState(ev))
						cancel()
						return
					}
				}
			}
		}()
		body(cctx, ifi)
		cancel()
		if ctx.Err() != nil {
			return
		}
		// Avoid a hot loop when body fails immediately
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func linkState(ev linkEvent) string {
	if ev.Gone {
		return "removed"
	}
	if ev.Up {
		return "UP"
	}
	return "DOWN"
}
