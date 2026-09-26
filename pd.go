package main

import (
	"context"
	"net/netip"
	"time"
)

// holdDelegations keeps an unreachable route for every upstream delegation (RFC 7084 WPD-5). The
// LAN and downstream routes are more specific, so only traffic for a part assigned to neither
// reaches it, and that is dropped here instead of looping between this router and the ISP.
func holdDelegations(ctx context.Context, ch <-chan Snapshot) {
	held := map[netip.Prefix]bool{}
	defer func() {
		for p := range held {
			routeUnreachable(p, 0, true)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			now := time.Now()
			want := map[netip.Prefix]time.Duration{}
			for _, w := range s.WAN {
				if w.Source == sourcePD && w.Prefix.Bits() < 64 {
					if v := w.validLeft(now); v > want[w.Prefix] {
						want[w.Prefix] = v
					}
				}
			}
			for p, v := range want {
				if err := routeUnreachable(p, v, false); err != nil {
					warnf("[route] unreachable route for %s failed: %v", p, err)
				} else if !held[p] {
					infof("[route] %s unreachable except for the parts assigned to a LAN or a downstream router", p)
					held[p] = true
				}
			}
			for p := range held {
				if _, ok := want[p]; !ok {
					routeUnreachable(p, 0, true)
					delete(held, p)
				}
			}
		}
	}
}
