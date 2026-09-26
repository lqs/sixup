package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"
)

// PDLease is one prefix delegated to a downstream router, keyed by DUID+IAID, persisted to disk.
type PDLease struct {
	DUID    string       `json:"duid"`
	IAID    uint32       `json:"iaid"`
	Prefix  netip.Prefix `json:"prefix"`
	Iface   string       `json:"iface"`
	Peer    netip.Addr   `json:"peer"` // the router's link-local, next hop of the route to Prefix
	Expires time.Time    `json:"expires"`
}

// pdPool delegates prefixes to downstream routers out of the upstream delegation. One pool serves
// every LAN interface, so delegations never overlap each other or a LAN prefix. Callers hold mu
// across a pick and the commit that follows it.
type pdPool struct {
	plen   int // the shortest prefix length delegated, -dhcp6s-pd-len
	file   string
	mu     sync.Mutex
	leases map[string]*PDLease
}

// maxProbes bounds the search for a free block of one length; a pool that full takes a longer one.
const maxProbes = 4096

func newPDPool(plen int, file string) *pdPool {
	p := &pdPool{plen: plen, file: file, leases: map[string]*PDLease{}}
	b, err := os.ReadFile(file)
	if err != nil {
		return p
	}
	var list []*PDLease
	if err := json.Unmarshal(b, &list); err != nil {
		warnf("[dhcpv6-server] delegation file corrupt, ignoring: %v", err)
		return p
	}
	now := time.Now()
	for _, l := range list {
		if now.Before(l.Expires) {
			p.leases[leaseKey(l.DUID, l.IAID)] = l
		}
	}
	infof("[dhcpv6-server] loaded %d delegations", len(p.leases))
	return p
}

// save writes the delegations to disk; the caller holds mu.
func (p *pdPool) save() {
	if p.file == "" {
		return
	}
	list := make([]*PDLease, 0, len(p.leases))
	for _, l := range p.leases {
		list = append(list, l)
	}
	slices.SortFunc(list, func(a, b *PDLease) int { return a.Prefix.Addr().Compare(b.Prefix.Addr()) })
	b, _ := json.MarshalIndent(list, "", "  ")
	tmp := p.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		debugf("[dhcpv6-server] write delegations failed: %v", err)
		return
	}
	os.Rename(tmp, p.file)
}

// delegable returns the upstream delegations a downstream prefix can be carved from.
func delegable(s Snapshot) []Prefix {
	var out []Prefix
	for _, w := range s.WAN {
		if w.Source == sourcePD && !w.Deprecated && w.Prefix.Bits() < 64 {
			out = append(out, w)
		}
	}
	return out
}

// pick returns the prefix for the IA key and the upstream delegation it lies in: the current
// delegation while it is still usable, else the prefix the router asked for when free, else a
// free block. The block is the router's hinted length when that is longer than p.plen, and grows
// towards /64 until one is free, so a hint for more space is cut down, never refused.
func (p *pdPool) pick(s Snapshot, key string, want netip.Prefix) (netip.Prefix, Prefix, bool) {
	ups := delegable(s)
	usable := func(pf netip.Prefix) (Prefix, bool) {
		if pf.Bits() < p.plen || pf.Bits() > 64 || !p.free(s, pf, key) {
			return Prefix{}, false
		}
		for _, u := range ups {
			if u.Prefix.Bits() < pf.Bits() && u.Prefix.Contains(pf.Addr()) {
				return u, true
			}
		}
		return Prefix{}, false
	}
	if l := p.leases[key]; l != nil {
		if u, ok := usable(l.Prefix); ok {
			return l.Prefix, u, true
		}
	}
	if want.IsValid() && !want.Addr().IsUnspecified() {
		if u, ok := usable(want.Masked()); ok {
			return want.Masked(), u, true
		}
	}
	for _, u := range ups {
		for n := max(p.plen, min(want.Bits(), 64), u.Prefix.Bits()+1); n <= 64; n++ {
			if pf, ok := p.block(s, u.Prefix, n, key); ok {
				return pf, u, true
			}
		}
	}
	return netip.Prefix{}, Prefix{}, false
}

// block finds a free /n inside up, starting from a slot hashed from the key so that a router
// keeps getting the same block.
func (p *pdPool) block(s Snapshot, up netip.Prefix, n int, key string) (netip.Prefix, bool) {
	b := up.Masked().Addr().As16()
	base := binary.BigEndian.Uint64(b[:8])
	count := uint64(1) << (n - up.Bits())
	h := fnv.New64a()
	h.Write([]byte(key))
	start := h.Sum64() % count
	for i := range min(count, maxProbes) {
		binary.BigEndian.PutUint64(b[:8], base+((start+i)%count)<<(64-n))
		pf := netip.PrefixFrom(netip.AddrFrom16(b), n)
		if p.free(s, pf, key) {
			return pf, true
		}
	}
	return netip.Prefix{}, false
}

// free reports whether pf overlaps no LAN prefix, no on-link prefix of the WAN link and no live
// delegation other than key's. An expired one no longer counts, even on an interface that is gone.
func (p *pdPool) free(s Snapshot, pf netip.Prefix, key string) bool {
	for _, ps := range s.LAN {
		for _, l := range ps {
			if l.Prefix.Overlaps(pf) {
				return false
			}
		}
	}
	for _, w := range s.WAN {
		if w.Source == sourceRA && w.Prefix.Overlaps(pf) {
			return false
		}
	}
	now := time.Now()
	for k, l := range p.leases {
		if k != key && now.Before(l.Expires) && l.Prefix.Overlaps(pf) {
			return false
		}
	}
	return true
}

// drop removes and returns the delegations on iface that match; the caller holds mu.
func (p *pdPool) drop(iface string, match func(*PDLease) bool) []*PDLease {
	var out []*PDLease
	for k, l := range p.leases {
		if l.Iface == iface && match(l) {
			delete(p.leases, k)
			out = append(out, l)
		}
	}
	if len(out) > 0 {
		p.save()
	}
	return out
}

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
