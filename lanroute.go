package main

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// lanRoutes keeps what a LAN needs in place of an address of this router in each of its prefixes:
// the on-link route of every prefix, and a proxy neighbor entry for each address of this router
// that lies in one of them but sits on another interface, such as the WAN's /128 in the LAN's /64,
// which LAN hosts resolve on the LAN. Both are read back from the kernel each round, so the
// routes and entries an earlier run left behind go as soon as they are no longer wanted.
type lanRoutes struct {
	ifname string
	layout shared64Layout
	sysctl bool // set proxy_ndp and proxy_delay on the LAN, unless -no-sysctl
	snap   Snapshot
}

func (r *lanRoutes) run(ctx context.Context, hub *linkHub, store *Store, ch <-chan Snapshot) {
	addrs := make(chan struct{}, 1)
	if err := addrWatch(ctx, addrs); err != nil {
		warnf("[lan-route %s] cannot follow address changes, so proxy entries follow only prefix changes: %v", r.ifname, err)
	}
	hub.supervise(ctx, r.ifname, func(cctx context.Context, ifi *net.Interface) {
		if r.sysctl {
			// the kernel answers for proxy entries only with proxy_ndp, and at once only without the delay
			sysctlSet(r.ifname, "proxy_ndp", "1")
			sysctlWrite(filepath.Join("/proc/sys/net/ipv6/neigh", strings.ReplaceAll(r.ifname, ".", "/"), "proxy_delay"), "0")
		}
		r.snap = store.Current()
		r.apply(ifi)
		for {
			select {
			case <-cctx.Done():
				return
			case s := <-ch:
				r.snap = s
				r.apply(ifi)
			case <-addrs:
				r.apply(ifi)
			}
		}
	})
}

// apply brings the routes and proxy entries of the LAN in line with the snapshot and the
// addresses of this router.
func (r *lanRoutes) apply(ifi *net.Interface) {
	now := time.Now()
	var have []netip.Prefix
	var proxied []netip.Addr
	addrs, err := addrList(0)
	if err == nil {
		have, err = lanRouteList(ifi.Index)
	}
	if err == nil {
		proxied, err = neighProxyList(ifi.Index)
	}
	if err != nil {
		warnf("[lan-route %s] cannot read the addresses, routes and proxy entries: %v", r.ifname, err)
		return
	}
	want := lanRoutePlan(r.snap, r.ifname, r.layout, addrs, ifi.Index, now)
	for dst, rt := range want {
		if err := lanRouteSet(ifi.Index, dst, rt.src, rt.expires); err != nil {
			warnf("[lan-route %s] failed to route %s: %v", r.ifname, dst, err)
			continue
		}
		if !slices.Contains(have, dst) {
			infof("[lan-route %s] routed %s on-link, source %s", r.ifname, dst, rt.srcName())
		}
	}
	for _, dst := range have {
		if _, ok := want[dst]; ok {
			continue
		}
		if err := lanRouteDel(ifi.Index, dst); err != nil {
			warnf("[lan-route %s] failed to remove the route of %s: %v", r.ifname, dst, err)
			continue
		}
		infof("[lan-route %s] removed the route of %s", r.ifname, dst)
	}

	prefixes := r.snap.LAN[r.ifname]
	wantP := lanProxyPlan(prefixes, addrs, ifi.Index, now)
	for _, a := range wantP {
		if slices.Contains(proxied, a) {
			continue
		}
		if err := neighProxySet(ifi.Index, a, false); err != nil {
			warnf("[lan-route %s] failed to answer for %s: %v", r.ifname, a, err)
			continue
		}
		infof("[lan-route %s] answering neighbor solicitations for %s, an address of this router on another interface", r.ifname, a)
	}
	for _, a := range proxied {
		// an entry outside the LAN prefixes is not one of ours to judge
		if slices.Contains(wantP, a) || !slices.ContainsFunc(prefixes, func(p Prefix) bool { return p.Prefix.Contains(a) }) {
			continue
		}
		if err := neighProxySet(ifi.Index, a, true); err != nil {
			warnf("[lan-route %s] failed to stop answering for %s: %v", r.ifname, a, err)
			continue
		}
		infof("[lan-route %s] no longer answering for %s", r.ifname, a)
	}
}

// lanRoute is the on-link route of one LAN prefix.
type lanRoute struct {
	src     netip.Addr // address of this router on the LAN in the prefix, the source to reach it from
	expires time.Duration
}

func (rt lanRoute) srcName() string {
	if rt.src.IsValid() {
		return rt.src.String()
	}
	return "by address selection"
}

// lanRoutePlan routes every prefix of the LAN on-link until it expires, except a /64 the layout
// leaves on the WAN, whose LAN hosts get /128 routes from the NDP proxy. The source is the
// address of this router on the LAN in the prefix: its ULA one, which is deprecated so that
// address selection never picks it for anything else. A tentative address cannot be a source
// yet; the route takes it once DAD lets it go.
func lanRoutePlan(s Snapshot, iface string, layout shared64Layout, addrs []ifAddr, ifindex int, now time.Time) map[netip.Prefix]lanRoute {
	out := map[netip.Prefix]lanRoute{}
	for _, p := range s.LAN[iface] {
		valid := p.validLeft(now)
		if valid == 0 || layout.plen(sideLAN, s.sharedWith(p.Prefix)) == 128 {
			continue
		}
		rt := lanRoute{expires: valid}
		for _, ia := range addrs {
			if ia.Index == ifindex && p.Prefix.Contains(ia.Addr) && ia.Flags&(ifaFTentative|ifaFDadFailed) == 0 &&
				(!rt.src.IsValid() || ia.Addr.Less(rt.src)) {
				rt.src = ia.Addr
			}
		}
		out[p.Prefix] = rt
	}
	return out
}

// lanProxyPlan lists the addresses of this router on other interfaces that lie in a prefix of
// the LAN, sorted.
func lanProxyPlan(prefixes []Prefix, addrs []ifAddr, ifindex int, now time.Time) []netip.Addr {
	var out []netip.Addr
	for _, ia := range addrs {
		if ia.Index == ifindex || !ia.Addr.IsGlobalUnicast() || ia.Flags&ifaFDadFailed != 0 {
			continue
		}
		if slices.ContainsFunc(prefixes, func(p Prefix) bool { return p.validLeft(now) > 0 && p.Prefix.Contains(ia.Addr) }) {
			out = append(out, ia.Addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}
