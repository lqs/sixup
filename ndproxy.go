package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// ndProxy replaces ndppd: it treats the WAN and LAN interfaces as one link for neighbor
// discovery (the shape of RFC 4389). forward mode works both ways: an NS on one side triggers a
// probe on the other, and on a hit it replies for the target and adds the /128 route the layout needs.
// proxyMode is what -ndproxy-mode selects; auto behaves like forward when the prefix is a /64 and
// stays off otherwise.
type proxyMode string

const (
	proxyAuto    proxyMode = "auto"
	proxyOff     proxyMode = "off"
	proxyStatic  proxyMode = "static"
	proxyPrefix  proxyMode = "prefix"
	proxyForward proxyMode = "forward"
)

// maxProxySessions caps the session table. A real LAN holds far fewer neighbours than this; the
// limit exists so that a host walking the /64 cannot grow the table, and the /128 routes derived
// from it, without bound. Hitting it costs the newest targets their proxy entry, never the process.
const maxProxySessions = 4096

// maxAskers caps how many hosts are remembered as waiting for one probe. They all receive the same
// answer, so a longer list buys nothing and is one more thing an attacker could grow.
const maxAskers = 8

type ndProxy struct {
	mode       proxyMode
	autoOn     bool // whether auto mode is currently enabled
	wanIf      string
	lanIf      string
	static     []netip.Prefix
	exclude    []netip.Prefix
	ttl        time.Duration
	layout     shared64Layout
	wanIfi     *net.Interface
	lanIfi     *net.Interface
	wanConn    *ndp.Conn
	lanConn    *ndp.Conn
	mu         sync.Mutex
	prefixes   []netip.Prefix // proxy scope driven by the snapshot
	sessions   map[netip.Addr]*proxySession
	pending    map[netip.Addr][]solicitor // forward-mode probes awaiting an NA: target -> askers
	kernelSet  map[netip.Addr]int         // targets with a /128 route -> outgoing interface index
	selfAddrs  map[netip.Addr]bool        // our own addresses on both sides, to ignore packets we sent
	fullSince  time.Time                  // when the table was last found full, to stop sweeping it per packet
	warnedFull bool                       // the table being full is reported once per episode
}

type proxySession struct {
	State   string    `json:"state"`          // probing / valid / invalid
	Side    side      `json:"side,omitempty"` // side the host is on: wan / lan
	Expires time.Time `json:"expires"`
	Asked   time.Time `json:"-"`
}

type solicitor struct {
	addr netip.Addr
	side side
}

// setPrefixes updates the proxy scope from a snapshot. auto mode enables only when a LAN /64 is
// also the upstream's on-link /64 on a broadcast WAN, where the upstream resolves LAN addresses.
func (n *ndProxy) setPrefixes(s Snapshot) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.mode == "auto" {
		// A point-to-point WAN has no address resolution: the upstream sends the whole /64 down
		// the link, so there is nothing to answer for (RFC 7278).
		on := !n.wanPointToPoint() && slices.ContainsFunc(s.LAN[n.lanIf], func(p Prefix) bool {
			return !p.Deprecated && s.sharedWith(p.Prefix)
		})
		if on != n.autoOn {
			if on {
				infof("[ndp-proxy] LAN shares the on-link /64 with the upstream, enabling NDP proxy (forward mode)")
			} else {
				infof("[ndp-proxy] LAN prefix is routed to us, disabling NDP proxy")
			}
			n.autoOn = on
		}
		if !on {
			n.prefixes = n.prefixes[:0]
			return
		}
	}
	n.prefixes = n.prefixes[:0]
	for _, p := range s.LAN[n.lanIf] {
		if !p.Deprecated && p.Source != "ula" {
			n.prefixes = append(n.prefixes, p.Prefix)
		}
	}
}

func (n *ndProxy) wanPointToPoint() bool {
	return n.wanIfi != nil && n.wanIfi.Flags&net.FlagPointToPoint != 0
}

func (n *ndProxy) effectiveMode() proxyMode {
	if n.mode == "auto" {
		return proxyForward
	}
	return n.mode
}

func (n *ndProxy) run(ctx context.Context, hub *linkHub, store *Store, ch <-chan Snapshot) {
	n.sessions = map[netip.Addr]*proxySession{}
	n.pending = map[netip.Addr][]solicitor{}
	n.kernelSet = map[netip.Addr]int{}
	hub.supervise(ctx, n.wanIf, func(cctx context.Context, ifi *net.Interface) {
		n.wanIfi = ifi
		if n.lanIfi = waitIface(cctx, n.lanIf); n.lanIfi == nil {
			return
		}
		n.mu.Lock()
		// kernel proxy entries and /128 routes are lost once the interface is rebuilt
		n.kernelSet = map[netip.Addr]int{}
		n.refreshSelfAddrs()
		n.mu.Unlock()
		n.setPrefixes(store.Current())
		n.serve(cctx, ch)
	})
}

// refreshSelfAddrs collects our own addresses on both sides; the caller holds the lock.
func (n *ndProxy) refreshSelfAddrs() {
	n.selfAddrs = map[netip.Addr]bool{}
	for _, ifi := range []*net.Interface{n.wanIfi, n.lanIfi} {
		if ifi == nil {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, x := range addrs {
			if ipn, ok := x.(*net.IPNet); ok {
				if a, ok := netip.AddrFromSlice(ipn.IP); ok {
					n.selfAddrs[a.Unmap()] = true
				}
			}
		}
	}
}

func openNDConn(ifi *net.Interface, types ...ipv6.ICMPType) (*ndp.Conn, error) {
	c, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return nil, err
	}
	c.SetControlMessage(ipv6.FlagHopLimit, true)
	f := &ipv6.ICMPFilter{}
	f.SetAll(true)
	for _, t := range types {
		f.Accept(t)
	}
	c.SetICMPFilter(f)
	return c, nil
}

func (n *ndProxy) serve(ctx context.Context, ch <-chan Snapshot) {
	if n.effectiveMode() == proxyStatic {
		n.applyStatic()
		<-ctx.Done()
		return
	}
	var err error
	n.wanConn, err = openNDConn(n.wanIfi, ipv6.ICMPTypeNeighborSolicitation, ipv6.ICMPTypeNeighborAdvertisement)
	if err != nil {
		errorf("[ndp-proxy] failed to open %s: %v", n.wanIf, err)
		return
	}
	defer n.wanConn.Close()
	// upstream NS goes to a solicited-node multicast group; joining one per address in the prefix is impractical, so receive in promiscuous mode
	setAllMulti(n.wanIfi.Name)

	if n.effectiveMode() == proxyForward {
		n.lanConn, err = openNDConn(n.lanIfi, ipv6.ICMPTypeNeighborSolicitation, ipv6.ICMPTypeNeighborAdvertisement)
		if err != nil {
			errorf("[ndp-proxy] failed to open %s: %v", n.lanIf, err)
			return
		}
		defer n.lanConn.Close()
		setAllMulti(n.lanIfi.Name)
		go n.reader(sideLAN, n.lanConn)
	}
	go n.reader(sideWAN, n.wanConn)
	gc := time.NewTicker(n.ttl / 2)
	defer gc.Stop()
	selfTick := time.NewTicker(30 * time.Second)
	defer selfTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			n.setPrefixes(s)
		case <-selfTick.C:
			n.mu.Lock()
			n.refreshSelfAddrs()
			n.mu.Unlock()
		case <-gc.C:
			n.mu.Lock()
			n.sweep(time.Now())
			n.mu.Unlock()
		}
	}
}

// applyStatic implements static mode through the kernel proxy neighbor table.
func (n *ndProxy) applyStatic() {
	// the kernel proxy neighbor table only takes effect with proxy_ndp=1
	sysctlSet(n.wanIf, "proxy_ndp", "1")
	for _, p := range n.static {
		if p.Bits() != 128 {
			warnf("[ndp-proxy] static mode only accepts single addresses, skipping %s", p)
			continue
		}
		if err := neighProxySet(n.wanIfi.Index, p.Addr(), false); err != nil {
			warnf("[ndp-proxy] failed to add proxy %s: %v", p.Addr(), err)
		}
	}
}

// sweep drops the sessions whose time is up; the caller holds the lock.
func (n *ndProxy) sweep(now time.Time) {
	for a, s := range n.sessions {
		if now.After(s.Expires) {
			n.forget(a)
		}
	}
}

// forget removes a session and everything derived from it; the caller holds the lock.
func (n *ndProxy) forget(a netip.Addr) {
	delete(n.sessions, a)
	delete(n.pending, a)
	n.dropRoute(a)
}

// admit makes room for one new session and reports whether it fits. Entries whose time is up go
// first, then the probes still waiting for an answer: those are unconfirmed, and a host walking the
// prefix produces almost nothing else. Neighbours an NA has confirmed are kept and the newcomer is
// turned away instead, so a flood degrades the proxy for new targets rather than for the hosts
// already using it. The caller holds the lock.
func (n *ndProxy) admit(now time.Time) bool {
	if len(n.sessions) < maxProxySessions {
		return true
	}
	// Walking the table costs O(n); without this an attacker would pay one packet for one walk.
	if now.Sub(n.fullSince) < time.Second {
		return false
	}
	n.sweep(now)
	if len(n.sessions) >= maxProxySessions {
		for a, s := range n.sessions {
			if s.State == "probing" {
				n.forget(a)
			}
		}
	}
	if len(n.sessions) < maxProxySessions {
		n.warnedFull = false
		return true
	}
	n.fullSince = now
	if !n.warnedFull {
		n.warnedFull = true
		warnf("[ndp-proxy] session table full at %d entries, refusing new targets; a host may be scanning the prefix", maxProxySessions)
	}
	return false
}

// covered reports whether a target falls in the proxy scope; the caller holds the lock.
func (n *ndProxy) covered(a netip.Addr) bool {
	for _, e := range n.exclude {
		if e.Contains(a) {
			return false
		}
	}
	// never proxy the router's own addresses
	if n.selfAddrs[a] {
		return false
	}
	for _, p := range n.static {
		if p.Contains(a) {
			return true
		}
	}
	for _, p := range n.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (n *ndProxy) conn(side side) *ndp.Conn {
	if side == sideWAN {
		return n.wanConn
	}
	return n.lanConn
}

func (n *ndProxy) ifi(side side) *net.Interface {
	if side == sideWAN {
		return n.wanIfi
	}
	return n.lanIfi
}

// reader handles the NS and NA arriving on one side.
func (n *ndProxy) reader(side side, c *ndp.Conn) {
	for {
		msg, cm, from, err := c.ReadFrom()
		if err != nil {
			return
		}
		if cm == nil || cm.HopLimit != 255 {
			continue
		}
		n.mu.Lock()
		self := n.selfAddrs[from]
		switch m := msg.(type) {
		case *ndp.NeighborSolicitation:
			if self {
				// our own probe NS echoed back, ignore it; otherwise the kernel is resolving a neighbor for
				// the router itself, so probe the other side and add the /128 route before the kernel retransmits
				if ps := n.sessions[m.TargetAddress]; ps != nil && ps.State == "probing" && ps.Side == side {
					n.mu.Unlock()
					continue
				}
				n.onSolicit(side, m.TargetAddress, netip.Addr{})
				continue
			}
			n.onSolicit(side, m.TargetAddress, from)
		case *ndp.NeighborAdvertisement:
			if self {
				n.mu.Unlock()
				continue
			}
			n.onAdvert(side, m.TargetAddress)
		default:
			n.mu.Unlock()
		}
	}
}

// onSolicit handles an NS received on side; it is entered holding the lock and releases it before returning.
// A zero from means the NS came from the router itself (kernel neighbor resolution): probe only, never reply.
func (n *ndProxy) onSolicit(side side, target, from netip.Addr) {
	if !n.covered(target) {
		n.mu.Unlock()
		return
	}
	self := !from.IsValid()
	now := time.Now()
	// a LAN host's NS carries the address it is actually using, so learn it here instead of waiting for the upstream to ask for the wan-layout /128 route
	if side == sideLAN && !self && n.effectiveMode() == proxyForward && !from.IsUnspecified() && from != target && n.covered(from) {
		n.learn(sideLAN, from, now)
	}
	// prefix mode replies unconditionally on the WAN side for LAN hosts only, never the reverse
	if n.effectiveMode() == proxyPrefix {
		if side != sideWAN || self {
			n.mu.Unlock()
			return
		}
		if n.admit(now) {
			n.sessions[target] = &proxySession{State: "valid", Side: sideLAN, Expires: now.Add(n.ttl)}
		}
		n.mu.Unlock()
		n.reply(sideWAN, target, from)
		return
	}
	s := n.sessions[target]
	switch {
	case s != nil && s.State == "valid":
		n.mu.Unlock()
		if s.Side != side && !self {
			// the host is on the other side, so reply for it; on the same side they talk directly
			n.reply(side, target, from)
		}
		return
	case s != nil && s.State == "invalid":
		n.mu.Unlock()
		return
	}
	// forward mode: probe the other side, suppressing duplicate NS
	probeSide := side.other()
	if s != nil && s.State == "probing" && now.Sub(s.Asked) < time.Second {
		if !self {
			n.pending[target] = appendAsker(n.pending[target], solicitor{from, side})
		}
		n.mu.Unlock()
		return
	}
	if s == nil {
		if !n.admit(now) {
			n.mu.Unlock()
			return
		}
		s = &proxySession{State: "probing"}
		n.sessions[target] = s
	}
	s.Asked = now
	s.Side = probeSide
	s.Expires = now.Add(3 * time.Second)
	if !self {
		n.pending[target] = appendAsker(n.pending[target], solicitor{from, side})
	}
	n.mu.Unlock()
	n.probe(probeSide, target)
}

// onAdvert handles an NA received on side, meaning the target lives there; it is entered holding the lock and releases it before returning.
func (n *ndProxy) onAdvert(side side, target netip.Addr) {
	s := n.sessions[target]
	if s == nil {
		// a LAN host sends an unsolicited NA once DAD completes, which lets us learn it early
		if side == sideLAN && n.covered(target) {
			n.learn(sideLAN, target, time.Now())
		}
		n.mu.Unlock()
		return
	}
	n.learn(side, target, time.Now())
	askers := n.pending[target]
	delete(n.pending, target)
	n.mu.Unlock()
	for _, a := range askers {
		if a.side != side {
			n.reply(a.side, target, a.addr)
		}
	}
}

// learn records that the target is on side and adds the /128 route the layout needs; the caller holds the lock.
func (n *ndProxy) learn(side side, target netip.Addr, now time.Time) {
	s := n.sessions[target]
	if s == nil {
		if !n.admit(now) {
			return
		}
		s = &proxySession{}
		n.sessions[target] = s
	}
	s.State = "valid"
	s.Side = side
	s.Expires = now.Add(n.ttl)
	need := (side == sideLAN && n.layout.lanHostRoutes()) || (side == sideWAN && !n.layout.wanOnLink())
	ifi := n.ifi(side)
	if !need || ifi == nil {
		return
	}
	if idx, ok := n.kernelSet[target]; ok && idx == ifi.Index {
		return
	}
	n.dropRoute(target)
	if err := routeSet(ifi.Index, netip.PrefixFrom(target, 128), netip.Addr{}, 0, 0); err == nil {
		n.kernelSet[target] = ifi.Index
	}
}

// dropRoute removes the /128 route added for a target; the caller holds the lock.
func (n *ndProxy) dropRoute(target netip.Addr) {
	if idx, ok := n.kernelSet[target]; ok {
		routeDel(idx, netip.PrefixFrom(target, 128), netip.Addr{}, 0)
		delete(n.kernelSet, target)
	}
}

func appendAsker(list []solicitor, a solicitor) []solicitor {
	for _, x := range list {
		if x == a {
			return list
		}
	}
	if len(list) >= maxAskers {
		return list
	}
	return append(list, a)
}

// probe sends an NS on side to find out whether the target exists.
func (n *ndProxy) probe(side side, target netip.Addr) {
	c, ifi := n.conn(side), n.ifi(side)
	if c == nil || ifi == nil {
		return
	}
	snm, err := ndp.SolicitedNodeMulticast(target)
	if err != nil {
		return
	}
	ns := &ndp.NeighborSolicitation{
		TargetAddress: target,
		Options:       []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: ifi.HardwareAddr}},
	}
	if err := c.WriteTo(ns, ifCM(ifi), snm.WithZone(ifi.Name)); err != nil {
		debugf("[ndp-proxy] probe on the %s side for %s failed: %v", side, target, err)
	}
}

// reply sends an NA with Override on side; the target link-layer address is that side's own interface MAC.
func (n *ndProxy) reply(side side, target, to netip.Addr) {
	c, ifi := n.conn(side), n.ifi(side)
	if c == nil || ifi == nil {
		return
	}
	na := &ndp.NeighborAdvertisement{
		Router:        true,
		Solicited:     !to.IsUnspecified(),
		Override:      true,
		TargetAddress: target,
		Options:       []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Target, Addr: ifi.HardwareAddr}},
	}
	dst := to
	if to.IsUnspecified() {
		dst = allNodes
	}
	if err := c.WriteTo(na, ifCM(ifi), dst.WithZone(ifi.Name)); err != nil {
		debugf("[ndp-proxy] reply on the %s side for %s failed: %v", side, target, err)
		return
	}
	debugf("[ndp-proxy] proxy reply on the %s side for %s -> %s", side, target, dst)
}
