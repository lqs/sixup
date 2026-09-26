package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// raClient is the RA host side on the WAN interface: a prefix source besides PD, and the only
// place a default route can come from, since DHCPv6 carries no gateway.
type raClient struct {
	ifname string
	ifi    *net.Interface
	conn   *ndp.Conn
	store  *Store
	dhcp   *dhcpClient // started according to the M/O bits
	slaac  bool        // do SLAAC on the WAN
	iid    iidPolicy   // IID source of the SLAAC address reported as the WAN address (the first -wan-iid entry)
	layout shared64Layout
	secret []byte // RFC 7217 secret

	routers     map[netip.Addr]*routerInfo
	started     bool
	lastSet     map[netip.Prefix]bool // RA prefix set from the last publish, for change detection
	lastOpenErr string
}

type routerInfo struct {
	pref     ndp.Preference
	lifetime time.Time // default route expiry; zero means lifetime=0
	prefixes []Prefix  // prefixes advertised by this router
	dns      []netip.Addr
	dnssl    []string
	pref64   netip.Prefix
	mtu      int
	routes   map[netip.Prefix]time.Time
	seen     time.Time
	dhcp     bool // M or O set: the router says DHCPv6 is available
}

func routerMetric(p ndp.Preference) uint32 {
	switch p {
	case ndp.High:
		return 512
	case ndp.Low:
		return 2048
	}
	return 1024
}

func (c *raClient) run(ctx context.Context, hub *linkHub) {
	hub.supervise(ctx, c.ifname, c.serve)
}

// serve runs on one interface instance; ctx is cancelled when the interface goes down or is recreated, and supervise reruns it.
func (c *raClient) serve(ctx context.Context, ifi *net.Interface) {
	c.ifi = ifi
	// take over RA handling from the kernel so two implementations do not both configure the interface
	sysctlSet(c.ifname, "accept_ra", "0")
	sysctlSet(c.ifname, "autoconf", "0")
	// a recreated interface has lost its routes and addresses; reset and tell downstream to revoke
	c.routers = map[netip.Addr]*routerInfo{}
	c.store.Set("ra", SourceUpdate{})
	conn, _, err := ndp.Listen(c.ifi, ndp.LinkLocal)
	if err != nil {
		// supervise retries every second; report each distinct error once
		if msg := err.Error(); msg != c.lastOpenErr {
			c.lastOpenErr = msg
			errorf("[ra-client] failed to open %s: %v (further identical errors suppressed)", c.ifname, err)
		}
		return
	}
	c.lastOpenErr = ""
	defer conn.Close()
	conn.SetControlMessage(ipv6.FlagHopLimit, true)
	f := &ipv6.ICMPFilter{}
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeRouterAdvertisement)
	conn.SetICMPFilter(f)
	c.conn = conn

	msgs := make(chan raMsg, 8)
	go func() {
		for {
			m, cm, from, err := conn.ReadFrom()
			if err != nil {
				return
			}
			ra, ok := m.(*ndp.RouterAdvertisement)
			if !ok || cm == nil || cm.HopLimit != 255 || !from.IsLinkLocalUnicast() {
				continue
			}
			msgs <- raMsg{ra, from}
		}
	}()

	// send up to 3 RS at startup, 4s apart
	rsLeft := 3
	rsTimer := time.NewTimer(0)
	expire := time.NewTimer(time.Hour)
	for {
		select {
		case <-ctx.Done():
			return
		case <-rsTimer.C:
			if rsLeft == 0 && len(c.routers) == 0 {
				// No RA after all RS: a point-to-point link like PPP needs no gateway address, so
				// point the default route at the device. Ethernet has no such option and must wait
				pppDefaultRoute(c.ifi)
			}
			if rsLeft > 0 && len(c.routers) == 0 {
				rsLeft--
				rs := &ndp.RouterSolicitation{Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: c.ifi.HardwareAddr}}}
				if err := conn.WriteTo(rs, ifCM(c.ifi), allRouters2.WithZone(c.ifi.Name)); err != nil {
					debugf("[ra-client] failed to send RS: %v", err)
					statInc("send_error")
				} else {
					debugf("[ra-client] sent RS (%d of 3)", 3-rsLeft)
					statInc("rs_sent")
				}
				rsTimer.Reset(4 * time.Second)
			}
		case m := <-msgs:
			c.handle(m.ra, m.from)
			c.publish()
			expire.Reset(c.nextExpiry())
		case <-expire.C:
			c.publish()
			expire.Reset(c.nextExpiry())
		}
	}
}

// pppDefaultRoute adds a gateway-less default route on a point-to-point interface with a metric
// above any RA route, so a later RA still wins. Only PPP-style single-peer links allow this.
func pppDefaultRoute(ifi *net.Interface) {
	if ifi == nil || ifi.Flags&net.FlagPointToPoint == 0 {
		return
	}
	if err := routeSet(ifi.Index, netip.MustParsePrefix("::/0"), netip.Addr{}, 4096, 0); err != nil {
		warnf("[ra-client] failed to set device default route on %s: %v", ifi.Name, err)
		return
	}
	infof("[ra-client] %s is point-to-point with no RA; default route points at the device (metric 4096, an RA takes over when it arrives)", ifi.Name)
	statInc("ppp_default_route")
}

type raMsg struct {
	ra   *ndp.RouterAdvertisement
	from netip.Addr
}

func (c *raClient) nextExpiry() time.Duration {
	next := time.Hour
	now := time.Now()
	for _, r := range c.routers {
		if !r.lifetime.IsZero() {
			if d := r.lifetime.Sub(now); d < next {
				next = d
			}
		}
		for _, p := range r.prefixes {
			if d := p.Valid.Sub(now); d < next {
				next = d
			}
			if d := p.Preferred.Sub(now); d > 0 && d < next {
				next = d
			}
		}
	}
	if next < time.Second {
		next = time.Second
	}
	return next + 100*time.Millisecond
}

// raInfo is what one Router Advertisement says, before any side effect is applied.
// Kept separate from handle so the parsing rules can be tested without sockets.
type raInfo struct {
	prefixes []Prefix                       // usable PIOs
	revoked  []netip.Prefix                 // PIOs advertised with valid lifetime 0
	onLink   map[netip.Prefix]time.Duration // PIOs that need an on-link route, with lifetime
	routes   map[netip.Prefix]rioInfo       // RIOs; lifetime 0 means withdraw
	dns      []netip.Addr
	dnssl    []string
	pref64   netip.Prefix
	mtu      int // 0 when absent or outside [1280, ifMTU]
	badMTU   int // the rejected MTU value, for logging
}

type rioInfo struct {
	pref     ndp.Preference
	lifetime time.Duration
}

// parseRA applies RFC 4861 host rules to one RA. slaac marks /64 PIOs with the A bit as
// SLAAC candidates; wanOnLink is false when the shared /64 lives on the LAN side, in
// which case no on-link route is installed on the WAN for a /64 (it would compete with LAN).
func parseRA(ra *ndp.RouterAdvertisement, now time.Time, ifMTU int, slaac, wanOnLink bool) raInfo {
	info := raInfo{onLink: map[netip.Prefix]time.Duration{}, routes: map[netip.Prefix]rioInfo{}}
	for _, o := range ra.Options {
		switch opt := o.(type) {
		case *ndp.PrefixInformation:
			pf := netip.PrefixFrom(opt.Prefix, int(opt.PrefixLength)).Masked()
			if pf.Addr().IsLinkLocalUnicast() {
				continue
			}
			if opt.ValidLifetime == 0 {
				info.revoked = append(info.revoked, pf)
				continue
			}
			// A router with lifetime 0 is not a default router; RFC 4861 still allows its
			// PIOs, but in practice that is a router shutting down, so do not adopt them.
			if ra.RouterLifetime == 0 {
				continue
			}
			p := Prefix{Prefix: pf, Preferred: now.Add(opt.PreferredLifetime), Valid: now.Add(opt.ValidLifetime), Source: "ra"}
			p.SLAAC = opt.AutonomousAddressConfiguration && opt.PrefixLength == 64 && slaac
			info.prefixes = append(info.prefixes, p)
			if opt.OnLink && (opt.PrefixLength != 64 || wanOnLink) {
				info.onLink[pf] = opt.ValidLifetime
			}
		case *ndp.RouteInformation:
			pf := netip.PrefixFrom(opt.Prefix, int(opt.PrefixLength)).Masked()
			info.routes[pf] = rioInfo{opt.Preference, opt.RouteLifetime}
		case *ndp.RecursiveDNSServer:
			if opt.Lifetime > 0 {
				info.dns = append(info.dns, opt.Servers...)
			}
		case *ndp.DNSSearchList:
			if opt.Lifetime > 0 {
				info.dnssl = append(info.dnssl, opt.DomainNames...)
			}
		case *ndp.PREF64:
			if opt.Lifetime > 0 {
				info.pref64 = opt.Prefix
			}
		case *ndp.MTU:
			m := int(opt.MTU)
			if m >= 1280 && (ifMTU <= 0 || m <= ifMTU) {
				info.mtu = m
			} else {
				info.badMTU = m
			}
		}
	}
	return info
}

func (c *raClient) handle(ra *ndp.RouterAdvertisement, from netip.Addr) {
	now := time.Now()
	statInc("ra_recv")
	debugf("[ra-client] RA from %s, M=%v O=%v lifetime=%s, %d options", from, ra.ManagedConfiguration, ra.OtherConfiguration, ra.RouterLifetime, len(ra.Options))
	r := c.routers[from]
	if r == nil {
		r = &routerInfo{routes: map[netip.Prefix]time.Time{}}
		c.routers[from] = r
		infof("[ra-client] discovered router %s", from)
	}
	r.seen = now
	r.pref = ra.RouterSelectionPreference
	r.dhcp = ra.ManagedConfiguration || ra.OtherConfiguration
	if ra.RouterLifetime > 0 {
		r.lifetime = now.Add(ra.RouterLifetime)
		if err := routeSet(c.ifi.Index, netip.MustParsePrefix("::/0"), from, routerMetric(r.pref), ra.RouterLifetime); err != nil {
			errorf("[ra-client] failed to set default route: %v", err)
		}
	} else {
		if !r.lifetime.IsZero() {
			warnf("[ra-client] router %s lifetime went to zero, withdrawing default route and prefixes", from)
		}
		r.lifetime = time.Time{}
		routeDel(c.ifi.Index, netip.MustParsePrefix("::/0"), from, routerMetric(r.pref))
		r.prefixes = nil
	}
	// The first RA wakes the DHCPv6 client; it decides what to do from the M/O bits.
	if c.dhcp != nil && !c.started {
		c.started = true
		select {
		case c.dhcp.start <- raFlags{ra.ManagedConfiguration, ra.OtherConfiguration}:
		default:
		}
	}
	info := parseRA(ra, now, c.ifi.MTU, c.slaac, c.layout.wanOnLink())
	for _, pf := range info.revoked {
		infof("[ra-client] prefix %s revoked", pf)
	}
	for range info.prefixes {
		statInc("ra_prefix")
	}
	for pf, lifetime := range info.onLink {
		routeSet(c.ifi.Index, pf, netip.Addr{}, 256, lifetime)
	}
	for pf, ri := range info.routes {
		if ri.lifetime == 0 {
			routeDel(c.ifi.Index, pf, from, routerMetric(ri.pref))
			delete(r.routes, pf)
			continue
		}
		r.routes[pf] = now.Add(ri.lifetime)
		routeSet(c.ifi.Index, pf, from, routerMetric(ri.pref), ri.lifetime)
	}
	r.dns, r.dnssl, r.pref64 = info.dns, info.dnssl, info.pref64
	if info.badMTU != 0 {
		debugf("[ra-client] ignoring unreasonable upstream MTU %d", info.badMTU)
	}
	if info.mtu != 0 {
		r.mtu = info.mtu
		if info.mtu < c.ifi.MTU {
			// RFC 4861 §6.3.4: the RA MTU sets the link's IPv6 MTU only, not the interface MTU.
			if cur, _ := sysctlGet(c.ifname, "mtu"); cur != strconv.Itoa(info.mtu) {
				infof("[ra-client] upstream RA requests MTU %d (interface %d), setting WAN IPv6 MTU", info.mtu, c.ifi.MTU)
				sysctlSet(c.ifname, "mtu", strconv.Itoa(info.mtu))
			}
		}
	}
	if ra.RouterLifetime > 0 {
		r.prefixes = info.prefixes
	}
	if ra.CurrentHopLimit > 0 {
		sysctlSet(c.ifname, "hop_limit", strconv.Itoa(int(ra.CurrentHopLimit)))
	}
}

// publish merges all routers' state, picking options from the highest preference, and writes it to the Store.
func (c *raClient) publish() {
	now := time.Now()
	var upd SourceUpdate
	best := ndp.Preference(-10)
	seen := map[netip.Prefix]bool{}
	for addr, r := range c.routers {
		if !r.lifetime.IsZero() && now.After(r.lifetime) {
			warnf("[ra-client] router %s timed out", addr)
			routeDel(c.ifi.Index, netip.MustParsePrefix("::/0"), addr, routerMetric(r.pref))
			delete(c.routers, addr)
			continue
		}
		for _, p := range r.prefixes {
			if now.After(p.Valid) || seen[p.Prefix] {
				continue
			}
			seen[p.Prefix] = true
			upd.Prefixes = append(upd.Prefixes, p)
		}
		upd.DHCPv6 = upd.DHCPv6 || r.dhcp
		if prefRank(r.pref) > prefRank(best) || best == -10 {
			best = r.pref
			upd.DNS, upd.DNSSL, upd.PREF64 = r.dns, r.dnssl, r.pref64
			upd.MTU = r.mtu
		}
	}
	// without an MTU option the WAN path MTU is the interface MTU (ppp0 under PPPoE is usually 1492)
	if upd.MTU == 0 && c.ifi != nil {
		upd.MTU = c.ifi.MTU
	}
	for _, p := range upd.Prefixes {
		if p.SLAAC && now.Before(p.Preferred) {
			upd.WANAddr = c.iid.addr(c.secret, p.Prefix, c.ifi, 0)
			break
		}
	}
	c.store.Set("ra", upd)

	// a changed RA prefix set suggests the upstream link changed (re-dial, ISP renumbering); make the PD client reconfirm now
	if c.dhcp != nil && c.lastSet != nil && !samePrefixSet(c.lastSet, seen) {
		c.dhcp.Reconfirm("upstream RA prefix set changed")
	}
	c.lastSet = seen
}

func samePrefixSet(a, b map[netip.Prefix]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for p := range a {
		if !b[p] {
			return false
		}
	}
	return true
}

func prefRank(p ndp.Preference) int {
	switch p {
	case ndp.High:
		return 2
	case ndp.Medium:
		return 1
	}
	return 0
}
