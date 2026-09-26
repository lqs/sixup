package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

var (
	allNodes    = netip.MustParseAddr("ff02::1")
	allRouters2 = netip.MustParseAddr("ff02::2")
)

// raServer advertises RAs on one LAN interface, replacing radvd.
type raServer struct {
	ifname    string
	ifi       *net.Interface
	conn      *ndp.Conn
	minI      time.Duration
	maxI      time.Duration
	lifetime  time.Duration
	mtu       uint32
	managed   bool
	other     bool
	routes    []netip.Prefix // extra RIOs
	pref64    netip.Prefix   // -ra-pref64 naming a NAT64 elsewhere
	pref64Off bool           // -ra-pref64 off
	dns       lanDNS
	// A PREF64 no longer announced is withdrawn with lifetime 0 (RFC 8781) in the next few RAs;
	// left out, clients would go on using it for the rest of its lifetime.
	withdraw     netip.Prefix
	withdrawLeft int
	snap         Snapshot
	rs           chan struct{}
	lastSent     time.Time
}

func (r *raServer) open() error {
	c, _, err := ndp.Listen(r.ifi, ndp.LinkLocal)
	if err != nil {
		return err
	}
	if err := c.JoinGroup(allRouters2); err != nil {
		c.Close()
		return err
	}
	c.SetControlMessage(ipv6.FlagHopLimit, true)
	f := &ipv6.ICMPFilter{}
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeRouterSolicitation)
	c.SetICMPFilter(f)
	r.conn = c
	r.rs = make(chan struct{}, 1)
	go r.reader()
	return nil
}

func (r *raServer) reader() {
	for {
		msg, cm, from, err := r.conn.ReadFrom()
		if err != nil {
			return
		}
		if cm == nil || cm.HopLimit != 255 {
			continue
		}
		if _, ok := msg.(*ndp.RouterSolicitation); !ok {
			continue
		}
		if !from.IsLinkLocalUnicast() && !from.IsUnspecified() {
			continue
		}
		infof("[ra-server %s] received RS from %s", r.ifname, from)
		select {
		case r.rs <- struct{}{}:
		default:
		}
	}
}

func (r *raServer) run(ctx context.Context, hub *linkHub, store *Store, ch <-chan Snapshot) {
	hub.supervise(ctx, r.ifname, func(cctx context.Context, ifi *net.Interface) {
		r.ifi = ifi
		r.serve(cctx, store, ch)
	})
}

func (r *raServer) serve(ctx context.Context, store *Store, ch <-chan Snapshot) {
	if err := r.open(); err != nil {
		// the link-local address may still be in DAD; supervise retries later
		errorf("[ra-server %s] failed to open interface: %v", r.ifname, err)
		return
	}
	defer r.conn.Close()
	// advertise immediately: first RA must go out within 2s of startup
	r.snap = store.Current()
	r.burst(ctx)
	next := time.NewTimer(r.interval())
	defer next.Stop()
	for {
		select {
		case <-ctx.Done():
			// on process exit advertise lifetime=0; skip when the restart is due to the interface going down
			if ctx.Err() != nil && r.ifi != nil {
				if ifi, err := ifaceByName(r.ifname); err == nil && ifi.Flags&net.FlagUp != 0 {
					saved := r.lifetime
					// Jool's namespace goes with this process
					exit := r.snap
					exit.NAT64 = netip.Prefix{}
					r.update(exit)
					r.snap.LAN = nil
					r.lifetime = 0
					r.send("exit")
					r.lifetime = saved
				}
			}
			return
		case s := <-ch:
			if r.update(s) {
				r.burst(ctx)
				next.Reset(r.interval())
			}
		case <-next.C:
			r.send("periodic")
			next.Reset(r.interval())
		case <-r.rs:
			// RS reply is delayed 0..500ms at random, and further if within MIN_DELAY_BETWEEN_RAS (3s) of the last send
			delay := time.Duration(rand.Int64N(int64(500 * time.Millisecond)))
			if since := time.Since(r.lastSent); since < 3*time.Second {
				delay += 3*time.Second - since
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			r.send("RS reply")
			next.Reset(r.interval())
		}
	}
}

// update takes a new snapshot and reports whether it calls for RAs right away: a prefix appeared or
// went, or the PREF64 changed, whose old value is then withdrawn.
func (r *raServer) update(s Snapshot) bool {
	old := r.pref64Now()
	r.snap = s
	cur := r.pref64Now()
	if cur == old {
		return s.Change == "add" || s.Change == "revoke"
	}
	if old.IsValid() {
		r.withdraw, r.withdrawLeft = old, 3 // as many as a burst sends
	}
	return true
}

// pref64Now is the NAT64 prefix to announce. -ra-pref64 auto takes this router's own while it
// translates, else the upstream's; a prefix nothing translates would send the CLAT of an
// IPv6-only client into a void. -ra-pref64 off announces none, and a prefix given there is a NAT64
// elsewhere, which cannot be combined with one here.
func (r *raServer) pref64Now() netip.Prefix {
	switch {
	case r.pref64Off:
		return netip.Prefix{}
	case r.pref64.IsValid():
		return r.pref64
	case r.snap.NAT64.IsValid():
		return r.snap.NAT64
	}
	return r.snap.PREF64
}

func (r *raServer) interval() time.Duration {
	if r.maxI <= r.minI {
		return r.maxI
	}
	return r.minI + time.Duration(rand.Int64N(int64(r.maxI-r.minI)))
}

// burst sends 3 RAs at most 3s apart (MAX_INITIAL_RTR_ADVERTISEMENTS).
func (r *raServer) burst(ctx context.Context) {
	for i := range 3 {
		r.send(fmt.Sprintf("initial %d/3", i+1))
		if i == 2 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(rand.Int64N(int64(2*time.Second))) + 500*time.Millisecond):
		}
	}
}

func (r *raServer) build() *ndp.RouterAdvertisement {
	now := time.Now()
	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		ManagedConfiguration: r.managed,
		OtherConfiguration:   r.other,
		RouterLifetime:       r.lifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: r.ifi.HardwareAddr},
		},
	}
	// MTU option: config wins; otherwise advertise the WAN path MTU when it is below the LAN MTU
	// (PPPoE 1492, tunnels) so hosts do not rely on PMTU discovery, which ICMPv6 filtering often breaks
	mtu := r.mtu
	if mtu == 0 && r.snap.WANMTU > 0 && (r.ifi.MTU <= 0 || r.snap.WANMTU < r.ifi.MTU) {
		mtu = uint32(r.snap.WANMTU)
	}
	if mtu > 0 {
		ra.Options = append(ra.Options, ndp.NewMTU(mtu))
	}
	hasActive := false
	for _, p := range r.snap.LAN[r.ifname] {
		valid := p.validLeft(now)
		if valid == 0 {
			continue
		}
		pref := p.preferredLeft(now)
		if pref > valid {
			pref = valid
		}
		if !p.Deprecated {
			hasActive = true
		}
		ra.Options = append(ra.Options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(p.Prefix.Bits()),
			OnLink:                         true,
			AutonomousAddressConfiguration: true,
			ValidLifetime:                  valid,
			PreferredLifetime:              pref,
			Prefix:                         p.Prefix.Masked().Addr(),
		})
	}
	// with no active prefix and no upstream, lifetime 0 tells clients not to use us as default gateway
	if !hasActive && len(r.snap.WAN) == 0 {
		ra.RouterLifetime = 0
	}
	dns := r.dns.resolve(r.snap, r.ifi)
	// RFC 8106: RDNSS/DNSSL lifetime between MaxRtrAdvInterval and twice that, capped by the upstream prefix's remaining valid time
	dnsLft := 2 * r.maxI
	for _, p := range r.snap.WAN {
		if v := p.validLeft(now); v > 0 && v < dnsLft && !p.Deprecated {
			dnsLft = v
		}
	}
	if len(dns) > 0 {
		ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{Lifetime: dnsLft, Servers: dns})
	}
	if len(r.snap.DNSSL) > 0 {
		ra.Options = append(ra.Options, &ndp.DNSSearchList{Lifetime: dnsLft, DomainNames: r.snap.DNSSL})
	}
	// PREF64 (RFC 8781) lets 464XLAT-capable hosts enable CLAT. Lifetime should be at least
	// 3 * MaxRtrAdvInterval; the library rounds it to the 8s granularity the RFC requires.
	pref64 := r.pref64Now()
	if pref64.IsValid() {
		ra.Options = append(ra.Options, &ndp.PREF64{Lifetime: 3 * r.maxI, Prefix: pref64})
	}
	if r.withdrawLeft > 0 && r.withdraw != pref64 {
		ra.Options = append(ra.Options, &ndp.PREF64{Lifetime: 0, Prefix: r.withdraw})
	}
	for _, rt := range r.routes {
		ra.Options = append(ra.Options, &ndp.RouteInformation{
			PrefixLength:  uint8(rt.Bits()),
			Preference:    ndp.Medium,
			RouteLifetime: r.lifetime,
			Prefix:        rt.Masked().Addr(),
		})
	}
	return ra
}

// send multicasts one RA; reason says what triggered it and goes into the log.
func (r *raServer) send(reason string) {
	ra := r.build()
	if err := r.conn.WriteTo(ra, ifCM(r.ifi), allNodes.WithZone(r.ifi.Name)); err != nil {
		warnf("[ra-server %s] send failed (%s): %v", r.ifname, reason, err)
		return
	}
	r.lastSent = time.Now()
	if r.withdrawLeft > 0 {
		r.withdrawLeft--
	}
	var prefixes []string
	for _, o := range ra.Options {
		if pi, ok := o.(*ndp.PrefixInformation); ok {
			prefixes = append(prefixes, fmt.Sprintf("%s/%d(preferred=%s valid=%s)", pi.Prefix, pi.PrefixLength, pi.PreferredLifetime.Round(time.Second), pi.ValidLifetime.Round(time.Second)))
		}
	}
	infof("[ra-server %s] sent RA (%s), lifetime=%s, prefixes=[%s], %d options", r.ifname, reason, ra.RouterLifetime, strings.Join(prefixes, " "), len(ra.Options))
}

// ifCM pins the outgoing interface. Without it macOS reports no route to host for link-local
// multicast and Linux may pick the wrong interface, so every NDP send carries the index.
func ifCM(ifi *net.Interface) *ipv6.ControlMessage {
	return &ipv6.ControlMessage{IfIndex: ifi.Index}
}

// lanDNS is -ra-dns: the DNS servers announced on a LAN, in order.
type lanDNS struct {
	list   []dnsEntry
	iid    iidPolicy // the first -lan-iid, which self is built from
	secret []byte
}

// dnsEntry is one -ra-dns entry: a fixed address, self, or upstream.
type dnsEntry struct {
	addr     netip.Addr
	self     bool // this router's address on the LAN
	upstream bool // the routable servers the upstream hands out
}

// parseLANDNS reads -ra-dns: off, or a comma-separated list of self, upstream and IPv6 addresses.
func parseLANDNS(spec string) ([]dnsEntry, error) {
	if strings.TrimSpace(spec) == "off" {
		return nil, nil
	}
	var out []dnsEntry
	for f := range strings.SplitSeq(spec, ",") {
		switch f = strings.TrimSpace(f); f {
		case "self":
			out = append(out, dnsEntry{self: true})
		case "upstream":
			out = append(out, dnsEntry{upstream: true})
		default:
			a, err := netip.ParseAddr(f)
			if err != nil || !a.Is6() || a.Zone() != "" {
				return nil, fmt.Errorf("%q is not off, self, upstream or an IPv6 address", f)
			}
			out = append(out, dnsEntry{addr: a})
		}
	}
	return out, nil
}

// resolve returns the DNS servers for the LAN on ifi. self takes the router's address in the
// LAN's ULA when it has one, which renumbering leaves valid, else in its global prefix; it is
// left out while the LAN has neither.
func (d lanDNS) resolve(s Snapshot, ifi *net.Interface) []netip.Addr {
	var out []netip.Addr
	for _, e := range d.list {
		switch {
		case e.upstream:
			out = append(out, routableDNS(s.DNS)...)
		case e.self:
			if p, ok := selfPrefix(s.LAN[ifi.Name]); ok {
				out = append(out, d.iid.addr(d.secret, p, ifi, 0))
			}
		default:
			out = append(out, e.addr)
		}
	}
	return out
}

func selfPrefix(ps []Prefix) (netip.Prefix, bool) {
	var gua netip.Prefix
	for _, p := range ps {
		switch {
		case p.Deprecated:
		case p.Source == sourceULA:
			return p.Prefix, true
		case !gua.IsValid():
			gua = p.Prefix
		}
	}
	return gua, gua.IsValid()
}

// parseNAT64Prefix accepts a prefix that RFC 6052 can embed an IPv4 address in and RFC 8781 can
// announce.
func parseNAT64Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv6 prefix, such as 64:ff9b::/96", s)
	}
	switch p.Bits() {
	case 32, 40, 48, 56, 64, 96:
		return p.Masked(), nil
	}
	return netip.Prefix{}, fmt.Errorf("%s: the length must be 32, 40, 48, 56, 64 or 96", p)
}

// parsePref64 reads -ra-pref64: auto, off, or the prefix of a NAT64 elsewhere.
func parsePref64(s string) (p netip.Prefix, off bool, err error) {
	switch s {
	case "auto":
		return netip.Prefix{}, false, nil
	case "off":
		return netip.Prefix{}, true, nil
	}
	if p, err = parseNAT64Prefix(s); err != nil {
		return p, false, fmt.Errorf("not auto or off, and %w", err)
	}
	return p, false, nil
}
