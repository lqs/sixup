package main

import (
	"context"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
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
	ifname   string
	ifi      *net.Interface
	conn     *ndp.Conn
	minI     time.Duration
	maxI     time.Duration
	lifetime time.Duration
	mtu      uint32
	managed  bool
	other    bool
	routes   []netip.Prefix // extra RIOs
	pref64   netip.Prefix   // configured NAT64 prefix, overrides upstream
	dns      []netip.Addr   // configured DNS, overrides upstream
	snap     Snapshot
	rs       chan struct{}
	lastSent time.Time
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
		log.Printf("[ra-server %s] failed to open interface: %v", r.ifname, err)
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
					r.snap.LAN = nil
					r.lifetime = 0
					r.send()
					r.lifetime = saved
				}
			}
			return
		case s := <-ch:
			changed := s.Change == "add" || s.Change == "revoke"
			r.snap = s
			if changed {
				r.burst(ctx)
				next.Reset(r.interval())
			}
		case <-next.C:
			r.send()
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
			r.send()
			next.Reset(r.interval())
		}
	}
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
		r.send()
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
	dns := r.dns
	if len(dns) == 0 {
		dns = routableDNS(r.snap.DNS)
	}
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
	pref64 := r.pref64
	if !pref64.IsValid() {
		pref64 = r.snap.PREF64
	}
	if pref64.IsValid() {
		ra.Options = append(ra.Options, &ndp.PREF64{Lifetime: 3 * r.maxI, Prefix: pref64})
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

func (r *raServer) send() {
	ra := r.build()
	if err := r.conn.WriteTo(ra, ifCM(r.ifi), allNodes.WithZone(r.ifi.Name)); err != nil {
		log.Printf("[ra-server %s] send failed: %v", r.ifname, err)
		return
	}
	r.lastSent = time.Now()
	log2("[ra-server %s] sent RA, %d options, lifetime=%s", r.ifname, len(ra.Options), ra.RouterLifetime)
}

// ifCM pins the outgoing interface. Without it macOS reports no route to host for link-local
// multicast and Linux may pick the wrong interface, so every NDP send carries the index.
func ifCM(ifi *net.Interface) *ipv6.ControlMessage {
	return &ipv6.ControlMessage{IfIndex: ifi.Index}
}
