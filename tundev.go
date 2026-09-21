package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// IFLA_IPTUN_* (linux/if_tunnel.h), not exported by x/sys/unix
const (
	iflaIptunLink       = 1
	iflaIptunLocal      = 2
	iflaIptunRemote     = 3
	iflaIptunTTL        = 4
	iflaIptunEncapLimit = 6
	iflaIptunFlags      = 8
	iflaIptunProto      = 9
	ip6TnlIgnEncapLimit = 0x1 // IP6_TNL_F_IGN_ENCAP_LIMIT: omit the encapsulation limit header, required by most Japanese IPoE tunnels
)

// tunnelSpec describes the IPv4-in-IPv6 tunnel to build: local endpoint, remote endpoint, optional public IPv4.
type tunnelSpec struct {
	Local, Remote netip.Addr
	IPv4          netip.Addr
	Kind          tunnelKind
}

// tunnelSpecOf reads the tunnel the store already resolved; the priority order lives in TunnelParams.resolve.
func tunnelSpecOf(s Snapshot) (tunnelSpec, bool) {
	t := s.Tunnel
	if t == nil || !t.Local.IsValid() || !t.Remote.IsValid() {
		return tunnelSpec{}, false
	}
	return tunnelSpec{Local: t.Local, Remote: t.Remote, IPv4: t.IPv4, Kind: t.Kind}, true
}

// tunnelManager maintains one ip6tnl device: creates or modifies it via netlink when parameters change
// (like ip tunnel add/change), brings it up, sets MTU, assigns the public IPv4 when known and adds
// a high-metric IPv4 default route through it. NAT is left to external policy.
type tunnelManager struct {
	dev     string
	wan     string
	mtu     int
	metric4 uint32 // metric of the IPv4 default route through the tunnel, 0 means no route
	store   *Store
	cur     tunnelSpec
	applied bool
	wanMTU  int
}

func (m *tunnelManager) run(ctx context.Context, ch <-chan Snapshot) {
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			spec, ok := tunnelSpecOf(s)
			if !ok {
				continue
			}
			mtuChanged := s.WANMTU != 0 && s.WANMTU != m.wanMTU
			m.wanMTU = s.WANMTU
			if m.applied && spec == m.cur && !mtuChanged {
				continue
			}
			// The local endpoint must be on the WAN interface and past DAD, or the kernel cannot send
			if conflicted(s, spec.Local) {
				warnf("[tunnel-dev %s] local endpoint %s has a DAD conflict, deferring tunnel setup", m.dev, spec.Local)
				continue
			}
			m.apply(spec)
		}
	}
}

func conflicted(s Snapshot, a netip.Addr) bool {
	if s.Tunnel == nil {
		return false
	}
	for _, c := range s.Tunnel.Conflicts {
		if c == a {
			return true
		}
	}
	return false
}

// tunnelMTU picks the tunnel MTU: the override when given, otherwise the smaller of the WAN
// interface MTU and the upstream path MTU, less the 40-byte IPv6 header. The encapsulation limit
// option is disabled, so it costs no further 8 bytes.
func tunnelMTU(override, ifMTU, pathMTU int) int {
	if override != 0 {
		return override
	}
	base := ifMTU
	if pathMTU > 0 && pathMTU < base {
		base = pathMTU
	}
	if mtu := base - 40; mtu >= 1280-40 {
		return mtu
	}
	return 1280 - 40
}

// tunnelPlan is what sixup would configure for the tunnel device, reported by dry-run so the
// parameters can be checked, or applied by hand, before anything touches the system.
type tunnelPlan struct {
	Dev    string       `json:"dev"`
	Kind   tunnelKind   `json:"kind"`
	Source tunnelSource `json:"source"`
	Link   string       `json:"link"`
	Local  netip.Addr   `json:"local"`
	Remote netip.Addr   `json:"remote"`
	MTU    int          `json:"mtu"`
	IPv4   netip.Addr   `json:"ipv4,omitzero"`
	// Metric of the IPv4 default route added through the device, 0 when no route is added
	Route4Metric uint32   `json:"route4_metric,omitempty"`
	Commands     []string `json:"equivalent_commands"`
	Note         string   `json:"note,omitempty"`
}

// planTunnel describes the device sixup would build from the snapshot. dev may be empty, meaning
// -tunnel-dev was cleared and nothing would actually be created.
func planTunnel(s Snapshot, dev, wan string, mtuOverride, wanIfMTU int, metric4 uint32) (*tunnelPlan, bool) {
	spec, ok := tunnelSpecOf(s)
	if !ok {
		return nil, false
	}
	p := &tunnelPlan{
		Dev: dev, Kind: spec.Kind, Link: wan, Local: spec.Local, Remote: spec.Remote, IPv4: spec.IPv4,
		MTU: tunnelMTU(mtuOverride, wanIfMTU, s.WANMTU),
	}
	if s.Tunnel != nil {
		p.Source = s.Tunnel.Source
	}
	if dev == "" {
		p.Dev = "sixup-ipv4"
		p.Note = "nothing is created with an empty -tunnel-dev; this is what the default device would look like"
	}
	if conflicted(s, spec.Local) {
		p.Note = "the local endpoint lost DAD, so the device would not be created until the conflict clears"
	} else if other := addr4Holder(p.Dev, spec.IPv4); other != "" {
		p.Note = "IPv4 " + spec.IPv4.String() + " is already configured on " + other + ", so the device would be built but the address and the route skipped; the commands below assume you remove it there first"
	}
	p.Commands = []string{
		fmt.Sprintf("ip -6 tunnel add %s mode ipip6 local %s remote %s dev %s encaplimit none ttl 64", p.Dev, p.Local, p.Remote, wan),
		fmt.Sprintf("ip link set %s mtu %d up", p.Dev, p.MTU),
	}
	if p.IPv4.IsValid() {
		p.Commands = append(p.Commands, fmt.Sprintf("ip addr add %s/32 dev %s", p.IPv4, p.Dev))
		if metric4 != 0 {
			p.Route4Metric = metric4
			p.Commands = append(p.Commands, fmt.Sprintf("ip route add default dev %s metric %d", p.Dev, metric4))
		}
	}
	return p, true
}

func (m *tunnelManager) apply(spec tunnelSpec) {
	wan, err := ifaceByName(m.wan)
	if err != nil {
		warnf("[tunnel-dev %s] WAN interface %s: %v", m.dev, m.wan, err)
		return
	}
	mtu := tunnelMTU(m.mtu, wan.MTU, m.wanMTU)
	verb := "created"
	if _, err := net.InterfaceByName(m.dev); err == nil {
		verb = "modified"
	}
	if err := tunnelSet(m.dev, wan.Index, spec.Local, spec.Remote, mtu); err != nil {
		errorf("[tunnel-dev %s] tunnel %s failed: %v", m.dev, verb, err)
		return
	}
	infof("[tunnel-dev %s] %s ip6tnl: %s → %s, link %s, mtu %d (%s)", m.dev, verb, spec.Local, spec.Remote, m.wan, mtu, spec.Kind)
	if spec.IPv4.IsValid() {
		if other := addr4Holder(m.dev, spec.IPv4); other != "" {
			warnf("[tunnel-dev %s] IPv4 %s is already configured on %s, leaving the tunnel without an address and without a route: remove it there, or point -tunnel-dev at that device", m.dev, spec.IPv4, other)
			return
		}
		if err := addr4Set(m.dev, spec.IPv4); err != nil {
			errorf("[tunnel-dev %s] failed to configure IPv4 %s: %v", m.dev, spec.IPv4, err)
		} else {
			infof("[tunnel-dev %s] IPv4 %s/32 configured; NAT is left to external policy", m.dev, spec.IPv4)
			m.route4()
		}
	}
	m.cur, m.applied = spec, true
}

// route4 adds the IPv4 default route through the tunnel with a high metric, so any other IPv4
// default route on the box keeps winning and the tunnel only carries what nothing else claims.
func (m *tunnelManager) route4() {
	if m.metric4 == 0 {
		return
	}
	dev, err := net.InterfaceByName(m.dev)
	if err != nil {
		warnf("[tunnel-dev %s] IPv4 default route skipped: %v", m.dev, err)
		return
	}
	if err := routeSet(dev.Index, netip.MustParsePrefix("0.0.0.0/0"), netip.Addr{}, m.metric4, 0); err != nil {
		warnf("[tunnel-dev %s] IPv4 default route failed: %v", m.dev, err)
		return
	}
	infof("[tunnel-dev %s] IPv4 default route points at the device with metric %d", m.dev, m.metric4)
}

// addr4Holder names the other interface that already carries this IPv4 address, empty when none
// does. Only this host is checked: MAP-E shares one public IPv4 between many subscribers, each with
// its own port set, so the same address on the link belongs to a neighbour and is not a conflict,
// which is also why IPv4 here gets no equivalent of DAD. A duplicate on this host is a real problem:
// it breaks source address selection and makes both interfaces answer ARP, and the usual cause is a
// tunnel device left over under an old -tunnel-dev name.
func addr4Holder(dev string, a netip.Addr) string {
	ifis, err := net.Interfaces()
	if err != nil {
		warnf("[tunnel-dev %s] cannot list interfaces to check for a duplicate IPv4: %v", dev, err)
		return ""
	}
	for _, ifi := range ifis {
		if ifi.Name == dev {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			n, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := n.IP.To4(); v4 != nil && netip.AddrFrom4([4]byte(v4)) == a {
				return ifi.Name
			}
		}
	}
	return ""
}
