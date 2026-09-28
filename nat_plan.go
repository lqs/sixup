package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// natPlan is what the ruleset should contain for a snapshot, and doubles as the fingerprint.
type natPlan struct {
	kind     tunnelKind
	ipv4     netip.Addr
	ports    []portSpan
	mtu      int
	mappings []portMapping // PCP mappings of external ports to LAN hosts
}

// portMapping sends an external port of the tunnel's IPv4 to a LAN host, and that host's traffic
// from the port out through the same external port.
type portMapping struct {
	proto    byte // IP protocol number, TCP or UDP
	internal netip.AddrPort
	external uint16
}

// describe states what the translation does, which is the part an operator has to check against
// the line: a MAP-E subscriber owns a fraction of a shared address, and nothing else does.
func (p natPlan) describe() string {
	switch {
	case !p.ipv4.IsValid():
		return string(p.kind) + ", no source NAT here (the far end translates)"
	case len(p.ports) > 0:
		return fmt.Sprintf("%s, source NAT to %s, %d ports in %d ranges", p.kind, p.ipv4, portCount(p.ports), len(p.ports))
	default:
		return fmt.Sprintf("%s, source NAT to %s, every port", p.kind, p.ipv4)
	}
}

// mssNote reports the clamp as a maximum segment size, the number that appears in a packet capture.
func mssNote(mtu int) string {
	if mtu <= 0 {
		return ""
	}
	return fmt.Sprintf(", MSS clamped to %d", mtu-40)
}

func (p natPlan) key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|%d|", p.kind, p.ipv4, p.mtu)
	for _, s := range p.ports {
		fmt.Fprintf(&b, "%d-%d,", s.Start, s.End)
	}
	for _, m := range p.mappings {
		fmt.Fprintf(&b, "|%d:%d>%s", m.proto, m.external, m.internal)
	}
	return b.String()
}

func natPlanFor(snap Snapshot, mtu int) (natPlan, bool) {
	t := snap.Tunnel
	if t == nil || !t.Local.IsValid() || !t.Remote.IsValid() {
		return natPlan{}, false
	}
	p := natPlan{kind: t.Kind, mtu: mtu}
	switch {
	case t.Kind == "ds-lite":
		// The AFTR translates; a B4 that also translated would hide the subscriber from it
	case t.RuleMAPE != nil && len(t.RuleMAPE.Ports) > 0:
		p.ipv4, p.ports = t.RuleMAPE.IPv4, t.RuleMAPE.Ports
	case t.IPv4.IsValid() && t.IPv4.Is4():
		p.ipv4 = t.IPv4
	}
	return p, true
}

func protoName(p byte) string {
	if p == pcpProtoTCP {
		return "TCP"
	}
	return "UDP"
}

// setMappings hands the NAT the complete set of PCP mappings, replacing a set it has not taken yet;
// the table is rebuilt with them.
func (m *natManager) setMappings(ms []portMapping) {
	select {
	case <-m.mapIn:
	default:
	}
	m.mapIn <- ms
}

// setPinholes hands the IPv6 filter the complete set of PCP pinholes, replacing a set it has not
// taken yet. Only proto and internal matter: nothing is translated.
func (f *firewall) setPinholes(ms []portMapping) {
	select {
	case <-f.holeIn:
	default:
	}
	f.holeIn <- ms
}

// setDelegations hands the IPv6 filter the prefixes delegated to downstream routers, whose own
// firewalls filter them, replacing a set it has not taken yet.
func (f *firewall) setDelegations(ps []netip.Prefix) {
	select {
	case <-f.delegIn:
	default:
	}
	f.delegIn <- ps
}
