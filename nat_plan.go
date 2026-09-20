package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// natPlan is what the ruleset should contain for a snapshot, and doubles as the fingerprint.
type natPlan struct {
	kind  tunnelKind
	ipv4  netip.Addr
	ports []portSpan
	mtu   int
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
	return b.String()
}

// joolSplit is what is left for the source NAT once Jool has taken its share.
func joolSplit(spans []portSpan, joolRanges int) []portSpan {
	forNAT, _ := splitPortSpans(spans, joolRanges)
	return forNAT
}

// splitPortSpans divides a MAP-E port set between the two translators that may draw from it. Each
// keeps whole ranges of its own: netfilter and Jool allocate independently, and a port handed out
// twice would send one of the two flows' replies to the wrong translator. Jool takes the last
// ranges, netfilter the rest; with nothing left for netfilter the split is refused.
func splitPortSpans(spans []portSpan, joolRanges int) (forNAT, forJool []portSpan) {
	if joolRanges <= 0 || len(spans) == 0 {
		return spans, nil
	}
	if joolRanges >= len(spans) {
		joolRanges = len(spans) - 1
	}
	if joolRanges <= 0 {
		return spans, nil
	}
	cut := len(spans) - joolRanges
	return spans[:cut], spans[cut:]
}

func natPlanFor(snap Snapshot, mtu, joolRanges int) (natPlan, bool) {
	t := snap.Tunnel
	if t == nil || !t.Local.IsValid() || !t.Remote.IsValid() {
		return natPlan{}, false
	}
	p := natPlan{kind: t.Kind, mtu: mtu}
	switch {
	case t.Kind == "ds-lite":
		// The AFTR translates; a B4 that also translated would hide the subscriber from it
	case t.RuleMAPE != nil && len(t.RuleMAPE.Ports) > 0:
		p.ipv4, p.ports = t.RuleMAPE.IPv4, joolSplit(t.RuleMAPE.Ports, joolRanges)
	case t.IPv4.IsValid() && t.IPv4.Is4():
		p.ipv4 = t.IPv4
	}
	return p, true
}
