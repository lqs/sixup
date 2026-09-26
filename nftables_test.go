//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// exprsOf indexes a rule by expression type, which is what the assertions below are about; the
// order nftables evaluates them in is fixed by construction and not worth restating.
func immediates(r *nftables.Rule) map[uint32][]byte {
	out := map[uint32][]byte{}
	for _, e := range r.Exprs {
		if im, ok := e.(*expr.Immediate); ok {
			out[im.Register] = im.Data
		}
	}
	return out
}

func firstOf[T expr.Any](r *nftables.Rule) (T, bool) {
	for _, e := range r.Exprs {
		if v, ok := e.(T); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// A MAP-E line owns a set of disjoint port ranges, so it takes one rule per range: netfilter
// translates a flow once and a single rule carries a single range.
func TestSNATRulesCoverEveryPortRange(t *testing.T) {
	m := &natManager{dev: "sixup-ipv4"}
	ports := portSpans(4, 8, 0x56)
	ipv4 := netip.MustParseAddr("203.0.113.9")
	rules := m.snatRules(nil, nil, natPlan{kind: "map-e", ipv4: ipv4, ports: ports})
	if len(rules) != len(ports) {
		t.Fatalf("got %d rules for %d port ranges", len(rules), len(ports))
	}
	want4 := ipv4.As4()
	for i, r := range rules {
		ng, ok := firstOf[*expr.Numgen](r)
		if !ok || ng.Modulus != uint32(len(ports)) {
			t.Fatalf("rule %d must draw from all %d ranges: %+v", i, len(ports), ng)
		}
		im := immediates(r)
		if got := im[1]; string(got) != string(want4[:]) {
			t.Fatalf("rule %d translates to %v, want %v", i, got, want4)
		}
		start, end := binary.BigEndian.Uint16(im[3]), binary.BigEndian.Uint16(im[4])
		if start != ports[i].Start || end != ports[i].End {
			t.Fatalf("rule %d covers %d-%d, want %s", i, start, end, ports[i])
		}
		nat, ok := firstOf[*expr.NAT](r)
		if !ok || nat.Type != expr.NATTypeSourceNAT || nat.Family != unix.NFPROTO_IPV4 {
			t.Fatalf("rule %d is not an IPv4 source NAT: %+v", i, nat)
		}
		if nat.RegProtoMin != 3 || nat.RegProtoMax != 4 {
			t.Fatalf("rule %d does not restrict the port range: %+v", i, nat)
		}
		if meta, ok := firstOf[*expr.Meta](r); !ok || meta.Key != expr.MetaKeyOIFNAME {
			t.Fatalf("rule %d is not scoped to an outgoing interface", i)
		}
		if _, ok := firstOf[*expr.Ct](r); !ok {
			t.Fatalf("rule %d does not limit itself to new flows", i)
		}
	}
}

// A line with its own public IPv4 owns every port, so the rule carries no port range at all.
func TestSNATRuleWithoutPortRestriction(t *testing.T) {
	m := &natManager{dev: "sixup-ipv4"}
	rules := m.snatRules(nil, nil, natPlan{kind: "4in6", ipv4: netip.MustParseAddr("198.51.100.7")})
	if len(rules) != 1 {
		t.Fatalf("one rule is enough without a port set, got %d", len(rules))
	}
	nat, _ := firstOf[*expr.NAT](rules[0])
	if nat.RegProtoMin != 0 || nat.RegProtoMax != 0 {
		t.Fatalf("no port restriction should be requested: %+v", nat)
	}
	if _, ok := firstOf[*expr.Numgen](rules[0]); ok {
		t.Fatal("with one range there is nothing to draw between")
	}
}

// The clamp has to leave room for the IPv4 and TCP headers the tunnel adds back, and apply in both
// directions.
func TestMSSRulesClampToTunnelMTU(t *testing.T) {
	m := &natManager{dev: "sixup-ipv4"}
	rules := m.mssRules(nil, nil, 1460)
	if len(rules) != 2 {
		t.Fatalf("want one rule per direction, got %d", len(rules))
	}
	var dirs []expr.MetaKey
	for _, r := range rules {
		dir, _ := firstOf[*expr.Meta](r)
		dirs = append(dirs, dir.Key)
		if got := binary.BigEndian.Uint16(immediates(r)[1]); got != 1420 {
			t.Fatalf("MSS should be the tunnel MTU less 40 bytes, got %d", got)
		}
		eh, ok := firstOf[*expr.Exthdr](r)
		if !ok || eh.Op != expr.ExthdrOpTcpopt || eh.Type != 2 || eh.Len != 2 {
			t.Fatalf("the maximum segment size option is not the one being written: %+v", eh)
		}
	}
	if dirs[0] != expr.MetaKeyOIFNAME || dirs[1] != expr.MetaKeyIIFNAME {
		t.Fatalf("want the outgoing and the incoming direction, got %v", dirs)
	}
}

// apply talks to the kernel only when the ruleset has to change: the port set moves with the
// delegated prefix, and a renewal that changes nothing must not rewrite the table underneath
// established flows.
func TestNATApplyWritesOnlyOnChange(t *testing.T) {
	sent := 0
	m := &natManager{dev: "sixup-ipv4", mtu: 1460, warned: true, dial: func() (*nftables.Conn, error) {
		return nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			sent += len(req)
			return req, nil
		}))
	}}
	snap := func(psid uint16) Snapshot {
		return Snapshot{Tunnel: &TunnelParams{
			Kind: "map-e", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
			RuleMAPE: &mapeResult{IPv4: netip.MustParseAddr("203.0.113.9"), Ports: portSpans(4, 8, psid)},
		}}
	}
	m.apply(snap(0x56))
	first := sent
	if first == 0 {
		t.Fatal("the first snapshot has to install the table")
	}
	m.apply(snap(0x56))
	if sent != first {
		t.Fatalf("an unchanged snapshot wrote %d more messages", sent-first)
	}
	m.apply(snap(0x57))
	if sent == first {
		t.Fatal("a different port set has to be installed")
	}
}
