//go:build linux

package main

import (
	"context"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// natTable is the only table sixup ever writes. Everything else in the ruleset belongs to the
// operator and is never read for content, never flushed and never reordered.
const natTable = "sixup"

// natManager maintains the NAPT44 that a MAP-E customer edge is required to have: RFC 7597 gives the
// subscriber one shared IPv4 and a port set selected by the PSID, and the border relay returns
// traffic by looking the destination port up in that set. A source port outside it is either dropped
// or delivered to whichever subscriber owns it, so the translation is part of the tunnel rather than
// a matter of local policy. It is derived from the delegated prefix, which means it has to be
// rewritten whenever the prefix changes; a ruleset pasted in by hand goes stale at that moment and
// fails silently.
//
// DS-Lite needs no translation here at all, because the AFTR carries the carrier-grade NAT, and a
// line with its own public IPv4 needs an ordinary one. Both still want the MSS clamp, since the
// tunnel costs 40 bytes and path MTU discovery is blocked often enough to matter.
type natManager struct {
	dev string // tunnel device; rules are scoped to traffic leaving through it
	mtu int    // tunnel MTU, for the MSS clamp; 0 leaves the clamp out
	// How many of the port ranges are Jool's rather than ours, so that the two never hand out the
	// same port; see splitPortSpans.
	joolRanges int
	applied    string // fingerprint of what is installed, so an unchanged snapshot writes nothing
	warned     bool
	dial       func() (*nftables.Conn, error) // tests substitute a connection that talks to no kernel
}

func (m *natManager) conn() (*nftables.Conn, error) {
	if m.dial != nil {
		return m.dial()
	}
	return nftables.New()
}

func (m *natManager) run(ctx context.Context, ch <-chan Snapshot) {
	defer m.remove()
	for {
		select {
		case <-ctx.Done():
			return
		case snap := <-ch:
			m.apply(snap)
		}
	}
}

func (m *natManager) apply(snap Snapshot) {
	plan, ok := natPlanFor(snap, m.tunnelMTU(), m.joolRanges)
	if !ok {
		m.remove()
		return
	}
	if k := plan.key(); k == m.applied {
		return
	} else {
		m.applied = k
	}
	c, err := m.conn()
	if err != nil {
		errorf("[nat] cannot talk to nftables: %v", err)
		return
	}
	m.warnConflicts(c)

	// Replace wholesale: the port set moves as a unit when the prefix changes, and a half-updated
	// set would translate to ports the border relay no longer routes here.
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: natTable}
	c.DelTable(tbl)
	c.Flush() // a missing table is not an error worth reporting, so the result is ignored
	tbl = c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: natTable})

	if plan.ipv4.IsValid() {
		post := c.AddChain(&nftables.Chain{
			Name: "postrouting", Table: tbl, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
			Policy: chainPolicy(nftables.ChainPolicyAccept),
		})
		for _, r := range m.snatRules(tbl, post, plan) {
			c.AddRule(r)
		}
	}
	if plan.mtu > 0 {
		fwd := c.AddChain(&nftables.Chain{
			Name: "forward", Table: tbl, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityMangle,
			Policy: chainPolicy(nftables.ChainPolicyAccept),
		})
		c.AddRule(m.mssRule(tbl, fwd, plan.mtu))
	}
	if err := c.Flush(); err != nil {
		errorf("[nat] failed to install the ruleset: %v", err)
		m.applied = ""
		return
	}
	infof("[nat] table inet %s installed for %s: %s%s", natTable, m.dev, plan.describe(), mssNote(plan.mtu))
	if len(plan.ports) > 0 {
		// The ranges themselves, because this is the number to quote when an ISP is asked why a
		// connection was refused, and the only way to tell a wrong PSID from a wrong rule table.
		infof("[nat] port ranges: %s", spansString(plan.ports))
	}
}

func chainPolicy(p nftables.ChainPolicy) *nftables.ChainPolicy { return &p }

// snatRules builds one rule per port range. netfilter translates a flow once, so the ranges cannot
// be given as one rule; numgen spreads new flows over them and conntrack keeps each flow on the
// range it drew. ICMP needs no rule of its own, the identifier being what netfilter translates there.
func (m *natManager) snatRules(tbl *nftables.Table, ch *nftables.Chain, p natPlan) []*nftables.Rule {
	v4 := p.ipv4.As4()
	if len(p.ports) == 0 {
		return []*nftables.Rule{{Table: tbl, Chain: ch, Exprs: append(m.egress(),
			&expr.Immediate{Register: 1, Data: v4[:]},
			&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
		)}}
	}
	var out []*nftables.Rule
	for i, span := range p.ports {
		out = append(out, &nftables.Rule{Table: tbl, Chain: ch, Exprs: append(m.egress(),
			&expr.Numgen{Register: 2, Modulus: uint32(len(p.ports)), Type: unix.NFT_NG_RANDOM},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 2, Data: binaryutil.NativeEndian.PutUint32(uint32(i))},
			&expr.Immediate{Register: 1, Data: v4[:]},
			&expr.Immediate{Register: 3, Data: binaryutil.BigEndian.PutUint16(span.Start)},
			&expr.Immediate{Register: 4, Data: binaryutil.BigEndian.PutUint16(span.End)},
			&expr.NAT{
				Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV4,
				RegAddrMin: 1, RegProtoMin: 3, RegProtoMax: 4,
			},
		)})
	}
	return out
}

// egress matches new flows leaving through the tunnel device. Keeping the match this narrow is what
// lets the table coexist with whatever else is loaded: nothing else on the box is touched.
func (m *natManager) egress() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(m.dev)},
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// mssRule clamps the MSS of outgoing SYNs to what fits the tunnel. Large transfers stall without it
// whenever the ICMP that path MTU discovery depends on is filtered upstream.
func (m *natManager) mssRule(tbl *nftables.Table, ch *nftables.Chain, mtu int) *nftables.Rule {
	mss := uint16(mtu - 40) // IPv4 and TCP headers
	return &nftables.Rule{Table: tbl, Chain: ch, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(m.dev)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x02 | 0x04}, Xor: []byte{0x00}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}}, // SYN set, RST clear
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(mss)},
		&expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	}}
}

// warnConflicts reports other source-NAT chains that may translate the same traffic first. netfilter
// translates a flow once, so whichever chain runs first wins: a masquerade rule left over from a
// firewall of its own would hand out a source port outside the PSID set, and the failure shows up as
// IPv4 that works for some connections and not others. Reporting beats quietly winning or losing.
func (m *natManager) warnConflicts(c *nftables.Conn) {
	if m.warned {
		return
	}
	chains, err := c.ListChains()
	if err != nil {
		return
	}
	var other []string
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name == natTable || ch.Type != nftables.ChainTypeNAT {
			continue
		}
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookPostrouting {
			continue
		}
		other = append(other, ch.Table.Name+"/"+ch.Name)
	}
	m.warned = true
	if len(other) > 0 {
		warnf("[nat] other source NAT chains are loaded (%s). A masquerade rule covering %s would "+
			"translate to a port outside the range this line owns, and only some connections would work. "+
			"Restrict those rules to the interfaces they are meant for, or run with -tunnel-nat off",
			strings.Join(other, " "), m.dev)
	}
}

func (m *natManager) remove() {
	if m.applied == "" {
		return
	}
	m.applied = ""
	c, err := m.conn()
	if err != nil {
		return
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: natTable})
	if err := c.Flush(); err != nil {
		warnf("[nat] failed to remove table inet %s: %v", natTable, err)
		return
	}
	infof("[nat] table inet %s removed", natTable)
}

// tunnelMTU reads the MTU the tunnel device ended up with, which the tunnel manager derives from the
// WAN interface. Reading it back keeps the clamp correct without repeating that derivation here.
func (m *natManager) tunnelMTU() int {
	if m.mtu > 0 {
		return m.mtu
	}
	ifi, err := net.InterfaceByName(m.dev)
	if err != nil {
		return 0
	}
	return ifi.MTU
}

// ifname pads an interface name to the fixed-width field nftables compares against.
func ifname(s string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, s)
	return b
}
