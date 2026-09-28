//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// filterTable holds the IPv6 filter; it is apart from natTable, which exists only with a tunnel
// and is rebuilt whenever the NAT changes.
const filterTable = "sixup-filter"

// eifTimeout is how long an endpoint stays reachable after it last sent something out: the five
// minutes RFC 6092 REC-14 sets as the default for UDP state.
const eifTimeout = 5 * time.Minute

// eifMax bounds each endpoint set, which a LAN host could otherwise grow by sending from ever new
// ports. Once it is full, new endpoints stay unreachable until old ones time out.
const eifMax = 65536

// ipprotoHIP is the Host Identity Protocol (RFC 7401), which x/sys/unix does not name.
const ipprotoHIP = 139

// firewall keeps the IPv6 border of RFC 7084 in every mode: nothing from a ULA of another site
// crosses the WAN (ULA-4), nothing from the WAN comes from the LAN prefixes (RFC 6092 REC-6), and,
// unless source is off for a prefix routed into the LAN by other means, the LAN sends out only
// from its own prefixes and is told why otherwise (S-2, L-14), and the WAN reaches only those
// prefixes, none at all before the line has handed any out (G-3).
//
// With inbound set, for -unsolicited request and deny, it is also the simple security of RFC 6092.
// Traffic from the WAN to the LAN is then let through when it belongs to a flow the LAN started,
// when it is one of the ICMPv6 messages RFC 4890 says must pass, when it is IPsec or HIP (REC-21
// to REC-26), when it goes to an endpoint that has recently sent something out (the
// endpoint-independent filtering REC-17 and REC-33 make the default, which is what lets
// peer-to-peer programs meet), or when PCP opened a pinhole for it. Traffic for a prefix
// delegated to a downstream router is that router's to filter. Anything else from the WAN is
// dropped. Only forwarded traffic is looked at; the router's own services are the operator's.
type firewall struct {
	wan     string
	inbound bool                // filter unsolicited traffic from the WAN
	source  bool                // refuse LAN sources outside ours (-source-filter)
	holeIn  chan []portMapping  // PCP's pinholes, the latest set replacing the last
	delegIn chan []netip.Prefix // the prefixes delegated to downstream routers, likewise
	holes   *nftables.Set
	deleg   *nftables.Set
	ours    *nftables.Set  // the LAN prefixes and the delegations: what the border lets through
	shared  *nftables.Set  // the /64 shared with the WAN link, which has hosts on both sides
	upULA   *nftables.Set  // the ULA prefixes the upstream advertises, of the same site
	upULAs  []netip.Prefix // what upULA holds
	lan     []netip.Prefix // the live LAN prefixes other than the ULA
	wanLink []netip.Prefix // what shared holds
	delegs  []netip.Prefix
	applied []netip.Prefix // what ours holds
}

func (f *firewall) run(ctx context.Context, ch <-chan Snapshot) {
	if err := f.install(); err != nil {
		errorf("[firewall] cannot install table inet %s, IPv6 is not filtered: %v", filterTable, err)
		return
	}
	defer f.remove()
	if f.inbound {
		infof("[firewall] IPv6 from %s to the LAN is let through only when the LAN asked for it", f.wan)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			f.lan = f.lan[:0]
			var shared []netip.Prefix
			for _, ps := range s.LAN {
				for _, p := range ps {
					if !p.Stale && p.Source != sourceULA {
						f.lan = append(f.lan, p.Prefix)
						if s.sharedWith(p.Prefix) {
							shared = append(shared, p.Prefix)
						}
					}
				}
			}
			f.applyOurs()
			if shared = disjoint(shared); !slices.Equal(shared, f.wanLink) {
				f.wanLink = shared
				f.replace(f.shared, delegationElements(shared))
			}
			if !slices.Equal(s.UpstreamULA, f.upULAs) {
				f.upULAs = s.UpstreamULA
				f.replace(f.upULA, delegationElements(s.UpstreamULA))
			}
		case holes := <-f.holeIn:
			f.replace(f.holes, pinholeElements(holes))
		case ps := <-f.delegIn:
			f.delegs = ps
			f.replace(f.deleg, delegationElements(ps))
			f.applyOurs()
		}
	}
}

// applyOurs puts the LAN prefixes and the delegations in the border set, when they changed.
func (f *firewall) applyOurs() {
	ps := disjoint(append(slices.Clone(f.lan), f.delegs...))
	if slices.Equal(ps, f.applied) {
		return
	}
	f.applied = ps
	f.replace(f.ours, delegationElements(ps))
}

func (f *firewall) table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: filterTable}
}

func (f *firewall) install() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	tbl := f.table()
	c.AddTable(tbl) // replaced whole, as the NAT table is
	c.DelTable(tbl)
	tbl = c.AddTable(f.table())
	endpoint := nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService)
	eifUDP := &nftables.Set{Table: tbl, Name: "eif_udp", KeyType: endpoint, Concatenation: true, Dynamic: true, HasTimeout: true, Timeout: eifTimeout, Size: eifMax}
	eifTCP := &nftables.Set{Table: tbl, Name: "eif_tcp", KeyType: endpoint, Concatenation: true, Dynamic: true, HasTimeout: true, Timeout: eifTimeout, Size: eifMax}
	f.holes = &nftables.Set{Table: tbl, Name: "pinholes", Concatenation: true,
		KeyType: nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetProto, nftables.TypeInetService)}
	f.deleg = &nftables.Set{Table: tbl, Name: "delegated", KeyType: nftables.TypeIP6Addr, Interval: true}
	f.ours = &nftables.Set{Table: tbl, Name: "ours", KeyType: nftables.TypeIP6Addr, Interval: true}
	f.shared = &nftables.Set{Table: tbl, Name: "wan_link", KeyType: nftables.TypeIP6Addr, Interval: true}
	f.upULA = &nftables.Set{Table: tbl, Name: "upstream_ula", KeyType: nftables.TypeIP6Addr, Interval: true}
	f.applied, f.wanLink, f.upULAs = nil, nil, nil
	for _, s := range []*nftables.Set{eifUDP, eifTCP, f.holes, f.deleg, f.ours, f.shared, f.upULA} {
		if err := c.AddSet(s, nil); err != nil {
			return err
		}
	}

	fwd := c.AddChain(&nftables.Chain{
		Name: "forward", Table: tbl, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter,
		Policy: chainPolicy(nftables.ChainPolicyAccept),
	})
	// The border, in every mode. A ULA the upstream advertises is of the same site and crosses the
	// WAN (RFC 4193 section 4.3); what leaves for another is refused with code 1, so that its
	// sender learns it at once instead of timing out.
	for _, dir := range []struct {
		key     expr.MetaKey
		what    string
		verdict expr.Any
	}{
		{expr.MetaKeyOIFNAME, "leave by", &expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 1}},
		{expr.MetaKeyIIFNAME, "arrive on", &expr.Verdict{Kind: expr.VerdictDrop}},
	} {
		for _, addr := range []struct {
			offset uint32
			what   string
		}{{8, "from"}, {24, "to"}} {
			c.AddRule(newRule(tbl, fwd, fmt.Sprintf("nothing %s a ULA of another site may %s %s (RFC 7084 ULA-4)", addr.what, dir.what, f.wan), append(f.ipv6(dir.key),
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addr.offset, Len: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0xfe}, Xor: []byte{0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0xfc}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addr.offset, Len: 16},
				&expr.Lookup{SourceRegister: 1, SetName: f.upULA.Name, Invert: true}),
				dir.verdict))
		}
	}
	if f.source {
		c.AddRule(newRule(tbl, fwd, "the LAN sends out only from its own prefixes, and is told so otherwise (RFC 7084 S-2 and L-14)", append(f.ipv6(expr.MetaKeyOIFNAME),
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(f.wan)},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: f.ours.Name, Invert: true}),
			&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 5}))
	}
	// A /64 shared with the WAN link (RFC 7278) has hosts on the WAN side too, the upstream router
	// and whatever else is on its LAN, so a source in it may come from there
	c.AddRule(newRule(tbl, fwd, "nothing from the WAN comes from the LAN prefixes, which would be spoofed (RFC 6092 REC-6)", append(f.ipv6(expr.MetaKeyIIFNAME),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		&expr.Lookup{SourceRegister: 1, SetName: f.ours.Name},
		&expr.Lookup{SourceRegister: 1, SetName: f.shared.Name, Invert: true}),
		&expr.Verdict{Kind: expr.VerdictDrop}))
	if f.source {
		c.AddRule(newRule(tbl, fwd, "the WAN reaches only the LAN prefixes, none before the line hands one out (RFC 7084 G-3)", append(f.ipv6(expr.MetaKeyIIFNAME),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: f.ours.Name, Invert: true}),
			&expr.Verdict{Kind: expr.VerdictDrop}))
	}
	if !f.inbound {
		return c.Flush()
	}

	icmp := &nftables.Set{Table: tbl, Anonymous: true, Constant: true, KeyType: nftables.TypeICMP6Type}
	// RFC 4890: destination unreachable, packet too big, time exceeded, parameter problem, echo request
	if err := c.AddSet(icmp, []nftables.SetElement{{Key: []byte{1}}, {Key: []byte{2}}, {Key: []byte{3}}, {Key: []byte{4}}, {Key: []byte{128}}}); err != nil {
		return err
	}

	in := c.AddChain(&nftables.Chain{Name: "wan_in", Table: tbl})
	for _, r := range []struct {
		set   *nftables.Set
		proto byte
		what  string
	}{{eifUDP, unix.IPPROTO_UDP, "UDP"}, {eifTCP, unix.IPPROTO_TCP, "TCP"}} {
		c.AddRule(newRule(tbl, fwd, "remember the LAN "+r.what+" endpoints that send out, which may then be reached (RFC 6092 endpoint-independent filtering)",
			append(f.ipv6(expr.MetaKeyOIFNAME), l4(r.proto)...),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			&expr.Payload{DestRegister: 12, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Dynset{SrcRegKey: 1, SetName: r.set.Name, Operation: unix.NFT_DYNSET_OP_UPDATE, Timeout: eifTimeout},
		))
	}
	c.AddRule(newRule(tbl, fwd, "filter IPv6 arriving from "+f.wan, f.ipv6(expr.MetaKeyIIFNAME),
		&expr.Verdict{Kind: expr.VerdictJump, Chain: in.Name}))

	c.AddRule(newRule(tbl, in, "let flows the LAN started through", ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
		&expr.Verdict{Kind: expr.VerdictAccept}))
	c.AddRule(newRule(tbl, in, "drop what conntrack cannot place", ctState(expr.CtStateBitINVALID),
		&expr.Verdict{Kind: expr.VerdictDrop}))
	c.AddRule(newRule(tbl, in, "let the ICMPv6 RFC 4890 needs through", append(l4(unix.IPPROTO_ICMPV6),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
		&expr.Lookup{SourceRegister: 1, SetName: icmp.Name, SetID: icmp.ID}),
		&expr.Verdict{Kind: expr.VerdictAccept}))
	// RFC 6092 REC-21, REC-22, REC-24 and REC-26: the default mode must not block IPsec and HIP
	c.AddRule(newRule(tbl, in, "let AH through (RFC 6092 REC-21)", []expr.Any{
		&expr.Exthdr{Op: expr.ExthdrOpIpv6, Type: unix.IPPROTO_AH, Len: 1, Flags: unix.NFT_EXTHDR_F_PRESENT, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
	}, &expr.Verdict{Kind: expr.VerdictAccept}))
	c.AddRule(newRule(tbl, in, "let ESP through (RFC 6092 REC-22)", l4(unix.IPPROTO_ESP),
		&expr.Verdict{Kind: expr.VerdictAccept}))
	c.AddRule(newRule(tbl, in, "let IKE through (RFC 6092 REC-24)", append(l4(unix.IPPROTO_UDP),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 500)}),
		&expr.Verdict{Kind: expr.VerdictAccept}))
	c.AddRule(newRule(tbl, in, "let HIP through (RFC 6092 REC-26)", l4(ipprotoHIP),
		&expr.Verdict{Kind: expr.VerdictAccept}))
	for _, r := range []struct {
		set   *nftables.Set
		proto byte
		what  string
	}{{eifUDP, unix.IPPROTO_UDP, "UDP"}, {eifTCP, unix.IPPROTO_TCP, "TCP"}} {
		c.AddRule(newRule(tbl, in, "let "+r.what+" to a LAN endpoint that recently sent out through", append(append(nfIPv6(), l4(r.proto)...),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Payload{DestRegister: 12, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: r.set.Name}),
			&expr.Verdict{Kind: expr.VerdictAccept}))
	}
	c.AddRule(newRule(tbl, in, "let what PCP opened through", append(nfIPv6(),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 12},
		&expr.Payload{DestRegister: 13, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: 1, SetName: f.holes.Name},
	), &expr.Verdict{Kind: expr.VerdictAccept}))
	// Dropped rather than rejected at once as RFC 6092 REC-34 would have after a 6 second wait: an
	// early unreachable aborts the remote end of a TCP simultaneous open, which a drop lets retry.
	c.AddRule(newRule(tbl, in, "leave a downstream router's delegation to its own firewall", append(nfIPv6(),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Lookup{SourceRegister: 1, SetName: f.deleg.Name},
	), &expr.Verdict{Kind: expr.VerdictAccept}))
	c.AddRule(newRule(tbl, in, "drop unsolicited inbound", nil, &expr.Verdict{Kind: expr.VerdictDrop}))
	return c.Flush()
}

// replace swaps the elements of set in one transaction.
func (f *firewall) replace(set *nftables.Set, elems []nftables.SetElement) {
	c, err := nftables.New()
	if err != nil {
		errorf("[firewall] cannot talk to nftables: %v", err)
		return
	}
	c.FlushSet(set)
	if len(elems) > 0 {
		if err := c.SetAddElements(set, elems); err != nil {
			errorf("[firewall] %s: %v", set.Name, err)
			return
		}
	}
	if err := c.Flush(); err != nil {
		errorf("[firewall] failed to update the set %s: %v", set.Name, err)
	}
}

// pinholeElements keys each pinhole as address . protocol . port, each part padded to 4 bytes.
func pinholeElements(holes []portMapping) []nftables.SetElement {
	var out []nftables.SetElement
	for _, h := range holes {
		k := make([]byte, 24)
		a := h.internal.Addr().As16()
		copy(k, a[:])
		k[16] = h.proto
		binary.BigEndian.PutUint16(k[20:], h.internal.Port())
		out = append(out, nftables.SetElement{Key: k})
	}
	return out
}

// delegationElements makes each prefix an interval: its first address, and the one after its last
// as the end.
func delegationElements(ps []netip.Prefix) []nftables.SetElement {
	var out []nftables.SetElement
	for _, p := range ps {
		first := p.Masked().Addr().As16()
		last := first
		for i := p.Bits(); i < 128; i++ {
			last[i/8] |= 0x80 >> (i % 8)
		}
		end := netip.AddrFrom16(last).Next().As16()
		out = append(out, nftables.SetElement{Key: first[:]}, nftables.SetElement{Key: end[:], IntervalEnd: true})
	}
	return out
}

func (f *firewall) remove() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	c.DelTable(f.table())
	if err := c.Flush(); err != nil {
		warnf("[firewall] failed to remove table inet %s: %v", filterTable, err)
		return
	}
	infof("[firewall] table inet %s removed", filterTable)
}

// ipv6 matches IPv6 on the WAN interface, in or out.
func (f *firewall) ipv6(dir expr.MetaKey) []expr.Any {
	return append(nfIPv6(),
		&expr.Meta{Key: dir, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(f.wan)},
	)
}

// nfIPv6 matches IPv6. Rules reading addresses repeat it even in wan_in, which only IPv6 reaches,
// so that nft list shows "ip6 daddr" rather than a raw @nh offset.
func nfIPv6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
	}
}

func l4(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func ctState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}
