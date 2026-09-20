package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// mapeResult holds MAP-E parameters computed from the Japanese IPoE rule table.
// Ported from luci-app-fleth's fleth-map-e.lua, Copyright (c) 2024 huggy, MIT licensed;
// see NOTICE. That file is itself a rewrite of ipv4.web.fc2.com/map-e.html.
type mapeResult struct {
	Provider string       `json:"provider"`
	BR       netip.Addr   `json:"br"`
	IPv4     netip.Addr   `json:"ipv4"`      // shared IPv4 assigned to the subscriber
	Rule4    netip.Prefix `json:"rule_ipv4"` // Rule IPv4 prefix
	Rule6    netip.Prefix `json:"rule_ipv6"` // Rule IPv6 prefix
	EALen    uint8        `json:"ea_len"`
	PSIDLen  uint8        `json:"psid_len"`
	Offset   uint8        `json:"psid_offset"`
	PSID     uint16       `json:"psid"`
	CE       netip.Addr   `json:"ce"` // tunnel local endpoint address, in RFC 7597 §6 form
	Ports    []portSpan   `json:"ports"`
}

type portSpan struct {
	Start, End uint16
}

func (p portSpan) String() string { return fmt.Sprintf("%d-%d", p.Start, p.End) }

// calcMAPE computes MAP-E parameters from the subscriber prefix, which must be /56 or longer. Returns false for an unknown ISP or a prefix with no matching rule.
func calcMAPE(prefix netip.Prefix) (*mapeResult, bool) {
	if !prefix.IsValid() || prefix.Bits() < 56 {
		return nil, false
	}
	b := prefix.Masked().Addr().As16()
	h := [4]uint64{}
	for i := range h {
		h[i] = uint64(binary.BigEndian.Uint16(b[i*2:]))
	}
	r := &mapeResult{}
	switch {
	case h[0] == 0x240b:
		r.Provider, r.BR = "JPNE (v6plus)", netip.MustParseAddr("2404:9200:225:100::64")
	case h[0] == 0x2404 && h[1] >= 0x7a80 && h[1] < 0x7a84:
		r.Provider, r.BR = "BIGLOBE (east Japan)", netip.MustParseAddr("2001:260:700:1::1:275")
	case h[0] == 0x2404 && h[1] >= 0x7a84 && h[1] < 0x7a88:
		r.Provider, r.BR = "BIGLOBE (west Japan)", netip.MustParseAddr("2001:260:700:1::1:276")
	case h[0] == 0x2400:
		r.Provider, r.BR = "OCN", netip.MustParseAddr("2001:380:a120::9")
	case h[0] == 0x240d:
		r.Provider, r.BR = "NURO", netip.MustParseAddr("2001:3b8:200:ff9::1")
	default:
		return nil, false
	}

	key38 := h[0]<<24 | h[1]<<8 | (h[2]&0xfc00)>>8
	key31 := h[0]<<16 | (h[1] & 0xfffe)
	var octet, rule4 [4]byte
	var rule6Len, rule4Len int
	switch {
	case has38(mapeRule38, key38):
		t := mapeRule38[key38]
		octet = [4]byte{t[0], t[1], t[2] | byte((h[2]&0x0300)>>8), byte(h[2] & 0xff)}
		rule4 = [4]byte{t[0], t[1], t[2], 0}
		rule6Len, r.PSIDLen, r.Offset = 38, 8, 4
	case has31(key31):
		t := mapeRule31[key31]
		octet = [4]byte{t[0], t[1] | byte(h[1]&1), byte((h[2] & 0xff00) >> 8), byte(h[2] & 0xff)}
		rule4 = [4]byte{t[0], t[1], 0, 0}
		rule6Len, r.PSIDLen, r.Offset = 31, 8, 4
	case has38(mapeRule38x20, key38):
		t := mapeRule38x20[key38]
		octet = [4]byte{t[0], t[1], t[2] | byte((h[2]&0x03c0)>>6), byte((h[2]&0x3f)<<2 | (h[3]&0xc000)>>14)}
		rule4 = [4]byte{t[0], t[1], t[2], 0}
		rule6Len, r.PSIDLen, r.Offset = 38, 6, 6
	default:
		return nil, false
	}
	r.IPv4 = netip.AddrFrom4(octet)
	r.EALen = uint8(56 - rule6Len)
	rule4Len = 32 - (int(r.EALen) - int(r.PSIDLen))
	r.Rule4 = netip.PrefixFrom(netip.AddrFrom4(rule4), rule4Len).Masked()
	r.Rule6 = netip.PrefixFrom(prefix.Addr(), rule6Len).Masked()
	switch r.PSIDLen {
	case 8:
		r.PSID = uint16((h[3] & 0xff00) >> 8)
	case 6:
		r.PSID = uint16((h[3] & 0x3f00) >> 8)
	}
	r.Ports = portSpans(r.Offset, r.PSIDLen, r.PSID)
	// CE address: the leading 56 bits + an all-zero 8-bit subnet id + the IID (0 | IPv4 | PSID | 0)
	ce := [16]byte{}
	copy(ce[:7], b[:7])
	copy(ce[9:13], octet[:])
	binary.BigEndian.PutUint16(ce[13:15], r.PSID)
	r.CE = netip.AddrFrom16(ce)
	return r, true
}

// portSpans lists the port ranges a PSID owns. A starts at 1 because A=0 is the reserved system
// port range; each span is 2^(16-offset-psidlen) wide. With offset 0 there is no A field and the
// PSID owns one contiguous block, system ports included.
func portSpans(offset, psidLen uint8, psid uint16) []portSpan {
	if offset+psidLen > 16 {
		return nil
	}
	block := uint32(1) << (16 - uint(offset) - uint(psidLen))
	if offset == 0 {
		start := uint32(psid) << (16 - uint(psidLen))
		return []portSpan{{uint16(start), uint16(start + block - 1)}}
	}
	var out []portSpan
	for a := uint32(1); a < 1<<uint(offset); a++ {
		start := a<<(16-uint(offset)) | uint32(psid)<<(16-uint(offset)-uint(psidLen))
		out = append(out, portSpan{uint16(start), uint16(start + block - 1)})
	}
	return out
}

// bitsAt reads n bits out of a 128-bit address starting at bit start, n up to 64.
func bitsAt(b [16]byte, start, n int) uint64 {
	var v uint64
	for i := range n {
		bit := start + i
		v <<= 1
		v |= uint64(b[bit/8]>>(7-uint(bit%8))) & 1
	}
	return v
}

// bmrFor picks the Basic Mapping Rule for a delegated prefix: the most specific rule whose IPv6
// prefix contains it. RFC 7597 §5 leaves FMR-only rules to the mesh case, which sixup does not build.
func bmrFor(rules []S46Rule, pd netip.Prefix) (S46Rule, bool) {
	best, found := S46Rule{}, false
	for _, r := range rules {
		if !r.IPv6Prefix.IsValid() || !r.IPv6Prefix.Contains(pd.Addr()) {
			continue
		}
		if !found || r.IPv6Prefix.Bits() > best.IPv6Prefix.Bits() {
			best, found = r, true
		}
	}
	return best, found
}

// mapeFromS46 computes the MAP-E parameters from a DHCPv6 option 94 container and the delegated
// prefix, following RFC 7597 §5 and §6. calcMAPE covers the Japanese ISPs that send no option at
// all; this covers the ones that do, so both paths end in the same mapeResult and the tunnel device
// is configured either way.
func mapeFromS46(c *S46Cont, pd netip.Prefix) (*mapeResult, bool) {
	if c == nil || len(c.BR) == 0 || !pd.IsValid() {
		return nil, false
	}
	rule, ok := bmrFor(c.Rules, pd)
	if !ok || !rule.IPv4Prefix.IsValid() || !rule.IPv4Prefix.Addr().Is4() {
		return nil, false
	}
	rule6Len, rule4Len := rule.IPv6Prefix.Bits(), rule.IPv4Prefix.Bits()
	eaLen := int(rule.EALen)
	if pd.Bits() < rule6Len+eaLen || eaLen > 64 {
		return nil, false
	}
	v4Bits := 32 - rule4Len
	psidLen := eaLen - v4Bits
	if rule.PSIDLen != nil {
		psidLen = int(*rule.PSIDLen)
	}
	if psidLen < 0 || psidLen > 16 || v4Bits < 0 || psidLen+v4Bits > eaLen {
		return nil, false
	}
	offset := uint8(6) // RFC 7597 §5.1 default
	if rule.PSIDOffset != nil {
		offset = *rule.PSIDOffset
	}

	pdb := pd.Masked().Addr().As16()
	ea := bitsAt(pdb, rule6Len, eaLen)
	psid := uint16(ea & (1<<uint(psidLen) - 1))
	if eaLen == 0 && rule.PSID != nil {
		psid = *rule.PSID
	}

	base := rule.IPv4Prefix.Masked().Addr().As4()
	v4 := binary.BigEndian.Uint32(base[:]) | uint32(ea>>uint(psidLen))
	var v4b [4]byte
	binary.BigEndian.PutUint32(v4b[:], v4)

	// CE address (RFC 7597 §6): the end-user prefix with an all-zero subnet id, then an interface
	// identifier of 16 zero bits, the IPv4 address and the PSID. The rule-table path in calcMAPE
	// writes the identifier one octet to the left, which is what the Japanese ISPs it covers use.
	ce := [16]byte{}
	copy(ce[:8], pdb[:8])
	copy(ce[10:14], v4b[:])
	binary.BigEndian.PutUint16(ce[14:16], psid)

	return &mapeResult{
		Provider: "DHCPv6 option 94",
		BR:       c.BR[0],
		IPv4:     netip.AddrFrom4(v4b),
		Rule4:    rule.IPv4Prefix.Masked(),
		Rule6:    rule.IPv6Prefix.Masked(),
		EALen:    uint8(eaLen),
		PSIDLen:  uint8(psidLen),
		Offset:   offset,
		PSID:     psid,
		CE:       netip.AddrFrom16(ce),
		Ports:    portSpans(offset, uint8(psidLen), psid),
	}, true
}

func has38(m map[uint64][3]byte, k uint64) bool { _, ok := m[k]; return ok }
func has31(k uint64) bool                       { _, ok := mapeRule31[k]; return ok }

// s46 reshapes the rule-table result into a DHCPv6 option 94 container so consumers need not care about the source.
func (r *mapeResult) s46() *S46Cont {
	off, plen, psid := r.Offset, r.PSIDLen, r.PSID
	return &S46Cont{
		BR: []netip.Addr{r.BR},
		Rules: []S46Rule{{
			FMR: false, EALen: r.EALen, IPv4Prefix: r.Rule4, IPv6Prefix: r.Rule6,
			PSIDOffset: &off, PSIDLen: &plen, PSID: &psid,
		}},
	}
}

func (r *mapeResult) portsString() string { return spansString(r.Ports) }

func spansString(spans []portSpan) string {
	s := make([]string, 0, len(spans))
	for _, p := range spans {
		s = append(s, p.String())
	}
	return strings.Join(s, " ")
}

// portCount totals the usable ports, which is the number worth knowing on a MAP-E line: it bounds
// how many connections the whole network can have open at once.
func portCount(spans []portSpan) int {
	n := 0
	for _, p := range spans {
		n += int(p.End) - int(p.Start) + 1
	}
	return n
}
