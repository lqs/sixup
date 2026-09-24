package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// TunnelParams carries the tunnel for this line. The first group is the resolved answer, the one
// consumers should read; everything after it is provenance kept for diagnosis, because each source
// (DHCPv6 options, the rule table, packet capture) reports a different shape.
// tunnelKind is the encapsulation a line uses, and tunnelSource is what told us about it. Both are
// decided once, in TunnelParams.resolve, and everything downstream reads the answer rather than the
// evidence.
type tunnelKind string

const (
	tunnelDSLite tunnelKind = "ds-lite"
	tunnelMAPE   tunnelKind = "map-e"
	tunnel4in6   tunnelKind = "4in6" // a fixed public IPv4 carried in IPIP6
)

type tunnelSource string

const (
	fromDHCPv6  tunnelSource = "dhcpv6"  // the ISP sent the parameters
	fromRules   tunnelSource = "rules"   // derived from the prefix through the MAP-E rule tables
	fromCapture tunnelSource = "capture" // inferred from tunnel traffic on the wire
)

type TunnelParams struct {
	Kind       tunnelKind   `json:"kind,omitempty"`
	Source     tunnelSource `json:"source,omitempty"`
	Local      netip.Addr   `json:"local,omitzero"`
	Remote     netip.Addr   `json:"remote,omitzero"`
	IPv4       netip.Addr   `json:"ipv4,omitzero"` // address for the tunnel device: the line's public IPv4, or the RFC 6333 B4 address on DS-Lite
	Confidence string       `json:"confidence,omitempty"`
	Note       string       `json:"note,omitempty"`

	AFTRName  string       `json:"aftr_name,omitempty"`
	AFTRAddrs []netip.Addr `json:"aftr_addrs,omitempty"`
	MAPE      *S46Cont     `json:"mape,omitempty"`
	MAPT      *S46Cont     `json:"mapt,omitempty"`
	LW4o6     *S46Cont     `json:"lw4o6,omitempty"`
	RawMAPT   string       `json:"raw_mapt,omitempty"`
	RawLW4o6  string       `json:"raw_lw4o6,omitempty"`
	// MAPE source: dhcpv6 (option 94) or rules (Japanese IPoE rule table)
	MAPESource tunnelSource `json:"mape_source,omitempty"`
	RuleMAPE   *mapeResult  `json:"rule_mape,omitempty"` // full rule-table result, including CE address and port ranges
	// Evidence behind Source == "capture": packet and port counts, PSID candidates
	Captured *tunnelGuess `json:"capture,omitempty"`
	// Local endpoint addresses DAD found already in use on the link, e.g. an HGW still online
	Conflicts []netip.Addr `json:"conflicts,omitempty"`
	// Option numbers that failed to parse, with the reason
	Errors map[string]string `json:"errors,omitempty"`
}

// resolve fills the effective tunnel fields from whichever source won, in priority order:
// DHCPv6 AFTR (DS-Lite), MAP-E from the rule table, then the capture. wanAddr is the DS-Lite
// B4 endpoint, which reuses the WAN address instead of getting one of its own.
func (t *TunnelParams) resolve(wanAddr netip.Addr) {
	t.Kind, t.Source, t.Confidence, t.Note = "", "", "", ""
	t.Local, t.Remote, t.IPv4 = netip.Addr{}, netip.Addr{}, netip.Addr{}
	switch {
	case len(t.AFTRAddrs) > 0 && wanAddr.IsValid():
		t.Kind, t.Source = tunnelDSLite, fromDHCPv6
		t.Local, t.Remote, t.IPv4 = wanAddr, t.AFTRAddrs[0], netip.MustParseAddr("192.0.0.2")
	case t.RuleMAPE != nil && t.RuleMAPE.CE.IsValid() && t.RuleMAPE.BR.IsValid():
		t.Kind, t.Source = tunnelMAPE, t.MAPESource
		t.Local, t.Remote, t.IPv4 = t.RuleMAPE.CE, t.RuleMAPE.BR, t.RuleMAPE.IPv4
	case t.Captured != nil && t.Captured.Local.IsValid() && t.Captured.Remote.IsValid():
		g := t.Captured
		t.Kind, t.Source, t.Confidence, t.Note = g.Type, fromCapture, g.Confidence, g.Note
		t.Local, t.Remote, t.IPv4 = g.Local, g.Remote, g.IPv4
	}
}

// S46Cont corresponds to the RFC 7598 container options 94/95/96.
type S46Cont struct {
	BR    []netip.Addr  `json:"br,omitempty"`
	DMR   *netip.Prefix `json:"dmr,omitempty"`
	Rules []S46Rule     `json:"rules,omitempty"`
	// Lightweight 4over6 binding
	Bind *S46Bind `json:"bind,omitempty"`
}

type S46Rule struct {
	FMR        bool         `json:"fmr"`
	EALen      uint8        `json:"ea_len"`
	IPv4Prefix netip.Prefix `json:"ipv4_prefix"`
	IPv6Prefix netip.Prefix `json:"ipv6_prefix"`
	PSIDOffset *uint8       `json:"psid_offset,omitempty"`
	PSIDLen    *uint8       `json:"psid_len,omitempty"`
	PSID       *uint16      `json:"psid,omitempty"`
}

type S46Bind struct {
	IPv4Addr   netip.Addr   `json:"ipv4_addr"`
	IPv6Prefix netip.Prefix `json:"ipv6_prefix"`
	PSIDOffset *uint8       `json:"psid_offset,omitempty"`
	PSIDLen    *uint8       `json:"psid_len,omitempty"`
	PSID       *uint16      `json:"psid,omitempty"`
}

func tunnelEqual(a, b *TunnelParams) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(*a, *b)
}

// parseTunnel extracts tunnel parameters from a DHCPv6 REPLY; one bad option must not lose the others.
func parseTunnel(msg *dhcpv6.Message) *TunnelParams {
	t := &TunnelParams{}
	fail := func(code dhcpv6.OptionCode, err error) {
		if t.Errors == nil {
			t.Errors = map[string]string{}
		}
		t.Errors[fmt.Sprint(int(code))] = err.Error()
		debugf("[tunnel-options] failed to parse option %d: %v", code, err)
	}
	if o := msg.Options.GetOne(dhcpv6.OptionAFTRName); o != nil {
		name, err := parseFQDN(o.ToBytes())
		if err != nil {
			fail(dhcpv6.OptionAFTRName, err)
		} else {
			t.AFTRName = name
		}
	}
	if o := msg.Options.GetOne(dhcpv6.OptionS46ContMapE); o != nil {
		c, err := parseS46Cont(o.ToBytes())
		if err != nil {
			fail(dhcpv6.OptionS46ContMapE, err)
		} else {
			t.MAPE = c
		}
	}
	if o := msg.Options.GetOne(dhcpv6.OptionS46ContMapT); o != nil {
		t.RawMAPT = hex.EncodeToString(o.ToBytes())
		c, err := parseS46Cont(o.ToBytes())
		if err != nil {
			fail(dhcpv6.OptionS46ContMapT, err)
		} else {
			t.MAPT = c
		}
	}
	if o := msg.Options.GetOne(dhcpv6.OptionS46ContLW); o != nil {
		t.RawLW4o6 = hex.EncodeToString(o.ToBytes())
		c, err := parseS46Cont(o.ToBytes())
		if err != nil {
			fail(dhcpv6.OptionS46ContLW, err)
		} else {
			t.LW4o6 = c
		}
	}
	if t.AFTRName == "" && t.MAPE == nil && t.MAPT == nil && t.LW4o6 == nil && t.Errors == nil {
		return nil
	}
	return t
}

// parseFQDN decodes a single RFC 1035 encoded name; every length field is validated because it comes off the wire.
func parseFQDN(b []byte) (string, error) {
	if len(b) > 255 {
		return "", errors.New("domain name exceeds 255 bytes")
	}
	var labels []string
	for i := 0; i < len(b); {
		l := int(b[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(b) {
			return "", errors.New("invalid label length")
		}
		labels = append(labels, string(b[i:i+l]))
		i += l
	}
	if len(labels) == 0 {
		return "", errors.New("empty domain name")
	}
	return strings.Join(labels, "."), nil
}

// parseS46Cont reads the sub-options inside an RFC 7598 container: 89 rule, 90 BR, 91 DMR, 92 bind, 93 port params.
func parseS46Cont(b []byte) (*S46Cont, error) {
	if len(b) > 4096 {
		return nil, errors.New("container too large")
	}
	c := &S46Cont{}
	err := walkOptions(b, func(code uint16, v []byte) error {
		switch code {
		case 89:
			r, err := parseS46Rule(v)
			if err != nil {
				return err
			}
			c.Rules = append(c.Rules, r)
		case 90:
			if len(v) != 16 {
				return errors.New("invalid BR address length")
			}
			c.BR = append(c.BR, netip.AddrFrom16([16]byte(v)))
		case 91:
			if len(v) < 1 || len(v) > 17 {
				return errors.New("invalid DMR length")
			}
			p, err := prefixFromBits(v[1:], int(v[0]))
			if err != nil {
				return err
			}
			c.DMR = &p
		case 92:
			bd, err := parseS46Bind(v)
			if err != nil {
				return err
			}
			c.Bind = bd
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func parseS46Rule(v []byte) (S46Rule, error) {
	var r S46Rule
	if len(v) < 8 {
		return r, errors.New("rule too short")
	}
	r.FMR = v[0]&1 != 0
	r.EALen = v[1]
	p4len := int(v[2])
	if p4len > 32 {
		return r, errors.New("invalid ipv4 prefix length")
	}
	r.IPv4Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte(v[3:7])), p4len)
	p6len := int(v[7])
	n := (p6len + 7) / 8
	if p6len > 128 || len(v) < 8+n {
		return r, errors.New("invalid ipv6 prefix length")
	}
	p6, err := prefixFromBits(v[8:8+n], p6len)
	if err != nil {
		return r, err
	}
	r.IPv6Prefix = p6
	// Trailing bytes are nested options; only 93 port params is of interest
	err = walkOptions(v[8+n:], func(code uint16, pv []byte) error {
		if code != 93 {
			return nil
		}
		if len(pv) != 4 {
			return errors.New("invalid port params length")
		}
		off, plen := pv[0], pv[1]
		psid := binary.BigEndian.Uint16(pv[2:4])
		if plen > 0 {
			psid >>= 16 - uint(plen)
		}
		r.PSIDOffset, r.PSIDLen, r.PSID = &off, &plen, &psid
		return nil
	})
	return r, err
}

func parseS46Bind(v []byte) (*S46Bind, error) {
	if len(v) < 5 {
		return nil, errors.New("bind too short")
	}
	b := &S46Bind{IPv4Addr: netip.AddrFrom4([4]byte(v[0:4]))}
	p6len := int(v[4])
	n := (p6len + 7) / 8
	if p6len > 128 || len(v) < 5+n {
		return nil, errors.New("invalid bind ipv6 prefix length")
	}
	p6, err := prefixFromBits(v[5:5+n], p6len)
	if err != nil {
		return nil, err
	}
	b.IPv6Prefix = p6
	err = walkOptions(v[5+n:], func(code uint16, pv []byte) error {
		if code != 93 || len(pv) != 4 {
			return nil
		}
		off, plen := pv[0], pv[1]
		psid := binary.BigEndian.Uint16(pv[2:4])
		if plen > 0 {
			psid >>= 16 - uint(plen)
		}
		b.PSIDOffset, b.PSIDLen, b.PSID = &off, &plen, &psid
		return nil
	})
	return b, err
}

func prefixFromBits(b []byte, bits int) (netip.Prefix, error) {
	if bits < 0 || bits > 128 || len(b) > 16 {
		return netip.Prefix{}, errors.New("invalid prefix length")
	}
	var a [16]byte
	copy(a[:], b)
	return netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked(), nil
}

// walkOptions iterates DHCPv6 TLVs; on-wire lengths are untrusted, so any overrun is an error.
func walkOptions(b []byte, fn func(code uint16, v []byte) error) error {
	for i := 0; i < len(b); {
		if len(b)-i < 4 {
			return errors.New("truncated option header")
		}
		code := binary.BigEndian.Uint16(b[i:])
		l := int(binary.BigEndian.Uint16(b[i+2:]))
		i += 4
		if i+l > len(b) {
			return errors.New("option length out of bounds")
		}
		if err := fn(code, b[i:i+l]); err != nil {
			return err
		}
		i += l
	}
	return nil
}

// resolveAFTR resolves the AFTR name to AAAA records; a failure is only logged, never fatal.
func resolveAFTR(ctx context.Context, name string) []netip.Addr {
	if name == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", name)
	if err != nil {
		debugf("[tunnel-options] failed to resolve AFTR %s: %v", name, err)
		return nil
	}
	var out []netip.Addr
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out
}

// aftrResolver turns the DS-Lite AFTR name of DHCPv6 option 64 into addresses and feeds them back
// into the store, which is where TunnelParams.resolve picks the DS-Lite remote endpoint from.
// A failed lookup is retried, since the name is useless without an address. Lookups run outside
// the loop so a new name is seen at once; a result of any lookup but the latest is dropped.
type aftrResolver struct {
	store  *Store
	retry  time.Duration
	name   string
	addrs  []netip.Addr
	gen    int                // numbers the lookups, to tell the latest one's result
	cancel context.CancelFunc // of the lookup in flight, nil when none
}

type aftrResult struct {
	gen   int
	name  string
	addrs []netip.Addr
}

func (r *aftrResolver) run(ctx context.Context, ch <-chan Snapshot) {
	if r.retry == 0 {
		r.retry = 30 * time.Second
	}
	t := time.NewTicker(r.retry)
	defer t.Stop()
	results := make(chan aftrResult)
	lookup := func() {
		if r.cancel != nil {
			r.cancel()
		}
		lctx, cancel := context.WithCancel(ctx)
		r.cancel = cancel
		r.gen++
		go func(gen int, name string) {
			res := aftrResult{gen, name, resolveAFTR(lctx, name)}
			select {
			case results <- res:
			case <-lctx.Done():
			}
		}(r.gen, r.name)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case snap := <-ch:
			name := ""
			if snap.Tunnel != nil {
				name = snap.Tunnel.AFTRName
			}
			if name == "" || name == r.name {
				continue
			}
			r.name, r.addrs = name, nil
			lookup()
		case res := <-results:
			if res.gen != r.gen {
				continue
			}
			r.cancel()
			r.cancel = nil
			r.addrs = res.addrs
			r.store.SetAFTRAddrs(res.name, res.addrs)
		case <-t.C:
			if r.name != "" && len(r.addrs) == 0 && r.cancel == nil {
				lookup()
			}
		}
	}
}

// s46Env matches odhcp6c's MAPE variable format:
// one rule per "type=map-e,ealen=..,prefix4len=..,ipv4prefix=..,prefix6len=..,ipv6prefix=..,offset=..,psidlen=..,psid=..,br=..", rules separated by spaces.
func s46Env(c *S46Cont) string {
	var rules []string
	br := ""
	if len(c.BR) > 0 {
		br = c.BR[0].String()
	}
	for _, r := range c.Rules {
		parts := []string{
			fmt.Sprintf("ealen=%d", r.EALen),
			fmt.Sprintf("prefix4len=%d", r.IPv4Prefix.Bits()),
			"ipv4prefix=" + r.IPv4Prefix.Addr().String(),
			fmt.Sprintf("prefix6len=%d", r.IPv6Prefix.Bits()),
			"ipv6prefix=" + r.IPv6Prefix.Addr().String(),
		}
		if r.FMR {
			parts = append(parts, "fmr=1")
		}
		if r.PSIDOffset != nil {
			parts = append(parts, fmt.Sprintf("offset=%d,psidlen=%d,psid=%d", *r.PSIDOffset, *r.PSIDLen, *r.PSID))
		}
		if br != "" {
			parts = append(parts, "br="+br)
		}
		if c.DMR != nil {
			parts = append(parts, "dmr="+c.DMR.String())
		}
		rules = append(rules, strings.Join(parts, ","))
	}
	if c.Bind != nil {
		parts := []string{
			"ipv4addr=" + c.Bind.IPv4Addr.String(),
			fmt.Sprintf("prefix6len=%d", c.Bind.IPv6Prefix.Bits()),
			"ipv6prefix=" + c.Bind.IPv6Prefix.Addr().String(),
		}
		if c.Bind.PSIDOffset != nil {
			parts = append(parts, fmt.Sprintf("offset=%d,psidlen=%d,psid=%d", *c.Bind.PSIDOffset, *c.Bind.PSIDLen, *c.Bind.PSID))
		}
		if br != "" {
			parts = append(parts, "br="+br)
		}
		rules = append(rules, strings.Join(parts, ","))
	}
	return strings.Join(rules, " ")
}

// hasDelivered reports that DHCPv6 already gave tunnel information, so no capture-based inference is needed.
func (t *TunnelParams) hasDelivered() bool {
	return t != nil && (t.AFTRName != "" || t.MAPE != nil || t.MAPT != nil || t.LW4o6 != nil)
}

// endpoints lists the tunnel local endpoint addresses to configure on the WAN interface: only the rule-table
// MAP-E CE, which is computed and exists nowhere else. The local endpoint seen in a capture is never added:
// capture is not promiscuous, so the upstream already resolved that address to this host's MAC, meaning it
// is one of our addresses or one the NDP proxy answers for. DS-Lite's B4 reuses the existing WAN address.
func (t *TunnelParams) endpoints() []netip.Addr {
	if t.RuleMAPE != nil && t.RuleMAPE.CE.IsValid() {
		return []netip.Addr{t.RuleMAPE.CE}
	}
	return nil
}
