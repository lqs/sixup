package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Prefix stores absolute expiry times so downstream lifetimes, derived from the
// remaining time, can never exceed what the upstream granted.
// prefixSource is where a prefix came from, and which of them wins is what -wan-prefer decides.
type prefixSource string

const (
	sourcePD  prefixSource = "pd"  // DHCPv6 prefix delegation
	sourceRA  prefixSource = "ra"  // an on-link prefix from the upstream Router Advertisement
	sourceULA prefixSource = "ula" // generated here, never routed by the ISP
)

// changeKind is the strongest thing that happened to the prefix set, which decides whether
// consumers redo their work now or wait for the settle period.
type changeKind string

const (
	changeAdd    changeKind = "add"    // a prefix appeared, or one of them moved
	changeRenew  changeKind = "renew"  // the same prefixes, new lifetimes
	changeRevoke changeKind = "revoke" // a prefix is being withdrawn
	changeNone   changeKind = "none"
)

type Prefix struct {
	Prefix     netip.Prefix `json:"prefix"`
	Preferred  time.Time    `json:"preferred_until"`
	Valid      time.Time    `json:"valid_until"`
	Source     prefixSource `json:"source"`
	Deprecated bool         `json:"deprecated,omitempty"`
	SLAAC      bool         `json:"slaac,omitempty"` // upstream RA had the A bit set; SLAAC is possible on the WAN
}

func (p Prefix) preferredLeft(now time.Time) time.Duration {
	if p.Deprecated || now.After(p.Preferred) {
		return 0
	}
	return p.Preferred.Sub(now)
}

func (p Prefix) validLeft(now time.Time) time.Duration {
	if now.After(p.Valid) {
		return 0
	}
	return p.Valid.Sub(now)
}

// SourceUpdate is one complete state submitted by the PD client or the upstream RA listener.
type SourceUpdate struct {
	Prefixes []Prefix
	DNS      []netip.Addr
	DNSSL    []string
	PREF64   netip.Prefix  // NAT64 prefix from the upstream RA (RFC 8781); zero when absent
	MTU      int           // WAN path MTU: the RA MTU option, else the WAN interface MTU
	WANAddr  netip.Addr    // WAN address from IA_NA or SLAAC
	Tunnel   *TunnelParams // set only by the pd source
}

// Snapshot is the consistent view handed to every consumer.
type Snapshot struct {
	Seq     uint64              `json:"seq"`
	Time    time.Time           `json:"time"`
	Change  changeKind          `json:"change"`
	Source  prefixSource        `json:"source"` // source currently in effect
	WAN     []Prefix            `json:"wan_prefixes"`
	LAN     map[string][]Prefix `json:"lan_prefixes"`
	DNS     []netip.Addr        `json:"dns"`
	DNSSL   []string            `json:"dnssl"`
	PREF64  netip.Prefix        `json:"pref64,omitempty"`
	WANMTU  int                 `json:"wan_mtu,omitempty"` // drives both the downstream RA MTU option and the tunnel MTU
	WANAddr netip.Addr          `json:"wan_addr"`
	Tunnel  *TunnelParams       `json:"tunnel,omitempty"`
}

// wanSLAAC returns the SLAAC-capable /64s from the upstream RA, including deprecated ones so addresses can be retired.
func (s Snapshot) wanSLAAC() []Prefix {
	var out []Prefix
	for _, p := range s.WAN {
		if p.Source == "ra" && p.SLAAC && p.Prefix.Bits() == 64 {
			out = append(out, p)
		}
	}
	return out
}

type storeMsg struct {
	source prefixSource
	upd    SourceUpdate
}

// Store is the only goroutine that owns prefix state; all changes serialize through it.
// Each consumer gets a channel of capacity 1 that only ever holds the latest snapshot.
type Store struct {
	in       chan storeMsg
	subReq   chan chan Snapshot
	curReq   chan chan Snapshot
	prefer   prefixSource
	ula      []netip.Prefix // optional ULA, advertised alongside the GUA
	lans     []lanDef
	hold     time.Duration // how long a revoked prefix is advertised with preferred=0
	mapeRule bool          // derive MAP-E from the Japanese IPoE rule table when DHCPv6 gives none
	// PD startup grace: with PD preferred, RA prefixes are not handed to the LAN until PD
	// concludes, so an RA arriving a second early does not get advertised and then revoked.
	pdGrace  time.Time
	sources  map[prefixSource]SourceUpdate
	captured *tunnelGuess
	capIn    chan *tunnelGuess
	// DS-Lite option 64 carries a name; the resolved addresses come back from aftrResolver.
	aftrName  string
	aftrAddrs []netip.Addr
	aftrIn    chan aftrUpdate
	conflicts map[netip.Addr]bool // tunnel endpoints that failed DAD
	confIn    chan endpointState
	cur       Snapshot
	subs      []chan Snapshot
	// Settle period: at startup RA, PD, Information-Request and capture results arrive one by one;
	// publishing each would burst RAs repeatedly. Revocations skip the wait.
	settle    time.Duration
	pending   changeKind // strongest change type accumulated during the settle period
	pubTimer  <-chan time.Time
	shortWarn string                      // last reported set of LAN segments left without a prefix
	revoked   map[netip.Prefix]revokedLAN // LAN prefixes in their deprecate period
	revokedW  map[netip.Prefix]Prefix
}

type revokedLAN struct {
	iface string
	p     Prefix
}

type lanDef struct {
	iface string
	index int // subnet number used when carving a /64 out of the PD
}

func newStore(prefer prefixSource, lans []lanDef, hold time.Duration, ula []netip.Prefix, mapeRule bool, pdGrace, settle time.Duration) *Store {
	s := &Store{
		ula:       ula,
		mapeRule:  mapeRule,
		in:        make(chan storeMsg, 16),
		subReq:    make(chan chan Snapshot),
		curReq:    make(chan chan Snapshot),
		capIn:     make(chan *tunnelGuess, 4),
		aftrIn:    make(chan aftrUpdate, 4),
		confIn:    make(chan endpointState, 8),
		conflicts: map[netip.Addr]bool{},
		prefer:    prefer,
		lans:      lans,
		hold:      hold,
		settle:    settle,
		sources:   map[prefixSource]SourceUpdate{},
		revoked:   map[netip.Prefix]revokedLAN{},
		revokedW:  map[netip.Prefix]Prefix{},
	}
	s.cur.LAN = map[string][]Prefix{}
	if pdGrace > 0 && prefer == "pd" {
		s.pdGrace = time.Now().Add(pdGrace)
	}
	if len(ula) > 0 {
		// ULA needs no source, so compute it now so the first snapshot carries it
		s.recompute(time.Now())
	}
	go s.loop()
	return s
}

// Subscribe order is delivery order.
func (s *Store) Subscribe() <-chan Snapshot {
	ch := make(chan Snapshot, 1)
	s.subReq <- ch
	return ch
}

func (s *Store) Set(source prefixSource, upd SourceUpdate) {
	s.in <- storeMsg{source, upd}
}

type endpointState struct {
	addr     netip.Addr
	conflict bool
}

// SetEndpointConflict is called by the address manager when a tunnel endpoint fails or recovers DAD.
func (s *Store) SetEndpointConflict(addr netip.Addr, conflict bool) {
	s.confIn <- endpointState{addr, conflict}
}

// aftrUpdate carries the AAAA records of an AFTR name back into the store.
type aftrUpdate struct {
	name  string
	addrs []netip.Addr
}

// SetAFTRAddrs stores the addresses an AFTR name resolved to.
func (s *Store) SetAFTRAddrs(name string, addrs []netip.Addr) {
	s.aftrIn <- aftrUpdate{name, addrs}
}

// SetCaptured stores tunnel parameters inferred from capture; nil clears them.
func (s *Store) SetCaptured(g *tunnelGuess) {
	s.capIn <- g
}

func (s *Store) Current() Snapshot {
	ch := make(chan Snapshot, 1)
	s.curReq <- ch
	return <-ch
}

func (s *Store) loop() {
	expire := s.nextExpiry()
	for {
		select {
		case ch := <-s.subReq:
			s.subs = append(s.subs, ch)
			ch <- s.cur
		case ch := <-s.curReq:
			ch <- s.cur
		case m := <-s.in:
			s.sources[m.source] = m.upd
			s.recompute(time.Now())
			expire = s.nextExpiry()
		case g := <-s.capIn:
			s.captured = g
			s.recompute(time.Now())
		case a := <-s.aftrIn:
			s.aftrName, s.aftrAddrs = a.name, a.addrs
			s.recompute(time.Now())
		case e := <-s.confIn:
			if e.conflict {
				s.conflicts[e.addr] = true
			} else {
				delete(s.conflicts, e.addr)
			}
			s.recompute(time.Now())
		case <-expire:
			s.recompute(time.Now())
			expire = s.nextExpiry()
		case <-s.pubTimer:
			s.publish()
		}
	}
}

// nextExpiry wakes when the earliest deprecate period ends so expired prefixes leave the snapshot.
func (s *Store) nextExpiry() <-chan time.Time {
	var earliest time.Time
	for _, r := range s.revoked {
		if earliest.IsZero() || r.p.Valid.Before(earliest) {
			earliest = r.p.Valid
		}
	}
	for _, p := range s.revokedW {
		if earliest.IsZero() || p.Valid.Before(earliest) {
			earliest = p.Valid
		}
	}
	if _, ok := s.sources[sourcePD]; !ok && !s.pdGrace.IsZero() && time.Now().Before(s.pdGrace) {
		if earliest.IsZero() || s.pdGrace.Before(earliest) {
			earliest = s.pdGrace
		}
	}
	if earliest.IsZero() {
		return nil
	}
	return time.After(time.Until(earliest) + 50*time.Millisecond)
}

func (s *Store) pickSource() (prefixSource, SourceUpdate) {
	order := []prefixSource{sourcePD, sourceRA}
	if s.prefer == "ra" {
		order = []prefixSource{sourceRA, sourcePD}
	}
	_, pdConcluded := s.sources[sourcePD]
	for _, name := range order {
		u, ok := s.sources[name]
		if ok && len(u.Prefixes) > 0 {
			if name == sourceRA && !pdConcluded && time.Now().Before(s.pdGrace) {
				// PD has not concluded yet: keep RA prefixes as WAN info only
				u.Prefixes = nil
			}
			return name, u
		}
	}
	// keep DNS and WAN address even when no source has prefixes
	for _, name := range order {
		if u, ok := s.sources[name]; ok {
			return name, u
		}
	}
	return "", SourceUpdate{}
}

func (s *Store) recompute(now time.Time) {
	src, u := s.pickSource()
	next := Snapshot{
		Seq:     s.cur.Seq + 1,
		Time:    now,
		Source:  src,
		LAN:     map[string][]Prefix{},
		DNS:     u.DNS,
		DNSSL:   u.DNSSL,
		PREF64:  u.PREF64,
		WANMTU:  u.MTU,
		WANAddr: u.WANAddr,
	}
	// Prefixes and DNS often come from different sources (RA gives the /64, Information-Request gives DNS), so fill gaps from the other one
	for _, name := range []prefixSource{sourcePD, sourceRA} {
		if name == src {
			continue
		}
		if o, ok := s.sources[name]; ok {
			if len(next.DNS) == 0 {
				next.DNS = o.DNS
			}
			if len(next.DNSSL) == 0 {
				next.DNSSL = o.DNSSL
			}
			if !next.PREF64.IsValid() {
				next.PREF64 = o.PREF64
			}
			if !next.WANAddr.IsValid() {
				next.WANAddr = o.WANAddr
			}
			if next.WANMTU == 0 {
				next.WANMTU = o.MTU
			}
		}
	}
	if pd, ok := s.sources[sourcePD]; ok {
		next.Tunnel = pd.Tunnel
	}
	if next.Tunnel != nil && next.Tunnel.MAPE != nil {
		t := *next.Tunnel
		t.MAPESource = fromDHCPv6
		// The option carries the rule, not the answer: the CE address, the shared IPv4 and the port
		// set still have to be computed from the delegated prefix before a tunnel can be built.
		for _, p := range u.Prefixes {
			if p.validLeft(now) == 0 || p.preferredLeft(now) == 0 {
				continue
			}
			if r, ok := mapeFromS46(t.MAPE, p.Prefix); ok {
				t.RuleMAPE = r
				break
			}
		}
		next.Tunnel = &t
	} else if s.mapeRule {
		// Japanese IPoE does not deliver MAP-E via DHCPv6; derive it from the rule table
		for _, p := range u.Prefixes {
			if p.validLeft(now) == 0 || p.preferredLeft(now) == 0 {
				continue
			}
			if r, ok := calcMAPE(p.Prefix); ok {
				t := TunnelParams{}
				if next.Tunnel != nil {
					t = *next.Tunnel
				}
				t.MAPE, t.MAPESource, t.RuleMAPE = r.s46(), fromRules, r
				next.Tunnel = &t
				break
			}
		}
	}
	if s.captured != nil {
		t := TunnelParams{}
		if next.Tunnel != nil {
			t = *next.Tunnel
		}
		t.Captured = s.captured
		next.Tunnel = &t
	}
	if next.Tunnel != nil && next.Tunnel.AFTRName != "" && next.Tunnel.AFTRName == s.aftrName {
		t := *next.Tunnel
		t.AFTRAddrs = s.aftrAddrs
		next.Tunnel = &t
	}
	if next.Tunnel != nil {
		t := *next.Tunnel
		t.resolve(next.WANAddr)
		next.Tunnel = &t
	}
	if len(s.conflicts) > 0 && next.Tunnel != nil {
		t := *next.Tunnel
		for _, a := range t.endpoints() {
			if s.conflicts[a] {
				t.Conflicts = append(t.Conflicts, a)
			}
		}
		next.Tunnel = &t
	}

	// currently valid WAN prefixes and their LAN split
	active := map[netip.Prefix]bool{}
	activeW := map[netip.Prefix]bool{}
	var short []shortPrefix
	for _, p := range u.Prefixes {
		if p.validLeft(now) == 0 {
			continue
		}
		activeW[p.Prefix] = true
		if p.preferredLeft(now) == 0 {
			p.Deprecated = true
		}
		next.WAN = append(next.WAN, p)
		delete(s.revokedW, p.Prefix)
		for _, l := range s.lans {
			sub, ok := splitLAN(p.Prefix, l.index)
			if !ok {
				short = append(short, shortPrefix{p.Prefix, l})
				continue
			}
			lp := p
			lp.Prefix = sub
			next.LAN[l.iface] = append(next.LAN[l.iface], lp)
			active[sub] = true
			delete(s.revoked, sub)
		}
	}

	// ULA coexists with the GUA, is never revoked and takes no part in source selection; fixed 7d preferred / 30d valid, refreshed on every recompute
	for _, up := range s.ula {
		for _, l := range s.lans {
			sub, ok := splitLAN(up, l.index)
			if !ok {
				short = append(short, shortPrefix{up, l})
				continue
			}
			next.LAN[l.iface] = append(next.LAN[l.iface], Prefix{Prefix: sub, Preferred: now.Add(7 * 24 * time.Hour), Valid: now.Add(30 * 24 * time.Hour), Source: "ula"})
			active[sub] = true
		}
	}

	s.warnShort(short)

	// diff against the previous snapshot; revoked prefixes enter the deprecate period
	change := changeNone
	for iface, olds := range s.cur.LAN {
		for _, op := range olds {
			if active[op.Prefix] || op.Deprecated {
				continue
			}
			change = changeRevoke
			hold := now.Add(s.hold)
			if op.Valid.Before(hold) {
				hold = op.Valid
			}
			s.revoked[op.Prefix] = revokedLAN{iface, Prefix{Prefix: op.Prefix, Preferred: now, Valid: hold, Source: op.Source, Deprecated: true}}
			log.Printf("[prefix-store] %s on %s revoked, advertising preferred=0 until %s", iface, op.Prefix, hold.Format(time.TimeOnly))
		}
	}
	for _, op := range s.cur.WAN {
		if activeW[op.Prefix] || op.Deprecated {
			continue
		}
		hold := now.Add(s.hold)
		if op.Valid.Before(hold) {
			hold = op.Valid
		}
		s.revokedW[op.Prefix] = Prefix{Prefix: op.Prefix, Preferred: now, Valid: hold, Source: op.Source, Deprecated: true}
	}
	for k, r := range s.revoked {
		if !now.Before(r.p.Valid) {
			delete(s.revoked, k)
			change = changeRevoke
			continue
		}
		next.LAN[r.iface] = append(next.LAN[r.iface], r.p)
	}
	for k, p := range s.revokedW {
		if !now.Before(p.Valid) {
			delete(s.revokedW, k)
			change = changeRevoke // same event as the LAN side, but a WAN-only setup has no LAN entry to report it
			continue
		}
		next.WAN = append(next.WAN, p)
	}

	// classify add / renew
	if change == changeNone {
		oldSet := map[netip.Prefix]Prefix{}
		for _, ps := range s.cur.LAN {
			for _, p := range ps {
				oldSet[p.Prefix] = p
			}
		}
		for _, ps := range next.LAN {
			for _, p := range ps {
				if p.Source == "ula" {
					if _, ok := oldSet[p.Prefix]; !ok {
						change = changeAdd
					}
					continue
				}
				old, ok := oldSet[p.Prefix]
				if !ok || (old.Deprecated && !p.Deprecated) {
					change = changeAdd
				} else if change == changeNone && (!old.Valid.Equal(p.Valid) || !old.Preferred.Equal(p.Preferred)) {
					change = changeRenew
				}
			}
		}
		if change == changeNone && !tunnelEqual(s.cur.Tunnel, next.Tunnel) {
			change = changeRenew
		}
		if change == changeNone && s.cur.WANAddr != next.WANAddr {
			change = changeRenew
		}
		// DNS, search list, PREF64 and MTU reach hosts through the RA and the DHCPv6 server, so a
		// change in them has to be published too; otherwise "none" would hide it from every consumer.
		if change == changeNone && !slices.Equal(s.cur.DNS, next.DNS) {
			change = changeRenew
		}
		if change == changeNone && !slices.Equal(s.cur.DNSSL, next.DNSSL) {
			change = changeRenew
		}
		if change == changeNone && (s.cur.PREF64 != next.PREF64 || s.cur.WANMTU != next.WANMTU) {
			change = changeRenew
		}
	}
	next.Change = change
	s.cur = next
	if change == changeNone {
		return // nothing material changed; do not open a settle window for it
	}
	log.Printf("[prefix-store] change %s, source %s, %s", change, src, next.describe(now))
	if changeRank(change) > changeRank(s.pending) {
		s.pending = change
	}
	if s.settle == 0 || change == changeRevoke {
		s.publish()
		return
	}
	if s.pubTimer == nil {
		s.pubTimer = time.After(s.settle)
	}
}

// publish fans out the snapshot; Change is the strongest change seen during the settle period.
func (s *Store) publish() {
	s.pubTimer = nil
	if s.pending != "" {
		s.cur.Change = s.pending
	}
	s.pending = ""
	for _, ch := range s.subs {
		select {
		case <-ch:
		default:
		}
		ch <- s.cur
	}
}

func changeRank(c changeKind) int {
	switch c {
	case "revoke":
		return 3
	case "add":
		return 2
	case "renew":
		return 1
	}
	return 0
}

// shortPrefix records a LAN segment a prefix was too short to cover.
type shortPrefix struct {
	prefix netip.Prefix
	lan    lanDef
}

// warnShort reports LAN segments left without a prefix, once per distinct situation rather than on
// every renewal. A /64 holds exactly one segment, so this is what a multi-segment configuration on a
// line that delegates nothing looks like from the inside.
func (s *Store) warnShort(short []shortPrefix) {
	key := fmt.Sprint(short)
	if key == s.shortWarn {
		return
	}
	s.shortWarn = key
	byPrefix := map[netip.Prefix][]string{}
	var order []netip.Prefix
	for _, sp := range short {
		if _, seen := byPrefix[sp.prefix]; !seen {
			order = append(order, sp.prefix)
		}
		byPrefix[sp.prefix] = append(byPrefix[sp.prefix], fmt.Sprintf("%s(subnet %d)", sp.lan.iface, sp.lan.index))
	}
	for _, pf := range order {
		log.Printf("[prefix-store] %s is too short to cover %s: that segment gets no address from it. "+
			"A /64 holds one segment only; ask the ISP for a shorter delegation, or run -lan-ula for internal addresses",
			pf, strings.Join(byPrefix[pf], " "))
	}
}

// splitLAN carves the index-th /64 out of a PD prefix; a /64 only allows index 0.
func splitLAN(p netip.Prefix, index int) (netip.Prefix, bool) {
	bits := p.Bits()
	if bits > 64 || index < 0 {
		return netip.Prefix{}, false
	}
	free := uint(64 - bits)
	if free < 64 && uint64(index) >= uint64(1)<<free {
		return netip.Prefix{}, false
	}
	b := p.Masked().Addr().As16()
	v := binary.BigEndian.Uint64(b[:8]) | uint64(index)
	binary.BigEndian.PutUint64(b[:8], v)
	return netip.PrefixFrom(netip.AddrFrom16(b), 64), true
}

// sharedWith reports whether a LAN prefix is the upstream RA's on-link /64, shared by both sides.
// Only RA counts: a PD-delegated /64 is routed by the ISP and is not shared.
func (s Snapshot) sharedWith(p netip.Prefix) bool {
	if p.Bits() != 64 {
		return false
	}
	for _, w := range s.WAN {
		if w.Source == "ra" && w.Prefix == p {
			return true
		}
	}
	return false
}

// side names an interface role and matches the -wan and -lan flags. Direction words
// (upstream, downstream) say where traffic goes; a side says which interface it is on.
type side string

const (
	sideWAN side = "wan"
	sideLAN side = "lan"
)

func (s side) other() side {
	if s == sideWAN {
		return sideLAN
	}
	return sideWAN
}

// shared64Layout is the address and route layout when the upstream gives a single /64:
//   - wan: /64 on the WAN, /128 on the LAN; LAN hosts get /128 routes once the NDP proxy probes them
//   - lan: /64 on the LAN, /128 on the WAN, no WAN on-link /64 route; same-subnet hosts on the WAN side get /128 routes via the NDP proxy
//   - split: /128 on both sides, both directions rely on NDP proxy /128 routes
//
// The lan layout is the /64 sharing of RFC 7278, written there for a 3GPP interface, which is
// point-to-point and therefore needs no proxy; on an Ethernet WAN the NDP proxy supplies what the
// point-to-point link gave for free.
//
// The layout is irrelevant when the prefix is not shared (a /64 carved from a PD).
type shared64Layout string

func (l shared64Layout) plen(s side, shared bool) int {
	if !shared {
		return 64
	}
	switch l {
	case "wan":
		if s == sideLAN {
			return 128
		}
	case "lan":
		if s == sideWAN {
			return 128
		}
	case "split":
		return 128
	}
	return 64
}

// wanOnLink reports whether the /64 on-link route goes on the WAN.
func (l shared64Layout) wanOnLink() bool { return l == "wan" }

// lanHostRoutes reports whether the NDP proxy must add /128 routes for LAN hosts.
func (l shared64Layout) lanHostRoutes() bool { return l != "lan" }

// loadULA parses -ula: empty disables it; auto generates and persists a random RFC 4193 /48 under fd00::/8; otherwise the given prefixes are used.
func loadULA(stateDir, spec string) ([]netip.Prefix, error) {
	switch spec {
	case "":
		return nil, nil
	case "auto":
		p := filepath.Join(stateDir, "ula")
		if b, err := os.ReadFile(p); err == nil {
			if pf, err := netip.ParsePrefix(strings.TrimSpace(string(b))); err == nil {
				return []netip.Prefix{pf}, nil
			}
		}
		var a [16]byte
		a[0] = 0xfd
		rand.Read(a[1:6])
		pf := netip.PrefixFrom(netip.AddrFrom16(a), 48)
		if !dryRun {
			os.MkdirAll(stateDir, 0o755)
			if err := os.WriteFile(p, []byte(pf.String()+"\n"), 0o600); err != nil {
				return nil, err
			}
		}
		log.Printf("[prefix-store] generated ULA %s", pf)
		return []netip.Prefix{pf}, nil
	}
	var out []netip.Prefix
	for _, s := range strings.Split(spec, ",") {
		pf, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		if pf.Bits() > 64 || pf.Addr().As16()[0]&0xfe != 0xfc {
			return nil, fmt.Errorf("%s is not a ULA within fc00::/7 of length /64 or shorter", pf)
		}
		out = append(out, pf.Masked())
	}
	return out, nil
}

// describe compresses the snapshot into one log line: prefixes with remaining lifetimes, LAN split, WAN address, DNS, tunnel source.
func (s Snapshot) describe(now time.Time) string {
	var parts []string
	fmtP := func(p Prefix) string {
		state := ""
		if p.Deprecated {
			state = " deprecated"
		}
		return fmt.Sprintf("%s(%s pref=%s valid=%s%s)", p.Prefix, p.Source,
			p.preferredLeft(now).Round(time.Second), p.validLeft(now).Round(time.Second), state)
	}
	var wan []string
	for _, p := range s.WAN {
		wan = append(wan, fmtP(p))
	}
	parts = append(parts, "WAN prefixes="+strings.Join(wan, ","))
	for _, iface := range sortedKeys(s.LAN) {
		var lan []string
		for _, p := range s.LAN[iface] {
			lan = append(lan, fmtP(p))
		}
		parts = append(parts, iface+"="+strings.Join(lan, ","))
	}
	if s.WANAddr.IsValid() {
		parts = append(parts, "WAN addr="+s.WANAddr.String())
	}
	if len(s.DNS) > 0 {
		var d []string
		for _, a := range s.DNS {
			d = append(d, a.String())
		}
		parts = append(parts, "DNS="+strings.Join(d, ","))
	}
	if len(s.DNSSL) > 0 {
		parts = append(parts, "DNSSL="+strings.Join(s.DNSSL, ","))
	}
	if s.PREF64.IsValid() {
		parts = append(parts, "PREF64="+s.PREF64.String())
	}
	if s.WANMTU > 0 {
		parts = append(parts, fmt.Sprintf("MTU=%d", s.WANMTU))
	}
	if t := s.Tunnel; t != nil {
		if t.AFTRName != "" {
			parts = append(parts, "AFTR="+t.AFTRName)
		}
		if t.MAPE != nil {
			parts = append(parts, "MAPE("+string(t.MAPESource)+")="+s46Env(t.MAPE))
		}
		if t.RuleMAPE != nil {
			parts = append(parts, fmt.Sprintf("ISP=%s IPv4=%s PSID=%d ports=%s", t.RuleMAPE.Provider, t.RuleMAPE.IPv4, t.RuleMAPE.PSID, t.RuleMAPE.portsString()))
		}
		if t.Captured != nil {
			parts = append(parts, fmt.Sprintf("captured=%s remote=%s ipv4=%s", t.Captured.Type, t.Captured.Remote, t.Captured.IPv4))
		}
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string][]Prefix) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// tunnelEndpoints returns the local tunnel endpoints that must be configured on the WAN.
func (s Snapshot) tunnelEndpoints() []netip.Addr {
	if s.Tunnel == nil {
		return nil
	}
	return s.Tunnel.endpoints()
}

// routableDNS drops link-local DNS servers (e.g. fe80::1): they are reachable only on the WAN
// link, so LAN clients would just time out on them.
func routableDNS(in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		if !a.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}
