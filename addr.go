package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// IFA_F_* address flags (linux/if_addr.h)
const (
	ifaFTemporary  = 0x01
	ifaFNodad      = 0x02
	ifaFOptimistic = 0x04
	ifaFDeprecated = 0x20
	ifaFTentative  = 0x40
	ifaFDadFailed  = 0x08
)

// stableIID derives an RFC 7217 interface identifier: stable per network, unlinkable across networks.
func stableIID(secret []byte, prefix netip.Prefix, iface string, dadCounter uint8) netip.Addr {
	mac := hmac.New(sha256.New, secret)
	p := prefix.Masked().Addr().As16()
	mac.Write(p[:8])
	mac.Write([]byte(iface))
	mac.Write([]byte{dadCounter})
	sum := mac.Sum(nil)
	copy(p[8:], sum[:8])
	p[8] &^= 0x02 // clear the u bit so it cannot be mistaken for EUI-64
	return netip.AddrFrom16(p)
}

func randomIID(prefix netip.Prefix) netip.Addr {
	p := prefix.Masked().Addr().As16()
	rand.Read(p[8:])
	p[8] &^= 0x02
	return netip.AddrFrom16(p)
}

// loadSecret reads or generates the RFC 7217 secret, persisted in the state directory.
func loadSecret(stateDir string) []byte {
	p := filepath.Join(stateDir, "secret")
	if b, err := os.ReadFile(p); err == nil {
		if s, err := hex.DecodeString(string(trimSpace(b))); err == nil && len(s) == 32 {
			return s
		}
	}
	s := make([]byte, 32)
	rand.Read(s)
	if dryRun {
		return s
	}
	os.MkdirAll(stateDir, 0o755)
	os.WriteFile(p, []byte(hex.EncodeToString(s)+"\n"), 0o600)
	return s
}

// tempMode is what -tempaddr-mode selects for this host's own addresses, and iidMode how the
// interface identifier of the stable one is formed.
type tempMode string

const (
	tempOff       tempMode = "off"
	tempStable    tempMode = "stable"
	tempTemporary tempMode = "temporary"
	tempBoth      tempMode = "both"
)

type iidMode string

const (
	iidStable iidMode = "stable" // RFC 7217, derived from a persisted secret
	iidEUI64  iidMode = "eui64"
	iidFixed  iidMode = "fixed" // a suffix given on the command line
)

// tempConfig is what the -tempaddr-* options select for this host's own addresses.
type tempConfig struct {
	mode          tempMode
	regenInterval time.Duration
	preferredLft  time.Duration
	validLft      time.Duration
	maxConcurrent int
	desync        time.Duration
	skipDAD       bool
	grace         time.Duration
}

type tempAddr struct {
	addr     netip.Addr
	prefix   netip.Prefix
	plen     int
	created  time.Time
	state    string // preferred / deprecated / draining
	emptyCnt int
}

// addrManager owns this host's global addresses on one LAN interface:
// prefix addresses (::1 or RFC 7217 stable) follow the snapshot; temporary addresses rotate periodically and retire once no longer in use.
type addrManager struct {
	ifname string
	ifi    *net.Interface
	secret []byte
	cfg    tempConfig
	iid    iidPolicy               // IID source for static addresses
	pick   func(Snapshot) []Prefix // prefixes to address on this interface (LAN: split result; WAN: upstream A-bit prefixes)
	side   side                    // which interface role this manager runs on
	layout shared64Layout
	dadCnt map[netip.Prefix]uint8 // DAD_Counter per prefix
	dadDue bool                   // new addresses awaiting a DAD verdict
	// Tunnel endpoints: /128, preferred=0 (never a source for ordinary traffic), kernel DAD for conflict detection; on failure report instead of re-addressing
	extra     func(Snapshot) []netip.Addr
	endpoints map[netip.Addr]string // configured endpoints and their state: tentative / ok / conflict
	store     *Store
	snap      Snapshot
	applied   map[netip.Addr]Prefix // currently configured prefix addresses
	temps     []*tempAddr
	ctAvail   bool
	ctWarn    bool
}

func (m *addrManager) run(ctx context.Context, hub *linkHub, store *Store, ch <-chan Snapshot) {
	m.ctAvail = true
	hub.supervise(ctx, m.ifname, func(cctx context.Context, ifi *net.Interface) {
		m.ifi = ifi
		// A recreated interface loses all addresses; start from scratch
		m.applied = map[netip.Addr]Prefix{}
		m.temps = nil
		m.dadCnt = map[netip.Prefix]uint8{}
		m.endpoints = map[netip.Addr]string{}
		m.store = store
		m.snap = store.Current()
		m.serve(cctx, ch)
	})
}

func (m *addrManager) serve(ctx context.Context, ch <-chan Snapshot) {
	temp := m.cfg.mode == tempTemporary || m.cfg.mode == tempBoth
	if temp {
		// Take over the kernel's temporary address mechanism, otherwise both sides generate their own
		sysctlSet(m.ifname, "use_tempaddr", "0")
		if !m.cfg.skipDAD {
			sysctlSet(m.ifname, "optimistic_dad", "1")
			sysctlSet(m.ifname, "use_optimistic", "1")
		}
	}
	m.applyPrefixAddrs()
	m.applyEndpoints()
	regen := time.NewTimer(time.Hour)
	regen.Stop()
	if temp && m.ensureTemps() {
		regen.Reset(m.nextRegen())
	}
	drain := time.NewTicker(m.drainInterval())
	defer drain.Stop()
	// DAD results appear about 1s after adding an address; poll every 2s while any is still tentative
	dad := time.NewTicker(2 * time.Second)
	defer dad.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			m.snap = s
			m.applyPrefixAddrs()
			m.applyEndpoints()
			if temp && m.ensureTemps() {
				regen.Reset(m.nextRegen())
			}
		case <-regen.C:
			m.rotate()
			regen.Reset(m.nextRegen())
		case <-drain.C:
			m.drain()
		case <-dad.C:
			if m.dadDue {
				m.checkDAD()
			}
		}
	}
}

// checkDAD scans the interface address table and re-addresses anything that failed DAD.
// Prefix addresses bump the RFC 7217 DAD_Counter; temporary addresses are simply re-randomized.
func (m *addrManager) checkDAD() {
	list, err := addrList(m.ifi.Index)
	if err != nil {
		m.dadDue = false
		return
	}
	pending := false
	for _, ia := range list {
		if st, isEP := m.endpoints[ia.Addr]; isEP {
			switch {
			case ia.Flags&ifaFDadFailed != 0:
				if st != "conflict" {
					log.Printf("[address %s] tunnel local endpoint %s failed DAD: another device on the link is using it (HGW or another tunnel endpoint still online?), not enabling", m.ifname, ia.Addr)
					m.endpoints[ia.Addr] = "conflict"
					addrDel(m.ifi.Index, ia.Addr, 128)
					if m.store != nil {
						m.store.SetEndpointConflict(ia.Addr, true)
					}
				}
			case ia.Flags&ifaFTentative != 0:
				pending = true
			default:
				if st != "ok" {
					log.Printf("[address %s] tunnel local endpoint %s passed DAD, now active", m.ifname, ia.Addr)
					m.endpoints[ia.Addr] = "ok"
				}
			}
			continue
		}
		if ia.Flags&ifaFTentative != 0 && ia.Flags&ifaFDadFailed == 0 {
			if _, ours := m.applied[ia.Addr]; ours || m.tempOf(ia.Addr) != nil {
				pending = true
			}
			continue
		}
		if ia.Flags&ifaFDadFailed == 0 {
			continue
		}
		if p, ok := m.applied[ia.Addr]; ok {
			m.dadCnt[p.Prefix]++
			log.Printf("[address %s] %s failed DAD, switching to address with DAD_Counter=%d", m.ifname, ia.Addr, m.dadCnt[p.Prefix])
			addrDel(m.ifi.Index, ia.Addr, ia.PrefixLen)
			delete(m.applied, ia.Addr)
			m.applyPrefixAddrs()
			pending = true
			continue
		}
		if t := m.tempOf(ia.Addr); t != nil {
			log.Printf("[address %s] temporary address %s failed DAD, regenerating", m.ifname, ia.Addr)
			m.remove(t)
			if t.state == "preferred" {
				var pfx []Prefix
				for _, p := range m.activePrefixes() {
					if p.Prefix == t.prefix {
						pfx = append(pfx, p)
					}
				}
				m.rotateFor(pfx, m.activePrefixes())
			}
			pending = true
		}
	}
	m.dadDue = pending
}

func (m *addrManager) tempOf(a netip.Addr) *tempAddr {
	for _, t := range m.temps {
		if t.addr == a {
			return t
		}
	}
	return nil
}

func (m *addrManager) drainInterval() time.Duration {
	d := m.cfg.regenInterval / 4
	if d < m.cfg.grace {
		d = m.cfg.grace
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

func (m *addrManager) nextRegen() time.Duration {
	d := m.cfg.regenInterval
	if m.cfg.desync > 0 {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(m.cfg.desync)))
		d -= time.Duration(n.Int64())
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// applyPrefixAddrs configures one local address per LAN prefix in the snapshot; lifetimes follow the prefix.
func (m *addrManager) applyPrefixAddrs() {
	now := time.Now()
	want := map[netip.Addr]Prefix{}
	for _, p := range m.pick(m.snap) {
		if p.validLeft(now) == 0 {
			continue
		}
		want[m.iid.addr(m.secret, p.Prefix, m.ifi, m.dadCnt[p.Prefix])] = p
	}
	for a, p := range want {
		pref, valid := p.preferredLeft(now), p.validLeft(now)
		plen := m.plen(p.Prefix)
		if err := addrSet(m.ifi.Index, a, plen, pref, valid, false, 0); err != nil {
			log.Printf("[address %s] failed to configure %s: %v", m.ifname, a, err)
			continue
		}
		if _, ok := m.applied[a]; !ok {
			log.Printf("[address %s] added %s/%d preferred=%s valid=%s", m.ifname, a, plen, pref.Round(time.Second), valid.Round(time.Second))
			m.dadDue = true
		}
	}
	for a, p := range m.applied {
		if _, ok := want[a]; !ok {
			log.Printf("[address %s] removing %s", m.ifname, a)
			if err := addrDel(m.ifi.Index, a, m.plen(p.Prefix)); err != nil {
				log.Printf("[address %s] failed to delete %s: %v", m.ifname, a, err)
			}
		}
	}
	m.applied = want
	m.adoptStrays(want)
}

// adoptStrays takes over addresses inside a managed prefix that we did not compute this round:
// usually left by a previous run (restart, changed IID policy), possibly set by another tool.
// Addresses carry no ownership marker, but nothing else should live inside a managed prefix,
// so deprecate them (preferred=0) and let drain reclaim them once unused, without cutting existing connections.
func (m *addrManager) adoptStrays(want map[netip.Addr]Prefix) {
	if dryRun {
		return
	}
	list, err := addrList(m.ifi.Index)
	if err != nil {
		return
	}
	for _, ia := range strayAddrs(list, want, m.pick(m.snap), m.temps, m.endpoints) {
		var prefix netip.Prefix
		for _, p := range m.pick(m.snap) {
			if p.Prefix.Contains(ia.Addr) {
				prefix = p.Prefix
				break
			}
		}
		if err := addrSet(m.ifi.Index, ia.Addr, ia.PrefixLen, 0, 0, true, ifaFNodad); err != nil {
			log.Printf("[address %s] failed to deprecate stray address %s: %v", m.ifname, ia.Addr, err)
			continue
		}
		log.Printf("[address %s] adopted stray address %s/%d, will reclaim once no longer in use", m.ifname, ia.Addr, ia.PrefixLen)
		m.temps = append(m.temps, &tempAddr{addr: ia.Addr, prefix: prefix, plen: ia.PrefixLen, created: time.Now(), state: "deprecated"})
	}
}

// strayAddrs picks addresses inside a managed prefix that belong to none of the known sets.
func strayAddrs(list []ifAddr, want map[netip.Addr]Prefix, managed []Prefix, temps []*tempAddr, endpoints map[netip.Addr]string) []ifAddr {
	var out []ifAddr
outer:
	for _, ia := range list {
		a := ia.Addr
		if a.IsLinkLocalUnicast() || !a.Is6() {
			continue
		}
		if _, ok := want[a]; ok {
			continue
		}
		if _, ok := endpoints[a]; ok {
			continue
		}
		for _, t := range temps {
			if t.addr == a {
				continue outer
			}
		}
		for _, p := range managed {
			if p.Prefix.Contains(a) {
				out = append(out, ia)
				continue outer
			}
		}
	}
	return out
}

// plen picks the address prefix length according to the shared /64 layout.
func (m *addrManager) plen(p netip.Prefix) int {
	return m.layout.plen(m.side, m.snap.sharedWith(p))
}

// activePrefixes returns this interface's prefixes still within their preferred lifetime.
func (m *addrManager) activePrefixes() []Prefix {
	var out []Prefix
	for _, p := range m.pick(m.snap) {
		if !p.Deprecated {
			out = append(out, p)
		}
	}
	return out
}

// ensureTemps adds or retires temporary addresses when prefixes appear or vanish; it does not rotate.
func (m *addrManager) ensureTemps() bool {
	active := m.activePrefixes()
	var missing []Prefix
	for _, p := range active {
		has := false
		for _, t := range m.temps {
			has = has || (t.prefix == p.Prefix && t.state == "preferred")
		}
		if !has {
			missing = append(missing, p)
		}
	}
	return m.rotateFor(missing, active)
}

// rotate creates a new temporary address per active prefix and deprecates the previous one. Returns whether any was created.
func (m *addrManager) rotate() bool {
	active := m.activePrefixes()
	return m.rotateFor(active, active)
}

func (m *addrManager) rotateFor(targets, active []Prefix) bool {
	now := time.Now()
	made := false
	for _, p := range targets {
		flags := uint32(ifaFTemporary)
		if m.cfg.skipDAD {
			flags |= ifaFNodad
		} else {
			flags |= ifaFOptimistic
		}
		na := &tempAddr{addr: randomIID(p.Prefix), prefix: p.Prefix, plen: m.plen(p.Prefix), created: now, state: "preferred"}
		pref := m.cfg.preferredLft
		if left := p.preferredLeft(now); left < pref {
			pref = left
		}
		// valid lifetime is enforced by this process, so the kernel gets infinite
		if err := addrSet(m.ifi.Index, na.addr, na.plen, pref, 0, true, flags); err != nil {
			log.Printf("[address %s] failed to create temporary address %s: %v", m.ifname, na.addr, err)
			continue
		}
		made = true
		m.dadDue = true
		log2("[address %s] new temporary address %s", m.ifname, na.addr)
		for _, old := range m.temps {
			if old.prefix == p.Prefix && old.state == "preferred" {
				m.deprecate(old)
			}
		}
		m.temps = append(m.temps, na)
	}
	// Deprecate temporary addresses whose prefix is no longer active
	for _, t := range m.temps {
		inActive := false
		for _, p := range active {
			inActive = inActive || p.Prefix == t.prefix
		}
		if !inActive && t.state == "preferred" {
			m.deprecate(t)
		}
	}
	m.enforceMax()
	return made
}

func (m *addrManager) deprecate(t *tempAddr) {
	if err := addrSet(m.ifi.Index, t.addr, t.plen, 0, 0, true, ifaFTemporary|ifaFNodad); err != nil {
		log.Printf("[address %s] failed to deprecate %s: %v", m.ifname, t.addr, err)
		return
	}
	t.state = "deprecated"
	t.emptyCnt = 0
}

// enforceMax is the only hard limit: at the cap, forcibly reclaim the oldest and accept the disruption.
func (m *addrManager) enforceMax() {
	if m.cfg.maxConcurrent <= 0 || len(m.temps) <= m.cfg.maxConcurrent {
		return
	}
	slices.SortFunc(m.temps, func(a, b *tempAddr) int { return a.created.Compare(b.created) })
	for len(m.temps) > m.cfg.maxConcurrent {
		t := m.temps[0]
		log.Printf("[address %s] max_concurrent reached, forcibly reclaiming %s (may break connections)", m.ifname, t.addr)
		m.remove(t)
	}
}

func (m *addrManager) remove(t *tempAddr) {
	if err := addrDel(m.ifi.Index, t.addr, t.plen); err != nil {
		log.Printf("[address %s] failed to delete %s: %v", m.ifname, t.addr, err)
	}
	for i, x := range m.temps {
		if x == t {
			m.temps = append(m.temps[:i], m.temps[i+1:]...)
			return
		}
	}
}

// drain checks usage of deprecated/draining addresses and deletes only after two consecutive empty checks.
func (m *addrManager) drain() {
	for _, t := range append([]*tempAddr(nil), m.temps...) {
		if t.state == "preferred" {
			continue
		}
		t.state = "draining"
		n := m.inUse(t.addr)
		if n > 0 {
			t.emptyCnt = 0
			log2("[address %s] %s still in use by %d", m.ifname, t.addr, n)
			continue
		}
		t.emptyCnt++
		if t.emptyCnt >= 2 {
			log.Printf("[address %s] %s unused for two consecutive checks, reclaiming", m.ifname, t.addr)
			m.remove(t)
		}
	}
}

// inUse combines sock_diag and conntrack; if conntrack is unavailable, degrade and warn once.
func (m *addrManager) inUse(a netip.Addr) int {
	n, err := sockDiagInUse(a)
	if err != nil {
		log2("[address %s] sock_diag query failed: %v", m.ifname, err)
	}
	if m.ctAvail {
		c, err := conntrackInUse(a)
		if err != nil {
			if !m.ctWarn {
				log.Printf("[address %s] conntrack unavailable, retirement relies on sock_diag only: %v", m.ifname, err)
				m.ctWarn = true
			}
			m.ctAvail = false
		} else {
			n += c
		}
	}
	return n
}

// iidPolicy decides where the low 64 bits of a SLAAC address come from.
//   - empty: RFC 7217 stable address
//   - "eui64": derived from the MAC
//   - an address like ::1 / ::1111:2222:3333:4444: high 64 bits must be zero, low 64 bits used as a fixed IID
type iidPolicy struct {
	mode  iidMode
	fixed [8]byte
}

func parseIIDPolicy(s string) (iidPolicy, error) {
	s = strings.TrimSpace(s)
	switch iidMode(s) {
	case "", iidStable:
		return iidPolicy{mode: iidStable}, nil
	case iidEUI64:
		return iidPolicy{mode: iidEUI64}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() {
		return iidPolicy{}, fmt.Errorf("%q is not a valid IPv6 suffix", s)
	}
	b := a.As16()
	for _, x := range b[:8] {
		if x != 0 {
			return iidPolicy{}, fmt.Errorf("%q: high 64 bits must be zero, give only the suffix, e.g. ::1", s)
		}
	}
	p := iidPolicy{mode: iidFixed}
	copy(p.fixed[:], b[8:])
	return p, nil
}

// addr builds the address. dad is the RFC 7217 DAD_Counter, incremented on each DAD failure.
// eui64 and fixed have no alternative IID, so after one failure they fall back to the stable address.
func (p iidPolicy) addr(secret []byte, prefix netip.Prefix, ifi *net.Interface, dad uint8) netip.Addr {
	b := prefix.Masked().Addr().As16()
	switch p.mode {
	case iidEUI64:
		if hw := ifi.HardwareAddr; len(hw) == 6 && dad == 0 {
			b[8], b[9], b[10] = hw[0]^0x02, hw[1], hw[2]
			b[11], b[12] = 0xff, 0xfe
			b[13], b[14], b[15] = hw[3], hw[4], hw[5]
			return netip.AddrFrom16(b)
		}
	case iidFixed:
		if dad == 0 {
			copy(b[8:], p.fixed[:])
			return netip.AddrFrom16(b)
		}
	}
	return stableIID(secret, prefix, ifi.Name, dad)
}

// applyEndpoints configures tunnel local endpoint addresses. They are added tentative so the kernel runs DAD;
// checkDAD marks them active. Conflicting ones are removed and reported, never re-addressed (the peer only knows the agreed address).
func (m *addrManager) applyEndpoints() {
	if m.extra == nil {
		return
	}
	want := map[netip.Addr]bool{}
	for _, a := range m.extra(m.snap) {
		want[a] = true
		if _, ok := m.endpoints[a]; ok {
			continue
		}
		// preferred=0: tunnel endpoint only, never chosen as source for ordinary outbound traffic
		if err := addrSet(m.ifi.Index, a, 128, 0, 0, true, 0); err != nil {
			log.Printf("[address %s] failed to configure tunnel local endpoint %s: %v", m.ifname, a, err)
			continue
		}
		log.Printf("[address %s] tunnel local endpoint %s added, awaiting DAD", m.ifname, a)
		m.endpoints[a] = "tentative"
		m.dadDue = true
	}
	for a, st := range m.endpoints {
		if want[a] {
			continue
		}
		if st != "conflict" {
			addrDel(m.ifi.Index, a, 128)
		}
		if st == "conflict" && m.store != nil {
			m.store.SetEndpointConflict(a, false)
		}
		delete(m.endpoints, a)
		log.Printf("[address %s] tunnel local endpoint %s no longer needed, removed", m.ifname, a)
	}
}
