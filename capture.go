package main

import (
	"context"
	"encoding/binary"
	"log"
	"net/netip"
	"time"
)

// tunnelSniffer infers the tunnel type and parameters from inbound IPv4-in-IPv6 packets (protocol 4).
// It is the fallback for ISPs that do not deliver tunnel information over DHCPv6, such as v6plus and OCN MAP-E.
// Capture runs without promiscuous mode, so only frames addressed to this host's MAC arrive: this host must be the tunnel endpoint.
type tunnelSniffer struct {
	tunnels map[[2]netip.Addr]*tunnelObs // key: outer src (remote endpoint), dst (local endpoint)
}

// tunnelObs holds what was observed on one tunnel endpoint pair.
type tunnelObs struct {
	Remote  netip.Addr         `json:"remote"` // outer source: AFTR or BR
	Local   netip.Addr         `json:"local"`  // outer destination: this host's B4 / CE address
	Inner4  netip.Addr         `json:"ipv4"`   // inner IPv4 destination address
	Inner4s map[netip.Addr]int `json:"-"`
	Ports   map[uint16]int     `json:"-"`
	Packets int                `json:"packets"`
	First   time.Time          `json:"first_seen"`
	Last    time.Time          `json:"last_seen"`
}

// tunnelGuess is the decision reached for one endpoint pair.
// The first four fields and Confidence/Note are hoisted into TunnelParams when this guess wins,
// so they are not repeated in the evidence block.
type tunnelGuess struct {
	Type       tunnelKind `json:"-"`
	Remote     netip.Addr `json:"-"`
	Local      netip.Addr `json:"-"`
	IPv4       netip.Addr `json:"-"`
	PSIDOffset int        `json:"psid_offset,omitempty"`
	PSID       *uint16    `json:"psid,omitempty"`
	PSIDLen    []int      `json:"psid_len_candidates,omitempty"`
	PortMin    uint16     `json:"port_min,omitempty"`
	PortMax    uint16     `json:"port_max,omitempty"`
	Packets    int        `json:"packets"`
	Ports      int        `json:"distinct_ports"`
	Confidence string     `json:"-"`
	Note       string     `json:"-"`
}

// tunnelWatcher is the daemon-mode fallback: if a DHCPv6 binding carries no tunnel options it starts a capture,
// stores the result and stops once inference is confident, and restarts from scratch when the WAN prefix or address
// changes. It is capped by -tunnel-capture-max so it does not keep consuming every IPv6 frame indefinitely.
type tunnelWatcher struct {
	ifname string
	store  *Store
	pkts   *packetHub
	maxRun time.Duration
}

func (w *tunnelWatcher) run(ctx context.Context, ch <-chan Snapshot) {
	var (
		sub     *packetSub
		frames  chan []byte
		cc      *tunnelSniffer
		started time.Time
		lastKey string
	)
	end := func() {
		if sub != nil {
			sub.Close()
			sub = nil
			frames = nil
			log.Printf("[tunnel-capture] tunnel inference finished")
		}
	}
	defer end()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			key := s.WANAddr.String()
			for _, p := range s.WAN {
				if !p.Deprecated {
					key += "|" + p.Prefix.String()
				}
			}
			if key != lastKey {
				lastKey = key
				// Discard the old decision only once the captured local endpoint falls outside every WAN prefix; gaining a first prefix is not a change
				if s.Tunnel != nil && s.Tunnel.Captured != nil && len(s.WAN) > 0 && !localStillValid(s, s.Tunnel.Captured.Local) {
					log.Printf("[tunnel-capture] local endpoint %s is no longer inside a WAN prefix, discarding the old decision and inferring again", s.Tunnel.Captured.Local)
					w.store.SetCaptured(nil)
					end()
				}
			}
			bound := len(s.WAN) > 0 || s.WANAddr.IsValid()
			need := bound && !s.Tunnel.hasDelivered() && (s.Tunnel == nil || s.Tunnel.Captured == nil)
			if need && sub == nil {
				sub = w.pkts.Subscribe(kindTunnel)
				frames = sub.C
				started = time.Now()
				cc = &tunnelSniffer{tunnels: map[[2]netip.Addr]*tunnelObs{}}
				log.Printf("[tunnel-capture] DHCPv6 delivered no tunnel options, inferring from tunnel traffic (up to %s)", w.maxRun)
			}
			if !need && sub != nil {
				end()
			}
		case f := <-frames:
			if cc == nil {
				continue
			}
			cc.handleFrame(f)
			if g, ok := cc.any(); ok {
				logInferred(g)
				w.store.SetCaptured(&g)
				end()
			}
		case <-tick.C:
			if sub == nil {
				continue
			}
			// Decide as soon as any packet arrives: the type follows from the address format, so one packet suffices; ambiguous PSID lengths are exported as a candidate list
			if g, ok := cc.any(); ok {
				logInferred(g)
				w.store.SetCaptured(&g)
				end()
				continue
			}
			if time.Since(started) > w.maxRun {
				log.Printf("[tunnel-capture] no tunnel packets within %s, stopping capture", w.maxRun)
				end()
			}
		}
	}
}

// any returns the result with the most samples, which may still be low confidence.
func (c *tunnelSniffer) any() (tunnelGuess, bool) {
	var best *tunnelObs
	for _, o := range c.tunnels {
		if best == nil || o.Packets > best.Packets {
			best = o
		}
	}
	if best == nil {
		return tunnelGuess{}, false
	}
	return best.guess(), true
}

// handleFrame walks Ethernet (+VLAN) to IPv6 to the inner IPv4 of protocol 4.
func (c *tunnelSniffer) handleFrame(f []byte) {
	if len(f) < 14 {
		return
	}
	et := binary.BigEndian.Uint16(f[12:14])
	off := 14
	for et == 0x8100 || et == 0x88a8 {
		if len(f) < off+4 {
			return
		}
		et = binary.BigEndian.Uint16(f[off+2 : off+4])
		off += 4
	}
	if et != 0x86dd || len(f) < off+40 {
		return
	}
	ip := f[off:]
	plen := int(binary.BigEndian.Uint16(ip[4:6]))
	if len(ip) < 40+plen {
		return
	}
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))
	payload := ip[40 : 40+plen]
	if ip[6] == 4 { // IPv4-in-IPv6
		c.handleTunnel(src, dst, payload)
	}
}

func (c *tunnelSniffer) handleTunnel(src, dst netip.Addr, in []byte) {
	if len(in) < 20 || in[0]>>4 != 4 {
		return
	}
	ihl := int(in[0]&0x0f) * 4
	if ihl < 20 || len(in) < ihl {
		return
	}
	inner4 := netip.AddrFrom4([4]byte(in[16:20]))
	key := [2]netip.Addr{src, dst}
	o := c.tunnels[key]
	now := time.Now()
	if o == nil {
		o = &tunnelObs{Remote: src, Local: dst, Inner4s: map[netip.Addr]int{}, Ports: map[uint16]int{}, First: now}
		c.tunnels[key] = o
		log.Printf("[tunnel-capture] found tunnel %s -> %s, inner IPv4 destination %s", src, dst, inner4)
	}
	o.Packets++
	o.Last = now
	statInc("tunnel_pkt")
	o.Inner4s[inner4]++
	// Only unfragmented TCP/UDP packets carry a usable destination port
	frag := binary.BigEndian.Uint16(in[6:8]) & 0x1fff
	if frag == 0 && (in[9] == 6 || in[9] == 17) && len(in) >= ihl+4 {
		o.Ports[binary.BigEndian.Uint16(in[ihl+2:ihl+4])]++
	}
}

// guess decides the tunnel type for one endpoint pair.
//   - inner IPv4 destination in 192.0.0.0/29 (the RFC 6333 B4 range) or private -> DS-Lite, and the remote endpoint is the AFTR
//   - local IPv6 interface identifier in RFC 7597 §6 form (0 | IPv4 | PSID | 0) with an IPv4 matching the inner one -> MAP-E
//   - anything else -> plain 4in6, reporting only the endpoints
func (o *tunnelObs) guess() tunnelGuess {
	g := tunnelGuess{Remote: o.Remote, Local: o.Local, Packets: o.Packets, Ports: len(o.Ports)}
	best, n := netip.Addr{}, 0
	for a, k := range o.Inner4s {
		if k > n {
			best, n = a, k
		}
	}
	g.IPv4 = best
	b4 := netip.MustParsePrefix("192.0.0.0/29")
	if b4.Contains(best) || best.IsPrivate() {
		g.Type, g.Confidence = "ds-lite", "high"
		g.Note = "inner IPv4 destination is a B4-side address, so the remote endpoint is the AFTR"
		return g
	}
	iid := o.Local.As16()
	if iid[8] == 0 && iid[15] == 0 {
		embedded := netip.AddrFrom4([4]byte(iid[9:13]))
		psid := binary.BigEndian.Uint16(iid[13:15])
		if embedded == best {
			g.Type, g.Confidence = "map-e", "high"
			g.PSIDOffset = 6
			g.PSID = &psid
			g.PSIDLen = psidLenCandidates(psid, o.Ports)
			g.PortMin, g.PortMax = portRange(o.Ports)
			g.Note = "IPv4 embedded in the local interface identifier matches the inner one, so the remote endpoint is the BR"
			return g
		}
	}
	g.Type, g.Confidence = "4in6", "low"
	g.PortMin, g.PortMax = portRange(o.Ports)
	g.Note = "inner IPv4 is public but the interface identifier is not in MAP-E form, so this may be MAP-E with a non-standard IID or a static 4in6 tunnel"
	if softBankBR.Contains(o.Remote) {
		g.Note += "; the remote endpoint is inside SoftBank's own network, so this is a SoftBank Hikari line: keep the rented Hikari BB Unit somewhere safe and do not lose it"
	}
	return g
}

// logInferred reports the decision; the note carries the confidence reasoning, which is the
// only hint the operator gets on lines whose tunnel parameters never appear in DHCPv6.
func logInferred(g tunnelGuess) {
	log.Printf("[tunnel-capture] inferred %s, remote %s, local %s, IPv4 %s", g.Type, g.Remote, g.Local, g.IPv4)
	if g.Note != "" {
		log.Printf("[tunnel-capture] %s confidence: %s", g.Confidence, g.Note)
	}
}

// softBankBR is SOFTBANK Corp's own allocation (APNIC SBB-IPv6-20050712). The border relay of a
// SoftBank Hikari IPIP6 tunnel sits inside it; the subscriber prefix is not a reliable marker
// because it comes from BBIX, which also serves other ISPs.
var softBankBR = netip.MustParsePrefix("2400:2000::/20")

// psidLenCandidates derives the PSID length from the observed ports, assuming the usual offset of 6 bits (a=6):
// the k bits starting at bit 6 of a port must equal the PSID. Few samples leave several candidates, listed ascending.
func psidLenCandidates(psid uint16, ports map[uint16]int) []int {
	var out []int
	for k := 1; k <= 10; k++ {
		if psid >= 1<<uint(k) {
			continue
		}
		ok := true
		for p := range ports {
			if (p>>(16-6-uint(k)))&(1<<uint(k)-1) != psid {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, k)
		}
	}
	return out
}

func portRange(ports map[uint16]int) (uint16, uint16) {
	if len(ports) == 0 {
		return 0, 0
	}
	lo, hi := uint16(0xffff), uint16(0)
	for p := range ports {
		if p < lo {
			lo = p
		}
		if p > hi {
			hi = p
		}
	}
	return lo, hi
}

// bpfInsn is one classic BPF instruction, laid out like struct sock_filter. It lives in a platform-independent file so it can be tested anywhere.
type bpfInsn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

// cBPF opcodes (linux/filter.h)
const (
	bpfLdhAbs = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfLdbAbs = 0x30 // BPF_LD | BPF_B | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K
	bpfPass   = 0x40000
)

// captureFilter passes only IPv6 protocol 4 (IPv4-in-IPv6).
// Offsets assume an untagged Ethernet frame: the kernel strips the 802.1Q tag before AF_PACKET runs the filter, so the IPv6 header always starts at 14.
func captureFilter(frameKind) []bpfInsn {
	return []bpfInsn{
		{code: bpfLdhAbs, k: 12},                 // 0 ethertype
		{code: bpfJeqK, k: 0x86dd, jt: 0, jf: 2}, // 1 not IPv6 -> 4
		{code: bpfLdbAbs, k: 20},                 // 2 next header
		{code: bpfJeqK, k: 4, jt: 1, jf: 0},      // 3 protocol 4 -> 5
		{code: bpfRetK, k: 0},                    // 4 drop
		{code: bpfRetK, k: bpfPass},              // 5 accept
	}
}

// localStillValid reports whether the captured tunnel local endpoint is still inside a live WAN prefix.
func localStillValid(s Snapshot, local netip.Addr) bool {
	for _, p := range s.WAN {
		if !p.Deprecated && p.Prefix.Contains(local) {
			return true
		}
	}
	return false
}
