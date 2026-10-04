package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGuessMAPE(t *testing.T) {
	// CE interface identifier per RFC 7597 section 6: 0x00 | IPv4 203.0.18.52 | PSID 0x0012 | 0x00
	local := netip.MustParseAddr("2404:9200:0:8::").As16()
	copy(local[9:13], []byte{203, 0, 18, 52})
	local[13], local[14] = 0x00, 0x12
	o := &tunnelObs{
		Remote:  netip.MustParseAddr("2404:9200::8"),
		Local:   netip.AddrFrom16(local),
		Inner4s: map[netip.Addr]int{netip.MustParseAddr("203.0.18.52"): 5},
		Ports:   map[uint16]int{},
	}
	// PSID 0x12 = 0b00010010, psid-len 8, offset 6: port = A(6 bits) | PSID(8 bits) | 2 bits
	for _, a := range []uint16{1, 2, 17} {
		for _, low := range []uint16{0, 3} {
			o.Ports[a<<10|0x12<<2|low]++
		}
	}
	g := o.guess()
	if g.Type != "map-e" || g.PSID == nil || *g.PSID != 0x12 {
		t.Fatalf("%+v", g)
	}
	if len(g.PSIDLen) != 1 || g.PSIDLen[0] != 8 {
		t.Fatalf("psid-len candidates %v", g.PSIDLen)
	}
}

func TestGuessDSLite(t *testing.T) {
	o := &tunnelObs{
		Remote:  netip.MustParseAddr("2404:8e00::8"),
		Local:   netip.MustParseAddr("2409:10::8"),
		Inner4s: map[netip.Addr]int{netip.MustParseAddr("192.0.0.2"): 3},
		Ports:   map[uint16]int{},
	}
	if g := o.guess(); g.Type != "ds-lite" {
		t.Fatalf("%+v", g)
	}
}

// runBPF interprets only the four instructions this project uses, to verify jump offsets.
func runBPF(prog []bpfInsn, pkt []byte) uint32 {
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.code {
		case bpfLdhAbs:
			if int(in.k)+2 > len(pkt) {
				return 0
			}
			a = uint32(pkt[in.k])<<8 | uint32(pkt[in.k+1])
		case bpfLdbAbs:
			if int(in.k) >= len(pkt) {
				return 0
			}
			a = uint32(pkt[in.k])
		case bpfJeqK:
			if a == in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfRetK:
			return in.k
		default:
			panic("unknown instruction")
		}
	}
	panic("program did not end with ret")
}

func frame(nextHdr byte, sport, dport uint16) []byte {
	f := make([]byte, 14+40+8)
	f[12], f[13] = 0x86, 0xdd
	f[14] = 0x60
	f[14+6] = nextHdr
	f[54], f[55] = byte(sport>>8), byte(sport)
	f[56], f[57] = byte(dport>>8), byte(dport)
	return f
}

func TestCaptureFilter(t *testing.T) {
	tunnel, ns, na := frame(4, 0, 0), frame(58, 135<<8, 0), frame(58, 136<<8, 0)
	v4 := frame(4, 0, 0)
	v4[12], v4[13] = 0x08, 0x00
	for _, c := range []struct {
		kinds  frameKind
		accept [][]byte
	}{
		{kindTunnel, [][]byte{tunnel}},
		{kindNS, [][]byte{ns}},
		{kindTunnel | kindNS, [][]byte{tunnel, ns}},
	} {
		p := captureFilter(c.kinds)
		for i, in := range p {
			if in.code == bpfJeqK && (i+1+int(in.jt) >= len(p) || i+1+int(in.jf) >= len(p)) {
				t.Fatalf("instruction %d jumps out of the program", i)
			}
		}
		for _, f := range [][]byte{tunnel, ns, na, frame(6, 443, 50000), frame(17, 547, 546), v4} {
			if got, want := runBPF(p, f) != 0, slices.ContainsFunc(c.accept, func(a []byte) bool { return &a[0] == &f[0] }); got != want {
				t.Fatalf("kinds %d, frame %x: accepted %v", c.kinds, f[14:56], got)
			}
		}
	}
}

func TestClassifyFrame(t *testing.T) {
	if classifyFrame(frame(4, 0, 0)) != kindTunnel {
		t.Fatal("protocol 4 should be tunnel")
	}
	if classifyFrame(frame(58, 135<<8, 0)) != kindNS {
		t.Fatal("a Neighbor Solicitation should be NS")
	}
	if classifyFrame(frame(17, 547, 546)) != 0 || classifyFrame(frame(6, 80, 80)) != 0 || classifyFrame(frame(58, 136<<8, 0)) != 0 {
		t.Fatal("others should be 0")
	}
	// Fallback path for 802.1Q-tagged frames.
	base := frame(4, 0, 0)
	tagged := append([]byte{}, base[:12]...)
	tagged = append(tagged, 0x81, 0x00, 0x00, 0x01)
	tagged = append(tagged, base[12:]...)
	if classifyFrame(tagged) != kindTunnel {
		t.Fatal("VLAN-tagged frame should be recognized")
	}
}

func TestTunnelSpecPriority(t *testing.T) {
	wan := netip.MustParseAddr("2001:db8::1")
	ce, br := netip.MustParseAddr("2001:db8::c0a8:1:1234:0"), netip.MustParseAddr("2404:9200::8")
	tp := &TunnelParams{
		AFTRAddrs:  []netip.Addr{netip.MustParseAddr("2404:8e00::8")},
		MAPESource: "rules",
		RuleMAPE:   &mapeResult{CE: ce, BR: br, IPv4: netip.MustParseAddr("106.0.0.8")},
		Captured:   &tunnelGuess{Local: netip.MustParseAddr("2001:db8::1111"), Remote: netip.MustParseAddr("2400:2000::9"), Type: "4in6", Confidence: "low", Note: "guessed"},
	}
	s := Snapshot{WANAddr: wan, Tunnel: tp}

	tp.resolve(wan)
	spec, ok := tunnelSpecOf(s)
	if !ok || spec.Kind != "ds-lite" || spec.Remote != tp.AFTRAddrs[0] || spec.Local != wan || tp.Source != "dhcpv6" {
		t.Fatalf("DS-Lite should take priority: %+v %+v", spec, tp)
	}
	if tp.Note != "" || tp.Confidence != "" {
		t.Fatal("capture confidence must not leak into a DHCPv6-delivered tunnel")
	}

	tp.AFTRAddrs = nil
	tp.resolve(wan)
	if spec, _ = tunnelSpecOf(s); spec.Kind != "map-e" || spec.Local != ce || tp.Source != "rules" {
		t.Fatalf("the rule table comes next: %+v %+v", spec, tp)
	}

	tp.RuleMAPE = nil
	tp.resolve(wan)
	spec, ok = tunnelSpecOf(s)
	if !ok || spec.Kind != "4in6" || spec.Local != netip.MustParseAddr("2001:db8::1111") || tp.Source != "capture" {
		t.Fatalf("capture is the last resort: %+v %+v", spec, tp)
	}
	if tp.Confidence != "low" || tp.Note != "guessed" {
		t.Fatalf("capture confidence should surface at the top level: %+v", tp)
	}

	tp.Captured = nil
	tp.resolve(wan)
	if _, ok := tunnelSpecOf(s); ok {
		t.Fatal("no tunnel without parameters")
	}
}

// A SoftBank Hikari line is recognised by a border relay inside SOFTBANK Corp's own allocation.
func TestGuessSoftBankNote(t *testing.T) {
	o := &tunnelObs{
		Remote:  netip.MustParseAddr("2400:2000::8"),
		Local:   netip.MustParseAddr("2400:2410::8"),
		Inner4s: map[netip.Addr]int{netip.MustParseAddr("126.0.0.8"): 1},
		Ports:   map[uint16]int{41641: 1},
		Packets: 1,
	}
	g := o.guess()
	if g.Type != "4in6" {
		t.Fatalf("SoftBank tunnels are plain 4in6, got %q", g.Type)
	}
	if !strings.Contains(g.Note, "Hikari BB Unit") {
		t.Fatalf("note should mention the Hikari BB Unit: %q", g.Note)
	}
	// Same subscriber prefix, a relay belonging to some other ISP: no SoftBank note.
	o.Remote = netip.MustParseAddr("2404:8e00::9")
	if strings.Contains(o.guess().Note, "Hikari BB Unit") {
		t.Fatal("a relay outside SoftBank's network must not trigger the note")
	}
}

// captureFrame wraps payload in an IPv6 header with next header nh and an untagged Ethernet header.
func captureFrame(src, dst netip.Addr, nh byte, payload []byte) []byte {
	f := make([]byte, 14+40, 14+40+len(payload))
	f[12], f[13] = 0x86, 0xdd
	f[14] = 0x60
	binary.BigEndian.PutUint16(f[14+4:], uint16(len(payload)))
	f[14+6] = nh
	s, d := src.As16(), dst.As16()
	copy(f[14+8:], s[:])
	copy(f[14+24:], d[:])
	return append(f, payload...)
}

// captureInner4 builds an IPv4 header to dst with the protocol and fragment offset, followed by
// the ports of a TCP or UDP header.
func captureInner4(dst netip.Addr, proto byte, frag uint16, dport uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[6:], frag)
	p[9] = proto
	d := dst.As4()
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[22:], dport)
	return p
}

// Every malformed or unrelated frame is skipped; IPv4-in-IPv6 is counted per endpoint pair, with
// the destination port of unfragmented TCP and UDP only.
func TestTunnelSnifferFrames(t *testing.T) {
	remote, local := netip.MustParseAddr("2404:9200::8"), netip.MustParseAddr("2404:9200:0:8::1")
	v4 := netip.MustParseAddr("203.0.113.5")
	c := &tunnelSniffer{tunnels: map[[2]netip.Addr]*tunnelObs{}}
	tunnel := captureFrame(remote, local, 4, captureInner4(v4, 6, 0, 1234))
	tagged := append(append(append([]byte{}, tunnel[:12]...), 0x81, 0x00, 0x00, 0x05), tunnel[12:]...)
	ipv4 := append([]byte{}, tunnel...)
	ipv4[12], ipv4[13] = 0x08, 0x00
	overrun := append([]byte{}, tunnel...)
	binary.BigEndian.PutUint16(overrun[14+4:], 200)
	shortIHL := captureInner4(v4, 6, 0, 1)
	shortIHL[0] = 0x44 // 16 bytes, shorter than any IPv4 header
	longIHL := captureInner4(v4, 6, 0, 1)
	longIHL[0] = 0x4f // 60 bytes, more than there is
	v6 := captureInner4(v4, 6, 0, 1)
	v6[0] = 0x65
	for _, f := range [][]byte{
		tunnel[:10],
		append(append([]byte{}, tunnel[:12]...), 0x81, 0x00, 0x00), // tag cut short
		ipv4,
		tunnel[:14+39],
		overrun,
		captureFrame(remote, local, 17, captureInner4(v4, 6, 0, 1)),
		captureFrame(remote, local, 4, make([]byte, 19)),
		captureFrame(remote, local, 4, v6),
		captureFrame(remote, local, 4, shortIHL),
		captureFrame(remote, local, 4, longIHL),
	} {
		c.handleFrame(f)
	}
	if len(c.tunnels) != 0 {
		t.Fatalf("nothing should have been counted: %+v", c.tunnels)
	}
	if _, ok := c.any(); ok {
		t.Fatal("no tunnel seen, no guess")
	}

	c.handleFrame(tunnel)
	c.handleFrame(tagged)
	c.handleFrame(captureFrame(remote, local, 4, captureInner4(v4, 17, 0, 5678)))
	c.handleFrame(captureFrame(remote, local, 4, captureInner4(v4, 17, 0x20, 9999))) // a later fragment
	c.handleFrame(captureFrame(remote, local, 4, captureInner4(v4, 1, 0, 9999)))     // ICMP
	c.handleFrame(captureFrame(netip.MustParseAddr("2001:db8::9"), local, 4, captureInner4(v4, 6, 0, 80)))
	o := c.tunnels[[2]netip.Addr{remote, local}]
	if o == nil || o.Packets != 5 || o.Inner4s[v4] != 5 || len(o.Ports) != 2 || o.Ports[1234] != 2 || o.Ports[5678] != 1 {
		t.Fatalf("%+v", o)
	}
	if g, ok := c.any(); !ok || g.Remote != remote || g.Packets != 5 {
		t.Fatalf("the pair with the most packets wins: %+v", g)
	}
}

// A 4in6 guess without any port seen reports no port range, and the log carries the note when there is one.
func TestGuessWithoutPorts(t *testing.T) {
	o := &tunnelObs{
		Remote:  netip.MustParseAddr("2001:db8::8"),
		Local:   netip.MustParseAddr("2001:db8:1::8"),
		Inner4s: map[netip.Addr]int{netip.MustParseAddr("198.51.100.1"): 1},
		Ports:   map[uint16]int{},
	}
	g := o.guess()
	if g.Type != "4in6" || g.PortMin != 0 || g.PortMax != 0 {
		t.Fatalf("%+v", g)
	}
	logInferred(g)
	g.Note = ""
	logInferred(g)
}

// captureSubOf waits for the hub to have exactly n listeners and returns one of them.
func captureSubOf(t *testing.T, h *packetHub, n int) *packetSub {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		h.mu.Lock()
		var sub *packetSub
		for s := range h.subs {
			sub = s
		}
		got := len(h.subs)
		h.mu.Unlock()
		if got == n {
			return sub
		}
	}
	t.Fatalf("the hub never had %d listeners", n)
	return nil
}

// The watcher captures only while the line is bound and DHCPv6 gave no tunnel, stores the first
// decision, drops it once its local endpoint leaves the WAN prefixes, and stops when DHCPv6 delivers.
func TestTunnelWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hub := newPacketHub(ctx, "sixup-none0") // never opens, so frames are fed by hand
	st := &Store{capIn: make(chan *tunnelGuess, 4)}
	w := &tunnelWatcher{ifname: "sixup-none0", store: st, pkts: hub, maxRun: time.Hour}
	ch := make(chan Snapshot)
	done := make(chan struct{})
	go func() { w.run(ctx, ch); close(done) }()

	wan := Prefix{Prefix: netip.MustParsePrefix("2001:db8:1::/48")}
	old := Prefix{Prefix: netip.MustParsePrefix("2001:db8:2::/48"), Deprecated: true}
	ch <- Snapshot{} // not bound yet
	captureSubOf(t, hub, 0)
	ch <- Snapshot{WAN: []Prefix{wan, old}}
	sub := captureSubOf(t, hub, 1)

	remote, local := netip.MustParseAddr("2001:db8:f::1"), netip.MustParseAddr("2001:db8:1::5")
	sub.C <- frame(6, 443, 50000)
	sub.C <- captureFrame(remote, local, 4, captureInner4(netip.MustParseAddr("192.0.0.2"), 6, 0, 80))
	g := <-st.capIn
	if g == nil || g.Type != "ds-lite" || g.Remote != remote || g.Local != local {
		t.Fatalf("%+v", g)
	}
	captureSubOf(t, hub, 0)

	// The decision stands while its local endpoint stays inside a WAN prefix.
	ch <- Snapshot{WAN: []Prefix{wan, old}, Tunnel: &TunnelParams{Captured: g}}
	ch <- Snapshot{WANAddr: netip.MustParseAddr("2001:db8:1::9"), WAN: []Prefix{wan}, Tunnel: &TunnelParams{Captured: g}}
	ch <- Snapshot{WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:9::/48")}}, Tunnel: &TunnelParams{Captured: g}}
	if g := <-st.capIn; g != nil {
		t.Fatalf("a renumbered line must drop the old decision: %+v", g)
	}
	ch <- Snapshot{WANAddr: netip.MustParseAddr("2001:db8:9::1")}
	captureSubOf(t, hub, 1)
	ch <- Snapshot{WANAddr: netip.MustParseAddr("2001:db8:9::1"), Tunnel: &TunnelParams{AFTRName: "aftr.example"}}
	captureSubOf(t, hub, 0)
	cancel()
	<-done
}

// Without tunnel traffic the capture gives up after maxRun.
func TestTunnelWatcherGivesUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := newPacketHub(ctx, "sixup-none0")
	w := &tunnelWatcher{ifname: "sixup-none0", store: &Store{}, pkts: hub, maxRun: time.Nanosecond}
	ch := make(chan Snapshot)
	go w.run(ctx, ch)
	ch <- Snapshot{WANAddr: netip.MustParseAddr("2001:db8::1")}
	captureSubOf(t, hub, 1)
	captureSubOf(t, hub, 0)             // the first tick stops it
	time.Sleep(1100 * time.Millisecond) // and the next finds nothing running
}
