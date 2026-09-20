package main

import (
	"net/netip"
	"strings"
	"testing"
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
	p := captureFilter(kindTunnel)
	for i, in := range p {
		if in.code == bpfJeqK && (i+1+int(in.jt) >= len(p) || i+1+int(in.jf) >= len(p)) {
			t.Fatalf("instruction %d jumps out of the program", i)
		}
	}
	if runBPF(p, frame(4, 0, 0)) == 0 {
		t.Fatal("protocol 4 should be accepted")
	}
	for _, f := range [][]byte{frame(6, 443, 50000), frame(58, 0, 0), frame(17, 547, 546)} {
		if runBPF(p, f) != 0 {
			t.Fatal("non-protocol-4 should be dropped")
		}
	}
	v4 := frame(4, 0, 0)
	v4[12], v4[13] = 0x08, 0x00
	if runBPF(p, v4) != 0 {
		t.Fatal("non-IPv6 should be dropped")
	}
}

func TestClassifyFrame(t *testing.T) {
	if classifyFrame(frame(4, 0, 0)) != kindTunnel {
		t.Fatal("protocol 4 should be tunnel")
	}
	if classifyFrame(frame(17, 547, 546)) != 0 || classifyFrame(frame(6, 80, 80)) != 0 {
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
