//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

// A frame too short for an Ethernet header, or with no IP after it, is dropped.
func TestSlowPathFrames(t *testing.T) {
	p := &slowPath{}
	p.handle(make([]byte, 10))
	p.handle(make([]byte, 20))
	if n := p.dropped.Load(); n != 2 {
		t.Fatalf("want both frames dropped, got %d", n)
	}
}

// What is not a well-formed IPv4 or IPv6 packet is refused before anything is reassembled.
func TestSlowPathRefusesMalformed(t *testing.T) {
	p := &slowPath{groups: map[slowKey]*slowGroup{}, now: time.Now}
	v4 := func(ihl byte, tot uint16, n int) []byte {
		b := make([]byte, n)
		b[0] = 4<<4 | ihl
		binary.BigEndian.PutUint16(b[2:], tot)
		return b
	}
	v6 := func(plen uint16, next byte, n int) []byte {
		b := make([]byte, n)
		b[0], b[6] = 6<<4, next
		binary.BigEndian.PutUint16(b[4:], plen)
		return b
	}
	for name, pkt := range map[string][]byte{
		"empty":               nil,
		"IPv4 options":        v4(6, 24, 24),
		"IPv4 length short":   v4(5, 10, 20),
		"IPv4 length long":    v4(5, 40, 20),
		"IPv6 length long":    v6(10, 17, 40),
		"IPv6 fragment short": v6(4, 44, 44),
	} {
		if err := p.packet(pkt); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// Fragments come together in any order; a hole waits, an overlap or a malformed piece drops the
// datagram, and so do too many datagrams at once or one that takes too long.
func TestSlowPathReassembly(t *testing.T) {
	now := time.Unix(1000, 0)
	p := &slowPath{groups: map[slowKey]*slowGroup{}, now: func() time.Time { return now }}
	hdr := make([]byte, 40)
	hdr[0], hdr[6] = 6<<4, 44
	key := func(id uint32) slowKey {
		return slowKey{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("64:ff9b::1"), id, 58}
	}
	add := func(id uint32, off int, more bool, n int) ([]byte, []byte, error) {
		return p.reassemble(key(id), hdr, off, more, make([]byte, n))
	}

	if _, w, err := add(1, 16, false, 4); w != nil || err != nil {
		t.Fatalf("the last piece alone completes nothing: %v %v", w, err)
	}
	if _, w, err := add(1, 0, true, 8); w != nil || err != nil {
		t.Fatalf("a hole is left at 8: %v %v", w, err)
	}
	h, w, err := add(1, 8, true, 8)
	if err != nil || len(w) != 20 || h[6] != 58 {
		t.Fatalf("want 20 bytes and the header naming ICMPv6, got %d, %v, %v", len(w), h, err)
	}
	if len(p.groups) != 0 {
		t.Fatal("a datagram put together should be forgotten")
	}

	for name, step := range map[string]func() error{
		"a piece with more that is not a multiple of 8": func() error { _, _, err := add(2, 0, true, 7); return err },
		"a piece beyond 65535":                          func() error { _, _, err := add(3, 65528, false, 16); return err },
		"a piece beyond the end": func() error {
			add(4, 16, false, 8)
			_, _, err := add(4, 16, true, 16)
			return err
		},
		"overlapping pieces": func() error {
			add(5, 0, true, 16)
			_, _, err := add(5, 8, true, 16)
			return err
		},
	} {
		if err := step(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if len(p.groups) != 0 {
		t.Fatalf("each bad datagram should be dropped, %d left", len(p.groups))
	}

	for id := range uint32(slowGroups) {
		add(100+id, 0, true, 8)
	}
	if _, _, err := add(999, 0, true, 8); err == nil {
		t.Fatal("a datagram over the limit should be refused")
	}
	dropped := p.dropped.Load()
	now = now.Add(slowTimeout + time.Second)
	if _, _, err := add(999, 0, true, 8); err != nil {
		t.Fatalf("the expired datagrams should make room: %v", err)
	}
	if n := p.dropped.Load() - dropped; n != slowGroups {
		t.Fatalf("want the %d expired datagrams counted, got %d", slowGroups, n)
	}
}

// Only the original sources within the pool count, and what does not parse is passed over.
func TestPoolSources(t *testing.T) {
	flow := func(src [4]byte) netlink.Message {
		ae := netlink.NewAttributeEncoder()
		ae.Nested(ctaTupleOrig, func(ae *netlink.AttributeEncoder) error {
			ae.Uint8(9, 0) // not the IP tuple
			ae.Nested(ctaTupleIP, func(ae *netlink.AttributeEncoder) error {
				ae.Bytes(1, src[:])
				ae.Bytes(2, []byte{192, 0, 2, 2})
				return nil
			})
			return nil
		})
		ae.Nested(ctaTupleReply, func(ae *netlink.AttributeEncoder) error {
			ae.Nested(ctaTupleIP, func(ae *netlink.AttributeEncoder) error {
				ae.Bytes(1, []byte{198, 18, 9, 9})
				return nil
			})
			return nil
		})
		b, _ := ae.Encode()
		return netlink.Message{Data: append(make([]byte, nfgenmsgLen), b...)}
	}
	got := poolSources([]netlink.Message{
		flow([4]byte{198, 18, 0, 2}),
		flow([4]byte{10, 0, 0, 1}),
		{Data: []byte{0, 0}},             // shorter than nfgenmsg
		{Data: []byte{0, 0, 0, 0, 9, 0}}, // an attribute cut short
	}, bpfPool)
	if len(got) != 1 || !got[netip.MustParseAddr("198.18.0.2")] {
		t.Fatalf("want only 198.18.0.2, got %v", got)
	}
}

func TestInPool(t *testing.T) {
	for a, want := range map[string]bool{"198.18.0.0": false, "198.18.0.1": false, "198.18.0.2": true, "198.19.255.255": true, "198.20.0.0": false, "198.17.255.255": false} {
		if got := inPool(netip.MustParseAddr(a).As4()); got != want {
			t.Errorf("inPool(%s) = %v, want %v", a, got, want)
		}
	}
}

const ctaTupleReply = 2 // CTA_TUPLE_REPLY

// The examples of RFC 6052 section 2.4: 192.0.2.33 behind a prefix of each length.
var rfc6052Examples = map[string]string{
	"2001:db8::/32":         "2001:db8:c000:221::",
	"2001:db8:100::/40":     "2001:db8:1c0:2:21::",
	"2001:db8:122::/48":     "2001:db8:122:c000:2:2100::",
	"2001:db8:122:300::/56": "2001:db8:122:3c0:0:221::",
	"2001:db8:122:344::/64": "2001:db8:122:344:c0:2:2100:0",
	"2001:db8:122:344::/96": "2001:db8:122:344::c000:221",
}

func TestRFC6052(t *testing.T) {
	v4 := [4]byte{192, 0, 2, 33}
	for prefix, want := range rfc6052Examples {
		p := netip.MustParsePrefix(prefix)
		a := embed4(p, v4)
		if got := netip.AddrFrom16(a); got != netip.MustParseAddr(want) {
			t.Errorf("%s: embedded %s, want %s", prefix, got, want)
		}
		if got := extract4(p, a); got != v4 {
			t.Errorf("%s: extracted %v", prefix, got)
		}
	}
}

// The CLAT's slow path maps as its program does: the NAT64 prefix both ways, the CLAT address and
// 192.0.0.4, and a router on the IPv6 path to 192.0.0.8.
func TestCLATMapping(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::c1a7")
	m := clatMapping(nat64WKP, addr)
	for in, want := range map[string]string{"64:ff9b::c000:202": "192.0.2.2", addr.String(): "192.0.0.4", "2001:db8::1": "192.0.0.8"} {
		if got, err := m.v4of6(netip.MustParseAddr(in).As16(), false); err != nil || netip.AddrFrom4(got).String() != want {
			t.Errorf("%s: got %v %v, want %s", in, netip.AddrFrom4(got), err, want)
		}
	}
	for in, want := range map[string]netip.Addr{"192.0.2.2": netip.MustParseAddr("64:ff9b::c000:202"), "192.0.0.4": addr} {
		if got, err := m.v6of4(netip.MustParseAddr(in).As4()); err != nil || netip.AddrFrom16(got) != want {
			t.Errorf("%s: got %v %v, want %s", in, netip.AddrFrom16(got), err, want)
		}
	}
}
