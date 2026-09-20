//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
)

// The module compares the version in every request against its own and refuses anything else, so
// the number has to come from the module that is actually loaded.
func TestJoolHeaderCarriesTheModuleVersion(t *testing.T) {
	h := joolHeader(0x04010700, "sixup") // 4.1.7.0
	if len(h) != 28 {
		t.Fatalf("struct joolnlhdr is 28 bytes, got %d", len(h))
	}
	if string(h[:4]) != "jool" {
		t.Fatalf("the magic should be jool, got %q", h[:4])
	}
	if got := binary.BigEndian.Uint32(h[4:8]); got != 0x04010700 {
		t.Fatalf("version 4.1.7.0 encodes as 0x04010700, got %#x", got)
	}
	if h[8] != xtNAT64 {
		t.Fatalf("the request is for a NAT64 translator, got xt=%d", h[8])
	}
	if name := string(h[12:17]); name != "sixup" {
		t.Fatalf("the instance name should follow the flags, got %q", name)
	}
	if h[len(h)-1] != 0 {
		t.Fatal("the instance name has to stay terminated")
	}
}

// A name of exactly the maximum length would leave no terminator, which the module requires.
func TestJoolHeaderTruncatesALongName(t *testing.T) {
	h := joolHeader(1, "0123456789abcdefghij")
	if got := string(h[12 : 12+joolINameLen-1]); got != "0123456789abcde" {
		t.Fatalf("the name should be cut to 15 characters, got %q", got)
	}
	if h[len(h)-1] != 0 {
		t.Fatal("the terminator is missing")
	}
}

func decodeNested(t *testing.T, b []byte, want uint16) *netlink.AttributeDecoder {
	t.Helper()
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for ad.Next() {
		if ad.Type() == want {
			inner, err := netlink.NewAttributeDecoder(ad.Bytes())
			if err != nil {
				t.Fatalf("decoding nested %d: %v", want, err)
			}
			return inner
		}
	}
	t.Fatalf("attribute %d is missing", want)
	return nil
}

// The instance carries the prefix it translates, which is the well-known one: a prefix carved out
// of the delegation would have to be re-announced to every client on a renumbering.
func TestJoolInstanceAttributes(t *testing.T) {
	m := &joolManager{iname: "sixup"}
	ad := decodeNested(t, m.instanceAttrs(), jnlarOperand)
	var xf uint8
	var prefix netip.Prefix
	for ad.Next() {
		switch ad.Type() {
		case jnlaiaXF:
			xf = ad.Uint8()
		case jnlaiaPool6:
			inner, err := netlink.NewAttributeDecoder(ad.Bytes())
			if err != nil {
				t.Fatalf("pool6: %v", err)
			}
			var addr netip.Addr
			var bits uint8
			for inner.Next() {
				switch inner.Type() {
				case jnlapAddr:
					a, ok := netip.AddrFromSlice(inner.Bytes())
					if !ok {
						t.Fatalf("pool6 address: %v", inner.Bytes())
					}
					addr = a
				case jnlapLen:
					bits = inner.Uint8()
				}
			}
			prefix = netip.PrefixFrom(addr, int(bits))
		}
	}
	if xf != xfNetfilter {
		t.Fatalf("the instance should hook into netfilter, got xf=%d", xf)
	}
	if prefix != joolNAT64 {
		t.Fatalf("pool6 should be %s, got %s", joolNAT64, prefix)
	}
}

// A MAP-E subscriber may use only its own ports, so one pool4 entry describes each range it was
// given. Jool has to carry that restriction itself: its output reaches POSTROUTING without a
// conntrack entry, where a nat chain does nothing.
func TestJoolPool4Entries(t *testing.T) {
	m := &joolManager{iname: "sixup"}
	pool := pool4Entry{addr: netip.MustParseAddr("203.0.113.9"), ports: portSpans(4, 8, 0x56)[12:]}
	for _, proto := range joolProtos {
		entries := m.pool4Entries(pool, proto)
		if len(entries) != len(pool.ports) {
			t.Fatalf("%d entries for %d ranges", len(entries), len(pool.ports))
		}
		for i, e := range entries {
			ad := decodeNested(t, e, jnlarOperand)
			var gotProto uint8
			var min, max uint16
			var addr netip.Addr
			var bits uint8
			for ad.Next() {
				switch ad.Type() {
				case jnlap4Proto:
					gotProto = ad.Uint8()
				case jnlap4PortMin:
					min = ad.Uint16()
				case jnlap4PortMax:
					max = ad.Uint16()
				case jnlap4Prefix:
					inner, err := netlink.NewAttributeDecoder(ad.Bytes())
					if err != nil {
						t.Fatalf("prefix: %v", err)
					}
					for inner.Next() {
						switch inner.Type() {
						case jnlapAddr:
							a, ok := netip.AddrFromSlice(inner.Bytes())
							if !ok {
								t.Fatalf("pool4 address: %v", inner.Bytes())
							}
							addr = a
						case jnlapLen:
							bits = inner.Uint8()
						}
					}
				}
			}
			if gotProto != proto {
				t.Fatalf("protocol %d came back as %d", proto, gotProto)
			}
			if min != pool.ports[i].Start || max != pool.ports[i].End {
				t.Fatalf("entry %d covers %d-%d, want %s", i, min, max, pool.ports[i])
			}
			if addr != pool.addr || bits != 32 {
				t.Fatalf("pool4 should be %s/32, got %s/%d", pool.addr, addr, bits)
			}
		}
	}

	// A line that owns its whole address needs no restriction
	entries := m.pool4Entries(pool4Entry{addr: netip.MustParseAddr("198.51.100.7")}, 0)
	if len(entries) != 1 {
		t.Fatalf("one entry covers every port, got %d", len(entries))
	}
}

// The two translators must never be told they own the same port.
func TestPortSetSplitDoesNotOverlap(t *testing.T) {
	spans := portSpans(4, 8, 0x56)
	forNAT, forJool := splitPortSpans(spans, 3)
	if len(forNAT) != 12 || len(forJool) != 3 {
		t.Fatalf("split gave %d and %d ranges", len(forNAT), len(forJool))
	}
	seen := map[uint16]bool{}
	for _, s := range append(append([]portSpan{}, forNAT...), forJool...) {
		for p := int(s.Start); p <= int(s.End); p++ {
			if seen[uint16(p)] {
				t.Fatalf("port %d is in both shares", p)
			}
			seen[uint16(p)] = true
		}
	}
	if len(seen) != portCount(spans) {
		t.Fatalf("the two shares cover %d ports, the set has %d", len(seen), portCount(spans))
	}

	// Asking for everything still leaves the source NAT a range to work with
	forNAT, forJool = splitPortSpans(spans, len(spans)+5)
	if len(forNAT) != 1 || len(forJool) != len(spans)-1 {
		t.Fatalf("an oversized share gave %d and %d", len(forNAT), len(forJool))
	}
	if forNAT, forJool = splitPortSpans(spans, 0); forJool != nil || len(forNAT) != len(spans) {
		t.Fatal("without NAT64 the whole set stays with the source NAT")
	}
}
