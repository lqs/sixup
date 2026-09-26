//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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

// The instance carries the prefix it translates: the well-known one by default, or a
// network-specific one from -ra-pref64, which private IPv4 destinations need (RFC 6052).
func TestJoolInstanceAttributes(t *testing.T) {
	nsp := netip.MustParsePrefix("fd00:64::/96")
	ad := decodeNested(t, instanceAttrs(nsp), jnlarOperand)
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
	if prefix != nsp {
		t.Fatalf("pool6 should be %s, got %s", nsp, prefix)
	}
}

// pool4 is Jool's side of the /31 with every port short of the namespace's ephemeral range, which
// Jool refuses to overlap: nothing else in its namespace uses the address, and the line's ports
// belong to the source NAT outside.
func TestJoolPool4(t *testing.T) {
	outside, inside := joolAddrs(netip.MustParsePrefix("192.168.255.254/31"))
	if outside != netip.MustParseAddr("192.168.255.254") || inside != netip.MustParseAddr("192.168.255.255") {
		t.Fatalf("the /31 splits into %s outside and %s inside", outside, inside)
	}
	for _, proto := range joolProtos {
		ad := decodeNested(t, pool4Attrs(inside, proto), jnlarOperand)
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
		wantMax := uint16(joolPortMax) // below the namespace's ephemeral range, which Jool checks
		if proto == joolICMP {
			wantMax = 65535 // identifiers, which Jool does not check against it
		}
		if gotProto != proto || min != 1 || max != wantMax || addr != inside || bits != 32 {
			t.Fatalf("protocol %d: got proto %d, ports %d-%d, %s/%d", proto, gotProto, min, max, addr, bits)
		}
	}
}

// Jool reports a failure inside its own reply rather than as a netlink error, so the reply has to
// be read for it: an instance that already exists must come back as EEXIST.
func TestJoolReplyError(t *testing.T) {
	reply := func(flags byte, attrs []byte) []byte {
		h := joolHeader(0x04010700, "sixup")
		h[9] = flags
		return append(h, attrs...)
	}
	if err := joolReplyError(reply(0, nil)); err != nil {
		t.Fatalf("a reply without the error flag is a success, got %v", err)
	}
	attrs := encodeAttrs(func(ae *netlink.AttributeEncoder) {
		ae.Uint16(jnlaerrCode, uint16(unix.EEXIST))
		ae.String(jnlaerrMsg, "This namespace already has a Jool instance named 'sixup'.")
	})
	err := joolReplyError(reply(joolFlagError, attrs))
	if !errors.Is(err, unix.EEXIST) || !strings.Contains(err.Error(), "already has a Jool instance") {
		t.Fatalf("want EEXIST with Jool's message, got %v", err)
	}
	if joolReplyError([]byte("jool")) != nil {
		t.Fatal("a reply too short for the header carries no report")
	}
}
