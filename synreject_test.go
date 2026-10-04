//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// synrejectSegment builds an IPv6 packet carrying a TCP header with the flags; no checksum.
func synrejectSegment(from, to netip.AddrPort, flags byte) []byte {
	p := make([]byte, 60)
	p[0], p[6] = 0x60, 6
	binary.BigEndian.PutUint16(p[4:], 20)
	s, d := from.Addr().As16(), to.Addr().As16()
	copy(p[8:], s[:])
	copy(p[24:], d[:])
	binary.BigEndian.PutUint16(p[40:], from.Port())
	binary.BigEndian.PutUint16(p[42:], to.Port())
	p[52], p[53] = 5<<4, flags
	return p
}

var (
	synrejectFrom = netip.MustParseAddrPort("[2001:db8:f::1]:40000")
	synrejectTo   = netip.MustParseAddrPort("[2001:db8:1::10]:22")
)

func TestParseSYN(t *testing.T) {
	syn := synrejectSegment(synrejectFrom, synrejectTo, tcpFlagSYN)
	if f, ok := parseSYN(syn); !ok || f.from != synrejectFrom || f.to != synrejectTo {
		t.Fatalf("%+v %v", f, ok)
	}
	udp := synrejectSegment(synrejectFrom, synrejectTo, tcpFlagSYN)
	udp[6] = 17
	v4 := synrejectSegment(synrejectFrom, synrejectTo, tcpFlagSYN)
	v4[0] = 0x45
	for _, p := range [][]byte{
		syn[:59],
		udp,
		v4,
		synrejectSegment(synrejectFrom, synrejectTo, tcpFlagSYN|tcpFlagACK),
		synrejectSegment(synrejectFrom, synrejectTo, tcpFlagACK),
	} {
		if f, ok := parseSYN(p); ok {
			t.Fatalf("not a SYN: %+v", f)
		}
	}
}

// add ignores what is not a SYN, retransmissions and SYNs beyond the bound, and once the wait is
// over nothing is sent when the rejecter is shutting down.
func TestSYNRejecterAdd(t *testing.T) {
	old := synWait
	synWait = 10 * time.Millisecond
	defer func() { synWait = old }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &synRejecter{pending: map[synFlow][]byte{}}
	syn := synrejectSegment(synrejectFrom, synrejectTo, tcpFlagSYN)
	r.add(ctx, synrejectSegment(synrejectFrom, synrejectTo, tcpFlagACK))
	r.add(ctx, syn)
	r.add(ctx, syn)
	r.mu.Lock()
	n := len(r.pending)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d SYNs waiting, want 1", n)
	}
	for deadline := time.Now().Add(time.Second); n != 0 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		n = len(r.pending)
		r.mu.Unlock()
	}
	if n != 0 {
		t.Fatal("the SYN should have left the table after the wait")
	}

	full := &synRejecter{pending: map[synFlow][]byte{}}
	for i := range synPendingMax {
		full.pending[synFlow{from: netip.AddrPortFrom(synrejectFrom.Addr(), uint16(i))}] = nil
	}
	full.add(ctx, syn)
	if len(full.pending) != synPendingMax {
		t.Fatal("a full table takes no more")
	}
}
