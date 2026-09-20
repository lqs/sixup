//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Jool (https://jool.mx) is an out-of-tree NAT64 module configured over generic netlink. The
// protocol below is the one its 4.1 series speaks; the constants come from src/common/config.h and
// src/common/types.h of the release tarball.
const (
	joolFamily   = "Jool"
	joolMagic    = "jool"
	joolINameLen = 16 // INAME_MAX_SIZE
	joolModule   = "/sys/module/jool/version"

	xtNAT64     = 1 << 1 // XT_NAT64
	xfNetfilter = 1 << 2 // XF_NETFILTER

	opInstanceAdd = 1  // JNLOP_INSTANCE_ADD
	opInstanceRm  = 3  // JNLOP_INSTANCE_RM
	opPool4Add    = 19 // JNLOP_POOL4_ADD
	opPool4Flush  = 21 // JNLOP_POOL4_FLUSH

	jnlarOperand = 10 // JNLAR_OPERAND

	jnlaiaXF    = 1 // JNLAIA_XF
	jnlaiaPool6 = 2 // JNLAIA_POOL6

	jnlapAddr = 1 // JNLAP_ADDR
	jnlapLen  = 2 // JNLAP_LEN

	jnlap4Mark       = 1 // JNLAP4_MARK
	jnlap4Iterations = 2
	jnlap4Flags      = 3
	jnlap4Proto      = 4
	jnlap4Prefix     = 5
	jnlap4PortMin    = 6
	jnlap4PortMax    = 7

	iterationsAuto = 1 << 1 // ITERATIONS_AUTO: let the module size the table
)

// l4 protocols, in Jool's own numbering rather than the IP one
var joolProtos = []uint8{0, 1, 2} // L4PROTO_TCP, L4PROTO_UDP, L4PROTO_ICMP

// joolManager configures one NAT64 instance. Jool translates and sends the result with
// dst_output, which skips LOCAL_OUT, and it clears the packet's conntrack association on the way
// (nf_reset_ct in its rfc7915 code). The packet therefore reaches POSTROUTING with no conntrack
// entry, and a nat chain does nothing without one: the source NAT this daemon installs for the
// tunnel never sees Jool's traffic. Jool has to put the right address and port on the packet
// itself, which on a MAP-E line means the shared IPv4 and a share of the port set that netfilter
// then leaves alone.
type joolManager struct {
	iname   string // instance name
	ranges  int    // how many of the line's port ranges are Jool's
	applied string // fingerprint of what is installed
	lastErr string // the module may be absent for hours; the same complaint is logged once
}

// pool4Entry is the address Jool sources from and the ports it may use on it.
type pool4Entry struct {
	addr  netip.Addr
	ports []portSpan // empty means every port
}

func (p pool4Entry) key() string {
	return fmt.Sprintf("%s|%s", p.addr, spansString(p.ports))
}

// pool4For reads the line's own IPv4 out of a snapshot. A MAP-E subscriber owns part of a shared
// address; DS-Lite has only the B4 address, which the AFTR translates again, so every port of it is
// available here.
func pool4For(snap Snapshot, ranges int) (pool4Entry, bool) {
	t := snap.Tunnel
	if t == nil || !t.IPv4.IsValid() || !t.IPv4.Is4() {
		return pool4Entry{}, false
	}
	if t.RuleMAPE != nil && len(t.RuleMAPE.Ports) > 0 {
		_, mine := splitPortSpans(t.RuleMAPE.Ports, ranges)
		if len(mine) == 0 {
			return pool4Entry{}, false
		}
		return pool4Entry{addr: t.RuleMAPE.IPv4, ports: mine}, true
	}
	return pool4Entry{addr: t.IPv4}, true
}

func (m *joolManager) run(ctx context.Context, ch <-chan Snapshot) {
	defer m.remove()
	for {
		select {
		case <-ctx.Done():
			return
		case snap := <-ch:
			pool, ok := pool4For(snap, m.ranges)
			if !ok {
				continue // no IPv4 of our own yet; nothing to translate towards
			}
			if pool.key() == m.applied {
				continue
			}
			if err := m.configure(pool); err != nil {
				m.report(err)
				continue
			}
			m.applied = pool.key()
			m.report(nil)
		}
	}
}

// report keeps the log quiet while nothing changes: a box without the module loaded would otherwise
// carry the same line every minute for as long as it runs.
func (m *joolManager) report(err error) {
	if err == nil {
		m.lastErr = ""
		return
	}
	if msg := err.Error(); msg != m.lastErr {
		m.lastErr = msg
		log.Printf("[jool] %s", msg)
	}
}

func (m *joolManager) configure(pool pool4Entry) error {
	ver, err := joolVersion()
	if err != nil {
		return err
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("cannot open generic netlink: %w", err)
	}
	defer c.Close()
	fam, err := c.GetFamily(joolFamily)
	if err != nil {
		return fmt.Errorf("the jool module is loaded but offers no %s netlink family: %w", joolFamily, err)
	}

	switch err := m.request(c, fam.ID, ver, opInstanceAdd, m.instanceAttrs()); {
	case err == nil:
		log.Printf("[jool] instance %q created, translating %s", m.iname, joolNAT64)
	case errors.Is(err, unix.EEXIST):
		// Left over from a previous run or created by hand; its pool4 is rewritten below either way
	default:
		return fmt.Errorf("cannot create instance %q: %w", m.iname, err)
	}

	// The address and the ports both move with the delegated prefix, so the pool is replaced rather
	// than added to; a leftover entry would keep translating towards an address the line no longer has.
	if err := m.request(c, fam.ID, ver, opPool4Flush, nil); err != nil {
		return fmt.Errorf("cannot clear pool4: %w", err)
	}
	for _, proto := range joolProtos {
		for _, e := range m.pool4Entries(pool, proto) {
			if err := m.request(c, fam.ID, ver, opPool4Add, e); err != nil {
				return fmt.Errorf("cannot add %s to pool4: %w", pool.addr, err)
			}
		}
	}
	if len(pool.ports) > 0 {
		log.Printf("[jool] translating to %s, %d ports in %d ranges: %s",
			pool.addr, portCount(pool.ports), len(pool.ports), spansString(pool.ports))
	} else {
		log.Printf("[jool] translating to %s, every port", pool.addr)
	}
	return nil
}

func (m *joolManager) remove() {
	ver, err := joolVersion()
	if err != nil {
		return
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return
	}
	defer c.Close()
	fam, err := c.GetFamily(joolFamily)
	if err != nil {
		return
	}
	if err := m.request(c, fam.ID, ver, opInstanceRm, nil); err != nil {
		log.Printf("[jool] cannot remove instance %q: %v", m.iname, err)
		return
	}
	log.Printf("[jool] instance %q removed", m.iname)
}

func (m *joolManager) request(c *genetlink.Conn, family uint16, ver uint32, op uint8, attrs []byte) error {
	data := append(joolHeader(ver, m.iname), attrs...)
	_, err := c.Execute(
		genetlink.Message{Header: genetlink.Header{Command: op, Version: 1}, Data: data},
		family,
		netlink.Request|netlink.Acknowledge,
	)
	return err
}

// joolHeader is struct joolnlhdr: the module rejects a request whose version is not exactly its own,
// so the number is read from the loaded module rather than compiled in.
func joolHeader(ver uint32, iname string) []byte {
	b := make([]byte, 4+4+4+joolINameLen)
	copy(b, joolMagic)
	binary.BigEndian.PutUint32(b[4:8], ver)
	b[8] = xtNAT64
	// b[9] flags, b[10] and b[11] reserved
	copy(b[12:12+joolINameLen-1], iname)
	return b
}

func (m *joolManager) instanceAttrs() []byte {
	return encodeAttrs(func(ae *netlink.AttributeEncoder) {
		ae.Nested(jnlarOperand, func(ae *netlink.AttributeEncoder) error {
			ae.Uint8(jnlaiaXF, xfNetfilter)
			ae.Nested(jnlaiaPool6, prefix6Attrs(joolNAT64))
			return nil
		})
	})
}

// pool4Entries describes the address and, on a MAP-E line, each range of it Jool may draw from.
// Jool stores one entry per range, the same shape the source NAT rules take on the netfilter side.
func (m *joolManager) pool4Entries(pool pool4Entry, proto uint8) [][]byte {
	spans := pool.ports
	if len(spans) == 0 {
		spans = []portSpan{{1, 65535}}
	}
	out := make([][]byte, 0, len(spans))
	for _, span := range spans {
		out = append(out, encodeAttrs(func(ae *netlink.AttributeEncoder) {
			ae.Nested(jnlarOperand, func(ae *netlink.AttributeEncoder) error {
				ae.Uint32(jnlap4Mark, 0)
				ae.Uint32(jnlap4Iterations, 0)
				ae.Uint8(jnlap4Flags, iterationsAuto)
				ae.Uint8(jnlap4Proto, proto)
				ae.Nested(jnlap4Prefix, prefix4Attrs(netip.PrefixFrom(pool.addr, 32)))
				ae.Uint16(jnlap4PortMin, span.Start)
				ae.Uint16(jnlap4PortMax, span.End)
				return nil
			})
		}))
	}
	return out
}

func prefix6Attrs(p netip.Prefix) func(*netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		a := p.Addr().As16()
		ae.Bytes(jnlapAddr, a[:])
		ae.Uint8(jnlapLen, uint8(p.Bits()))
		return nil
	}
}

func prefix4Attrs(p netip.Prefix) func(*netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		a := p.Addr().As4()
		ae.Bytes(jnlapAddr, a[:])
		ae.Uint8(jnlapLen, uint8(p.Bits()))
		return nil
	}
}

func encodeAttrs(fill func(*netlink.AttributeEncoder)) []byte {
	ae := netlink.NewAttributeEncoder()
	fill(ae)
	b, err := ae.Encode()
	if err != nil {
		return nil
	}
	return b
}

// joolVersion reads the version of the loaded module, which MODULE_VERSION publishes as
// "major.minor.rev.dev". Every request carries it and the module refuses anything else.
func joolVersion() (uint32, error) {
	b, err := os.ReadFile(joolModule)
	if err != nil {
		return 0, fmt.Errorf("the jool module does not look loaded (%s): try modprobe jool", joolModule)
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("cannot read the jool version from %s: %q", joolModule, b)
	}
	var v uint32
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("cannot read the jool version from %s: %q", joolModule, b)
		}
		v = v<<8 | uint32(n)
	}
	return v, nil
}
