//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// The slow path of the BPF translators takes the datagrams bpf/nat64.c and bpf/clat.c cannot give
// a right checksum one fragment at a time: fragmented ICMP, and IPv4 UDP without a checksum. It puts
// them together, translates them whole, cuts them into fragments again where they are too large
// for the device, or for the smallest LAN, and sends them back out of the device marked
// bpfSlowMark. The program hands them to the device's ingress, where they enter the stack like
// everything else it translates.

const (
	slowGroups  = 64               // fragmented datagrams being put together at once
	slowTimeout = 30 * time.Second // ipfrag_time
	bpfProbes   = 8                // PROBES in bpf/nat64.c
	bpfSlowMark = 0x64ff9b         // the packets the slow path sends back; any mark of the operator's is gone by then
)

type slowPath struct {
	slowMapping
	dev     *net.Interface
	mtu6    int // what an IPv6 packet sent on may be at most
	fd      int // a packet socket, sending marked
	groups  map[slowKey]*slowGroup
	id      uint32
	dropped atomic.Uint64
	now     func() time.Time
}

// slowMapping maps addresses between the families as the program the slow path serves does.
type slowMapping struct {
	v4of6 func(a [16]byte, alloc bool) ([4]byte, error) // a new pool address for a source if alloc
	v6of4 func(a [4]byte) ([16]byte, error)
}

// nat64Mapping is bpf/nat64.c's: the NAT64 prefix carries IPv4 addresses, and the pool stands for
// IPv6 sources.
func nat64Mapping(prefix netip.Prefix, v4of, v6of *bpfMap) slowMapping {
	return slowMapping{
		v4of6: func(a [16]byte, alloc bool) ([4]byte, error) {
			var v [4]byte
			switch {
			case prefix.Contains(netip.AddrFrom16(a)):
				return extract4(prefix, a), nil
			case alloc:
				v, ok := map4(v4of, v6of, a)
				if !ok {
					return v, errors.New("the pool is full")
				}
				return v, nil
			case v4of.lookup(a[:], v[:]) != nil:
				return v, fmt.Errorf("%s has no pool address", netip.AddrFrom16(a))
			}
			return v, nil
		},
		v6of4: func(a [4]byte) ([16]byte, error) {
			var v [16]byte
			if !bpfPool.Contains(netip.AddrFrom4(a)) {
				return embed4(prefix, a), nil
			}
			if v6of.lookup(a[:], v[:]) != nil {
				return v, fmt.Errorf("no source has %s", netip.AddrFrom4(a))
			}
			return v, nil
		},
	}
}

// slowKey tells the fragments of one datagram from those of others (RFC 791, RFC 8200).
type slowKey struct {
	src, dst netip.Addr
	id       uint32
	proto    uint8
}

type slowGroup struct {
	hdr     []byte         // the first fragment's IP header, without a fragment header
	parts   map[int][]byte // payload by offset
	total   int            // the payload's length, once the last fragment has come
	expires time.Time
}

func newSlowPath(m slowMapping, dev *net.Interface, mtu6 int) (*slowPath, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, bpfSlowMark) // CAP_NET_RAW, which the socket took, allows it
	return &slowPath{slowMapping: m, dev: dev, mtu6: min(mtu6, dev.MTU), fd: fd, groups: map[slowKey]*slowGroup{}, now: time.Now}, nil
}

func (p *slowPath) close() { unix.Close(p.fd) }

// send hands a translated packet to the device, addressed to it.
func (p *slowPath) send(pkt []byte) error {
	proto := uint16(unix.ETH_P_IP)
	if pkt[0]>>4 == 6 {
		proto = unix.ETH_P_IPV6
	}
	to := &unix.SockaddrLinklayer{Protocol: proto<<8 | proto>>8, Ifindex: p.dev.Index, Halen: 6}
	copy(to.Addr[:], p.dev.HardwareAddr)
	return unix.Sendto(p.fd, pkt, 0, to)
}

// serve reads what the program hands over until the reader is closed.
func (p *slowPath) serve(rd *ringReader) {
	for {
		rec, err := rd.read()
		if err != nil {
			return
		}
		p.handle(rec)
	}
}

// handle takes one frame the program handed over.
func (p *slowPath) handle(frame []byte) {
	if len(frame) < 14 {
		p.dropped.Add(1)
		return
	}
	if err := p.packet(frame[14:]); err != nil {
		p.dropped.Add(1)
		debugf("[nat64] slow path: %v", err)
	}
}

// packet takes an IP packet, a whole one or a fragment, and sends on what it completes.
func (p *slowPath) packet(pkt []byte) error {
	var k slowKey
	var hdr, payload []byte
	var off int
	var more bool
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4:
		tot := int(binary.BigEndian.Uint16(pkt[2:4]))
		if pkt[0]&0xf != 5 || tot < 20 || tot > len(pkt) {
			return errors.New("malformed IPv4")
		}
		fo := binary.BigEndian.Uint16(pkt[6:8])
		hdr, payload = pkt[:20], pkt[20:tot]
		off, more = int(fo&0x1fff)*8, fo&0x2000 != 0
		k = slowKey{netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), uint32(binary.BigEndian.Uint16(pkt[4:6])), pkt[9]}
	case len(pkt) >= 40 && pkt[0]>>4 == 6:
		end := 40 + int(binary.BigEndian.Uint16(pkt[4:6]))
		if end > len(pkt) {
			return errors.New("malformed IPv6")
		}
		hdr, payload = pkt[:40], pkt[40:end]
		k = slowKey{netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40])), 0, pkt[6]}
		if pkt[6] == unix.IPPROTO_FRAGMENT {
			if len(payload) < 8 {
				return errors.New("malformed fragment header")
			}
			fo := binary.BigEndian.Uint16(payload[2:4])
			off, more = int(fo>>3)*8, fo&1 != 0
			k.proto, k.id = payload[0], binary.BigEndian.Uint32(payload[4:8])
			payload = payload[8:]
		}
	default:
		return errors.New("not IP")
	}
	if off == 0 && !more {
		return p.whole(hdr, k.proto, payload)
	}
	hdr, whole, err := p.reassemble(k, hdr, off, more, payload)
	if whole == nil || err != nil {
		return err
	}
	return p.whole(hdr, k.proto, whole)
}

// reassemble adds a fragment to its datagram, and returns the first fragment's header and the
// payload once all of it is there. Overlapping fragments drop the datagram (RFC 5722).
func (p *slowPath) reassemble(k slowKey, hdr []byte, off int, more bool, data []byte) ([]byte, []byte, error) {
	now := p.now()
	for key, g := range p.groups {
		if now.After(g.expires) {
			delete(p.groups, key)
			p.dropped.Add(1)
		}
	}
	g := p.groups[k]
	if g == nil {
		if len(p.groups) >= slowGroups {
			return nil, nil, errors.New("too many datagrams being reassembled")
		}
		g = &slowGroup{parts: map[int][]byte{}, total: -1, expires: now.Add(slowTimeout)}
		p.groups[k] = g
	}
	if off == 0 {
		g.hdr = slices.Clone(hdr)
		if hdr[0]>>4 == 6 {
			g.hdr[6] = k.proto // the header the datagram has without its fragment header
		}
	}
	if !more {
		g.total = off + len(data)
	}
	if (more && len(data)%8 != 0) || off+len(data) > 0xffff || (g.total >= 0 && off+len(data) > g.total) {
		delete(p.groups, k)
		return nil, nil, errors.New("malformed fragment")
	}
	for o, d := range g.parts {
		if off < o+len(d) && o < off+len(data) {
			delete(p.groups, k)
			return nil, nil, errors.New("overlapping fragments")
		}
	}
	g.parts[off] = slices.Clone(data)
	if g.total < 0 || g.hdr == nil {
		return nil, nil, nil
	}
	whole := make([]byte, 0, g.total)
	for _, o := range slices.Sorted(maps.Keys(g.parts)) {
		if o != len(whole) {
			return nil, nil, nil // a hole yet
		}
		whole = append(whole, g.parts[o]...)
	}
	// Whole now: the last piece is among the parts, and nothing lies beyond it
	delete(p.groups, k)
	return g.hdr, whole, nil
}

// whole translates a complete datagram and sends it on.
func (p *slowPath) whole(hdr []byte, proto uint8, payload []byte) error {
	if hdr[0]>>4 == 4 {
		return p.to6(hdr, proto, payload)
	}
	return p.to4(hdr, proto, payload)
}

// to6 translates IPv4: ICMP echo, or UDP whose checksum it computes.
func (p *slowPath) to6(hdr []byte, proto uint8, payload []byte) error {
	src, err := p.v6of4([4]byte(hdr[12:16]))
	if err != nil {
		return err
	}
	dst, err := p.v6of4([4]byte(hdr[16:20]))
	if err != nil {
		return err
	}
	msg := slices.Clone(payload)
	var csum int
	switch {
	case proto == unix.IPPROTO_ICMP && len(msg) >= 8 && (msg[0] == 8 || msg[0] == 0):
		msg[0] = map[byte]byte{8: 128, 0: 129}[msg[0]]
		proto, csum = unix.IPPROTO_ICMPV6, 2
	case proto == unix.IPPROTO_UDP && len(msg) >= 8:
		csum = 6
	default:
		return fmt.Errorf("cannot translate protocol %d whole", proto)
	}
	msg[csum], msg[csum+1] = 0, 0
	c := l4Checksum(src[:], dst[:], proto, msg)
	if c == 0 && proto == unix.IPPROTO_UDP {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(msg[csum:], c)
	h := make([]byte, 40)
	h[0] = 6<<4 | hdr[1]>>4
	h[1] = hdr[1] << 4
	h[6], h[7] = proto, hdr[8]
	copy(h[8:], src[:])
	copy(h[24:], dst[:])
	return p.send6(h, msg)
}

// to4 translates IPv6 ICMP echo.
func (p *slowPath) to4(hdr []byte, proto uint8, payload []byte) error {
	if proto != unix.IPPROTO_ICMPV6 || len(payload) < 8 || (payload[0] != 128 && payload[0] != 129) {
		return fmt.Errorf("cannot translate protocol %d whole", proto)
	}
	dst, err := p.v4of6([16]byte(hdr[24:40]), false)
	if err != nil {
		return err
	}
	src, err := p.v4of6([16]byte(hdr[8:24]), true)
	if err != nil {
		return err
	}
	msg := slices.Clone(payload)
	msg[0] = map[byte]byte{128: 8, 129: 0}[msg[0]]
	msg[2], msg[3] = 0, 0
	binary.BigEndian.PutUint16(msg[2:], l4Checksum(nil, nil, 0, msg))
	h := make([]byte, 20)
	h[0] = 4<<4 | 5
	h[1] = hdr[0]<<4 | hdr[1]>>4
	h[8], h[9] = hdr[7], unix.IPPROTO_ICMP
	copy(h[12:], src[:])
	copy(h[16:], dst[:])
	return p.send4(h, msg)
}

// send4 sends an IPv4 datagram, in fragments when it is larger than the device takes.
func (p *slowPath) send4(h, msg []byte) error {
	p.id++
	binary.BigEndian.PutUint16(h[4:6], uint16(p.id))
	chunk := (p.dev.MTU - 20) &^ 7
	for off := 0; off < len(msg); off += chunk {
		part := msg[off:min(off+chunk, len(msg))]
		fo := off / 8
		if off+len(part) < len(msg) {
			fo |= 0x2000
		}
		binary.BigEndian.PutUint16(h[2:4], uint16(20+len(part)))
		binary.BigEndian.PutUint16(h[6:8], uint16(fo))
		h[10], h[11] = 0, 0
		binary.BigEndian.PutUint16(h[10:], l4Checksum(nil, nil, 0, h))
		if err := p.send(slices.Concat(h, part)); err != nil {
			return err
		}
	}
	return nil
}

// send6 sends an IPv6 datagram, in fragments when it is larger than mtu6.
func (p *slowPath) send6(h, msg []byte) error {
	if 40+len(msg) <= p.mtu6 {
		binary.BigEndian.PutUint16(h[4:6], uint16(len(msg)))
		return p.send(slices.Concat(h, msg))
	}
	p.id++
	proto := h[6]
	h[6] = unix.IPPROTO_FRAGMENT
	chunk := (p.mtu6 - 48) &^ 7
	for off := 0; off < len(msg); off += chunk {
		part := msg[off:min(off+chunk, len(msg))]
		fo := off
		if off+len(part) < len(msg) {
			fo |= 1
		}
		fh := []byte{proto, 0, byte(fo >> 8), byte(fo), 0, 0, 0, 0}
		binary.BigEndian.PutUint32(fh[4:], p.id)
		binary.BigEndian.PutUint16(h[4:6], uint16(8+len(part)))
		if err := p.send(slices.Concat(h, fh, part)); err != nil {
			return err
		}
	}
	return nil
}

// v4Positions is where RFC 6052 puts the four bytes of an IPv4 address after a prefix of bits:
// right after it, but never in byte 8, the u octet, which stays zero.
func v4Positions(bits int) [4]byte {
	var pos [4]byte
	for i, b := 0, bits/8; i < 4; b++ {
		if b != 8 {
			pos[i] = byte(b)
			i++
		}
	}
	return pos
}

// embed4 is the IPv6 address of an IPv4 one behind the NAT64 prefix (RFC 6052 section 2.2).
func embed4(prefix netip.Prefix, v4 [4]byte) [16]byte {
	a := prefix.Masked().Addr().As16()
	for i, pos := range v4Positions(prefix.Bits()) {
		a[pos] = v4[i]
	}
	return a
}

// extract4 is the IPv4 address an address in the NAT64 prefix carries.
func extract4(prefix netip.Prefix, a [16]byte) [4]byte {
	var v4 [4]byte
	for i, pos := range v4Positions(prefix.Bits()) {
		v4[i] = a[pos]
	}
	return v4
}

// l4Checksum is the Internet checksum of msg, after an IPv6 pseudo-header when src is given.
func l4Checksum(src, dst []byte, proto uint8, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	if src != nil {
		add(src)
		add(dst)
		sum += uint32(len(msg)) + uint32(proto)
	}
	add(msg)
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// map4 is map4 of bpf/nat64.c: the pool address of an IPv6 source, a free one the first time.
func map4(v4of, v6of *bpfMap, src [16]byte) ([4]byte, bool) {
	var a [4]byte
	if v4of.lookup(src[:], a[:]) == nil {
		return a, true
	}
	h := hash6(src)
	base := binary.BigEndian.Uint32(bpfPool.Addr().AsSlice())
	mask := uint32(1)<<(32-bpfPool.Bits()) - 1
	for i := range uint32(bpfProbes) {
		binary.BigEndian.PutUint32(a[:], base+((h+i)&mask))
		if v6of.update(a[:], src[:], unix.BPF_NOEXIST) != nil {
			continue
		}
		if v4of.update(src[:], a[:], unix.BPF_NOEXIST) == nil {
			return a, true
		}
		v6of.delete(a[:]) // the program mapped the same source meanwhile
		return a, v4of.lookup(src[:], a[:]) == nil
	}
	return a, false
}

// hash6 is hash6 of bpf/nat64.c, which reads the address as words in the host's byte order.
func hash6(a [16]byte) uint32 {
	w := func(i int) uint32 { return binary.NativeEndian.Uint32(a[4*i:]) }
	h := w(0) * 0x9e3779b1
	h = (h ^ w(1)) * 0x85ebca6b
	h = (h ^ w(2)) * 0xc2b2ae35
	h = (h ^ w(3)) * 0x27d4eb2f
	return h ^ h>>15
}
