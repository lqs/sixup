//go:build linux && integration

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// slowFixture is a slow path sending through a dummy device of its own, with maps of its own,
// and a socket that sees what leaves the device.
type slowFixture struct {
	p          *slowPath
	v4of, v6of *bpfMap
	cap        int
}

func newSlowFixture(t *testing.T, mtu int) *slowFixture {
	t.Helper()
	ifi, err := dummyAdd("slowtest0", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { linkDel(ifi.Index) })
	if err := linkSetUp(ifi.Index); err != nil {
		t.Fatal(err)
	}
	ifi.MTU = mtu
	v4of, v6of := testMaps(t, 64, 64)
	p, err := newSlowPath(nat64Mapping(nat64WKP, v4of, v6of), ifi, 1500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.close)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		t.Fatal(err)
	}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000})
	return &slowFixture{p: p, v4of: v4of, v6of: v6of, cap: fd}
}

// sent returns the IP packets that left the device since the last call.
func (f *slowFixture) sent() [][]byte {
	var pkts [][]byte
	for {
		buf := make([]byte, 2000)
		n, _, err := unix.Recvfrom(f.cap, buf, 0)
		if err != nil {
			return pkts
		}
		if buf[0]>>4 == 4 || buf[0]>>4 == 6 {
			pkts = append(pkts, buf[:n])
		}
	}
}

// v4Packet builds an IPv4 packet whose header checksum is right.
func v4Packet(src, dst string, proto uint8, fo uint16, payload []byte) []byte {
	h := make([]byte, 20)
	h[0], h[1], h[8], h[9] = 0x45, 0xb8, 64, proto
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[4:], 0x4242)
	binary.BigEndian.PutUint16(h[6:], fo)
	copy(h[12:], netip.MustParseAddr(src).AsSlice())
	copy(h[16:], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(h[10:], l4Checksum(nil, nil, 0, h))
	return append(h, payload...)
}

func v6Packet(src, dst string, next uint8, payload []byte) []byte {
	h := make([]byte, 40)
	h[0], h[1], h[6], h[7] = 0x6b, 0x80, next, 64
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	copy(h[8:], netip.MustParseAddr(src).AsSlice())
	copy(h[24:], netip.MustParseAddr(dst).AsSlice())
	return append(h, payload...)
}

// reassembled puts IPv4 or IPv6 fragments back together, checking each against mtu.
func reassembled(t *testing.T, pkts [][]byte, mtu int) (hdr, payload []byte) {
	t.Helper()
	whole := map[int][]byte{}
	for _, p := range pkts {
		if len(p) > mtu {
			t.Fatalf("a %d-byte packet is over the MTU of %d", len(p), mtu)
		}
		if p[0]>>4 == 4 {
			hdr = p[:20]
			whole[int(binary.BigEndian.Uint16(p[6:])&0x1fff)*8] = p[20:]
			continue
		}
		hdr = p[:40]
		off := 0
		data := p[40:]
		if p[6] == unix.IPPROTO_FRAGMENT {
			off, data = int(binary.BigEndian.Uint16(p[42:])&^7), p[48:]
		}
		whole[off] = data
	}
	for _, o := range slices.Sorted(func(yield func(int) bool) {
		for o := range whole {
			if !yield(o) {
				return
			}
		}
	}) {
		if o != len(payload) {
			t.Fatalf("a hole at %d", len(payload))
		}
		payload = append(payload, whole[o]...)
	}
	return hdr, payload
}

// The slow path's translations, whole and in fragments, with checksums a receiver accepts.
func TestSlowPathTranslates(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	f := newSlowFixture(t, 600)
	p := f.p
	host := netip.MustParseAddr("2001:db8::5").As16()
	pool := [4]byte{198, 18, 0, 5}
	if err := f.v6of.update(pool[:], host[:], 0); err != nil {
		t.Fatal(err)
	}

	// IPv4 UDP without a checksum gets one
	udp := []byte{0, 53, 0, 99, 0, 12, 0, 0, 'h', 'e', 'y', '!'}
	if err := p.packet(v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_UDP, 0, udp)); err != nil {
		t.Fatal(err)
	}
	pkts := f.sent()
	if len(pkts) != 1 {
		t.Fatalf("want one packet, got %d", len(pkts))
	}
	got := pkts[0]
	if src := netip.AddrFrom16([16]byte(got[8:24])); src != netip.MustParseAddr("64:ff9b::c000:202") || [16]byte(got[24:40]) != host || got[6] != unix.IPPROTO_UDP {
		t.Fatalf("want UDP from 64:ff9b::c000:202 to 2001:db8::5, got % x", got[:40])
	}
	if got[0] != 0x6b || got[1] != 0x80 || got[7] != 64 {
		t.Fatalf("the traffic class and hop limit should carry over, got % x", got[:8])
	}
	if l4Checksum(got[8:24], got[24:40], unix.IPPROTO_UDP, got[40:]) != 0 {
		t.Fatal("the UDP checksum should be right")
	}
	// A checksum that computes to zero is sent as all ones
	zero := slices.Clone(udp)
	binary.BigEndian.PutUint16(zero[8:], 0)
	binary.BigEndian.PutUint16(zero[10:], 0)
	pfx := netip.MustParseAddr("64:ff9b::c000:202").As16()
	binary.BigEndian.PutUint16(zero[8:], l4Checksum(pfx[:], host[:], unix.IPPROTO_UDP, zero))
	p.packet(v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_UDP, 0, zero))
	if pkts := f.sent(); len(pkts) != 1 || binary.BigEndian.Uint16(pkts[0][46:]) != 0xffff {
		t.Fatalf("want a checksum of 0xffff, got %v", pkts)
	}

	// A fragmented echo comes out in fragments for an MTU of 1280
	p.mtu6 = 1280
	echo := append([]byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}, bytes.Repeat([]byte{7}, 2992)...)
	binary.BigEndian.PutUint16(echo[2:], l4Checksum(nil, nil, 0, echo))
	for _, part := range []struct {
		fo   uint16
		data []byte
	}{{0x2000 | 1480/8, echo[1480:2960]}, {2960 / 8, echo[2960:]}, {0x2000, echo[:1480]}} {
		if err := p.packet(v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_ICMP, part.fo, part.data)); err != nil {
			t.Fatal(err)
		}
	}
	hdr, msg := reassembled(t, f.sent(), 1280)
	if msg[0] != 128 || len(msg) != len(echo) || l4Checksum(hdr[8:24], hdr[24:40], unix.IPPROTO_ICMPV6, msg) != 0 {
		t.Fatalf("want a 3000-byte echo request with a right checksum, got type %d, %d bytes", msg[0], len(msg))
	}

	// An IPv6 echo from a new source gets the pool address the program would give it, and goes
	// out in fragments the device takes
	reply := append([]byte{129, 0, 0, 0, 0x12, 0x34, 0, 1}, bytes.Repeat([]byte{9}, 1992)...)
	src := netip.MustParseAddr("2001:db8::77")
	binary.BigEndian.PutUint16(reply[2:], l4Checksum(src.AsSlice(), pfx[:], unix.IPPROTO_ICMPV6, reply))
	frag := func(off int, more bool, data []byte) []byte {
		fh := []byte{unix.IPPROTO_ICMPV6, 0, 0, 0, 0, 0, 0, 9}
		fo := uint16(off)
		if more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(fh[2:], fo)
		return v6Packet(src.String(), "64:ff9b::c000:202", unix.IPPROTO_FRAGMENT, append(fh, data...))
	}
	p.packet(frag(0, true, reply[:1024]))
	if err := p.packet(frag(1024, false, reply[1024:])); err != nil {
		t.Fatal(err)
	}
	hdr, msg = reassembled(t, f.sent(), 600)
	var a4 [4]byte
	if err := f.v4of.lookup(src.AsSlice(), a4[:]); err != nil {
		t.Fatal(err)
	}
	base, mask := binary.BigEndian.Uint32(bpfPool.Addr().AsSlice()), uint32(1)<<(32-bpfPool.Bits())-1
	if want := base + hash6(src.As16())&mask; binary.BigEndian.Uint32(a4[:]) != want || [4]byte(hdr[12:16]) != a4 {
		t.Fatalf("want the source numbered %#x, got %v and a packet from %v", want, a4, hdr[12:16])
	}
	if msg[0] != 0 || len(msg) != len(reply) || l4Checksum(nil, nil, 0, msg) != 0 || hdr[1] != 0xb8 || hdr[8] != 64 {
		t.Fatalf("want a 2000-byte echo reply with a right checksum, TOS and TTL, got % x", hdr)
	}

	// A source the pool already numbers is found again without a new address
	if got, err := p.v4of6(src.As16(), false); err != nil || got != a4 {
		t.Fatalf("want %v again, got %v: %v", a4, got, err)
	}

	// What cannot be translated
	for name, pkt := range map[string][]byte{
		"IPv4 from a pool address no source has": v4Packet("198.18.0.99", "198.18.0.5", unix.IPPROTO_UDP, 0, udp),
		"IPv4 to an address no source has":       v4Packet("192.0.2.2", "198.18.0.6", unix.IPPROTO_UDP, 0, udp),
		"IPv4 TCP":                               v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_TCP, 0, udp),
		"an IPv4 error":                          v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_ICMP, 0, []byte{3, 3, 0, 0, 0, 0, 0, 0}),
		"IPv6 outside the prefix":                v6Packet("2001:db8::77", "2001:db8::1", unix.IPPROTO_ICMPV6, reply[:8]),
		"IPv6 UDP":                               v6Packet("2001:db8::77", "64:ff9b::1", unix.IPPROTO_UDP, udp),
		"an IPv6 error":                          v6Packet("2001:db8::77", "64:ff9b::1", unix.IPPROTO_ICMPV6, []byte{1, 4, 0, 0, 0, 0, 0, 0}),
	} {
		if err := p.packet(pkt); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A source whose every slot is taken
	busy := netip.MustParseAddr("2001:db8::99").As16()
	for i := range uint32(bpfProbes) {
		var slot [4]byte
		binary.BigEndian.PutUint32(slot[:], base+((hash6(busy)+i)&mask))
		f.v6of.update(slot[:], host[:], 0)
	}
	if err := p.packet(v6Packet("2001:db8::99", "64:ff9b::1", unix.IPPROTO_ICMPV6, reply[:8])); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("want the pool full, got %v", err)
	}

	// Without the socket nothing goes out, whole or in fragments
	unix.Close(p.fd)
	p.fd = -1
	p.mtu6 = 1500
	for name, pkt := range map[string][]byte{
		"whole IPv6":     v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_UDP, 0, udp),
		"fragments IPv6": v4Packet("192.0.2.2", "198.18.0.5", unix.IPPROTO_ICMP, 0, echo),
		"IPv4":           v6Packet(src.String(), "64:ff9b::1", unix.IPPROTO_ICMPV6, reply[:8]),
	} {
		if strings.HasPrefix(name, "fragments") {
			p.mtu6 = 1280
		}
		if err := p.packet(pkt); err == nil {
			t.Errorf("%s: want the send refused", name)
		}
	}
}

// map4 gives up when the map of sources has no room, after taking back the slot it claimed.
func TestMap4WithoutRoom(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	v4of, v6of := testMaps(t, 1, 4)
	v4of.update(netip.MustParseAddr("2001:db8::1").AsSlice(), []byte{198, 18, 0, 1}, 0)
	if _, ok := map4(v4of, v6of, netip.MustParseAddr("2001:db8::2").As16()); ok {
		t.Fatal("a full map should refuse a new source")
	}
	if keys := v6of.keys(); len(keys) != 0 {
		t.Fatalf("the claimed slot %v should be given back", keys)
	}
}

// The program numbers a new source the way map4 does, and passes what the slow path sends back
// to the device's ingress untouched.
func TestBPFProgram(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	b := &bpfNAT64{prefix: nat64WKP}
	ifi, err := dummyAdd("progtest0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer linkDel(ifi.Index)
	b.ifindex = ifi.Index
	if err := b.load(); err != nil {
		t.Fatal(err)
	}
	defer b.stop()
	frame := func(pkt []byte, proto uint16) []byte {
		return append(binary.BigEndian.AppendUint16(make([]byte, 12), proto), pkt...)
	}
	src := netip.MustParseAddr("2001:db8::abcd")
	udp := []byte{0, 1, 0, 2, 0, 8, 0x12, 0x34}
	if ret, _, _ := b.objs.testRun(t, frame(v6Packet(src.String(), "64:ff9b::c000:202", unix.IPPROTO_UDP, udp), unix.ETH_P_IPV6), nil); ret != 7 { // TC_ACT_REDIRECT
		t.Fatalf("want the packet redirected, got %d", ret)
	}
	var a [4]byte
	if err := b.objs.maps[nat64MapV4Of].lookup(src.AsSlice(), a[:]); err != nil {
		t.Fatal(err)
	}
	base, mask := binary.BigEndian.Uint32(bpfPool.Addr().AsSlice()), uint32(1)<<(32-bpfPool.Bits())-1
	if want := base + hash6(src.As16())&mask; binary.BigEndian.Uint32(a[:]) != want {
		t.Fatalf("the program numbered %v, map4 would give %#x", a, want)
	}
	// Attaching to a device that is not there fails, naming what tcx needs
	gone := &bpfNAT64{prefix: nat64WKP, ifindex: 1 << 30}
	if err := gone.load(); err == nil || !strings.Contains(err.Error(), "6.6") {
		t.Fatalf("want the attachment refused, got %v", err)
	}
	gone.ifindex = 0
	gone.stop()

	// struct __sk_buff from its start to mark, the third word
	ctx := nativeEndian.AppendUint32(make([]byte, 8), bpfSlowMark)
	ret, _, out := b.objs.testRun(t, frame(make([]byte, 40), unix.ETH_P_IPV6), ctx)
	if mark := nativeEndian.Uint32(out[8:]); ret != 7 || mark != 0 {
		t.Fatalf("want a marked packet redirected with its mark cleared, got %d, mark %#x", ret, mark)
	}
}

// Whatever fails part way, start leaves no device behind; given enough descriptors it succeeds.
func TestBPFNAT64StartUndoes(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	b := &bpfNAT64{prefix: nat64WKP}
	// Once with room, which also gets the runtime's poller its descriptor beforehand
	if err := b.start(); err != nil {
		t.Fatal(err)
	}
	b.stop()
	for extra := 0; ; extra++ {
		if extra > 500 {
			t.Fatal("start never succeeded")
		}
		err := joolWithFDs(t, extra, b.start)
		if err == nil {
			break
		}
		if _, err := net.InterfaceByName(joolOutside); err == nil {
			t.Fatalf("with room for %d descriptors start failed and left %s", extra, joolOutside)
		}
	}
	b.stop()
	// A device of the same name, as a crash would leave, is replaced
	if _, err := dummyAdd("reptest0", 0); err != nil {
		t.Fatal(err)
	}
	ifi, err := dummyAdd("reptest0", 0)
	if err != nil {
		t.Fatalf("the old device should be replaced: %v", err)
	}
	linkDel(ifi.Index)
	if _, err := net.InterfaceByName(joolOutside); err == nil {
		t.Fatalf("%s should be gone", joolOutside)
	}
}

// Without the right to change links, the old device cannot be removed; without the right to ask
// conntrack, the sweep leaves every mapping alone; without descriptors, likewise.
func TestBPFNAT64WithoutPrivileges(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	b := &bpfNAT64{prefix: nat64WKP}
	if err := b.start(); err != nil {
		t.Fatal(err)
	}
	defer b.stop()
	b.objs.maps[nat64MapV6Of].update([]byte{198, 18, 0, 1}, netip.MustParseAddr("2001:db8::1").AsSlice(), 0)
	if err := syscall.Setresuid(-1, 65534, -1); err != nil {
		t.Fatal(err)
	}
	_, addErr := dummyAdd(joolOutside, 0)
	b.sweep()
	b.sweep()
	if err := syscall.Setresuid(-1, 0, -1); err != nil {
		t.Fatal(err)
	}
	if addErr == nil || !strings.Contains(addErr.Error(), "removing the old") {
		t.Fatalf("want the old device's removal refused, got %v", addErr)
	}
	joolWithFDs(t, 0, func() error { b.sweep(); b.sweep(); return nil })
	if len(b.objs.maps[nat64MapV6Of].keys()) == 0 {
		t.Fatal("a sweep that cannot ask conntrack should remove nothing")
	}
	// The slow path's drops are reported with the program's
	b.slow.dropped.Add(2)
	if d := b.drops(); d != "slow-path 2" {
		t.Fatalf("want the slow path's drops, got %q", d)
	}
}

// Without CAP_NET_RAW start gets as far as the slow path's packet socket, and takes down what it
// set up.
func TestBPFNAT64WithoutRawSockets(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	b := &bpfNAT64{prefix: nat64WKP}
	ch := make(chan error)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread leaves with its capabilities
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		unix.Capget(&hdr, &data[0])
		data[0].Effective &^= 1 << unix.CAP_NET_RAW
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			ch <- err
			return
		}
		ch <- b.start()
	}()
	if err := <-ch; err == nil || !strings.Contains(err.Error(), "packet socket") {
		t.Fatalf("want the packet socket refused, got %v", err)
	}
	if _, err := net.InterfaceByName(joolOutside); err == nil {
		t.Fatalf("%s should be gone", joolOutside)
	}
}

// Without descriptors there is no packet socket.
func TestSlowPathWithoutDescriptors(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := joolWithFDs(t, 0, func() error { _, err := newSlowPath(slowMapping{}, lo, 1500); return err }); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("want the socket refused, got %v", err)
	}
}

// The program's ICMP translation against RFC 7915 sections 4.2 and 5.2, one message at a time:
// type, code and the rest of the header, both checksums, and the quote turned around.
func TestBPFICMPTranslation(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	b := &bpfNAT64{prefix: nat64WKP}
	ifi, err := dummyAdd("icmptest0", 0)
	if err != nil {
		t.Fatal(err)
	}
	b.ifindex = ifi.Index
	if err := b.load(); err != nil {
		t.Fatal(err)
	}
	defer b.stop()
	host := netip.MustParseAddr("2001:db8::5")
	b.objs.maps[nat64MapV6Of].update([]byte{198, 18, 0, 5}, host.AsSlice(), 0)
	b.objs.maps[nat64MapV4Of].update(host.AsSlice(), []byte{198, 18, 0, 5}, 0)
	run := func(pkt []byte, proto uint16) ([]byte, bool) {
		t.Helper()
		ret, out, _ := b.objs.testRun(t, append(binary.BigEndian.AppendUint16(make([]byte, 12), proto), pkt...), nil)
		return out[14:], ret == 7
	}
	udp := []byte{0, 7, 0x30, 0x39, 0, 8, 0xab, 0xcd}

	// From IPv4: an error from 192.0.2.9 about what 198.18.0.5 sent 192.0.2.2
	quote4 := v4Packet("198.18.0.5", "192.0.2.2", unix.IPPROTO_UDP, 0x4000, udp)
	for _, c := range []struct {
		typ, code byte
		rest      uint32
		want      []uint32 // type, code, rest; none to be dropped
	}{
		{3, 0, 0, []uint32{1, 0, 0}},
		{3, 1, 0, []uint32{1, 0, 0}},
		{3, 2, 0, []uint32{4, 1, 6}},
		{3, 3, 0, []uint32{1, 4, 0}},
		{3, 4, 1400, []uint32{2, 0, 1420}},
		{3, 4, 1000, []uint32{2, 0, 1280}},
		{3, 4, 0, []uint32{2, 0, 1280}},
		{3, 5, 0, []uint32{1, 0, 0}},
		{3, 6, 0, []uint32{1, 0, 0}},
		{3, 7, 0, []uint32{1, 0, 0}},
		{3, 8, 0, []uint32{1, 0, 0}},
		{3, 9, 0, []uint32{1, 1, 0}},
		{3, 10, 0, []uint32{1, 1, 0}},
		{3, 11, 0, []uint32{1, 0, 0}},
		{3, 12, 0, []uint32{1, 0, 0}},
		{3, 13, 0, []uint32{1, 1, 0}},
		{3, 14, 0, nil},
		{3, 15, 0, []uint32{1, 1, 0}},
		{3, 16, 0, nil},
		{11, 0, 0, []uint32{3, 0, 0}},
		{11, 1, 0, []uint32{3, 1, 0}},
		{12, 0, 0 << 24, []uint32{4, 0, 0}},
		{12, 0, 1 << 24, []uint32{4, 0, 1}},
		{12, 0, 2 << 24, []uint32{4, 0, 4}},
		{12, 0, 3 << 24, []uint32{4, 0, 4}},
		{12, 0, 4 << 24, nil},
		{12, 0, 8 << 24, []uint32{4, 0, 7}},
		{12, 0, 9 << 24, []uint32{4, 0, 6}},
		{12, 0, 10 << 24, nil},
		{12, 2, 13 << 24, []uint32{4, 0, 8}},
		{12, 0, 17 << 24, []uint32{4, 0, 24}},
		{12, 0, 20 << 24, nil},
		{12, 1, 0, nil},
		{5, 0, 0, nil},  // Redirect
		{13, 0, 0, nil}, // Timestamp
	} {
		msg := binary.BigEndian.AppendUint32([]byte{c.typ, c.code, 0, 0}, c.rest)
		msg = append(msg, quote4...)
		binary.BigEndian.PutUint16(msg[2:], l4Checksum(nil, nil, 0, msg))
		got, ok := run(v4Packet("192.0.2.9", "198.18.0.5", unix.IPPROTO_ICMP, 0, msg), unix.ETH_P_IP)
		if ok != (c.want != nil) {
			t.Errorf("ICMP %d/%d: translated %v, want %v", c.typ, c.code, ok, c.want != nil)
			continue
		}
		if !ok {
			continue
		}
		icmp := got[40:]
		if g := []uint32{uint32(icmp[0]), uint32(icmp[1]), binary.BigEndian.Uint32(icmp[4:])}; !slices.Equal(g, c.want) {
			t.Errorf("ICMP %d/%d: got %v, want %v", c.typ, c.code, g, c.want)
		}
		if l4Checksum(got[8:24], got[24:40], unix.IPPROTO_ICMPV6, icmp) != 0 {
			t.Errorf("ICMP %d/%d: the ICMPv6 checksum is wrong", c.typ, c.code)
		}
		if q := icmp[8:]; [16]byte(q[8:24]) != host.As16() || netip.AddrFrom16([16]byte(q[24:40])) != netip.MustParseAddr("64:ff9b::c000:202") || q[6] != unix.IPPROTO_UDP || binary.BigEndian.Uint16(q[4:]) != 8 || !bytes.Equal(q[40:48], udp) {
			t.Errorf("ICMP %d/%d: the quote should be the UDP from 2001:db8::5 to 64:ff9b::c000:202, got % x", c.typ, c.code, q)
		}
	}

	// From IPv6: an error from 2001:db8::5 about what 64:ff9b::c000:209 sent it
	quote6 := v6Packet("64:ff9b::c000:209", host.String(), unix.IPPROTO_UDP, udp)
	src, dst := host.As16(), netip.MustParseAddr("64:ff9b::c000:209").As16()
	for _, c := range []struct {
		typ, code byte
		rest      uint32
		want      []uint32
	}{
		{1, 0, 0, []uint32{3, 1, 0}},
		{1, 1, 0, []uint32{3, 10, 0}},
		{1, 2, 0, []uint32{3, 1, 0}},
		{1, 3, 0, []uint32{3, 1, 0}},
		{1, 4, 0, []uint32{3, 3, 0}},
		{1, 5, 0, nil},
		{2, 0, 1500, []uint32{3, 4, 1480}},
		{2, 0, 70, []uint32{3, 4, 68}},
		{2, 0, 100000, []uint32{3, 4, 0xffff}},
		{3, 0, 0, []uint32{11, 0, 0}},
		{3, 1, 0, []uint32{11, 1, 0}},
		{4, 0, 0, []uint32{12, 0, 0}},
		{4, 0, 1, []uint32{12, 0, 1 << 24}},
		{4, 0, 2, nil},
		{4, 0, 4, []uint32{12, 0, 2 << 24}},
		{4, 0, 6, []uint32{12, 0, 9 << 24}},
		{4, 0, 7, []uint32{12, 0, 8 << 24}},
		{4, 0, 9, []uint32{12, 0, 12 << 24}},
		{4, 0, 30, []uint32{12, 0, 16 << 24}},
		{4, 0, 40, nil},
		{4, 1, 0, []uint32{3, 2, 0}},
		{4, 2, 0, nil},
		{133, 0, 0, nil}, // Router Solicitation
	} {
		msg := binary.BigEndian.AppendUint32([]byte{c.typ, c.code, 0, 0}, c.rest)
		msg = append(msg, quote6...)
		binary.BigEndian.PutUint16(msg[2:], l4Checksum(src[:], dst[:], unix.IPPROTO_ICMPV6, msg))
		got, ok := run(v6Packet(host.String(), "64:ff9b::c000:209", unix.IPPROTO_ICMPV6, msg), unix.ETH_P_IPV6)
		if ok != (c.want != nil) {
			t.Errorf("ICMPv6 %d/%d: translated %v, want %v", c.typ, c.code, ok, c.want != nil)
			continue
		}
		if !ok {
			continue
		}
		icmp := got[20:binary.BigEndian.Uint16(got[2:])]
		if g := []uint32{uint32(icmp[0]), uint32(icmp[1]), binary.BigEndian.Uint32(icmp[4:])}; !slices.Equal(g, c.want) {
			t.Errorf("ICMPv6 %d/%d: got %v, want %v", c.typ, c.code, g, c.want)
		}
		if l4Checksum(nil, nil, 0, icmp) != 0 || l4Checksum(nil, nil, 0, got[:20]) != 0 {
			t.Errorf("ICMPv6 %d/%d: a checksum is wrong", c.typ, c.code)
		}
		if q := icmp[8:]; l4Checksum(nil, nil, 0, q[:20]) != 0 || [4]byte(q[12:16]) != [4]byte{192, 0, 2, 9} || [4]byte(q[16:20]) != [4]byte{198, 18, 0, 5} || !bytes.Equal(q[20:28], udp) {
			t.Errorf("ICMPv6 %d/%d: the quote should be the UDP from 192.0.2.9 to 198.18.0.5, got % x", c.typ, c.code, q)
		}
	}
}

// The program embeds and extracts IPv4 addresses the way RFC 6052 does behind a prefix of every
// length, and leaves alone what is outside the prefix.
func TestBPFRFC6052(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	host := netip.MustParseAddr("2001:db8::5")
	udp := []byte{0, 7, 0x30, 0x39, 0, 8, 0xab, 0xcd}
	for prefix, want := range rfc6052Examples {
		b := &bpfNAT64{prefix: netip.MustParsePrefix(prefix)}
		ifi, err := dummyAdd("rfctest0", 0)
		if err != nil {
			t.Fatal(err)
		}
		b.ifindex = ifi.Index
		if err := b.load(); err != nil {
			t.Fatal(err)
		}
		b.objs.maps[nat64MapV6Of].update([]byte{198, 18, 0, 5}, host.AsSlice(), 0)
		run := func(pkt []byte, proto uint16) ([]byte, bool) {
			ret, out, _ := b.objs.testRun(t, append(binary.BigEndian.AppendUint16(make([]byte, 12), proto), pkt...), nil)
			return out[14:], ret == 7
		}
		got, ok := run(v4Packet("192.0.2.33", "198.18.0.5", unix.IPPROTO_UDP, 0, udp), unix.ETH_P_IP)
		if src := netip.AddrFrom16([16]byte(got[8:24])); !ok || src != netip.MustParseAddr(want) {
			t.Errorf("%s: 192.0.2.33 became %s, want %s", prefix, src, want)
		}
		got, ok = run(v6Packet(host.String(), want, unix.IPPROTO_UDP, udp), unix.ETH_P_IPV6)
		if dst := netip.AddrFrom4([4]byte(got[16:20])); !ok || dst != netip.MustParseAddr("192.0.2.33") {
			t.Errorf("%s: %s became %s, want 192.0.2.33", prefix, want, dst)
		}
		if _, ok := run(v6Packet(host.String(), "2001:db9::1", unix.IPPROTO_UDP, udp), unix.ETH_P_IPV6); ok {
			t.Errorf("%s: an address outside the prefix should not be translated", prefix)
		}
		b.stop()
	}
}

// testMaps creates the two maps of the address mapping, with room for so many sources and pool
// addresses.
func testMaps(t *testing.T, sources, pool uint32) (v4of, v6of *bpfMap) {
	t.Helper()
	v4of, err := bpfMapCreate(bpfMapSpec{name: "v4_of", typ: unix.BPF_MAP_TYPE_HASH, keySize: 16, valueSize: 4, maxEntries: sources})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v4of.close)
	v6of, err = bpfMapCreate(bpfMapSpec{name: "v6_of", typ: unix.BPF_MAP_TYPE_HASH, keySize: 4, valueSize: 16, maxEntries: pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v6of.close)
	return v4of, v6of
}

// testRun runs the program once on a frame (BPF_PROG_TEST_RUN), with ctx as the start of its
// struct __sk_buff, and returns the verdict, the frame and the whole context after.
func (o *bpfObjects) testRun(t *testing.T, frame, ctx []byte) (uint32, []byte, []byte) {
	t.Helper()
	out, ctxOut := make([]byte, 2000), make([]byte, 192)
	attr := struct {
		prog, retval, dataSizeIn, dataSizeOut uint32
		dataIn, dataOut                       uint64
		repeat, duration                      uint32
		ctxSizeIn, ctxSizeOut                 uint32
		ctxIn, ctxOut                         uint64
	}{prog: uint32(o.prog), dataSizeIn: uint32(len(frame)), dataSizeOut: uint32(len(out)), dataIn: ptr(frame), dataOut: ptr(out)}
	if ctx != nil {
		attr.ctxSizeIn, attr.ctxSizeOut, attr.ctxIn, attr.ctxOut = uint32(len(ctx)), uint32(len(ctxOut)), ptr(ctx), ptr(ctxOut)
	}
	if _, err := bpfSys(unix.BPF_PROG_TEST_RUN, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(frame)
	runtime.KeepAlive(ctx)
	return attr.retval, out[:attr.dataSizeOut], ctxOut
}
