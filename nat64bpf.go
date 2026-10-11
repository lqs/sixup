//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run ./tools/bpfgen bpf/nat64.c nat64

// The counters of bpf/nat64.c, in its order; the unnamed ones count no drops
var bpfStatNames = []string{"", "", "protocol", "", "icmp", "pool-full", "unmapped", "error"}

// bpfNAT64 translates the NAT64 prefix with the program in bpf/nat64.c, attached to the egress of
// a dummy device that the prefix and the pool are routed to. Translated packets come back in on
// the same device as the other family, so conntrack and the source NAT see an ordinary IPv4 host.
// What the program cannot translate a fragment at a time goes through slowPath. The program and
// the device go when sixup does: the tcx link belongs to its descriptor.
type bpfNAT64 struct {
	prefix netip.Prefix
	lans   []string // whose smallest MTU bounds what the pool route lets through whole
	store  *Store
	idle   map[[4]byte]int // pool addresses conntrack had no flow for, by how many sweeps in a row

	// While translating
	ifindex int
	objs    *bpfObjects
	link    *os.File // the tcx link, which detaches the program when closed
	slow    *slowPath
	reader  *ringReader
	served  chan struct{} // closed when the slow path stops reading
}

// bpfTick is how often the mappings are swept and the drops reported.
var bpfTick = time.Minute

// bpfIdleSweeps is how many sweeps in a row a pool address has to go without a flow before its
// mapping is removed, so that a flow conntrack has not confirmed yet is not cut.
const bpfIdleSweeps = 2

func (b *bpfNAT64) run(ctx context.Context) {
	if err := b.start(); err != nil {
		warnf("[nat64] %v", err)
		return
	}
	defer func() {
		b.stop()
		b.store.SetNAT64(netip.Prefix{})
	}()
	b.store.SetNAT64(b.prefix)
	infof("[nat64] translating %s through %s with BPF, IPv6 sources numbered from %s", b.prefix, joolOutside, bpfPool)
	tick := time.NewTicker(bpfTick)
	defer tick.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		b.sweep()
		if s := b.drops(); s != last {
			last = s
			infof("[nat64] dropped so far: %s", s)
		}
	}
}

// start sets the translator up, and on failure undoes what it did.
func (b *bpfNAT64) start() (err error) {
	ifi, err := dummyAdd(joolOutside, 0)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", joolOutside, err)
	}
	b.ifindex = ifi.Index
	defer func() {
		if err != nil {
			b.stop()
		}
	}()
	if err := b.load(); err != nil {
		return err
	}
	if err := b.route(ifi); err != nil {
		return err
	}
	if b.slow, err = newSlowPath(nat64Mapping(b.prefix, b.objs.maps[nat64MapV4Of], b.objs.maps[nat64MapV6Of]), ifi, b.lanMTU()); err != nil {
		return err
	}
	if b.reader, err = newRingReader(b.objs.maps[nat64MapSlow]); err != nil {
		return fmt.Errorf("reading the slow path: %w", err)
	}
	b.served = make(chan struct{})
	go func() {
		b.slow.serve(b.reader)
		close(b.served)
	}()
	return nil
}

// stop takes down whatever start set up.
func (b *bpfNAT64) stop() {
	if b.reader != nil {
		b.reader.close()
		<-b.served
		b.reader.free()
		b.reader = nil
	}
	if b.slow != nil {
		b.slow.close()
		b.slow = nil
	}
	if b.link != nil {
		b.link.Close()
		b.link = nil
	}
	if b.objs != nil {
		b.objs.close()
		b.objs = nil
	}
	if b.ifindex != 0 {
		linkDel(b.ifindex)
		b.ifindex = 0
	}
}

func (b *bpfNAT64) load() error {
	ro := slices.Clone(nat64Rodata)
	set := func(v bpfVar, b []byte) { copy(ro[v.off:v.off+v.size], b) }
	var mask [16]byte
	for i := range b.prefix.Bits() {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	pref, pos := b.prefix.Masked().Addr().As16(), v4Positions(b.prefix.Bits())
	set(nat64VarPoolBase, nativeEndian.AppendUint32(nil, binary.BigEndian.Uint32(bpfPool.Addr().AsSlice())))
	set(nat64VarPoolMask, nativeEndian.AppendUint32(nil, uint32(1)<<(32-bpfPool.Bits())-1))
	set(nat64VarPref6, pref[:])
	set(nat64VarMask6, mask[:])
	set(nat64VarV4pos, pos[:])
	set(nat64VarSlowMark, nativeEndian.AppendUint32(nil, bpfSlowMark))
	objs, err := bpfLoad(bpfProgram{code: nat64Code, maps: nat64Maps, relocs: nat64Relocs, rodata: ro, license: nat64License})
	if err != nil {
		return fmt.Errorf("loading the BPF translator: %w", err)
	}
	b.objs = objs
	if b.link, err = objs.attachTCX(b.ifindex, unix.BPF_TCX_EGRESS); err != nil {
		return fmt.Errorf("the BPF translator: %w", err)
	}
	return nil
}

// route brings the device up and routes the NAT64 prefix and the pool to it. The device takes no
// address: it never answers for one, and NOARP spares the neighbour lookups.
//
// The pool's route carries an MTU 28 bytes below the smallest LAN's, the IPv6 header's 20 more
// and a fragment header's 8. IPv4 that conntrack reassembled is cut again to it on the way to the
// program, so each piece, translated, still crosses the LAN; a whole packet with DF that would
// not fit earns its sender a Fragmentation Needed from the router.
func (b *bpfNAT64) route(ifi *net.Interface) error {
	err := errors.Join(linkSetUp(ifi.Index), routeSet(ifi.Index, b.prefix, netip.Addr{}, 0, 0), route4MTU(ifi.Index, bpfPool, b.lanMTU()-28))
	if err != nil {
		return fmt.Errorf("bringing %s up and routing %s and %s to it: %w", ifi.Name, b.prefix, bpfPool, err)
	}
	return nil
}

// lanMTU is the smallest MTU of the LANs, 1500 when none can be read.
func (b *bpfNAT64) lanMTU() int {
	mtu := 0
	for _, name := range b.lans {
		if ifi, err := net.InterfaceByName(name); err == nil && (mtu == 0 || ifi.MTU < mtu) {
			mtu = ifi.MTU
		}
	}
	if mtu < 1280 {
		return 1500
	}
	return mtu
}

// sweep removes the mappings of pool addresses conntrack has had no flow for over bpfIdleSweeps
// sweeps, so that the pool and the maps do not fill with sources long gone. Without conntrack to
// ask, nothing is removed.
func (b *bpfNAT64) sweep() {
	active, err := conntrackSources4(bpfPool)
	if err != nil {
		return
	}
	if b.idle == nil {
		b.idle = map[[4]byte]int{}
	}
	v4of, v6of := b.objs.maps[nat64MapV4Of], b.objs.maps[nat64MapV6Of]
	for _, key := range v6of.keys() {
		a4 := [4]byte(key)
		if active[netip.AddrFrom4(a4)] {
			delete(b.idle, a4)
			continue
		}
		if b.idle[a4]++; b.idle[a4] >= bpfIdleSweeps {
			a6 := make([]byte, 16)
			if v6of.lookup(key, a6) == nil {
				v4of.delete(a6)
			}
			v6of.delete(key)
			delete(b.idle, a4)
		}
	}
}

// conntrackSources4 dumps conntrack's IPv4 flows and returns the original sources within pool.
func conntrackSources4(pool netip.Prefix) (map[netip.Addr]bool, error) {
	c, err := nfDial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<nfnlSubsysShift | ipctnlMsgCtGet), Flags: netlink.Request | netlink.Dump},
		Data:   nfgenmsg(unix.AF_INET, 0),
	})
	if err != nil {
		return nil, err
	}
	return poolSources(msgs, pool), nil
}

// poolSources reads the original sources within pool from a dump of conntrack's IPv4 flows.
func poolSources(msgs []netlink.Message, pool netip.Prefix) map[netip.Addr]bool {
	const ctaIPv4Src = 1 // CTA_IP_V4_SRC
	found := map[netip.Addr]bool{}
	for _, m := range msgs {
		ad, err := netlink.NewAttributeDecoder(m.Data[min(nfgenmsgLen, len(m.Data)):])
		if err != nil {
			continue
		}
		for ad.Next() {
			if ad.Type() != ctaTupleOrig {
				continue
			}
			ad.Nested(func(ad *netlink.AttributeDecoder) error {
				for ad.Next() {
					if ad.Type() != ctaTupleIP {
						continue
					}
					ad.Nested(func(ad *netlink.AttributeDecoder) error {
						for ad.Next() {
							if a, ok := netip.AddrFromSlice(ad.Bytes()); ad.Type() == ctaIPv4Src && ok && pool.Contains(a) {
								found[a] = true
							}
						}
						return nil
					})
				}
				return nil
			})
		}
	}
	return found
}

// route4MTU routes an IPv4 prefix to a device with an MTU of its own.
func route4MTU(ifi int, dst netip.Prefix, mtu int) error {
	hdr := make([]byte, 12) // rtmsg
	hdr[0] = unix.AF_INET
	hdr[1] = byte(dst.Bits())
	hdr[4] = unix.RT_TABLE_MAIN
	hdr[5] = unix.RTPROT_STATIC
	hdr[6] = unix.RT_SCOPE_UNIVERSE
	hdr[7] = unix.RTN_UNICAST
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, addrBytes(dst.Masked().Addr()))
	ae.Uint32(unix.RTA_OIF, uint32(ifi))
	ae.Nested(unix.RTA_METRICS, func(ae *netlink.AttributeEncoder) error {
		ae.Uint32(unix.RTAX_MTU, uint32(mtu))
		return nil
	})
	attrs, _ := ae.Encode() // fixed attributes, which always encode
	return linkRequest(unix.RTM_NEWROUTE, netlink.Create|netlink.Replace, hdr, attrs)
}

// drops names the program's drop counters that are not zero, and what the slow path dropped.
func (b *bpfNAT64) drops() string { return drops(b.objs.maps[nat64MapStats], bpfStatNames, b.slow) }

// dummyAdd creates a dummy device, with an MTU of its own unless mtu is 0, replacing one of the
// same name.
func dummyAdd(name string, mtu int) (*net.Interface, error) {
	if ifi, err := net.InterfaceByName(name); err == nil {
		if err := linkDel(ifi.Index); err != nil {
			return nil, fmt.Errorf("removing the old %s: %w", name, err)
		}
	}
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, name)
	if mtu > 0 {
		ae.Uint32(unix.IFLA_MTU, uint32(mtu))
	}
	ae.Nested(unix.IFLA_LINKINFO, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.IFLA_INFO_KIND, "dummy")
		return nil
	})
	attrs, _ := ae.Encode() // fixed attributes, which always encode
	if err := linkRequest(unix.RTM_NEWLINK, netlink.Create|netlink.Excl, make([]byte, 16), attrs); err != nil {
		return nil, err
	}
	return net.InterfaceByName(name)
}
