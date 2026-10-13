//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run ./tools/bpfgen bpf/clat.c clat

var (
	clat4      = netip.MustParseAddr("192.0.0.4") // the host's IPv4 address behind the CLAT (RFC 7335)
	clatDummy4 = netip.MustParseAddr("192.0.0.8") // the source of errors from the IPv6 path (RFC 7600)
)

// clatMetric puts the CLAT's default route behind every other IPv4 one: it carries only what
// nothing else would.
const clatMetric = math.MaxUint32

// clatManager runs a CLAT (RFC 6877) for this host's own IPv4 while the upstream RA announces a
// PREF64 (RFC 8781), router or not. IPv4 that no other route takes leaves by the device
// sixup-clat from 192.0.0.4, bpf/clat.c translates it to the host's CLAT address, and the line's
// NAT64 does the rest. The CLAT address is one the WAN's address manager keeps on the WAN
// (clatAddr), so that the link delivers its packets here; the program on the WAN's ingress takes
// them before the stack does. The WAN has to be an Ethernet link.
type clatManager struct {
	wan    string
	secret []byte
	sysctl bool
	warned bool // that the WAN is no Ethernet link

	// While running
	cfg     clatConfig
	ifindex int
	objs    *bpfObjects
	links   []*os.File
	slow    *slowPath
	reader  *ringReader
	served  chan struct{}
}

// clatConfig is what the CLAT is built from; another one rebuilds it.
type clatConfig struct {
	pref64 netip.Prefix
	addr   netip.Addr // the host's CLAT address
	wan    int        // the WAN's index
	mtu    int        // and its MTU
}

func (c *clatManager) run(ctx context.Context, ch <-chan Snapshot) {
	defer c.stop()
	tick := time.NewTicker(bpfTick)
	defer tick.Stop()
	var last string
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			c.apply(s)
		case <-tick.C:
			if c.objs == nil {
				continue
			}
			if d := drops(c.objs.maps[clatMapStats], bpfStatNames, c.slow); d != last {
				last = d
				infof("[clat] dropped so far: %s", d)
			}
		}
	}
}

// apply builds, rebuilds or takes down the CLAT for a snapshot.
func (c *clatManager) apply(s Snapshot) {
	var want clatConfig
	if a := s.clatAddr(c.secret); a.IsValid() {
		ifi, err := net.InterfaceByName(c.wan)
		switch {
		case err != nil:
		case len(ifi.HardwareAddr) != 6:
			if !c.warned {
				c.warned = true
				warnf("[clat] the line announces the NAT64 prefix %s, but %s is no Ethernet link, which the CLAT needs", s.PREF64, c.wan)
			}
		default:
			want = clatConfig{s.PREF64, a, ifi.Index, ifi.MTU}
		}
	}
	if want == c.cfg {
		return
	}
	if c.objs != nil {
		c.stop()
		infof("[clat] stopped")
	}
	c.cfg = want
	if !want.addr.IsValid() {
		return
	}
	if err := c.start(); err != nil {
		warnf("[clat] %v", err)
		return
	}
	infof("[clat] this host's IPv4 reaches the NAT64 prefix %s from %s through %s", want.pref64, want.addr, clatDev)
}

// start builds the CLAT for c.cfg, and on failure undoes what it did.
func (c *clatManager) start() (err error) {
	// Room for the IPv6 header and a fragment header once translated
	ifi, err := dummyAdd(clatDev, c.cfg.mtu-28)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", clatDev, err)
	}
	c.ifindex = ifi.Index
	defer func() {
		if err != nil {
			c.stop()
		}
	}()
	// The device speaks no IPv6 of its own, and IPv4 from anywhere comes back on it while other
	// routes lead elsewhere
	if c.sysctl {
		err = errors.Join(sysctlWrite("/proc/sys/net/ipv6/conf/"+clatDev+"/disable_ipv6", "1"),
			sysctlWrite("/proc/sys/net/ipv4/conf/"+clatDev+"/rp_filter", "2"))
	}
	err = errors.Join(err, linkSetUp(ifi.Index), addr4Set(clatDev, netip.PrefixFrom(clat4, 32)),
		routeOp(unix.RTM_NEWROUTE, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Replace, unix.RTN_UNICAST, 0,
			ifi.Index, netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.Addr{}, clat4, clatMetric, 0))
	if err != nil {
		return fmt.Errorf("setting up %s: %w", clatDev, err)
	}

	ro := slices.Clone(clatRodata)
	set := func(v bpfVar, b []byte) { copy(ro[v.off:v.off+v.size], b) }
	var mask [16]byte
	for i := range c.cfg.pref64.Bits() {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	pref, pos, a6, a4 := c.cfg.pref64.Masked().Addr().As16(), v4Positions(c.cfg.pref64.Bits()), c.cfg.addr.As16(), clat4.As4()
	set(clatVarPref6, pref[:])
	set(clatVarMask6, mask[:])
	set(clatVarV4pos, pos[:])
	set(clatVarClat6, a6[:])
	set(clatVarClat4, a4[:])
	set(clatVarClatIfindex, nativeEndian.AppendUint32(nil, uint32(ifi.Index)))
	set(clatVarClatMac, ifi.HardwareAddr)
	set(clatVarWanIfindex, nativeEndian.AppendUint32(nil, uint32(c.cfg.wan)))
	set(clatVarSlowMark, nativeEndian.AppendUint32(nil, bpfSlowMark))
	if c.objs, err = bpfLoad(bpfProgram{code: clatCode, maps: clatMaps, relocs: clatRelocs, rodata: ro, license: clatLicense}); err != nil {
		return fmt.Errorf("loading the CLAT: %w", err)
	}
	for _, at := range []struct {
		ifindex int
		typ     uint32
	}{{ifi.Index, unix.BPF_TCX_EGRESS}, {c.cfg.wan, unix.BPF_TCX_INGRESS}} {
		l, err := c.objs.attachTCX(at.ifindex, at.typ)
		if err != nil {
			return fmt.Errorf("the CLAT: %w", err)
		}
		c.links = append(c.links, l)
	}
	if c.slow, err = newSlowPath(clatMapping(c.cfg.pref64, c.cfg.addr), ifi, c.cfg.mtu); err != nil {
		return err
	}
	if c.reader, err = newRingReader(c.objs.maps[clatMapSlow]); err != nil {
		return fmt.Errorf("reading the CLAT's slow path: %w", err)
	}
	c.served = make(chan struct{})
	go func() {
		c.slow.serve(c.reader)
		close(c.served)
	}()
	return nil
}

// stop takes down whatever start set up; the device takes its address and route with it.
func (c *clatManager) stop() {
	if c.reader != nil {
		c.reader.close()
		<-c.served
		c.reader.free()
		c.reader = nil
	}
	if c.slow != nil {
		c.slow.close()
		c.slow = nil
	}
	for _, l := range c.links {
		l.Close()
	}
	c.links = nil
	if c.objs != nil {
		c.objs.close()
		c.objs = nil
	}
	if c.ifindex != 0 {
		linkDel(c.ifindex)
		c.ifindex = 0
	}
}

// clatMapping is bpf/clat.c's: the NAT64 prefix carries IPv4 addresses, the CLAT address stands
// for 192.0.0.4, and any other IPv6 address is a router on the path, 192.0.0.8.
func clatMapping(prefix netip.Prefix, addr netip.Addr) slowMapping {
	a6 := addr.As16()
	return slowMapping{
		v4of6: func(a [16]byte, _ bool) ([4]byte, error) {
			switch {
			case prefix.Contains(netip.AddrFrom16(a)):
				return extract4(prefix, a), nil
			case a == a6:
				return clat4.As4(), nil
			}
			return clatDummy4.As4(), nil
		},
		v6of4: func(a [4]byte) ([16]byte, error) {
			if a == clat4.As4() {
				return a6, nil
			}
			return embed4(prefix, a), nil
		},
	}
}
