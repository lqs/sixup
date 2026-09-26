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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Jool (https://jool.mx) is an out-of-tree NAT64 module configured over generic netlink. The
// protocol below is the one its 4.1 series speaks; the constants come from src/common/config.h and
// src/common/types.h of the release tarball.
const (
	joolFamilyName = "Jool"
	joolMagic      = "jool"
	joolINameLen   = 16 // INAME_MAX_SIZE
	joolModule     = "/sys/module/jool/version"

	xtNAT64     = 1 << 1 // XT_NAT64
	xfNetfilter = 1 << 2 // XF_NETFILTER

	opInstanceAdd = 1  // JNLOP_INSTANCE_ADD
	opInstanceRm  = 3  // JNLOP_INSTANCE_RM
	opPool4Add    = 19 // JNLOP_POOL4_ADD

	jnlarOperand = 10 // JNLAR_OPERAND

	joolHdrLen    = 4 + 4 + 4 + joolINameLen // struct joolnlhdr, already aligned
	joolFlagError = 1 << 0                   // JOOLNLHDR_FLAGS_ERROR
	jnlaerrCode   = 1                        // JNLAERR_CODE
	jnlaerrMsg    = 2                        // JNLAERR_MSG

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

	vethInfoPeer = 1 // VETH_INFO_PEER (linux/veth.h), not exported by x/sys/unix
)

// l4 protocols, in Jool's own numbering rather than the IP one
var joolProtos = []uint8{0, 1, 2} // L4PROTO_TCP, L4PROTO_UDP, L4PROTO_ICMP

// joolManager runs one NAT64 instance in a network namespace of its own, joined to this one by a
// veth pair. Jool hooks PREROUTING, so in the host's own namespace it would never see the router's
// own traffic, and it sends its output on with dst_output after clearing its conntrack association
// (nf_reset_ct in its rfc7915 code), so no nat chain could rewrite it either. Across the veth both
// problems go: whatever is routed to the NAT64 prefix enters the namespace through PREROUTING, and the
// IPv4 it becomes comes back as a new packet that leaves by this host's IPv4 route, the tunnel's or
// any other, where the source NAT treats it like any other, so a MAP-E line's ports have one
// allocator. Jool's pool4 is a private address nothing else uses, and the namespace is held only by
// a descriptor: when sixup ends, however it ends, the kernel removes the namespace, the veth pair
// and the instance with it.
//
// The namespace exists only while Jool translates in it, and the prefix is announced only then: a
// prefix nothing translates would send the CLAT of an IPv6-only client into a void.
type joolManager struct {
	prefix  netip.Prefix // pool6: -ra-pref64, or the well-known 64:ff9b::/96
	link    netip.Prefix // -jool-ipv4, the /31 between the namespaces
	store   *Store
	active  bool
	ns      int    // descriptor holding the namespace while active
	family  uint16 // Jool's generic netlink family then; the kernel hands out a new one when the module is reloaded
	lastErr string // the module may be absent for hours; the same complaint is logged once
}

const (
	joolIName   = "sixup"
	joolOutside = "sixup-nat64" // the veth end in the host's namespace
	joolInside  = "nat64"       // the end in Jool's namespace
)

var (
	joolLLOutside = netip.MustParseAddr("fe80::1")
	joolLLInside  = netip.MustParseAddr("fe80::2")
)

// joolAddrs splits the /31: the lower address is the gateway on the host's side, the upper one
// Jool's side and its pool4.
func joolAddrs(link netip.Prefix) (outside, inside netip.Addr) {
	outside = link.Masked().Addr()
	return outside, outside.Next()
}

func (m *joolManager) run(ctx context.Context) {
	defer m.stop()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		m.check()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// check follows the module: it starts NAT64 once Jool is loaded, and stops it when the module goes
// away or comes back as a new one, whose instances do not include ours.
func (m *joolManager) check() {
	family, err := joolFamily()
	if m.active && (err != nil || family != m.family) {
		m.stop()
		warnf("[jool] the module was unloaded or reloaded, NAT64 stopped until it translates again")
	}
	if err != nil {
		m.report(err)
		return
	}
	if !m.active {
		m.report(m.start(family))
	}
}

func (m *joolManager) start(family uint16) error {
	removeOldInstance()
	if err := m.setup(); err != nil {
		return fmt.Errorf("cannot build the namespace for NAT64: %w", err)
	}
	if err := inNetns(m.ns, m.configure); err != nil {
		unix.Close(m.ns)
		return err
	}
	m.active, m.family = true, family
	m.store.SetNAT64(m.prefix)
	return nil
}

// stop closes the namespace, which the kernel then removes with the veth pair and the instance.
func (m *joolManager) stop() {
	if !m.active {
		return
	}
	unix.Close(m.ns)
	m.active = false
	m.store.SetNAT64(netip.Prefix{})
}

// joolFamily returns the generic netlink family of the loaded module, or why there is none.
// Families are not per namespace, so the host's view is Jool's too.
func joolFamily() (uint16, error) {
	if _, err := joolVersion(); err != nil {
		return 0, err
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("cannot open generic netlink: %w", err)
	}
	defer c.Close()
	fam, err := c.GetFamily(joolFamilyName)
	if err != nil {
		return 0, fmt.Errorf("the jool module is loaded but offers no %s netlink family: %w", joolFamilyName, err)
	}
	return fam.ID, nil
}

// setup creates the namespace and the veth pair and routes 64:ff9b::/96 and the pool4 address
// through it. The host's side of the /31 is the namespace's IPv4 gateway.
func (m *joolManager) setup() (err error) {
	ns, err := newNetns()
	if err != nil {
		return err
	}
	m.ns = ns
	// Closing the descriptor is all it takes to undo a half-built namespace
	defer func() {
		if err != nil {
			unix.Close(ns)
		}
	}()
	if err := vethAdd(joolOutside, joolInside, ns); err != nil {
		return err
	}
	outside, inside := joolAddrs(m.link)
	ifi, err := net.InterfaceByName(joolOutside)
	if err != nil {
		return err
	}
	if err := joolLinkUp(ifi, joolLLOutside, netip.PrefixFrom(outside, 31)); err != nil {
		return err
	}
	if err := routeSet(ifi.Index, m.prefix, joolLLInside, 0, 0); err != nil {
		return fmt.Errorf("route %s: %w", m.prefix, err)
	}
	if err := inNetns(ns, func() error {
		ifi, err := net.InterfaceByName(joolInside)
		if err != nil {
			return err
		}
		if err := joolLinkUp(ifi, joolLLInside, netip.PrefixFrom(inside, 31)); err != nil {
			return err
		}
		if err := routeSet(ifi.Index, netip.MustParsePrefix("0.0.0.0/0"), outside, 0, 0); err != nil {
			return err
		}
		if err := routeSet(ifi.Index, netip.MustParsePrefix("::/0"), joolLLOutside, 0, 0); err != nil {
			return err
		}
		// Jool takes the packets it translates in PREROUTING. Without it, loaded late or not at
		// all, the rest would follow the default route back out and bounce between the two
		// namespaces until the hop limit ran out; this sends an unreachable instead.
		if err := routeUnreachable(m.prefix, 0, false); err != nil {
			return err
		}
		// Jool translates in PREROUTING and the result is forwarded like any packet
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
			return err
		}
		return sysctlWrite("/proc/sys/net/ipv4/ip_forward", "1")
	}); err != nil {
		return fmt.Errorf("configuring the namespace: %w", err)
	}
	return nil
}

// joolLinkUp brings one veth end up with a fixed link-local address, which the routes use as
// their next hop, and its end of the /31.
func joolLinkUp(ifi *net.Interface, ll netip.Addr, v4 netip.Prefix) error {
	if err := linkSetUp(ifi.Index); err != nil {
		return fmt.Errorf("%s up: %w", ifi.Name, err)
	}
	if err := addrSet(ifi.Index, ll, 64, time.Duration(infiniteLft)*time.Second, 0, true, ifaFNodad); err != nil {
		return fmt.Errorf("%s on %s: %w", ll, ifi.Name, err)
	}
	if err := addr4Set(ifi.Name, v4); err != nil {
		return fmt.Errorf("%s on %s: %w", v4, ifi.Name, err)
	}
	return nil
}

// removeOldInstance deletes an instance an earlier version left in the host's namespace, where it
// would go on translating ahead of the one in the namespace.
func removeOldInstance() {
	ver, err := joolVersion()
	if err != nil {
		return
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return
	}
	defer c.Close()
	fam, err := c.GetFamily(joolFamilyName)
	if err != nil {
		return
	}
	if joolRequest(c, fam.ID, ver, opInstanceRm, nil) == nil {
		infof("[jool] removed instance %q from the host's namespace, left by an earlier version", joolIName)
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
		warnf("[jool] %s", msg)
	}
}

// configure creates the instance; it runs inside the namespace, where the netlink socket belongs.
func (m *joolManager) configure() error {
	ver, err := joolVersion()
	if err != nil {
		return err
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("cannot open generic netlink: %w", err)
	}
	defer c.Close()
	fam, err := c.GetFamily(joolFamilyName)
	if err != nil {
		return fmt.Errorf("the jool module is loaded but offers no %s netlink family: %w", joolFamilyName, err)
	}
	// A retry after a partial failure finds what the last attempt got done
	if err := joolRequest(c, fam.ID, ver, opInstanceAdd, instanceAttrs(m.prefix)); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot create instance %q: %w", joolIName, err)
	}
	_, inside := joolAddrs(m.link)
	for _, proto := range joolProtos {
		if err := joolRequest(c, fam.ID, ver, opPool4Add, pool4Attrs(inside, proto)); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("cannot add %s to pool4: %w", inside, err)
		}
	}
	infof("[jool] translating %s through %s to IPv4 from %s, announced in the RA", m.prefix, joolOutside, inside)
	return nil
}

// joolRequest sends one request. Jool answers each with a message of its own, which carries its
// error when there is one (jresponse_send_simple in its nl_common.c). Asking for an ACK as well
// would leave that second reply queued, and the next request on the connection would read it and
// fail on its sequence number.
func joolRequest(c *genetlink.Conn, family uint16, ver uint32, op uint8, attrs []byte) error {
	data := append(joolHeader(ver, joolIName), attrs...)
	msgs, err := c.Execute(
		genetlink.Message{Header: genetlink.Header{Command: op, Version: 1}, Data: data},
		family,
		netlink.Request,
	)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if err := joolReplyError(m.Data); err != nil {
			return err
		}
	}
	return nil
}

// joolReplyError reads the error report in a reply: the header's error flag, then the code, an
// errno, and Jool's own message as attributes.
func joolReplyError(b []byte) error {
	if len(b) < joolHdrLen || b[9]&joolFlagError == 0 {
		return nil
	}
	ad, err := netlink.NewAttributeDecoder(b[joolHdrLen:])
	if err != nil {
		return fmt.Errorf("unreadable error report from jool: %w", err)
	}
	var code uint16
	var msg string
	for ad.Next() {
		switch ad.Type() {
		case jnlaerrCode:
			code = ad.Uint16()
		case jnlaerrMsg:
			msg = ad.String()
		}
	}
	return fmt.Errorf("%s: %w", strings.TrimSpace(msg), unix.Errno(code))
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

func instanceAttrs(pool6 netip.Prefix) []byte {
	return encodeAttrs(func(ae *netlink.AttributeEncoder) {
		ae.Nested(jnlarOperand, func(ae *netlink.AttributeEncoder) error {
			ae.Uint8(jnlaiaXF, xfNetfilter)
			ae.Nested(jnlaiaPool6, prefix6Attrs(pool6))
			return nil
		})
	})
}

// pool4Attrs puts every port of addr in pool4 for one protocol: nothing else in the namespace
// uses the address, and the source NAT outside owns the line's ports.
func pool4Attrs(addr netip.Addr, proto uint8) []byte {
	return encodeAttrs(func(ae *netlink.AttributeEncoder) {
		ae.Nested(jnlarOperand, func(ae *netlink.AttributeEncoder) error {
			ae.Uint32(jnlap4Mark, 0)
			ae.Uint32(jnlap4Iterations, 0)
			ae.Uint8(jnlap4Flags, iterationsAuto)
			ae.Uint8(jnlap4Proto, proto)
			ae.Nested(jnlap4Prefix, prefix4Attrs(netip.PrefixFrom(addr, 32)))
			ae.Uint16(jnlap4PortMin, 1)
			ae.Uint16(jnlap4PortMax, 65535)
			return nil
		})
	})
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

// newNetns creates a network namespace and returns a descriptor holding it. The thread that made
// it is locked and never unlocked, so the runtime retires the thread instead of reusing it.
func newNetns() (int, error) {
	type result struct {
		fd  int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("new network namespace: %w", err)}
			return
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		ch <- result{fd, err}
	}()
	r := <-ch
	return r.fd, r.err
}

// inNetns runs fn on a thread in the namespace ns. Sockets fn opens stay in that namespace, and
// so do the sysctls it writes.
func inNetns(ns int, fn func() error) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // retired with the goroutine, never back in the host's namespace
		if err := unix.Setns(ns, unix.CLONE_NEWNET); err != nil {
			ch <- fmt.Errorf("entering the namespace: %w", err)
			return
		}
		ch <- fn()
	}()
	return <-ch
}

// vethAdd creates a veth pair with the peer end in the namespace ns, replacing a pair of the same
// name.
func vethAdd(name, peer string, ns int) error {
	if ifi, err := net.InterfaceByName(name); err == nil {
		if err := linkDel(ifi.Index); err != nil {
			return fmt.Errorf("removing the old %s: %w", name, err)
		}
	}
	pe := netlink.NewAttributeEncoder()
	pe.String(unix.IFLA_IFNAME, peer)
	pe.Uint32(unix.IFLA_NET_NS_FD, uint32(ns))
	peerAttrs, err := pe.Encode()
	if err != nil {
		return err
	}
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, name)
	ae.Nested(unix.IFLA_LINKINFO, func(ae *netlink.AttributeEncoder) error {
		ae.String(unix.IFLA_INFO_KIND, "veth")
		ae.Nested(unix.IFLA_INFO_DATA, func(ae *netlink.AttributeEncoder) error {
			ae.Bytes(vethInfoPeer, append(make([]byte, 16), peerAttrs...)) // ifinfomsg, then the peer's attributes
			return nil
		})
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	return linkRequest(unix.RTM_NEWLINK, netlink.Create|netlink.Excl, make([]byte, 16), attrs)
}

func linkSetUp(index int) error {
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[4:8], uint32(index))
	nativeEndian.PutUint32(hdr[8:12], unix.IFF_UP)
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_UP)
	return linkRequest(unix.RTM_NEWLINK, 0, hdr, nil)
}

func linkDel(index int) error {
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[4:8], uint32(index))
	return linkRequest(unix.RTM_DELLINK, 0, hdr, nil)
}

func linkRequest(typ netlink.HeaderType, flags netlink.HeaderFlags, hdr, attrs []byte) error {
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Execute(netlink.Message{Header: netlink.Header{Type: typ, Flags: netlink.Request | netlink.Acknowledge | flags}, Data: append(hdr, attrs...)})
	return err
}

// checkJoolIPv4 refuses a /31 that an address or a route of this host already covers: the two
// hosts behind it would become unreachable, or Jool's traffic would go to them. The default route
// covers everything and does not count, and neither does the veth of an earlier run, which the
// kernel may still be tearing down when sixup starts again.
func checkJoolIPv4(link netip.Prefix) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	old := 0
	for _, ifi := range ifaces {
		if ifi.Name == joolOutside {
			old = ifi.Index
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			ones, _ := n.Mask.Size()
			if netip.PrefixFrom(ip, ones).Masked().Overlaps(link) {
				return fmt.Errorf("%s overlaps the address %s on %s", link, n, ifi.Name)
			}
		}
	}
	routes, err := routes4()
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.dst.Bits() > 0 && (old == 0 || r.oif != old) && r.dst.Overlaps(link) {
			return fmt.Errorf("%s overlaps the route %s", link, r.dst)
		}
	}
	return nil
}

type route4 struct {
	dst netip.Prefix
	oif int
}

// routes4 lists the IPv4 routes in every table, by destination and outgoing interface.
func routes4() ([]route4, error) {
	c, err := rtDial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	msgs, err := c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_GETROUTE, Flags: netlink.Request | netlink.Dump}, Data: []byte{unix.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}})
	if err != nil {
		return nil, err
	}
	var out []route4
	for _, m := range msgs {
		if len(m.Data) < 12 {
			continue
		}
		r := route4{dst: netip.PrefixFrom(netip.IPv4Unspecified(), int(m.Data[1]))}
		ad, err := netlink.NewAttributeDecoder(m.Data[12:])
		if err != nil {
			continue
		}
		for ad.Next() {
			switch ad.Type() {
			case unix.RTA_DST:
				if a, ok := netip.AddrFromSlice(ad.Bytes()); ok {
					r.dst = netip.PrefixFrom(a, r.dst.Bits())
				}
			case unix.RTA_OIF:
				r.oif = int(ad.Uint32())
			}
		}
		out = append(out, r)
	}
	return out, nil
}
