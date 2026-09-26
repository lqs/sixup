//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Messages are assembled directly with mdlayher/netlink instead of an rtnetlink
// wrapper because those wrappers do not encode IFA_CACHEINFO, and address
// lifetimes are central to this project.

var nativeEndian = binary.NativeEndian

const infiniteLft = 0xffffffff

func lftSeconds(d time.Duration, infinite bool) uint32 {
	if infinite {
		return infiniteLft
	}
	if d <= 0 {
		return 0
	}
	s := d / time.Second
	if s > infiniteLft-1 {
		return infiniteLft - 1
	}
	return uint32(s)
}

func rtDial() (*netlink.Conn, error) {
	return netlink.Dial(unix.NETLINK_ROUTE, nil)
}

// addrSet adds or updates an address. valid=0 with infiniteValid=false expires it
// immediately, preferred=0 deprecates it, and infiniteValid keeps the kernel from
// reclaiming it.
func addrSet(ifi int, addr netip.Addr, plen int, preferred, valid time.Duration, infiniteValid bool, flags uint32) error {
	if dryRun {
		debugf("[dry-run] skip configuring address %s/%d", addr, plen)
		return nil
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	ae := netlink.NewAttributeEncoder()
	a := addr.As16()
	ae.Bytes(unix.IFA_LOCAL, a[:])
	ae.Bytes(unix.IFA_ADDRESS, a[:])
	ae.Uint32(unix.IFA_FLAGS, flags)
	ci := make([]byte, 16)
	nativeEndian.PutUint32(ci[0:4], lftSeconds(preferred, false))
	nativeEndian.PutUint32(ci[4:8], lftSeconds(valid, infiniteValid))
	ae.Bytes(unix.IFA_CACHEINFO, ci)
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	hdr := make([]byte, 8)
	hdr[0] = unix.AF_INET6
	hdr[1] = byte(plen)
	hdr[3] = unix.RT_SCOPE_UNIVERSE
	nativeEndian.PutUint32(hdr[4:8], uint32(ifi))
	msg := netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWADDR, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
		Data:   append(hdr, attrs...),
	}
	if _, err := c.Execute(msg); err != nil {
		return err
	}
	if infiniteValid {
		return nil
	}
	// Kernel bug since 4.18: when a permanent address gets a finite lifetime, the prefix route is
	// given an expiry in the past and GC deletes it. A second request sets the expiry right.
	// Keep this: unfixed kernels will be around for years, and on fixed ones it is a no-op.
	_, err = c.Execute(msg)
	return err
}

func addrDel(ifi int, addr netip.Addr, plen int) error {
	if dryRun {
		debugf("[dry-run] skip deleting address %s/%d", addr, plen)
		return nil
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	ae := netlink.NewAttributeEncoder()
	a := addr.As16()
	ae.Bytes(unix.IFA_LOCAL, a[:])
	ae.Bytes(unix.IFA_ADDRESS, a[:])
	attrs, _ := ae.Encode()
	hdr := make([]byte, 8)
	hdr[0] = unix.AF_INET6
	hdr[1] = byte(plen)
	nativeEndian.PutUint32(hdr[4:8], uint32(ifi))
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_DELADDR, Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(hdr, attrs...),
	})
	if errors.Is(err, unix.EADDRNOTAVAIL) {
		return nil
	}
	return err
}

type ifAddr struct {
	Addr      netip.Addr
	PrefixLen int
	Flags     uint32
	Preferred uint32
	Valid     uint32
}

// addrList lists the IPv6 addresses on an interface.
func addrList(ifi int) ([]ifAddr, error) {
	c, err := rtDial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	hdr := make([]byte, 8)
	hdr[0] = unix.AF_INET6
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETADDR, Flags: netlink.Request | netlink.Dump},
		Data:   hdr,
	})
	if err != nil {
		return nil, err
	}
	var out []ifAddr
	for _, m := range msgs {
		if len(m.Data) < 8 {
			continue
		}
		if int(nativeEndian.Uint32(m.Data[4:8])) != ifi {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[8:])
		if err != nil {
			continue
		}
		ia := ifAddr{PrefixLen: int(m.Data[1]), Flags: uint32(m.Data[2])}
		for ad.Next() {
			switch ad.Type() {
			case unix.IFA_ADDRESS:
				if b := ad.Bytes(); len(b) == 16 {
					ia.Addr = netip.AddrFrom16([16]byte(b))
				}
			case unix.IFA_FLAGS:
				ia.Flags = ad.Uint32()
			case unix.IFA_CACHEINFO:
				if b := ad.Bytes(); len(b) == 16 {
					ia.Preferred = nativeEndian.Uint32(b[0:4])
					ia.Valid = nativeEndian.Uint32(b[4:8])
				}
			}
		}
		if ia.Addr.IsValid() {
			out = append(out, ia)
		}
	}
	return out, nil
}

// routeSet adds or replaces a route; an invalid gw means a directly connected route.
func routeSet(ifi int, dst netip.Prefix, gw netip.Addr, metric uint32, expires time.Duration) error {
	return routeOp(unix.RTM_NEWROUTE, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Replace, unix.RTN_UNICAST, ifi, dst, gw, metric, expires)
}

func routeDel(ifi int, dst netip.Prefix, gw netip.Addr, metric uint32) error {
	err := routeOp(unix.RTM_DELROUTE, netlink.Request|netlink.Acknowledge, unix.RTN_UNICAST, ifi, dst, gw, metric, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// routeUnreachable adds, or with del removes, a route that drops traffic for dst with an ICMPv6
// Destination Unreachable.
func routeUnreachable(dst netip.Prefix, expires time.Duration, del bool) error {
	if !del {
		return routeOp(unix.RTM_NEWROUTE, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Replace, unix.RTN_UNREACHABLE, 0, dst, netip.Addr{}, 0, expires)
	}
	err := routeOp(unix.RTM_DELROUTE, netlink.Request|netlink.Acknowledge, unix.RTN_UNREACHABLE, 0, dst, netip.Addr{}, 0, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func routeOp(typ netlink.HeaderType, flags netlink.HeaderFlags, rtn uint8, ifi int, dst netip.Prefix, gw netip.Addr, metric uint32, expires time.Duration) error {
	if dryRun {
		debugf("[dry-run] skip route %s -> %s dev %d", dst, gw, ifi)
		return nil
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	v4 := dst.Addr().Is4()
	hdr := make([]byte, 12)
	hdr[0] = unix.AF_INET6
	if v4 {
		hdr[0] = unix.AF_INET
	}
	hdr[1] = byte(dst.Bits())
	hdr[4] = unix.RT_TABLE_MAIN
	hdr[5] = unix.RTPROT_STATIC
	hdr[6] = unix.RT_SCOPE_UNIVERSE
	hdr[7] = rtn
	// IPv6 routes come from an RA, IPv4 ones are ours; the protocol keeps them apart in the table.
	// A delete has to name the same protocol, or the kernel finds no IPv6 route to remove.
	if !v4 {
		hdr[5] = unix.RTPROT_RA
	}
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, addrBytes(dst.Masked().Addr()))
	if ifi != 0 {
		ae.Uint32(unix.RTA_OIF, uint32(ifi))
	}
	if gw.IsValid() {
		ae.Bytes(unix.RTA_GATEWAY, addrBytes(gw))
	}
	if metric != 0 {
		ae.Uint32(unix.RTA_PRIORITY, metric)
	}
	if expires > 0 {
		ae.Uint32(unix.RTA_EXPIRES, uint32(expires/time.Second))
	}
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = c.Execute(netlink.Message{Header: netlink.Header{Type: typ, Flags: flags}, Data: append(hdr, attrs...)})
	return err
}

// addrBytes returns the wire form of an address: 4 bytes for IPv4, 16 for IPv6.
func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

// neighProxySet is equivalent to ip -6 neigh add proxy ADDR dev IF.
func neighProxySet(ifi int, addr netip.Addr, del bool) error {
	if dryRun {
		debugf("[dry-run] skip proxy neighbor %s", addr)
		return nil
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	hdr := make([]byte, 12)
	hdr[0] = unix.AF_INET6
	nativeEndian.PutUint32(hdr[4:8], uint32(ifi))
	nativeEndian.PutUint16(hdr[8:10], unix.NUD_PERMANENT)
	hdr[10] = unix.NTF_PROXY
	ae := netlink.NewAttributeEncoder()
	a := addr.As16()
	ae.Bytes(unix.NDA_DST, a[:])
	attrs, _ := ae.Encode()
	typ, flags := netlink.HeaderType(unix.RTM_NEWNEIGH), netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Replace
	if del {
		typ, flags = unix.RTM_DELNEIGH, netlink.Request|netlink.Acknowledge
	}
	_, err = c.Execute(netlink.Message{Header: netlink.Header{Type: typ, Flags: flags}, Data: append(hdr, attrs...)})
	if del && errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// linkWatch subscribes to link state changes and reports (ifindex, up) events.
func linkWatch(ch chan<- linkEvent) error {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
		return err
	}
	go func() {
		defer c.Close()
		for {
			msgs, err := c.Receive()
			if err != nil {
				debugf("[netlink] link watch ended: %v", err)
				return
			}
			for _, m := range msgs {
				if (m.Header.Type != unix.RTM_NEWLINK && m.Header.Type != unix.RTM_DELLINK) || len(m.Data) < 16 {
					continue
				}
				ev := linkEvent{Index: int(nativeEndian.Uint32(m.Data[4:8]))}
				flags := nativeEndian.Uint32(m.Data[8:12])
				ev.Up = flags&unix.IFF_RUNNING != 0 && flags&unix.IFF_UP != 0
				ev.Gone = m.Header.Type == unix.RTM_DELLINK
				if ev.Gone {
					ev.Up = false
				}
				if ad, err := netlink.NewAttributeDecoder(m.Data[16:]); err == nil {
					for ad.Next() {
						if ad.Type() == unix.IFLA_IFNAME {
							ev.Name = ad.String()
						}
					}
				}
				if ev.Name == "" {
					continue
				}
				ch <- ev
			}
		}
	}()
	return nil
}

type linkEvent struct {
	Name  string
	Index int
	Up    bool
	Gone  bool // interface was removed
}

// sysctlSet writes /proc/sys/net/ipv6/conf/<iface>/<key>.
func sysctlSet(iface, key, val string) error {
	return sysctlWrite(filepath.Join("/proc/sys/net/ipv6/conf", strings.ReplaceAll(iface, ".", "/"), key), val)
}

// sysctlWrite writes one /proc/sys entry by path, for the switches that are not per-interface IPv6.
func sysctlWrite(path, val string) error {
	if dryRun {
		debugf("[dry-run] skip sysctl %s=%s", path, val)
		return nil
	}
	return os.WriteFile(path, []byte(val), 0)
}

func sysctlGet(iface, key string) (string, error) {
	p := filepath.Join("/proc/sys/net/ipv6/conf", strings.ReplaceAll(iface, ".", "/"), key)
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

// sockDiagInUse counts TCP/UDP sockets whose local address matches addr exactly,
// via INET_DIAG. Wildcard listeners bound to :: are excluded; TIME_WAIT counts.
func sockDiagInUse(addr netip.Addr) (int, error) {
	c, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	total := 0
	for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		// inet_diag_req_v2: family, protocol, ext, pad, states(4), id(48)
		req := make([]byte, 56)
		req[0] = unix.AF_INET6
		req[1] = proto
		nativeEndian.PutUint32(req[4:8], 0xffffffff) // all states
		msgs, err := c.Execute(netlink.Message{
			Header: netlink.Header{Type: unix.SOCK_DIAG_BY_FAMILY, Flags: netlink.Request | netlink.Dump},
			Data:   req,
		})
		if err != nil {
			return total, err
		}
		want := addr.As16()
		for _, m := range msgs {
			// inet_diag_msg: family, state, timer, retrans, id(48)... id.src at offset 8..24 (sport 4..6)
			if len(m.Data) < 72 {
				continue
			}
			src := [16]byte(m.Data[8:24])
			if src == want {
				total++
			}
		}
	}
	return total, nil
}

// conntrackInUse dumps NFNETLINK_CONNTRACK and counts flows whose original-direction
// source or reply-direction destination equals addr. Returns errConntrackUnavailable
// when the module is not loaded.
var errConntrackUnavailable = errors.New("conntrack unavailable")

func conntrackInUse(addr netip.Addr) (int, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return 0, errConntrackUnavailable
	}
	defer c.Close()
	const (
		nfnlSubsysCtnetlink = 1
		ipctnlMsgCtGet      = 1
		ctaTupleOrig        = 1
		ctaTupleReply       = 2
		ctaTupleIP          = 1
		ctaIPv6Src          = 3
		ctaIPv6Dst          = 4
		nlaFNested          = 0x8000
	)
	// nfgenmsg: family, version, res_id
	data := []byte{unix.AF_INET6, 0, 0, 0}
	msgs, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtGet), Flags: netlink.Request | netlink.Dump},
		Data:   data,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
			return 0, errErrConntrack(err)
		}
		return 0, err
	}
	want := addr.As16()
	n := 0
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			continue
		}
		hit := false
		for ad.Next() {
			t := ad.Type() &^ nlaFNested
			if t != ctaTupleOrig && t != ctaTupleReply {
				continue
			}
			ad.Nested(func(nd *netlink.AttributeDecoder) error {
				for nd.Next() {
					if nd.Type()&^nlaFNested != ctaTupleIP {
						continue
					}
					nd.Nested(func(ipd *netlink.AttributeDecoder) error {
						for ipd.Next() {
							typ := ipd.Type() &^ nlaFNested
							if typ != ctaIPv6Src && typ != ctaIPv6Dst {
								continue
							}
							if b := ipd.Bytes(); len(b) == 16 && [16]byte(b) == want {
								hit = true
							}
						}
						return nil
					})
				}
				return nil
			})
		}
		if hit {
			n++
		}
	}
	return n, nil
}

func errErrConntrack(err error) error {
	return fmt.Errorf("%w: %v", errConntrackUnavailable, err)
}

// ifaceByName resolves an interface and returns its MAC and link-local address.
func ifaceByName(name string) (*net.Interface, error) {
	return net.InterfaceByName(name)
}

// setAllMulti enables IFF_ALLMULTI so the NDP proxy receives NS sent to any solicited-node group.
func setAllMulti(name string) error {
	if dryRun {
		debugf("[dry-run] skip allmulti %s", name)
		return nil
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	hdr := make([]byte, 16)
	hdr[0] = unix.AF_UNSPEC
	nativeEndian.PutUint32(hdr[4:8], uint32(ifi.Index))
	nativeEndian.PutUint32(hdr[8:12], unix.IFF_ALLMULTI)
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_ALLMULTI)
	_, err = c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_SETLINK, Flags: netlink.Request | netlink.Acknowledge}, Data: hdr})
	return err
}

// reusePort lets the DHCPv6 servers of several LAN interfaces share port 547, each filtering by interface index.
func reusePort(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if serr == nil {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// packetCapture uses AF_PACKET to feed frames the IPv6 frames addressed to this host
// (unicast to our MAC, or multicast) on an interface. Promiscuous mode stays off since
// the targets are our own tunnel traffic and REPLYs to other local DHCPv6 clients.
// A classic BPF filter drops everything outside kinds in the kernel. onExit runs when
// the read loop ends, including when it was not stopped deliberately.
func packetCapture(ifindex int, frames chan<- []byte, kinds frameKind, onExit func()) (func(), error) {
	const ethPIPv6 = 0x86dd
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(ethPIPv6)))
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPIPv6), Ifindex: ifindex}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := attachCaptureFilter(fd, kinds); err != nil {
		debugf("[tunnel-capture] attaching BPF filter failed: %v, falling back to userspace filtering", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(frames)
		defer onExit()
		buf := make([]byte, 65536)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				select {
				case <-done:
				default:
					if !errors.Is(err, unix.EINTR) {
						debugf("[tunnel-capture] read failed: %v", err)
					}
				}
				if !errors.Is(err, unix.EINTR) {
					return
				}
				continue
			}
			f := make([]byte, n)
			copy(f, buf[:n])
			select {
			case frames <- f:
			default:
			}
		}
	}()
	return func() { close(done); unix.Close(fd) }, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// attachCaptureFilter attaches the cBPF program built by captureFilter to the socket.
func attachCaptureFilter(fd int, kinds frameKind) error {
	insns := captureFilter(kinds)
	prog := make([]unix.SockFilter, len(insns))
	for i, in := range insns {
		prog[i] = unix.SockFilter{Code: in.code, Jt: in.jt, Jf: in.jf, K: in.k}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}

// tunnelSet creates or modifies an ip6tnl device (IPv4-in-IPv6, protocol 4), brings it
// up and sets its MTU. An existing device is updated by index with RTM_NEWLINK
// (ip link set dev X type ip6tnl ...); otherwise it is created with
// NLM_F_CREATE|NLM_F_EXCL (ip tunnel add).
func tunnelSet(name string, link int, local, remote netip.Addr, mtu int) error {
	if dryRun {
		debugf("[dry-run] skip tunnel device %s: %s -> %s mtu %d", name, local, remote, mtu)
		return nil
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()

	data := netlink.NewAttributeEncoder()
	data.Uint32(iflaIptunLink, uint32(link))
	l, r := local.As16(), remote.As16()
	data.Bytes(iflaIptunLocal, l[:])
	data.Bytes(iflaIptunRemote, r[:])
	data.Uint8(iflaIptunTTL, 64)
	data.Uint8(iflaIptunEncapLimit, 0)
	data.Uint32(iflaIptunFlags, ip6TnlIgnEncapLimit)
	data.Uint8(iflaIptunProto, unix.IPPROTO_IPIP)
	dataB, err := data.Encode()
	if err != nil {
		return err
	}
	info := netlink.NewAttributeEncoder()
	info.String(unix.IFLA_INFO_KIND, "ip6tnl")
	info.Bytes(unix.IFLA_INFO_DATA, dataB)
	infoB, err := info.Encode()
	if err != nil {
		return err
	}
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.IFLA_IFNAME, name)
	ae.Uint32(unix.IFLA_MTU, uint32(mtu))
	ae.Bytes(unix.IFLA_LINKINFO, infoB)
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	// ifinfomsg: family, pad, type(2), index(4), flags(4), change(4); also sets IFF_UP
	hdr := make([]byte, 16)
	nativeEndian.PutUint32(hdr[8:12], unix.IFF_UP)
	nativeEndian.PutUint32(hdr[12:16], unix.IFF_UP)
	flags := netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl
	if ifi, err := net.InterfaceByName(name); err == nil {
		nativeEndian.PutUint32(hdr[4:8], uint32(ifi.Index))
		flags = netlink.Request | netlink.Acknowledge
	}
	_, err = c.Execute(netlink.Message{Header: netlink.Header{Type: unix.RTM_NEWLINK, Flags: flags}, Data: append(hdr, attrs...)})
	return err
}

// addr4Set assigns a /32 IPv4 address to the tunnel device, replacing any existing one.
func addr4Set(dev string, a netip.Addr) error {
	if dryRun {
		debugf("[dry-run] skip configuring IPv4 %s/32 on %s", a, dev)
		return nil
	}
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return err
	}
	c, err := rtDial()
	if err != nil {
		return err
	}
	defer c.Close()
	ae := netlink.NewAttributeEncoder()
	v4 := a.As4()
	ae.Bytes(unix.IFA_LOCAL, v4[:])
	ae.Bytes(unix.IFA_ADDRESS, v4[:])
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	hdr := make([]byte, 8)
	hdr[0] = unix.AF_INET
	hdr[1] = 32
	hdr[3] = unix.RT_SCOPE_UNIVERSE
	nativeEndian.PutUint32(hdr[4:8], uint32(ifi.Index))
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWADDR, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
		Data:   append(hdr, attrs...),
	})
	return err
}
