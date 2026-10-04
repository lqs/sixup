//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// synLogGroup is the NFLOG group the firewall hands the unsolicited SYNs it drops to.
const synLogGroup = 6092

// synWait is how long a dropped SYN waits for the LAN to open the same connection before the
// sender is told it is prohibited (RFC 6092 REC-34). A variable only so tests need not wait.
var synWait = 6 * time.Second

// synSnaplen keeps of a SYN what an ICMPv6 error can carry back within the minimum MTU.
const synSnaplen = 1280 - 40 - 8

// synPendingMax bounds the SYNs waiting, so that a flood of them cannot grow the table.
const synPendingMax = 4096

// nfnetlink_log and ctnetlink, which x/sys/unix does not name
const (
	nfulnlMsgPacket   = 0
	nfulnlMsgConfig   = 1
	nfulaPayload      = 9
	nfulaCfgCmd       = 1
	nfulaCfgMode      = 2
	nfulnlCfgCmdBind  = 1
	nfulnlCopyPacket  = 2
	ipctnlMsgCtGet    = 1
	ctaTupleOrig      = 1
	ctaTupleIP        = 1
	ctaTupleProto     = 2
	ctaIPv6Src        = 3
	ctaIPv6Dst        = 4
	ctaProtoNum       = 1
	ctaProtoSrcPort   = 2
	ctaProtoDstPort   = 3
	nfnlSubsysShift   = 8
	nfgenmsgLen       = 4
	tcpFlagsOffset    = 13
	tcpFlagSYN        = 0x02
	tcpFlagACK        = 0x10
	icmpUnreachProhib = 1
)

// synFlow is a dropped SYN: from the remote end, to the LAN.
type synFlow struct {
	from, to netip.AddrPort
}

// synRejecter answers the unsolicited SYNs the firewall drops with an ICMPv6 destination
// unreachable, administratively prohibited, after 6 seconds, as RFC 6092 REC-34 asks. A SYN the
// LAN host answers within that time with a SYN of its own, a TCP simultaneous open, is let be:
// the remote end's next SYN then passes as part of that connection.
type synRejecter struct {
	icmp    *icmp.PacketConn
	mu      sync.Mutex
	pending map[synFlow][]byte // the SYN, from its IPv6 header on
}

func (f *firewall) rejectSYNs(ctx context.Context) {
	log, err := nflogBind(synLogGroup, synSnaplen)
	if err != nil {
		warnf("[firewall] cannot receive the dropped SYNs, they are dropped without an ICMPv6 error (RFC 6092 REC-34): %v", err)
		return
	}
	defer log.Close()
	ic, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		warnf("[firewall] cannot send ICMPv6, dropped SYNs get no error (RFC 6092 REC-34): %v", err)
		return
	}
	defer ic.Close()
	var block ipv6.ICMPFilter
	block.SetAll(true) // send only
	ic.IPv6PacketConn().SetICMPFilter(&block)
	r := &synRejecter{icmp: ic, pending: map[synFlow][]byte{}}
	go func() {
		<-ctx.Done()
		log.Close()
	}()
	for {
		msgs, err := log.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// ENOBUFS after a burst: some SYNs are lost, the rest still come
			debugf("[firewall] reading dropped SYNs: %v", err)
			continue
		}
		for _, m := range msgs {
			if m.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<nfnlSubsysShift|nfulnlMsgPacket) || len(m.Data) < nfgenmsgLen {
				continue
			}
			ad, err := netlink.NewAttributeDecoder(m.Data[nfgenmsgLen:])
			if err != nil {
				continue
			}
			for ad.Next() {
				if ad.Type() == nfulaPayload {
					r.add(ctx, ad.Bytes())
				}
			}
		}
	}
}

// add schedules the error for a dropped SYN, unless one is already waiting for its flow.
func (r *synRejecter) add(ctx context.Context, pkt []byte) {
	flow, ok := parseSYN(pkt)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pending[flow]; ok || len(r.pending) >= synPendingMax {
		return // a retransmission, or too many waiting
	}
	r.pending[flow] = pkt
	time.AfterFunc(synWait, func() {
		r.mu.Lock()
		pkt := r.pending[flow]
		delete(r.pending, flow)
		r.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		r.due(flow, pkt)
	})
}

func (r *synRejecter) due(flow synFlow, pkt []byte) {
	open, err := conntrackHas(flow)
	if err != nil {
		// without conntrack nothing tells a simultaneous open from an unsolicited SYN
		debugf("[firewall] looking up %s -> %s in conntrack: %v", flow.from, flow.to, err)
		return
	}
	if open {
		debugf("[firewall] %s -> %s opened from the LAN meanwhile, no ICMPv6 error", flow.from, flow.to)
		return
	}
	msg := icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: icmpUnreachProhib, Body: &icmp.DstUnreach{Data: pkt}}
	b, _ := msg.Marshal(nil) // cannot fail for an ICMPv6 type and a body without extensions; the kernel fills in the checksum
	if _, err := r.icmp.WriteTo(b, &net.IPAddr{IP: flow.from.Addr().AsSlice()}); err != nil {
		debugf("[firewall] ICMPv6 error to %s: %v", flow.from.Addr(), err)
		return
	}
	statInc("syn_rejected")
}

// parseSYN reads the flow of a TCP SYN right after its IPv6 header.
func parseSYN(pkt []byte) (synFlow, bool) {
	if len(pkt) < 40+20 || pkt[0]>>4 != 6 || pkt[6] != unix.IPPROTO_TCP {
		return synFlow{}, false
	}
	tcp := pkt[40:]
	if tcp[tcpFlagsOffset]&(tcpFlagSYN|tcpFlagACK) != tcpFlagSYN {
		return synFlow{}, false
	}
	src, dst := netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
	return synFlow{
		from: netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		to:   netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
	}, true
}

func nfDial() (*netlink.Conn, error) {
	return netlink.Dial(unix.NETLINK_NETFILTER, nil)
}

// nfgenmsg is the header of every nfnetlink message: the family, version 0 and a resource id.
func nfgenmsg(family byte, resID uint16) []byte {
	return binary.BigEndian.AppendUint16([]byte{family, unix.NFNETLINK_V0}, resID)
}

// nflogBind subscribes to an NFLOG group, copying up to snaplen bytes of every packet.
func nflogBind(group uint16, snaplen uint32) (*netlink.Conn, error) {
	c, err := nfDial()
	if err != nil {
		return nil, err
	}
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})
	ae.Bytes(nfulaCfgMode, append(binary.BigEndian.AppendUint32(nil, snaplen), nfulnlCopyPacket, 0))
	attrs, _ := ae.Encode() // fixed attributes, which always encode
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<nfnlSubsysShift | nfulnlMsgConfig), Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(nfgenmsg(unix.AF_UNSPEC, group), attrs...),
	})
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// conntrackHas reports whether conntrack knows the TCP connection of flow, in either direction:
// one the LAN host opened towards the sender has the flow as its reply.
func conntrackHas(flow synFlow) (bool, error) {
	c, err := nfDial()
	if err != nil {
		return false, err
	}
	defer c.Close()
	ae := netlink.NewAttributeEncoder()
	ae.Nested(ctaTupleOrig, func(ae *netlink.AttributeEncoder) error {
		ae.Nested(ctaTupleIP, func(ae *netlink.AttributeEncoder) error {
			src, dst := flow.from.Addr().As16(), flow.to.Addr().As16()
			ae.Bytes(ctaIPv6Src, src[:])
			ae.Bytes(ctaIPv6Dst, dst[:])
			return nil
		})
		ae.Nested(ctaTupleProto, func(ae *netlink.AttributeEncoder) error {
			ae.Uint8(ctaProtoNum, unix.IPPROTO_TCP)
			ae.Bytes(ctaProtoSrcPort, binary.BigEndian.AppendUint16(nil, flow.from.Port()))
			ae.Bytes(ctaProtoDstPort, binary.BigEndian.AppendUint16(nil, flow.to.Port()))
			return nil
		})
		return nil
	})
	attrs, _ := ae.Encode() // fixed attributes, which always encode
	_, err = c.Send(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<nfnlSubsysShift | ipctnlMsgCtGet), Flags: netlink.Request},
		Data:   append(nfgenmsg(unix.AF_INET6, 0), attrs...),
	})
	if err != nil {
		return false, err
	}
	// The kernel answers with a single message, the connection or an error. It marks the
	// connection NLM_F_MULTI but sends no NLMSG_DONE after it, so Receive would wait for ever:
	// read the one datagram straight from the socket.
	rc, err := c.SyscallConn()
	if err != nil {
		return false, err
	}
	buf := make([]byte, 4096)
	var n int
	var rerr error
	if err := rc.Read(func(fd uintptr) bool {
		n, _, rerr = unix.Recvfrom(int(fd), buf, 0)
		return rerr != unix.EAGAIN
	}); err != nil {
		return false, err
	}
	if rerr != nil {
		return false, rerr
	}
	if n < unix.NLMSG_HDRLEN+4 {
		return false, errors.New("short conntrack reply")
	}
	if nativeEndian.Uint16(buf[4:6]) != unix.NLMSG_ERROR {
		return true, nil
	}
	switch errno := unix.Errno(-int32(nativeEndian.Uint32(buf[unix.NLMSG_HDRLEN:]))); errno {
	case unix.ENOENT:
		return false, nil
	default:
		return false, errno
	}
}
