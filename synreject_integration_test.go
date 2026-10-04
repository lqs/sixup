//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// synrejectNoFiles runs fn with room for only that many more file descriptors.
func synrejectNoFiles(t *testing.T, room int, fn func()) {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(0) // the lowest free descriptor
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	tight := lim
	tight.Cur = uint64(fd + room)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &tight); err != nil {
		t.Fatal(err)
	}
	defer unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
	fn()
}

// synrejectWaitFor polls a /proc/self/net table until a row's column col reads proto, and returns
// the column after it, unless that is 0, the id of the kernel's own socket; with col -1 any row will do.
func synrejectWaitFor(t *testing.T, table string, col int, proto string) string {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		b, err := os.ReadFile("/proc/self/net/" + table)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if f := strings.Fields(line); col < 0 && len(f) > 0 {
				return ""
			} else if col >= 0 && len(f) > col+1 && f[col] == proto && f[col+1] != "0" {
				return f[col+1]
			}
		}
	}
	t.Fatalf("no %s socket of protocol %s", table, proto)
	return ""
}

// synrejectULOG builds an NFLOG packet message with the attributes.
func synrejectULOG(t *testing.T, attrs []byte) netlink.Message {
	t.Helper()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_ULOG<<nfnlSubsysShift | nfulnlMsgPacket)},
		Data:   append(nfgenmsg(unix.AF_INET6, synLogGroup), attrs...),
	}
}

func synrejectPayload(t *testing.T, pkt []byte) netlink.Message {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	ae.Uint8(1, 0) // not the payload
	ae.Bytes(nfulaPayload, pkt)
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return synrejectULOG(t, b)
}

// The NFLOG socket gets messages straight from a socket of ours, as if the kernel logged them,
// so that every kind of message the reader may see can be fed to it.
func TestSYNRejecterAgainstKernel(t *testing.T) {
	if !ownNetns(t) { // the goroutines of rejectSYNs and its timers too
		return
	}
	loUp(t)
	old := synWait
	synWait = 20 * time.Millisecond
	defer func() { synWait = old }()
	f := &firewall{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unreachable := synFlow{from: netip.MustParseAddrPort("[2001:db8:dead::1]:1"), to: netip.MustParseAddrPort("[::1]:22")}

	// Another socket holding the NFLOG group leaves nothing to receive the SYNs with.
	hold, err := nflogBind(synLogGroup, 64)
	if err != nil {
		t.Fatal(err)
	}
	f.rejectSYNs(ctx) // returns at once
	hold.Close()

	// Out of file descriptors: first with room for the NFLOG socket only, then for nothing.
	synrejectNoFiles(t, 1, func() { f.rejectSYNs(ctx) })
	synrejectNoFiles(t, 0, func() {
		if c, err := nflogBind(synLogGroup, 64); err == nil {
			c.Close()
			t.Error("nflogBind without a descriptor to spare")
		}
		if _, err := conntrackHas(unreachable); err == nil {
			t.Error("conntrackHas without a descriptor to spare")
		}
		(&synRejecter{}).due(unreachable, nil) // without conntrack nothing is sent
	})

	done := make(chan struct{})
	go func() { f.rejectSYNs(ctx); close(done) }()
	synrejectWaitFor(t, "raw6", -1, "") // its ICMPv6 socket opens once the group is bound
	portid, err := strconv.ParseUint(synrejectWaitFor(t, "netlink", 1, "12"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	listen, err := icmp.ListenPacket("ip6:ipv6-icmp", "::1")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	inj, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(inj)
	send := func(msgs ...netlink.Message) {
		t.Helper()
		var buf []byte
		for _, m := range msgs {
			// by hand: the length is the exact one, padding follows, as a sender may well do
			buf = binary.NativeEndian.AppendUint32(buf, uint32(16+len(m.Data)))
			buf = binary.NativeEndian.AppendUint16(buf, uint16(m.Header.Type))
			buf = append(buf, make([]byte, 10)...)
			buf = append(buf, m.Data...)
			buf = append(buf, make([]byte, -len(buf)&3)...)
		}
		if err := unix.Sendto(inj, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: uint32(portid)}); err != nil {
			t.Fatal(err)
		}
	}

	// An error, which the reader skips like the ENOBUFS of a burst.
	errno := binary.NativeEndian.AppendUint32(nil, 0xffffffea) // -EINVAL
	send(netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: append(errno, make([]byte, 16)...)})
	ok := netip.MustParseAddrPort("[::1]:40001")
	send(
		synrejectULOG(t, []byte{6, 0}), // less than an attribute header
		synrejectPayload(t, synrejectSegment(ok, unreachable.to, tcpFlagACK)),
		synrejectPayload(t, synrejectSegment(unreachable.from, unreachable.to, tcpFlagSYN)),
		synrejectPayload(t, synrejectSegment(unreachable.from, unreachable.to, tcpFlagSYN)), // a retransmission
		synrejectPayload(t, synrejectSegment(ok, unreachable.to, tcpFlagSYN)),
	)

	// Only the SYN from a reachable sender gets its error back; the other has no route.
	listen.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := listen.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no ICMPv6 error came back: %v", err)
		}
		m, err := icmp.ParseMessage(unix.IPPROTO_ICMPV6, buf[:n])
		if err != nil || m.Type != ipv6.ICMPTypeDestinationUnreachable {
			continue
		}
		body, _ := m.Body.(*icmp.DstUnreach)
		if m.Code != icmpUnreachProhib || body == nil || !bytes.Equal(body.Data[40:42], []byte{40001 >> 8, 40001 & 0xff}) {
			t.Fatalf("code %d, body %+v", m.Code, m.Body)
		}
		break
	}
	time.Sleep(50 * time.Millisecond) // the unreachable sender's turn
	cancel()
	<-done
}

// synrejectWithin fails the test if fn does not return in time, rather than hanging the suite.
func synrejectWithin(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// A connection conntrack knows is open in both directions, so its SYN gets no error.
func TestConntrackHasOpenFlow(t *testing.T) {
	if !ownNetns(t) { // a conntrack table and an nftables table of its own
		return
	}
	loUp(t)
	c := &nftables.Conn{}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "synreject"})
	chain := c.AddChain(&nftables.Chain{Name: "out", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}}})
	if err := c.Flush(); err != nil {
		t.Fatalf("conntrack on: %v", err)
	}
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server, client := netip.MustParseAddrPort(ln.Addr().String()), netip.MustParseAddrPort(conn.LocalAddr().String())
	for _, flow := range []synFlow{{from: client, to: server}, {from: server, to: client}} {
		synrejectWithin(t, "conntrackHas", func() {
			if open, err := conntrackHas(flow); !open || err != nil {
				t.Errorf("%s -> %s: open %v, %v", flow.from, flow.to, open, err)
			}
		})
	}
	// a flow conntrack does not know
	synrejectWithin(t, "conntrackHas", func() {
		other := synFlow{from: netip.MustParseAddrPort("[::1]:1"), to: server}
		if open, err := conntrackHas(other); open || err != nil {
			t.Errorf("%s -> %s: open %v, %v", other.from, other.to, open, err)
		}
	})
	// no ICMPv6 socket needed: an open flow gets no error
	synrejectWithin(t, "due", func() { (&synRejecter{}).due(synFlow{from: server, to: client}, nil) })
}
