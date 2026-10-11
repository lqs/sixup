//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// An IPv6-only client reaches an IPv4-only server through the BPF translator and the router's
// masquerade, and the router reaches it too. The server sees the router's address, so the reply
// finds its way back only through conntrack, the pool route and the translator.
func TestBPFNAT64(t *testing.T) { bpfEndToEnd(t, nat64WKP) }

// The same behind a network-specific /64, where RFC 6052 skips the u octet.
func TestBPFNAT64BehindA64(t *testing.T) {
	bpfEndToEnd(t, netip.MustParsePrefix("2001:db8:64::/64"))
}

func bpfEndToEnd(t *testing.T, prefix netip.Prefix) {
	if !ownNetns(t) {
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("needs nft for the masquerade")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	nsOpen := func(name string) int {
		ns := fmt.Sprintf("sx%d-%s", os.Getpid(), name)
		ip("netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
		fd, err := unix.Open("/var/run/netns/"+ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		ip("link", "add", name, "type", "veth", "peer", "name", "eth0", "netns", ns)
		ip("link", "set", name, "up")
		ip("-n", ns, "link", "set", "eth0", "up")
		return fd
	}
	client, server := nsOpen("lan0"), nsOpen("wan0")
	for _, s := range []string{"net/ipv6/conf/all/forwarding", "net/ipv4/ip_forward"} {
		if err := sysctlWrite("/proc/sys/"+s, "1"); err != nil {
			t.Fatal(err)
		}
	}
	ip("addr", "add", "2001:db8:1::1/64", "dev", "lan0", "nodad")
	ip("addr", "add", "192.0.2.1/24", "dev", "wan0")
	cns := fmt.Sprintf("sx%d-lan0", os.Getpid())
	sns := fmt.Sprintf("sx%d-wan0", os.Getpid())
	ip("-n", cns, "addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
	ip("-n", cns, "route", "add", "default", "via", "2001:db8:1::1")
	ip("-n", sns, "addr", "add", "192.0.2.2/24", "dev", "eth0")
	// The masquerade, and conntrack for IPv6 as sixup's firewall has it, which reassembles IPv6
	// fragments for the device to cut again
	if out, err := exec.Command("nft", "add table ip t; add chain ip t post { type nat hook postrouting priority 100; }; add rule ip t post oifname wan0 masquerade; "+
		"add table inet f; add chain inet f filt { type filter hook forward priority 0; }; add rule inet f filt ct state invalid counter").CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}

	// The server: TCP and UDP echo on port 7, recording where UDP came from; 1400 bytes that must
	// not be fragmented in answer to anything on port 8; an echo without a UDP checksum on port
	// 11; and an echo cut into 1000-byte datagrams by UDP GSO on port 13
	var last atomic.Pointer[net.UDPAddr]
	var tl net.Listener
	var echo, big, nocheck, gso net.PacketConn
	setsockopt := func(c net.PacketConn, level, opt, v int) error {
		rc, err := c.(*net.UDPConn).SyscallConn()
		if err != nil {
			return err
		}
		var serr error
		rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), level, opt, v) })
		return serr
	}
	if err := inNetns(server, func() (err error) {
		if tl, err = net.Listen("tcp4", "192.0.2.2:7"); err != nil {
			return err
		}
		for _, l := range []struct {
			c    *net.PacketConn
			port string
		}{{&echo, "7"}, {&big, "8"}, {&nocheck, "11"}, {&gso, "13"}} {
			if *l.c, err = net.ListenPacket("udp4", "192.0.2.2:"+l.port); err != nil {
				return err
			}
		}
		return errors.Join(
			setsockopt(big, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO),
			setsockopt(nocheck, unix.SOL_SOCKET, unix.SO_NO_CHECK, 1),
			setsockopt(gso, unix.SOL_UDP, unix.UDP_SEGMENT, 1000))
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{tl, echo, big, nocheck, gso} {
		defer c.Close()
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	serve := func(c net.PacketConn, answer func([]byte) []byte) {
		buf := make([]byte, 4000)
		for {
			n, a, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			last.Store(a.(*net.UDPAddr))
			c.WriteTo(answer(buf[:n]), a)
		}
	}
	same := func(b []byte) []byte { return b }
	go serve(echo, same)
	go serve(big, func([]byte) []byte { return make([]byte, 1400) })
	go serve(nocheck, same)
	go serve(gso, same)

	b := &bpfNAT64{prefix: prefix, lans: []string{"lan0"}}
	if err := b.start(); err != nil {
		t.Fatal(err)
	}
	noDrops := func(what string) {
		t.Helper()
		if d := b.drops(); d != "" {
			t.Fatalf("%s: nothing should be dropped, got %q", what, d)
		}
	}

	dst := netip.AddrFrom16(embed4(prefix, [4]byte{192, 0, 2, 2})).String()
	ping := func(args ...string) ([]byte, error) {
		return exec.Command("ip", append([]string{"netns", "exec", cns, "ping", "-c", "1", "-W", "2"}, append(args, dst)...)...).CombinedOutput()
	}
	if out, err := ping(); err != nil {
		t.Fatalf("the client's ping: %v\n%s", err, out)
	}
	if out, err := exec.Command("ping", "-c", "1", "-W", "2", dst).CombinedOutput(); err != nil {
		t.Fatalf("the router's own ping: %v\n%s", err, out)
	}

	// Enough TCP for the veth to merge segments, both ways
	payload := bytes.Repeat([]byte("sixup nat64 "), 100000)
	if err := inNetns(client, func() error {
		c, err := net.DialTimeout("tcp6", "["+dst+"]:7", 3*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		go func() { c.Write(payload); c.(*net.TCPConn).CloseWrite() }()
		got, err := io.ReadAll(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("TCP echoed %d bytes of %d", len(got), len(payload))
		}
		return nil
	}); err != nil {
		t.Fatalf("TCP: %v", err)
	}

	// dial opens a UDP socket of the client's to port
	dial := func(port string) *net.UDPConn {
		t.Helper()
		var c net.Conn
		if err := inNetns(client, func() (err error) {
			c, err = net.Dial("udp6", "["+dst+"]:"+port)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c.(*net.UDPConn)
	}
	// udp sends size bytes to port and returns what comes back
	udp := func(port string, size int) ([]byte, error) {
		c := dial(port)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(bytes.Repeat([]byte{'x'}, size)); err != nil {
			return nil, err
		}
		buf := make([]byte, 4000)
		n, err := c.Read(buf)
		return buf[:n], err
	}
	if got, err := udp("7", 5); err != nil || len(got) != 5 {
		t.Fatalf("UDP echoed %d bytes: %v", len(got), err)
	}
	if a := last.Load(); a.IP.String() != "192.0.2.1" {
		t.Fatalf("the server should see the router's address, got %s", a)
	}

	// Fragments both ways: the client's datagram leaves its 1500 link in three pieces, and so does
	// the echo the server's kernel cuts
	if got, err := udp("7", 3000); err != nil || len(got) != 3000 {
		t.Fatalf("a fragmented UDP echo came back with %d bytes: %v", len(got), err)
	}
	// Fragmented ICMP goes through the slow path, both ways, for the client and the router alike
	if out, err := ping("-s", "3000"); err != nil {
		t.Fatalf("a fragmented ping: %v\n%s", err, out)
	}
	if out, err := exec.Command("ping", "-c", "1", "-W", "2", "-s", "3000", dst).CombinedOutput(); err != nil {
		t.Fatalf("the router's own fragmented ping: %v\n%s", err, out)
	}
	// UDP without a checksum gets one, whole and in fragments
	for _, size := range []int{5, 3000} {
		if got, err := udp("11", size); err != nil || len(got) != size {
			t.Fatalf("UDP without a checksum, %d bytes, came back with %d: %v", size, len(got), err)
		}
	}
	// UDP GSO both ways: three datagrams sent as one, echoed one by one, and echoed as one
	for _, port := range []string{"7", "13"} {
		c := dial(port)
		rc, _ := c.SyscallConn()
		if port == "7" {
			rc.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 1000) })
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(make([]byte, 3000)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4000)
		for i := range 3 {
			if n, err := c.Read(buf); err != nil || n != 1000 {
				t.Fatalf("UDP GSO to port %s: datagram %d has %d bytes: %v", port, i, n, err)
			}
		}
	}
	noDrops("after the slow path and GSO")

	// ICMP errors come back translated, quoting the packet the client sent
	if _, err := udp("9", 5); !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("a closed port should be refused, got %v", err)
	}
	if out, _ := ping("-t", "2"); !bytes.Contains(out, []byte("Time exceeded")) {
		t.Fatalf("a ping that runs out of hops should hear so:\n%s", out)
	}
	// An error quoting the first fragment of a datagram: the server's to the client gets a
	// fragment header in its quote, and the client's to the server loses it
	c := dial("7")
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("hi"))
	c.Read(make([]byte, 16))
	masq, cport := last.Load().Port, c.LocalAddr().(*net.UDPAddr).Port
	quote4 := make([]byte, 28)
	quote4[0], quote4[8], quote4[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(quote4[2:], 1008)
	binary.BigEndian.PutUint16(quote4[4:], 0x1234)
	binary.BigEndian.PutUint16(quote4[6:], 0x2000) // MF
	copy(quote4[12:], net.IPv4(192, 0, 2, 1).To4())
	copy(quote4[16:], net.IPv4(192, 0, 2, 2).To4())
	binary.BigEndian.PutUint16(quote4[10:], l4Checksum(nil, nil, 0, quote4[:20]))
	binary.BigEndian.PutUint16(quote4[20:], uint16(masq))
	binary.BigEndian.PutUint16(quote4[22:], 7)
	binary.BigEndian.PutUint16(quote4[24:], 988)
	unreach := append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, quote4...) // port unreachable
	binary.BigEndian.PutUint16(unreach[2:], l4Checksum(nil, nil, 0, unreach))
	if err := inNetns(server, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, unreach, 0, &unix.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 16)); !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("an error quoting an IPv4 fragment should reach the client, got %v", err)
	}
	var icmp4 int
	if err := inNetns(server, func() (err error) {
		icmp4, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(icmp4)
	unix.SetsockoptTimeval(icmp4, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	quote6 := make([]byte, 56)
	quote6[0], quote6[6], quote6[7] = 0x60, unix.IPPROTO_FRAGMENT, 64
	binary.BigEndian.PutUint16(quote6[4:], 1008)
	copy(quote6[8:], netip.MustParseAddr(dst).AsSlice())
	copy(quote6[24:], netip.MustParseAddr("2001:db8:1::2").AsSlice())
	quote6[40] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(quote6[42:], 1) // offset 0, M
	binary.BigEndian.PutUint32(quote6[44:], 0xabcd1234)
	binary.BigEndian.PutUint16(quote6[48:], 7)
	binary.BigEndian.PutUint16(quote6[50:], uint16(cport))
	binary.BigEndian.PutUint16(quote6[52:], 1000)
	if err := inNetns(client, func() error {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		msg := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, quote6...) // the kernel fills in the checksum
		return unix.Sendto(fd, msg, 0, &unix.SockaddrInet6{Addr: netip.MustParseAddr(dst).As16()})
	}); err != nil {
		t.Fatal(err)
	}
	for {
		buf := make([]byte, 1500)
		n, _, err := unix.Recvfrom(icmp4, buf, 0)
		if err != nil {
			t.Fatalf("the server should hear of the client's error: %v", err)
		}
		msg := buf[20:n] // after the IPv4 header
		if len(msg) < 36 || msg[0] != 3 {
			continue
		}
		if msg[1] != 3 || l4Checksum(nil, nil, 0, msg) != 0 {
			t.Fatalf("want a port unreachable with a good checksum, got % x", msg)
		}
		if q := msg[8:]; binary.BigEndian.Uint16(q[6:]) != 0x2000 || binary.BigEndian.Uint16(q[4:]) != 0x1234 || binary.BigEndian.Uint16(q[20:]) != 7 {
			t.Fatalf("the quote should be the first fragment of datagram 0x1234 from port 7, got % x", q)
		}
		break
	}

	// Fragmentation Needed on the IPv4 side reaches the client as Packet Too Big, 20 bytes larger
	ip("link", "set", "wan0", "mtu", "1400")
	ping("-s", "1400", "-M", "do")
	if out, _ := exec.Command("ip", "-n", cns, "-6", "route", "get", dst).CombinedOutput(); !bytes.Contains(out, []byte("mtu 1420")) {
		t.Fatalf("the client should have learnt an MTU of 1420:\n%s", out)
	}
	ip("link", "set", "wan0", "mtu", "1500")
	// Packet Too Big on the IPv6 side reaches the server as Fragmentation Needed, 20 bytes smaller
	ip("link", "set", "lan0", "mtu", "1280")
	udp("8", 5)
	if out, _ := exec.Command("ip", "-n", sns, "route", "get", "192.0.2.1").CombinedOutput(); !bytes.Contains(out, []byte("mtu 1260")) {
		t.Fatalf("the server should have learnt an MTU of 1260:\n%s", out)
	}
	ip("link", "set", "lan0", "mtu", "1500")
	noDrops("after the errors")

	// The mappings stay while conntrack has their flows, and go two sweeps after it forgets them
	mappings := func() int {
		n := 0
		var a4 [4]byte
		var a6 [16]byte
		for it := b.objs.V6Of.Iterate(); it.Next(&a4, &a6); {
			n++
		}
		return n
	}
	before := mappings()
	b.sweep()
	b.sweep()
	if n := mappings(); n == 0 || n != before {
		t.Fatalf("the mappings in use should stay, %d of %d left", n, before)
	}
	conntrackFlush(t)
	b.sweep()
	if mappings() != before {
		t.Fatal("one sweep without flows should not remove a mapping")
	}
	b.sweep()
	if n := mappings(); n != 0 {
		t.Fatalf("the idle mappings should go, %d left", n)
	}
	b.stop()

	// run announces the prefix while it translates, reports what is dropped as it changes, and
	// leaves nothing behind
	var logged lockedBuffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	bpfTick = 20 * time.Millisecond
	defer func() { bpfTick = time.Minute }()
	st := newStore("pd", nil, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { (&bpfNAT64{prefix: prefix, store: st}).run(ctx); close(done) }()
	if s := recv(t, ch); s.NAT64 != prefix {
		t.Fatalf("the prefix should be announced once translated, got %v", s.NAT64)
	}
	if out, err := ping(); err != nil {
		t.Fatalf("the ping through run: %v\n%s", err, out)
	}
	if err := inNetns(client, func() error {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_SCTP)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, make([]byte, 12), 0, &unix.SockaddrInet6{Addr: netip.MustParseAddr(dst).As16()})
	}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); !strings.Contains(logged.String(), "dropped so far: protocol 1"); {
		if time.Now().After(deadline) {
			t.Fatalf("the SCTP packet's drop should be reported:\n%s", logged.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if s := recv(t, ch); s.NAT64.IsValid() {
		t.Fatal("the prefix must be withdrawn when the translator stops")
	}
	if _, err := net.InterfaceByName(joolOutside); err == nil {
		t.Fatalf("%s should be gone", joolOutside)
	}
}

// When start fails, run says so and returns, announcing nothing.
func TestBPFNAT64RunWithoutDescriptors(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	net.InterfaceByName("lo") // the runtime's poller takes its descriptor now
	var logged lockedBuffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	joolWithFDs(t, 0, func() error { (&bpfNAT64{prefix: nat64WKP}).run(t.Context()); return nil })
	if !strings.Contains(logged.String(), "cannot create "+joolOutside) {
		t.Fatalf("the failure should be logged:\n%s", logged.String())
	}
}

// lockedBuffer collects the log of a goroutine while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// conntrackFlush empties conntrack's IPv4 table.
func conntrackFlush(t *testing.T) {
	t.Helper()
	c, err := nfDial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const ipctnlMsgCtDelete = 2
	if _, err := c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<nfnlSubsysShift | ipctnlMsgCtDelete), Flags: netlink.Request | netlink.Acknowledge},
		Data:   nfgenmsg(unix.AF_INET, 0),
	}); err != nil {
		t.Fatal(err)
	}
}
