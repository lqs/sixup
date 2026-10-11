//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// skbCtx is the start of a struct __sk_buff for a test run: the mark and the device.
func skbCtx(ifindex int, mark uint32) []byte {
	b := make([]byte, 44)
	nativeEndian.PutUint32(b[8:], mark)
	nativeEndian.PutUint32(b[40:], uint32(ifindex))
	return b
}

func ethFrame(pkt []byte) []byte {
	proto := uint16(unix.ETH_P_IP)
	if pkt[0]>>4 == 6 {
		proto = unix.ETH_P_IPV6
	}
	return append(binary.BigEndian.AppendUint16(make([]byte, 12), proto), pkt...)
}

// The program translates the host's IPv4 out of sixup-clat and what the NAT64 sends back on the
// WAN, with the errors routers on the way send; on the WAN it leaves everything else to the stack.
func TestCLATProgram(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	wan, err := dummyAdd("clatwan0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer linkDel(wan.Index)
	clat6 := netip.MustParseAddr("2001:db8::c1a7")
	c := &clatManager{wan: "clatwan0", cfg: clatConfig{nat64WKP, clat6, wan.Index, 1500}}
	if err := c.start(); err != nil {
		t.Fatal(err)
	}
	defer c.stop()
	dev, err := net.InterfaceByName(clatDev)
	if err != nil {
		t.Fatal(err)
	}
	if dev.MTU != 1472 {
		t.Errorf("%s should leave room for the IPv6 and fragment headers, has an MTU of %d", clatDev, dev.MTU)
	}
	var frame []byte
	run := func(pkt []byte, ifindex int, mark uint32) (uint32, []byte) {
		t.Helper()
		ret, out, _ := c.objs.testRun(t, ethFrame(pkt), skbCtx(ifindex, mark))
		frame = out
		return ret, out[14:]
	}
	server := "64:ff9b::c000:202"
	udp := func(src, dst []byte) []byte {
		u := []byte{0x30, 0x39, 0, 7, 0, 12, 0, 0, 'p', 'i', 'n', 'g'}
		binary.BigEndian.PutUint16(u[6:], l4Checksum(src, dst, unix.IPPROTO_UDP, u))
		return u
	}

	// Out: from 192.0.0.4, to the NAT64 from the CLAT address
	ret, got := run(v4Packet("192.0.0.4", "192.0.2.2", unix.IPPROTO_UDP, 0, udp([]byte{192, 0, 0, 4}, []byte{192, 0, 2, 2})), dev.Index, 0)
	if ret != 7 || netip.AddrFrom16([16]byte(got[8:24])) != clat6 || netip.AddrFrom16([16]byte(got[24:40])).String() != server ||
		l4Checksum(got[8:24], got[24:40], unix.IPPROTO_UDP, got[40:]) != 0 {
		t.Fatalf("want UDP from %s to %s, got %d % x", clat6, server, ret, got)
	}
	// In: from the NAT64 to the CLAT address, back to 192.0.0.4
	src6, dst6 := netip.MustParseAddr(server).AsSlice(), clat6.AsSlice()
	ret, got = run(v6Packet(server, clat6.String(), unix.IPPROTO_UDP, udp(src6, dst6)), wan.Index, 0)
	if ret != 7 || netip.AddrFrom4([4]byte(got[12:16])).String() != "192.0.2.2" || netip.AddrFrom4([4]byte(got[16:20])) != clat4 ||
		l4Checksum(got[12:16], got[16:20], unix.IPPROTO_UDP, got[20:]) != 0 {
		t.Fatalf("want UDP from 192.0.2.2 to 192.0.0.4, got %d % x", ret, got)
	}
	if !bytes.Equal(frame[:6], dev.HardwareAddr) {
		t.Fatalf("the frame should be addressed to %s, got % x", clatDev, frame[:6])
	}
	// A router on the path reports Packet Too Big about what the host sent: Fragmentation Needed
	// from 192.0.0.8, 20 bytes smaller, about what 192.0.0.4 sent
	quote := v6Packet(clat6.String(), server, unix.IPPROTO_UDP, udp(dst6, src6))
	ptb := append([]byte{2, 0, 0, 0, 0, 0, 0x05, 0x78}, quote...) // MTU 1400
	router := netip.MustParseAddr("2001:db8::1").AsSlice()
	binary.BigEndian.PutUint16(ptb[2:], l4Checksum(router, dst6, unix.IPPROTO_ICMPV6, ptb))
	ret, got = run(v6Packet("2001:db8::1", clat6.String(), unix.IPPROTO_ICMPV6, ptb), wan.Index, 0)
	if icmp := got[20:]; ret != 7 || netip.AddrFrom4([4]byte(got[12:16])) != clatDummy4 || icmp[0] != 3 || icmp[1] != 4 ||
		binary.BigEndian.Uint16(icmp[6:]) != 1380 || netip.AddrFrom4([4]byte(icmp[20:24])) != clat4 || l4Checksum(nil, nil, 0, icmp) != 0 {
		t.Fatalf("want Fragmentation Needed for 1380 from 192.0.0.8, got %d % x", ret, got)
	}

	// Left alone or dropped
	ns := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, dst6...)
	for name, c := range map[string]struct {
		pkt     []byte
		ifindex int
		want    uint32
	}{
		"IPv6 for another address":        {v6Packet(server, "2001:db8::2", unix.IPPROTO_UDP, udp(src6, src6)), wan.Index, 0},
		"IPv4 on the WAN":                 {v4Packet("192.0.2.2", "192.0.0.4", unix.IPPROTO_UDP, 0, udp(nil, nil)), wan.Index, 0},
		"a neighbour solicitation":        {v6Packet("fe80::1", clat6.String(), unix.IPPROTO_ICMPV6, ns), wan.Index, 0},
		"an echo from outside the prefix": {v6Packet("2001:db8::1", clat6.String(), unix.IPPROTO_ICMPV6, []byte{128, 0, 0, 0, 0, 1, 0, 1}), wan.Index, 0},
		"IPv4 from another address":       {v4Packet("10.0.0.1", "192.0.2.2", unix.IPPROTO_UDP, 0, udp(nil, nil)), dev.Index, 2},
		"the device's own IPv6":           {v6Packet("fe80::1", "ff02::2", unix.IPPROTO_ICMPV6, []byte{133, 0, 0, 0, 0, 0, 0, 0}), dev.Index, 2},
	} {
		if ret, _ := run(c.pkt, c.ifindex, 0); ret != c.want {
			t.Errorf("%s: verdict %d, want %d", name, ret, c.want)
		}
	}
	// What the slow path sends back goes on, either way, its mark cleared
	for _, pkt := range [][]byte{v6Packet(clat6.String(), server, unix.IPPROTO_UDP, nil), v4Packet("192.0.2.2", "192.0.0.4", unix.IPPROTO_UDP, 0, nil)} {
		ret, _, ctx := c.objs.testRun(t, ethFrame(pkt), skbCtx(dev.Index, bpfSlowMark))
		if ret != 7 || nativeEndian.Uint32(ctx[8:]) != 0 {
			t.Errorf("a marked packet: verdict %d, mark %#x", ret, nativeEndian.Uint32(ctx[8:]))
		}
	}
}

// A host with no IPv4 of its own reaches an IPv4-only server through its CLAT and the line's
// NAT64, sixup's own here, in a namespace that stands for the ISP.
func TestCLATAgainstANAT64(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	nsOpen := func(name string) (string, int) {
		ns := fmt.Sprintf("sx%d-%s", os.Getpid(), name)
		ip("netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
		fd, err := unix.Open("/var/run/netns/"+ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return ns, fd
	}
	isp, ispFD := nsOpen("isp")
	srv, srvFD := nsOpen("srv")
	ip("link", "add", "wan0", "type", "veth", "peer", "name", "eth0", "netns", isp)
	ip("-n", isp, "link", "add", "up0", "type", "veth", "peer", "name", "eth0", "netns", srv)
	ip("link", "set", "wan0", "up")
	ip("addr", "add", "2001:db8:1::2/64", "dev", "wan0", "nodad")
	ip("route", "add", "default", "via", "2001:db8:1::1")
	ip("-n", isp, "link", "set", "eth0", "up")
	ip("-n", isp, "link", "set", "up0", "up")
	ip("-n", isp, "addr", "add", "2001:db8:1::1/64", "dev", "eth0", "nodad")
	ip("-n", isp, "addr", "add", "192.0.2.1/24", "dev", "up0")
	ip("-n", srv, "link", "set", "eth0", "up")
	ip("-n", srv, "addr", "add", "192.0.2.2/24", "dev", "eth0")
	ip("netns", "exec", isp, "sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding; echo 1 > /proc/sys/net/ipv4/ip_forward")
	if out, err := exec.Command("ip", "netns", "exec", isp, "nft", "add table ip t; add chain ip t post { type nat hook postrouting priority 100; }; add rule ip t post oifname up0 masquerade").CombinedOutput(); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	nat64 := &bpfNAT64{prefix: nat64WKP}
	if err := inNetns(ispFD, nat64.start); err != nil {
		t.Fatal(err)
	}
	defer inNetns(ispFD, func() error { nat64.stop(); return nil })

	// The server echoes TCP and UDP
	var tl net.Listener
	var ul net.PacketConn
	if err := inNetns(srvFD, func() (err error) {
		if tl, err = net.Listen("tcp4", "192.0.2.2:7"); err != nil {
			return err
		}
		ul, err = net.ListenPacket("udp4", "192.0.2.2:7")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	defer ul.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	go func() {
		buf := make([]byte, 4000)
		for {
			n, a, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			ul.WriteTo(buf[:n], a)
		}
	}()

	// The line announces the NAT64's prefix; the WAN's address manager would add the CLAT address
	var logged lockedBuffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	bpfTick = 20 * time.Millisecond
	defer func() { bpfTick = time.Minute }()
	snap := Snapshot{PREF64: nat64WKP, WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Source: sourceRA, SLAAC: true, Valid: time.Now().Add(time.Hour)}}}
	secret := []byte("secret")
	a := snap.clatAddr(secret)
	wan, _ := net.InterfaceByName("wan0")
	if err := addrSet(wan.Index, a, 128, 0, 0, true, ifaFNodad); err != nil {
		t.Fatal(err)
	}
	ch := make(chan Snapshot)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	c := &clatManager{wan: "wan0", secret: secret, sysctl: true}
	go func() { c.run(ctx, ch); close(done) }()
	ch <- snap
	ch <- snap // nothing new
	ping := func(args ...string) ([]byte, error) {
		return exec.Command("ping", append([]string{"-c", "1", "-W", "2"}, append(args, "192.0.2.2")...)...).CombinedOutput()
	}
	if out, err := ping(); err != nil {
		t.Fatalf("ping through the CLAT: %v\n%s", err, out)
	}
	for path, want := range map[string]string{"/proc/sys/net/ipv4/conf/" + clatDev + "/rp_filter": "2", "/proc/sys/net/ipv6/conf/" + clatDev + "/disable_ipv6": "1"} {
		if b, _ := os.ReadFile(path); strings.TrimSpace(string(b)) != want {
			t.Errorf("%s = %q, want %s", path, b, want)
		}
	}
	if out, _ := exec.Command("ip", "route", "show", "default").CombinedOutput(); !bytes.Contains(out, []byte("dev "+clatDev)) || !bytes.Contains(out, []byte("src 192.0.0.4 metric 4294967295")) {
		t.Errorf("want a default route of last resort through %s:\n%s", clatDev, out)
	}

	payload := bytes.Repeat([]byte("sixup clat "), 100000)
	tc, err := net.DialTimeout("tcp4", "192.0.2.2:7", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { tc.Write(payload); tc.(*net.TCPConn).CloseWrite() }()
	if got, err := io.ReadAll(tc); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("TCP echoed %d bytes of %d: %v", len(got), len(payload), err)
	}
	tc.Close()
	for _, size := range []int{5, 3000} {
		uc, err := net.Dial("udp4", "192.0.2.2:7")
		if err != nil {
			t.Fatal(err)
		}
		uc.SetDeadline(time.Now().Add(2 * time.Second))
		uc.Write(make([]byte, size))
		buf := make([]byte, 4000)
		if n, err := uc.Read(buf); err != nil || n != size {
			t.Fatalf("UDP of %d bytes echoed %d: %v", size, n, err)
		}
		uc.Close()
	}
	// A fragmented ping takes the slow path out of the host and back into it
	if out, err := ping("-s", "3000"); err != nil {
		t.Fatalf("a fragmented ping: %v\n%s", err, out)
	}
	// The IPv4 path's MTU reaches the host through the NAT64, and that of the IPv6 path from the
	// router that cannot forward
	ip("-n", isp, "link", "set", "up0", "mtu", "1400")
	ping("-s", "1400", "-M", "do")
	if out, _ := exec.Command("ip", "route", "get", "192.0.2.2").CombinedOutput(); !bytes.Contains(out, []byte("mtu 1400")) {
		t.Errorf("the host should have learnt an MTU of 1400:\n%s", out)
	}
	ip("-n", isp, "link", "set", joolOutside, "mtu", "1300")
	ping("-s", "1300", "-M", "do")
	if out, _ := exec.Command("ip", "route", "get", "192.0.2.2").CombinedOutput(); !bytes.Contains(out, []byte("mtu 1280")) {
		t.Errorf("the host should have learnt an MTU of 1280 from the IPv6 path:\n%s", out)
	}
	// An IPv4 option the translation cannot carry is dropped and reported
	ping("-R")
	for deadline := time.Now().Add(2 * time.Second); !strings.Contains(logged.String(), "[clat] dropped so far: protocol 1"); {
		if time.Now().After(deadline) {
			t.Fatalf("the drop should be reported:\n%s", logged.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Without the PREF64 the CLAT goes, its device and route with it, and nothing is reported
	ch <- Snapshot{}
	time.Sleep(3 * bpfTick)
	cancel()
	<-done
	if _, err := net.InterfaceByName(clatDev); err == nil {
		t.Fatalf("%s should be gone", clatDev)
	}
	if !strings.Contains(logged.String(), "[clat] stopped") {
		t.Errorf("the stop should be reported:\n%s", logged.String())
	}
}

// The CLAT is built only on an Ethernet WAN that is there, and whatever fails part way, start
// leaves nothing behind.
func TestCLATWithoutItsNeeds(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	var logged lockedBuffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	snap := Snapshot{PREF64: nat64WKP, WAN: []Prefix{{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Source: sourceRA, SLAAC: true, Valid: time.Now().Add(time.Hour)}}}
	loUp(t)
	for _, wan := range []string{"lo", "absent0"} {
		c := &clatManager{wan: wan}
		c.apply(snap)
		c.apply(snap)
		if c.objs != nil {
			t.Fatalf("%s: no CLAT should be built", wan)
		}
	}
	if n := strings.Count(logged.String(), "no Ethernet link"); n != 1 {
		t.Fatalf("a WAN without Ethernet should be reported once, %d times:\n%s", n, logged.String())
	}

	wan, err := dummyAdd("clatwan0", 0)
	if err != nil {
		t.Fatal(err)
	}
	c := &clatManager{wan: "clatwan0", cfg: clatConfig{nat64WKP, netip.MustParseAddr("2001:db8::c1a7"), wan.Index, 1500}}
	if err := c.start(); err != nil {
		t.Fatal(err)
	}
	c.stop()
	for extra := 0; ; extra++ {
		if extra > 500 {
			t.Fatal("start never succeeded")
		}
		err := joolWithFDs(t, extra, c.start)
		if err == nil {
			break
		}
		if _, err := net.InterfaceByName(clatDev); err == nil {
			t.Fatalf("with room for %d descriptors start failed and left %s", extra, clatDev)
		}
	}
	c.stop()
	// A start that fails is reported: without the right to create the device
	c = &clatManager{wan: "clatwan0", secret: []byte("s")}
	if err := syscall.Setresuid(-1, 65534, -1); err != nil {
		t.Fatal(err)
	}
	c.apply(snap)
	if err := syscall.Setresuid(-1, 0, -1); err != nil {
		t.Fatal(err)
	}
	if c.objs != nil || !strings.Contains(logged.String(), "cannot create "+clatDev) {
		t.Fatalf("the failure should be reported:\n%s", logged.String())
	}
}
