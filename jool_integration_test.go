//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
	"golang.org/x/sys/unix"
)

// The namespace Jool runs in: without the module no translation happens, but the plumbing around
// it can be checked. 64:ff9b::/96 and the pool4 address are routed into it, IPv4 reaches the
// namespace and comes back, and closing the descriptor takes the namespace and the veth away.
func TestJoolNamespaceAgainstKernel(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	link := netip.MustParsePrefix("192.168.255.254/31")
	if err := checkJoolIPv4(link); err != nil {
		t.Fatalf("an empty namespace has nothing to overlap: %v", err)
	}
	m := &joolManager{prefix: nat64WKP, link: link}
	if err := m.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(routeTypes(t, nat64WKP)) != 1 {
		t.Fatalf("%s is not routed into the namespace", nat64WKP)
	}
	outside, inside := joolAddrs(link)

	// A UDP socket opened inside stays there; a datagram from outside has to reach it and the
	// answer has to find its way back
	var srv *net.UDPConn
	if err := inNetns(m.ns, func() error {
		var err error
		srv, err = net.ListenUDP("udp4", &net.UDPAddr{IP: inside.AsSlice(), Port: 9999})
		return err
	}); err != nil {
		t.Fatalf("listening inside: %v", err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: inside.AsSlice(), Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cli.Write([]byte("ping"))
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, from, err := srv.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("nothing reached the namespace: %v", err)
	}
	if got, _ := netip.AddrFromSlice(from.IP.To4()); got != outside {
		t.Fatalf("the host's side should talk from %s, got %s", outside, got)
	}
	srv.WriteToUDP([]byte("pong"), from)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := cli.Read(buf); err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("the answer did not come back: %v", err)
	}

	// Jool's output is forwarded inside, and untranslated packets for the prefix are refused there
	if err := inNetns(m.ns, func() error {
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			t.Errorf("IPv4 forwarding is off inside: %q %v", b, err)
		}
		// Jool accepts a pool4 only clear of the ephemeral range
		b, err = os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if f := strings.Fields(string(b)); err != nil || len(f) != 2 || f[0] != "65534" || f[1] != "65535" {
			t.Errorf("the ephemeral range inside should sit above pool4: %q %v", b, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A second run may start while the kernel still tears down the first one's namespace: its veth
	// is no conflict, and building a new pair replaces it
	if err := checkJoolIPv4(link); err != nil {
		t.Fatalf("the veth of an earlier run must not count as a conflict: %v", err)
	}
	srv.Close()
	cli.Close()
	st := newStore("pd", nil, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	again := &joolManager{prefix: nat64WKP, link: link, store: st}
	if err := again.setup(); err != nil {
		t.Fatalf("setup over an earlier run's veth: %v", err)
	}
	// start would get here once Jool had its instance; without the module the test stands in for it
	again.active = true
	st.SetNAT64(nat64WKP)
	recv(t, ch)
	unix.Close(m.ns)

	// Anything else routing into the /31 is
	if err := routeSet(1, netip.MustParsePrefix("192.168.255.0/24"), netip.Addr{}, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := checkJoolIPv4(link); err == nil {
		t.Fatal("a /31 inside another route must be refused")
	}
	routeDel(1, netip.MustParsePrefix("192.168.255.0/24"), netip.Addr{}, 0)

	again.stop()
	if s := recv(t, ch); s.NAT64.IsValid() {
		t.Fatal("stopping must withdraw the prefix from the RA")
	}
	// The kernel tears a namespace down in the background, which takes seconds
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := net.InterfaceByName(joolOutside); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the veth outlived the namespace")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// joolSkipIfLoaded skips a test of what happens without Jool where the module is there.
func joolSkipIfLoaded(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(joolModule); err == nil {
		t.Skip("the jool module is loaded")
	}
}

// joolDropVeth removes the outside end a failed setup left behind, rather than waiting the seconds
// the kernel takes to tear its namespace down.
func joolDropVeth() {
	if ifi, err := net.InterfaceByName(joolOutside); err == nil {
		linkDel(ifi.Index)
	}
}

// joolWithFDs runs fn with room for only extra more descriptors in the process, which makes the
// next netlink socket fail to open. It returns what fn returned.
func joolWithFDs(t *testing.T, extra int, fn func() error) error {
	t.Helper()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd) // the lowest free descriptor, which the next open takes
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: uint64(fd + extra), Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	defer syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old)
	return fn()
}

// Without the module, the check tries modprobe once and reports the failure; NAT64 that was
// running when the module went away is stopped and the prefix withdrawn from the RA.
func TestJoolCheckWithoutTheModule(t *testing.T) {
	joolSkipIfLoaded(t)
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	st := newStore("pd", nil, time.Second, nil, false, 0, 0, "")
	ch := st.Subscribe()
	recv(t, ch)
	m := &joolManager{prefix: nat64WKP, link: netip.MustParsePrefix("192.168.255.254/31"), store: st}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	m.run(ctx)
	if !m.probed || !strings.Contains(m.lastErr, "does not look loaded") {
		t.Fatalf("want modprobe tried and the missing module reported, got probed=%v %q", m.probed, m.lastErr)
	}

	ns, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0) // stands in for the namespace
	if err != nil {
		t.Fatal(err)
	}
	m.active, m.ns, m.family = true, ns, 1
	st.SetNAT64(nat64WKP)
	recv(t, ch)
	m.check()
	if m.active {
		t.Fatal("NAT64 must stop with the module gone")
	}
	if s := recv(t, ch); s.NAT64.IsValid() {
		t.Fatal("the prefix must be withdrawn from the RA")
	}
	if !bytes.Contains(logged.Bytes(), []byte("NAT64 stopped")) {
		t.Fatalf("the stop should be reported:\n%s", logged.String())
	}
}

// start builds the namespace, and when Jool cannot be configured in it closes it again. A setup
// that fails part way is undone the same way.
func TestJoolStartWithoutTheModule(t *testing.T) {
	joolSkipIfLoaded(t)
	enterNetNS(t)
	loUp(t)
	if err := checkJoolIPv4(netip.MustParsePrefix("127.0.0.0/31")); err == nil || !strings.Contains(err.Error(), "overlaps the address") {
		t.Fatalf("a /31 inside lo's 127.0.0.0/8 must be refused, got %v", err)
	}
	m := &joolManager{prefix: nat64WKP, link: netip.MustParsePrefix("192.168.255.254/31")}
	if err := m.start(1); err == nil || !strings.Contains(err.Error(), "does not look loaded") || m.active {
		t.Fatalf("without the module start fails in the namespace, got %v, active %v", err, m.active)
	}
	joolDropVeth()

	// From an odd address the two ends fall in different /31s, so Jool's side has no route to the
	// gateway
	m.link = netip.MustParsePrefix("10.0.0.1/32")
	if err := m.start(1); err == nil || !strings.Contains(err.Error(), "cannot build the namespace") {
		t.Fatalf("an unreachable gateway must fail the setup, got %v", err)
	}
	joolDropVeth()
	m.link = netip.MustParsePrefix("192.168.255.254/31")

	// An IPv4 pool6 cannot be routed through the veth's IPv6 next hop
	m.prefix = netip.MustParsePrefix("10.0.0.0/8")
	if err := m.setup(); err == nil || !strings.Contains(err.Error(), "route 10.0.0.0/8") {
		t.Fatalf("want the route refused, got %v", err)
	}
	joolDropVeth()
	m.prefix = nat64WKP

	// With IPv6 off on new interfaces the veth cannot take its link-local next hop
	const dflt = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
	if err := sysctlWrite(dflt, "1"); err != nil {
		t.Fatal(err)
	}
	err := m.setup()
	sysctlWrite(dflt, "0")
	if err == nil || !strings.Contains(err.Error(), joolLLOutside.String()+" on "+joolOutside) {
		t.Fatalf("want the link-local address refused, got %v", err)
	}
	joolDropVeth()

	// Out of descriptors: first for the namespace itself, then for the netlink socket that would
	// create the veth pair
	for extra := range 2 {
		if err := joolWithFDs(t, extra, m.setup); !errors.Is(err, unix.EMFILE) {
			t.Fatalf("with room for %d descriptors, want EMFILE, got %v", extra, err)
		}
	}
	if err := joolWithFDs(t, 0, func() error { return checkJoolIPv4(m.link) }); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("listing the interfaces needs a socket, got %v", err)
	}
	if err := joolWithFDs(t, 0, func() error { _, err := routes4(); return err }); !errors.Is(err, unix.EMFILE) {
		t.Fatalf("listing the routes needs a socket, got %v", err)
	}
}

// Each step of bringing a veth end up names what failed.
func TestJoolLinkUpReportsFailures(t *testing.T) {
	enterNetNS(t)
	loUp(t)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	v4 := netip.MustParsePrefix("192.0.2.0/31")
	if err := joolLinkUp(&net.Interface{Index: 9999, Name: "absent"}, joolLLOutside, v4); err == nil || !strings.Contains(err.Error(), "absent up") {
		t.Fatalf("a missing interface cannot come up, got %v", err)
	}
	if err := joolLinkUp(lo, netip.MustParseAddr("ff02::1"), v4); err == nil || !strings.Contains(err.Error(), "ff02::1 on lo") {
		t.Fatalf("a multicast address cannot be assigned, got %v", err)
	}
	if err := joolLinkUp(lo, joolLLOutside, netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 33)); err == nil || !strings.Contains(err.Error(), " on lo") {
		t.Fatalf("a prefix longer than 32 bits cannot be assigned, got %v", err)
	}
}

// With a module that only looks loaded, its version is read, and the missing netlink family stops
// every request. The version file is faked in a mount namespace of this thread alone.
func TestJoolAgainstAFakeModule(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting needs root")
	}
	joolSkipIfLoaded(t)
	runtime.LockOSThread() // never unlocked: the thread leaves with its mount namespace
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		t.Skipf("cannot enter a mount namespace of my own: %v", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(joolModule)
	if err := unix.Mount("sixup-test", filepath.Dir(dir), "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount over %s: %v", filepath.Dir(dir), err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"4.1\n", "4.1.x.0\n"} {
		if err := os.WriteFile(joolModule, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := joolVersion(); err == nil || !strings.Contains(err.Error(), "cannot read the jool version") {
			t.Fatalf("%q is no version, got %v", bad, err)
		}
	}
	if err := os.WriteFile(joolModule, []byte("4.1.13.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := joolVersion(); err != nil || v != 0x04010d00 {
		t.Fatalf("4.1.13.0 is 0x04010d00, got %#x %v", v, err)
	}
	if _, err := joolFamily(); err == nil || !strings.Contains(err.Error(), "offers no Jool netlink family") {
		t.Fatalf("want the missing family reported, got %v", err)
	}
	removeOldInstance() // finds no family and leaves
	m := &joolManager{prefix: nat64WKP, link: netip.MustParsePrefix("192.168.255.254/31")}
	if err := m.configure(); err == nil || !strings.Contains(err.Error(), "offers no Jool netlink family") {
		t.Fatalf("want the missing family reported, got %v", err)
	}
}

// joolRequest against families the kernel always has: one refusing the request, and one answering
// it with a reply that carries no report of Jool's.
func TestJoolRequestOverGenericNetlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SEG6 answers root only")
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctrl, err := c.GetFamily("nlctrl")
	if err != nil {
		t.Fatal(err)
	}
	// nlctrl's GETFAMILY has Jool's INSTANCE_RM number, and refuses a request naming no family
	if err := joolRequest(c, ctrl.ID, 0, opInstanceRm, nil); err == nil {
		t.Fatal("the refusal should come back as an error")
	}
	seg6, err := c.GetFamily("SEG6")
	if err != nil {
		t.Skipf("no SEG6 family: %v", err)
	}
	const seg6CmdGetTunsrc = 4 // SEG6_CMD_GET_TUNSRC, which ignores what it is sent
	if err := joolRequest(c, seg6.ID, 0, seg6CmdGetTunsrc, nil); err != nil {
		t.Fatalf("a plain reply is a success, got %v", err)
	}
}
