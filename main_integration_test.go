//go:build linux && integration

package main

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The daemon as a whole on a static prefix: it claims the interfaces, sets the sysctls, brings the
// links up, numbers the LAN, and exits cleanly on SIGTERM.
func TestMainAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	loUp(t)
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	for _, pair := range [][2]string{{"wan-test0", "up-test0"}, {"lan-test0", "host-test0"}} {
		if err := vethAdd(pair[0], pair[1], int(ns.Fd())); err != nil {
			t.Fatal(err)
		}
	}
	// Options only the daemon reads are checked once the components start.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-ra-dns", "nowhere"}, "-ra-dns:"},
		{[]string{"-dhcp6s-mode", "stateless", "-dhcp6s-pool", "1000"}, "must have the form start-end"},
		{[]string{"-dhcp6s-mode", "stateless", "-dhcp6s-pool", "ffff-1000"}, "-dhcp6s-pool \"ffff-1000\" is invalid"},
		{[]string{"-dhcp6s-mode", "stateless", "-dhcp6s-static", "mac=02:00:00:00:00:01,addr=x"}, "has an invalid address"},
		{[]string{"-dhcp6s-mode", "stateless", "-dhcp6s-static", "addr=::100"}, "needs mac or duid, plus addr"},
		{[]string{"-ndproxy-static", "x"}, `"x" is not a valid address or prefix`},
	} {
		args := append([]string{"-wan", "wan-test0", "-lan", "lan-test0", "-no-sysctl", "-dhcp6c-mode", "off", "-wan-ra=false", "-routed-prefix", "2001:db8:1::/48", "-tunnel-dev", ""}, c.args...)
		if _, errOut, code := runMain(t, args...); code != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: exit %d, want 1 with %q:\n%s", c.args, code, c.want, errOut)
		}
	}

	cmd, stdout, _ := mainCmd(t, "-wan", "wan-test0", "-lan", "lan-test0", "-state-dir", t.TempDir(), "-settle", "10ms",
		"-dhcp6c-mode", "off", "-wan-ra=false", "-routed-prefix", "2001:db8:1::/48", "-dhcp6s-mode", "stateful", "-nat64", "jool",
		"-ndproxy-static", "2001:db8:1:1::/64", "-ndproxy-exclude", "2001:db8:1:1::1", "-ra-route", "2001:db8:2::/48")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	kill := time.AfterFunc(20*time.Second, func() { cmd.Process.Kill() })
	defer kill.Stop()
	var stderr strings.Builder
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		stderr.WriteString(sc.Text() + "\n")
		if strings.Contains(sc.Text(), "[sixup] starting") {
			break
		}
	}

	want := netip.MustParsePrefix("2001:db8:1::/64")
	numbered := func() bool {
		ifi, err := net.InterfaceByName("lan-test0")
		if err != nil || ifi.Flags&net.FlagUp == 0 {
			return false
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && want.Contains(p.Addr()) {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(5 * time.Second); !numbered() && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	if !numbered() {
		t.Errorf("lan-test0 got no address in %s", want)
	}
	for path, val := range map[string]string{
		"/proc/sys/net/ipv6/conf/all/forwarding":       "1",
		"/proc/sys/net/ipv6/conf/lan-test0/accept_ra":  "0",
		"/proc/sys/net/ipv6/conf/wan-test0/forwarding": "1",
		"/proc/sys/net/ipv4/ip_forward":                "1",
	} {
		if b, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(b)) != val {
			t.Errorf("%s = %q, %v; want %s", path, b, err, val)
		}
	}
	// A second instance must refuse interfaces the first one holds.
	if _, errOut, code := runMain(t, "-wan", "wan-test0", "-lan", "lan-test0"); code != 1 || !strings.Contains(errOut, "another sixup is already using") {
		t.Errorf("second instance: exit %d:\n%s", code, errOut)
	}

	cmd.Process.Signal(syscall.SIGTERM)
	for sc.Scan() {
		stderr.WriteString(sc.Text() + "\n")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v:\n%s", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("the daemon wrote to stdout:\n%s", stdout)
	}
}

// An address configured on the WAN by hand is left as it is, and sixup adds none beside it: with
// -routed-prefix the LAN takes a /64 of the prefix; with -wan-prefix auto it takes a /128 in the
// /64 of that address, which stays on the WAN.
func TestMainHandConfiguredWANAgainstKernel(t *testing.T) {
	if !ownNetns(t) {
		return
	}
	needTools(t, "ip")
	loUp(t)
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	for _, pair := range [][2]string{{"wan-test0", "up-test0"}, {"lan-test0", "host-test0"}} {
		if err := vethAdd(pair[0], pair[1], int(ns.Fd())); err != nil {
			t.Fatal(err)
		}
	}
	wan, err := net.InterfaceByName("wan-test0")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		wanAddr netip.Prefix
		args    []string
		lan     netip.Prefix // the prefix of the LAN address and its length
	}{
		{netip.MustParsePrefix("2001:db8:ffff::2/126"), []string{"-routed-prefix", "2001:db8:1::/48"}, netip.MustParsePrefix("2001:db8:1::/64")},
		{netip.MustParsePrefix("2001:db8:5:6::2/64"), []string{"-wan-prefix", "auto"}, netip.MustParsePrefix("2001:db8:5:6::/128")},
	} {
		// configured as an administrator would, with both lifetimes infinite
		if out, err := exec.Command("ip", "-6", "addr", "add", c.wanAddr.String(), "dev", "wan-test0", "nodad").CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		args := append([]string{"-wan", "wan-test0", "-lan", "lan-test0", "-state-dir", t.TempDir(), "-settle", "10ms",
			"-dhcp6c-mode", "off", "-tunnel-dev", ""}, c.args...)
		// the /64 of that address stays on the WAN, so it cannot go on the LAN as well
		if c.wanAddr.Bits() == 64 {
			if _, errOut, code := runMain(t, append(args, "-wan-shared64", "lan")...); code != 1 || !strings.Contains(errOut, "-wan-shared64 lan:") {
				t.Errorf("%v: -wan-shared64 lan: exit %d:\n%s", c.args, code, errOut)
			}
		}
		cmd, _, stderr := mainCmd(t, args...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		lanAddr := func() (netip.Prefix, bool) {
			ifi, err := net.InterfaceByName("lan-test0")
			if err != nil {
				return netip.Prefix{}, false
			}
			addrs, _ := ifi.Addrs()
			for _, a := range addrs {
				p, err := netip.ParsePrefix(a.String())
				if err == nil && netip.PrefixFrom(c.lan.Addr(), 64).Contains(p.Addr()) {
					return p, true
				}
			}
			return netip.Prefix{}, false
		}
		got, ok := lanAddr()
		for deadline := time.Now().Add(5 * time.Second); !ok && time.Now().Before(deadline); got, ok = lanAddr() {
			time.Sleep(50 * time.Millisecond)
		}
		if !ok || got.Bits() != c.lan.Bits() {
			t.Errorf("%v: LAN address %v, want one in %s", c.args, got, c.lan)
		}
		list, err := addrList(wan.Index)
		if err != nil {
			t.Fatal(err)
		}
		for _, ia := range list {
			if !ia.Addr.IsLinkLocalUnicast() && (ia.Addr != c.wanAddr.Addr() || ia.PrefixLen != c.wanAddr.Bits() || !handConfigured(ia)) {
				t.Errorf("%v: the WAN has %s/%d flags %#x beside %s", c.args, ia.Addr, ia.PrefixLen, ia.Flags, c.wanAddr)
			}
		}
		cmd.Process.Signal(syscall.SIGTERM)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("%v: %v:\n%s", c.args, err, stderr)
		}
		if !strings.Contains(stderr.String(), "using "+c.wanAddr.Addr().String()+" as the WAN address") {
			t.Errorf("%v: the WAN address is not reported:\n%s", c.args, stderr)
		}
		if err := addrDel(wan.Index, c.wanAddr.Addr(), c.wanAddr.Bits()); err != nil {
			t.Fatal(err)
		}
	}
}
