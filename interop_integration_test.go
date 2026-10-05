//go:build linux && integration

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests put sixup against the packaged implementations it meets in the field. Each peer runs
// in a network namespace of its own, joined to sixup's by a veth pair, so neither side's addresses
// or routes leak into the other. A test is skipped when its program is not installed.

func needTools(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s is not installed", n)
		}
	}
}

// peerNetns makes a namespace for the other implementation, with remote in it and local here,
// both up and without DAD. It returns the namespace name for peerRun.
func peerNetns(t *testing.T, local, remote string, remoteAddrs ...string) string {
	t.Helper()
	ns := fmt.Sprintf("sixup-peer-%d", os.Getpid())
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	ip("netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	ip("netns", "exec", ns, "sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad; echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad")
	for _, k := range []string{"all", "default"} {
		if err := sysctlWrite("/proc/sys/net/ipv6/conf/"+k+"/accept_dad", "0"); err != nil {
			t.Fatal(err)
		}
	}
	ip("link", "add", local, "type", "veth", "peer", "name", remote, "netns", ns)
	ip("link", "set", local, "up")
	ip("-n", ns, "link", "set", "lo", "up")
	ip("-n", ns, "link", "set", remote, "up")
	for _, a := range remoteAddrs {
		ip("-n", ns, "addr", "add", a, "dev", remote, "nodad")
	}
	time.Sleep(200 * time.Millisecond) // link-local addresses
	return ns
}

// peerRun starts a program in the peer namespace and stops it when the test ends.
func peerRun(t *testing.T, ns string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	out, err := os.Create(filepath.Join(t.TempDir(), "peer.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(out.Name())
			t.Logf("%s:\n%s", args[0], b)
		}
	})
	return cmd
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// dryReportOf is the part of a dry-run report these tests look at.
type dryReportOf struct {
	Source  string `json:"source"`
	WANAddr string `json:"wan_addr"`
	WAN     []struct {
		Prefix string `json:"prefix"`
		Source string `json:"source"`
	} `json:"wan_prefixes"`
	LAN map[string][]string `json:"lan_split"`
	DNS []string            `json:"dns"`
}

// dryRunUntil runs sixup -dry-run on wan-test0 until a report satisfies done, and returns that report.
func dryRunUntil(t *testing.T, done func(dryReportOf) bool, args ...string) dryReportOf {
	t.Helper()
	cmd, _, stderr := mainCmd(t, append([]string{"-dry-run", "-wan", "wan-test0", "-state-dir", t.TempDir(), "-settle", "100ms"}, args...)...)
	cmd.Stdout = nil
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	kill := time.AfterFunc(30*time.Second, func() { cmd.Process.Kill() })
	defer kill.Stop()
	var last dryReportOf
	found := false
	for dec := json.NewDecoder(out); ; {
		var r dryReportOf
		if dec.Decode(&r) != nil {
			break
		}
		last = r
		if done(r) && !found {
			found = true
			cmd.Process.Signal(syscall.SIGINT)
		}
	}
	cmd.Wait()
	if !found {
		t.Fatalf("no report matched; last %+v\n%s", last, stderr)
	}
	return last
}

func inPrefix(p string, s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && netip.MustParsePrefix(p).Contains(a)
}

// radvd announces a SLAAC prefix with RDNSS and no M or O bit: sixup takes the /64 from the RA
// alone, computes its WAN address in it and passes the DNS server on.
func TestInteropRadvd(t *testing.T) {
	needTools(t, "ip", "radvd")
	if !ownNetns(t) {
		return
	}
	loUp(t)
	ns := peerNetns(t, "wan-test0", "up-test0")
	conf := writeFile(t, "radvd.conf", `interface up-test0 {
	AdvSendAdvert on;
	MinRtrAdvInterval 3;
	MaxRtrAdvInterval 4;
	prefix 2001:db8:1::/64 { AdvOnLink on; AdvAutonomous on; };
	RDNSS 2001:db8::53 { };
	DNSSL example.net { };
};
`)
	peerRun(t, ns, "radvd", "-n", "-C", conf, "-p", filepath.Join(t.TempDir(), "radvd.pid"), "-m", "stderr")
	r := dryRunUntil(t, func(r dryReportOf) bool {
		return len(r.WAN) > 0 && len(r.DNS) > 0 && inPrefix("2001:db8:1::/64", r.WANAddr)
	})
	if r.WAN[0].Prefix != "2001:db8:1::/64" || r.WAN[0].Source != "ra" || r.DNS[0] != "2001:db8::53" {
		t.Errorf("got %+v", r)
	}
}

// dnsmasq advertises the M bit and hands out addresses by DHCPv6: sixup in auto mode follows the
// RA into a stateful exchange and takes an address from the range, with the DNS server.
func TestInteropDnsmasq(t *testing.T) {
	needTools(t, "ip", "dnsmasq")
	if !ownNetns(t) {
		return
	}
	loUp(t)
	ns := peerNetns(t, "wan-test0", "up-test0", "2001:db8:2::1/64")
	peerRun(t, ns, "dnsmasq", "--keep-in-foreground", "--log-facility=-", "--log-dhcp", "--port=0", "--conf-file=/dev/null",
		"--interface=up-test0", "--bind-interfaces", "--enable-ra", "--ra-param=up-test0,4",
		"--dhcp-range=2001:db8:2::1000,2001:db8:2::1fff,64,1h", "--dhcp-option=option6:dns-server,[2001:db8::53]",
		"--dhcp-leasefile="+filepath.Join(t.TempDir(), "leases"), "--pid-file="+filepath.Join(t.TempDir(), "pid"))
	r := dryRunUntil(t, func(r dryReportOf) bool {
		return inPrefix("2001:db8:2::1000/116", r.WANAddr) && len(r.DNS) > 0
	}, "-dhcp6c-pd-len", "0")
	if !slices.Contains(r.DNS, "2001:db8::53") {
		t.Errorf("got %+v", r)
	}
}

// Kea delegates a /56 and assigns an address, with no RA at all: the prefix is split for the LAN.
func TestInteropKea(t *testing.T) {
	needTools(t, "ip", "kea-dhcp6")
	if !ownNetns(t) {
		return
	}
	loUp(t)
	ns := peerNetns(t, "wan-test0", "up-test0")
	dir := t.TempDir()
	conf := writeFile(t, "kea.json", `{"Dhcp6": {
	"interfaces-config": {"interfaces": ["up-test0"], "service-sockets-max-retries": 50, "service-sockets-retry-wait-time": 200},
	"lease-database": {"type": "memfile", "persist": false},
	"server-id": {"type": "LL", "persist": false},
	"option-data": [{"name": "dns-servers", "data": "2001:db8::53"}],
	"subnet6": [{
		"id": 1, "subnet": "2001:db8:3::/64", "interface": "up-test0",
		"pools": [{"pool": "2001:db8:3::1000-2001:db8:3::1fff"}],
		"pd-pools": [{"prefix": "2001:db8:100::", "prefix-len": 48, "delegated-len": 56}]
	}],
	"loggers": [{"name": "kea-dhcp6", "output_options": [{"output": "stderr"}], "severity": "INFO"}]
}}
`)
	// Ubuntu confines /usr/sbin/kea-dhcp6 with AppArmor, which keeps it out of the test's
	// directories; the profile is tied to that path, so a copy runs unconfined.
	src, _ := exec.LookPath("kea-dhcp6")
	bin, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	kea := writeFile(t, "kea-dhcp6", string(bin))
	peerRun(t, ns, "env", "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir, kea, "-c", conf)
	r := dryRunUntil(t, func(r dryReportOf) bool {
		return len(r.WAN) > 0 && r.WANAddr != "invalid IP" && len(r.DNS) > 0
	}, "-dhcp6c-mode", "on", "-wan-ra=false", "-dhcp6c-pd-len", "56")
	pd, err := netip.ParsePrefix(r.WAN[0].Prefix)
	if err != nil || pd.Bits() != 56 || !netip.MustParsePrefix("2001:db8:100::/48").Contains(pd.Addr()) || r.WAN[0].Source != "pd" {
		t.Errorf("delegation: %+v", r.WAN)
	}
	if !inPrefix("2001:db8:3::1000/116", r.WANAddr) || !slices.Contains(r.DNS, "2001:db8::53") {
		t.Errorf("got %+v", r)
	}
	if lan := r.LAN["lan"]; len(lan) == 0 || !pd.Contains(netip.MustParsePrefix(lan[0]).Addr()) {
		t.Errorf("LAN split %v is not in %s", r.LAN, pd)
	}
}

// dhcpcd on the LAN side asks sixup for an address and a delegated prefix, and forms one by SLAAC
// from sixup's RA.
func TestInteropDhcpcd(t *testing.T) {
	needTools(t, "ip", "dhcpcd")
	if !ownNetns(t) {
		return
	}
	loUp(t)
	ns := peerNetns(t, "lan-test0", "host-test0")
	if err := vethAdd("wan-test0", "isp-test0", ownNsFd(t)); err != nil {
		t.Fatal(err)
	}
	cmd, _, stderr := mainCmd(t, "-wan", "wan-test0", "-lan", "lan-test0", "-state-dir", t.TempDir(), "-settle", "10ms",
		"-dhcp6c-mode", "off", "-wan-ra=false", "-routed-prefix", "2001:db8:1::/48", "-tunnel-dev", "",
		"-dhcp6s-mode", "stateful", "-dhcp6s-pd-len", "60", "-ra-dns", "self", "-ra-min", "3s", "-ra-max", "4s")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		if t.Failed() {
			t.Logf("sixup:\n%s", stderr)
		}
	})

	env := filepath.Join(t.TempDir(), "env")
	hook := writeFile(t, "hook", "#!/bin/sh\nenv | sort > "+env+".$reason\n")
	conf := writeFile(t, "dhcpcd.conf", `ipv6only
duid
ia_na 1
ia_pd 2 -
option dhcp6_name_servers
`)
	peerRun(t, ns, "dhcpcd", "-B", "-d", "-f", conf, "-c", hook, "host-test0")

	var got string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if b, err := os.ReadFile(env + ".BOUND6"); err == nil {
			got = string(b)
			break
		}
	}
	if got == "" {
		t.Fatal("dhcpcd never bound")
	}
	vars := map[string]string{}
	for line := range strings.Lines(got) {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		vars[k] = v
	}
	// the default pool, 1000-ffff in the LAN's /64
	a, err := netip.ParseAddr(vars["new_dhcp6_ia_na1_ia_addr1"])
	if iid := binary.BigEndian.Uint64(a.AsSlice()[8:]); err != nil || !inPrefix("2001:db8:1::/64", a.String()) || iid < 0x1000 || iid > 0xffff {
		t.Errorf("address %q is not from the pool:\n%s", vars["new_dhcp6_ia_na1_ia_addr1"], got)
	}
	// -ra-dns self: this router's own address on the LAN
	if dns := vars["new_dhcp6_name_servers"]; !inPrefix("2001:db8:1::/64", dns) {
		t.Errorf("DNS server %q is not sixup's LAN address:\n%s", dns, got)
	}
	pd, err := netip.ParsePrefix(vars["new_dhcp6_ia_pd1_prefix1"] + "/" + vars["new_dhcp6_ia_pd1_prefix1_length"])
	if err != nil || pd.Bits() != 60 || !netip.MustParsePrefix("2001:db8:1::/48").Contains(pd.Addr()) {
		t.Errorf("delegated prefix %q:\n%s", pd, got)
	}
	// SLAAC from the RA, alongside the DHCPv6 address
	slaac := false
	for deadline := time.Now().Add(10 * time.Second); !slaac && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		out, _ := exec.Command("ip", "-n", ns, "-6", "addr", "show", "dev", "host-test0", "scope", "global").Output()
		for line := range strings.Lines(string(out)) {
			// the DHCPv6 address is a /128, so a /64 can only come from SLAAC
			if f := strings.Fields(line); len(f) > 1 && f[0] == "inet6" {
				p, err := netip.ParsePrefix(f[1])
				slaac = slaac || err == nil && p.Bits() == 64 && netip.MustParsePrefix("2001:db8:1::/64").Contains(p.Addr())
			}
		}
	}
	if !slaac {
		t.Error("dhcpcd formed no /64 address from the RA")
	}
}

func ownNsFd(t *testing.T) int {
	t.Helper()
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return int(f.Fd())
}
