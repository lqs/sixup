//go:build linux && integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// treeRouter is one sixup in TestDelegationTreeAgainstKernel, in a namespace of its own with wan0
// on its parent's link and the bridge lan0 as its own.
type treeRouter struct {
	ns     string
	level  int
	plen   int    // of the delegation it gets
	ula    string // -ula of a site of its own, else empty for a part of its parent's ULA
	parent *treeRouter
	state  string
	args   []string
	cmd    *exec.Cmd
	stderr *bytes.Buffer
}

// treeSpec shapes one tree of testDelegationTree.
type treeSpec struct {
	counts  []int             // routers on each level, from the top down to the /64s, then the ones sharing a /64
	plens   []int             // the length each level down to the /64s gets, the top's first
	manual  bool              // every router names the lengths it asks for and delegates, else the defaults decide
	ula     map[[2]int]string // -ula of the routers with a site of their own, by level and index
	restart [][2]int          // the routers restarted once everything is reached
}

// A /32 goes down a tree of sixup routers to /64s, four bits a level, each router naming the
// lengths it asks for and delegates.
func TestDelegationTreeAgainstKernel(t *testing.T) {
	testDelegationTree(t, treeSpec{
		counts:  []int{1, 3, 4, 2, 1, 2, 4, 3, 2, 2, 4, 3},
		plens:   []int{32, 36, 40, 44, 48, 52, 56, 60, 64},
		manual:  true,
		ula:     map[[2]int]string{{0, 0}: "auto", {5, 1}: "auto"},
		restart: [][2]int{{4, 0}, {9, 0}}, // the one every path goes through, and one sharing
	})
}

// The same with the default lengths: every router asks for more than it gets, and each level
// delegates the next of /48, /56, /60 and /64. The top's ULA is as long as its line's prefix, so
// that it lasts down to the /64s too.
func TestDelegationTreeAutoAgainstKernel(t *testing.T) {
	testDelegationTree(t, treeSpec{
		counts:  []int{1, 3, 4, 2, 2, 2, 4, 3},
		plens:   []int{32, 48, 56, 60, 64},
		ula:     map[[2]int]string{{0, 0}: "fd00:1::/32", {2, 1}: "auto"},
		restart: [][2]int{{2, 0}, {5, 0}},
	})
}

// testDelegationTree runs a tree of sixup routers: each router asks its parent for a delegation,
// and the routers behind one parent share its LAN. Below the /64s, more levels of routers share
// their WAN's /64 with their LAN (RFC 7278), the NDP proxy answering across each. The LANs hold
// only routes, so every hop rests on link-local next hops, the delegation routes and the proxy;
// a host behind each router at the bottom and at the end of the sharing reaches the upstream and
// every other host, also after the routers of spec.restart restart. The ULA goes down the same
// way: the routers of spec.ula have a site of their own, the others take a part of their
// parent's or share its /64, and the hosts reach each router of their own site by ULA but not
// one of the other.
func testDelegationTree(t *testing.T, spec treeSpec) {
	needTools(t, "ip", "ping")
	if os.Geteuid() != 0 {
		t.Skip("network namespaces need root")
	}
	counts, bottom := spec.counts, len(spec.plens)-1
	top := netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), spec.plens[0])
	internet := netip.MustParseAddr("2001:db9::1")
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	nsAdd := func(name string) string {
		ns := fmt.Sprintf("sx%d-%s", os.Getpid(), name)
		ip("netns", "add", ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		ip("netns", "exec", ns, "sh", "-c", "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad; echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad")
		ip("-n", ns, "link", "set", "lo", "up")
		return ns
	}
	// veth puts name in ns and peer in the bridge lan0 of up, or bare when up has none
	veth := func(ns, name, up, peer string, bridged bool) {
		ip("link", "add", name, "netns", ns, "type", "veth", "peer", "name", peer, "netns", up)
		ip("-n", ns, "link", "set", name, "up")
		if bridged {
			ip("-n", up, "link", "set", peer, "master", "lan0")
		}
		ip("-n", up, "link", "set", peer, "up")
	}
	linkLocal := func(ns, dev string) netip.Addr {
		t.Helper()
		var a netip.Addr
		eventually(t, 5*time.Second, ns+" "+dev+" has a link-local address", func() bool {
			a = addrOn(ns, dev, "link")
			return a.IsValid()
		})
		return a
	}

	isp := nsAdd("isp")
	ip("-n", isp, "addr", "add", internet.String()+"/128", "dev", "lo")
	var levels [][]*treeRouter
	for l, n := range counts {
		var row []*treeRouter
		for j := range n {
			r := &treeRouter{ns: nsAdd(fmt.Sprintf("r%d-%d", l, j)), level: l, plen: spec.plens[min(l, bottom)], ula: spec.ula[[2]int{l, j}], state: t.TempDir()}
			// a fixed MAC, so the bridge keeps its address as ports join
			ip("-n", r.ns, "link", "add", "lan0", "address", fmt.Sprintf("02:00:00:00:%02x:%02x", l, j), "type", "bridge", "mcast_snooping", "0")
			ip("-n", r.ns, "link", "set", "lan0", "up")
			r.args = []string{"-wan", "wan0", "-lan", "lan0", "-state-dir", r.state, "-tunnel-dev", "",
				"-unsolicited", "allow", "-ra-min", "3s", "-ra-max", "4s"}
			if l == 0 {
				veth(r.ns, "wan0", isp, "isp0", false)
				r.args = append(r.args, "-dhcp6c-mode", "off", "-wan-ra=false", "-routed-prefix", top.String())
			} else {
				r.parent = levels[l-1][j%counts[l-1]]
				veth(r.ns, "wan0", r.parent.ns, fmt.Sprintf("p%d", j), true)
				hint := 40 // more than any level gets, cut down by its parent
				if spec.manual {
					hint = r.plen
				}
				if l <= bottom {
					r.args = append(r.args, "-dhcp6c-mode", "on", "-dhcp6c-ia-na=false", "-dhcp6c-pd-len", strconv.Itoa(hint))
				} else {
					r.args = append(r.args, "-dhcp6c-mode", "off")
				}
			}
			if l < bottom {
				r.args = append(r.args, "-dhcp6s-mode", "stateless")
				if spec.manual {
					r.args = append(r.args, "-dhcp6s-pd-len", strconv.Itoa(spec.plens[l+1]))
				}
			}
			if r.ula != "" {
				r.args = append(r.args, "-ula", r.ula)
			}
			row = append(row, r)
		}
		levels = append(levels, row)
	}
	// a host behind each router at the bottom and each at the end of the sharing
	var hosts []string
	hostRouter := map[string]*treeRouter{}
	for _, r := range slices.Concat(levels[bottom], levels[len(levels)-1]) {
		h := nsAdd(fmt.Sprintf("h%d-%d", r.level, len(hosts)))
		veth(h, "eth0", r.ns, "host", true)
		hosts = append(hosts, h)
		hostRouter[h] = r
	}
	root := levels[0][0]
	ip("-n", isp, "-6", "route", "add", top.String(), "via", linkLocal(root.ns, "wan0").String(), "dev", "isp0")
	ip("-n", root.ns, "-6", "route", "add", "default", "via", linkLocal(isp, "isp0").String(), "dev", "wan0")

	// delegation is what r's parent leased to r, of the line or of the ULA, found by the
	// link-local address the route goes to
	delegation := func(r *treeRouter, ula bool) (PDLease, bool) {
		if r.parent == nil {
			return PDLease{Prefix: top}, !ula
		}
		b, _ := os.ReadFile(filepath.Join(r.parent.state, "pd-leases.json"))
		var leases []PDLease
		json.Unmarshal(b, &leases)
		ll := addrOn(r.ns, "wan0", "link")
		for _, l := range leases {
			if l.Peer == ll && l.Prefix.Addr().IsPrivate() == ula {
				return l, true
			}
		}
		return PDLease{}, false
	}
	// site is r's ULA: its own, kept in its state directory, or the part of its parent's it got;
	// selfOf is r's address in the ULA of its LAN, ::1
	site := map[*treeRouter]netip.Prefix{}
	selfOf := func(r *treeRouter) netip.Addr {
		lan, _ := splitLAN(site[r], 0)
		return lan.Addr().Next()
	}
	// bottomOf is the router at the bottom r shares the /64 of, siteOf the one whose ULA r is in
	bottomOf := func(r *treeRouter) *treeRouter {
		for r.level > bottom {
			r = r.parent
		}
		return r
	}
	siteOf := func(r *treeRouter) *treeRouter {
		for r.ula == "" {
			r = r.parent
		}
		return r
	}
	for l, row := range levels {
		for _, r := range row {
			treeStart(t, r)
		}
		var got []netip.Prefix
		for _, r := range row {
			if l > bottom {
				// no delegation: the LAN shares the WAN's /64
				shared, _ := delegation(bottomOf(r), false)
				eventually(t, 30*time.Second, fmt.Sprintf("%s shares %s with its LAN", r.ns, shared.Prefix), func() bool {
					return strings.Contains(ip("-n", r.ns, "-6", "route", "show", shared.Prefix.String(), "dev", "lan0"), "proto 66")
				})
				t.Logf("%s shares %s from %s", r.ns, shared.Prefix, r.parent.ns)
				continue
			}
			for _, ula := range []bool{false, true} {
				var d PDLease
				eventually(t, 30*time.Second, fmt.Sprintf("%s holds a delegation, ULA %v", r.ns, ula), func() bool {
					var ok bool
					d, ok = delegation(r, ula)
					return ok || ula && l == 0
				})
				if l == 0 {
					continue
				}
				up, _ := delegation(r.parent, false)
				if ula {
					up.Prefix = site[r.parent]
				} else if d.Prefix.Bits() != r.plen {
					t.Fatalf("%s holds %s, want a /%d", r.ns, d.Prefix, r.plen)
				}
				if !up.Prefix.Contains(d.Prefix.Addr()) || up.Prefix.Bits() >= d.Prefix.Bits() {
					t.Fatalf("%s holds %s, want a part of %s", r.ns, d.Prefix, up.Prefix)
				}
				if out := ip("-n", r.parent.ns, "-6", "route", "show", d.Prefix.String()); !strings.Contains(out, "via "+d.Peer.String()+" dev lan0") {
					t.Fatalf("%s routes %s %q, want it through %s", r.parent.ns, d.Prefix, out, d.Peer)
				}
				if slices.ContainsFunc(got, d.Prefix.Overlaps) {
					t.Fatalf("%s overlaps another delegation of level %d: %v", d.Prefix, l, got)
				}
				got = append(got, d.Prefix)
				t.Logf("%s holds %s, routed by %s to %s", r.ns, d.Prefix, r.parent.ns, d.Peer)
				if ula {
					site[r] = d.Prefix
				}
			}
			if r.ula != "" {
				eventually(t, 5*time.Second, r.ns+" keeps a ULA of its own", func() bool {
					b := []byte(r.ula)
					if r.ula == "auto" {
						b, _ = os.ReadFile(filepath.Join(r.state, "ula"))
					}
					p, err := netip.ParsePrefix(strings.TrimSpace(string(b)))
					site[r] = p
					return err == nil
				})
				t.Logf("%s has a site of its own, %s", r.ns, site[r])
			}
			eventually(t, 15*time.Second, fmt.Sprintf("%s takes %s on its LAN", r.ns, selfOf(r)), func() bool {
				return slices.Contains(addrsOn(r.ns, "lan0", "global"), selfOf(r))
			})
		}
	}

	// every host has an address of the line and one of its site's ULA
	var addrs []netip.Addr
	for _, h := range hosts {
		r := bottomOf(hostRouter[h])
		d, _ := delegation(r, false)
		ula, _ := splitLAN(site[r], 0)
		var gua netip.Addr
		eventually(t, 15*time.Second, h+" forms addresses in "+d.Prefix.String()+" and "+ula.String(), func() bool {
			got := addrsOn(h, "eth0", "global")
			if i := slices.IndexFunc(got, func(a netip.Addr) bool { return d.Prefix.Contains(a) }); i >= 0 {
				gua = got[i]
			}
			return gua.IsValid() && slices.ContainsFunc(got, ula.Contains)
		})
		t.Logf("%s behind %s has %v", h, hostRouter[h].ns, addrsOn(h, "eth0", "global"))
		addrs = append(addrs, gua)
	}
	ping := func(h string, dst netip.Addr) bool {
		return exec.Command("ip", "netns", "exec", h, "ping", "-c", "1", "-W", "1", dst.String()).Run() == nil
	}
	// each host reaches the upstream and every other host, the router it shares the /64 of and
	// the top of its site by ULA
	reach := func(when string) {
		t.Helper()
		for i, h := range hosts {
			r := hostRouter[h]
			dsts := []netip.Addr{internet, selfOf(bottomOf(r)), selfOf(siteOf(r))}
			for j, a := range addrs {
				if j != i {
					dsts = append(dsts, a)
				}
			}
			for _, dst := range dsts {
				eventually(t, 30*time.Second, fmt.Sprintf("%s behind %s reaches %s %s", h, r.ns, dst, when), func() bool { return ping(h, dst) })
			}
		}
	}
	reach("through the tree")
	// a ULA stays in its site
	top0 := levels[0][0]
	for _, h := range hosts {
		if siteOf(hostRouter[h]) != top0 && ping(h, selfOf(top0)) {
			t.Fatalf("%s reaches %s, a ULA of another site", h, selfOf(top0))
		}
	}

	// a router restarts and puts the routes to its delegations back, or its proxy entries
	for _, at := range spec.restart {
		mid := levels[at[0]][at[1]]
		treeStop(mid)
		treeStart(t, mid)
		reach("after " + mid.ns + " restarts")
	}
}

func treeStart(t *testing.T, r *treeRouter) {
	t.Helper()
	cmd, _, stderr := mainCmd(t, r.args...)
	cmd.Args = append([]string{"ip", "netns", "exec", r.ns}, cmd.Args...)
	cmd.Path, _ = exec.LookPath("ip")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.cmd, r.stderr = cmd, stderr
	t.Cleanup(func() {
		if treeStop(r) && t.Failed() {
			t.Logf("%s:\n%s", r.ns, stderr)
		}
	})
}

// treeStop stops the router once and reports whether it was running.
func treeStop(r *treeRouter) bool {
	if r.cmd == nil || r.cmd.ProcessState != nil {
		return false
	}
	r.cmd.Process.Signal(syscall.SIGTERM)
	r.cmd.Wait()
	return true
}

// addrsOn returns the addresses of scope (link or global) on dev in the namespace ns.
func addrsOn(ns, dev, scope string) []netip.Addr {
	out, _ := exec.Command("ip", "-n", ns, "-6", "-o", "addr", "show", "dev", dev, "scope", scope).Output()
	var addrs []netip.Addr
	for line := range strings.Lines(string(out)) {
		f := strings.Fields(line)
		if i := slices.Index(f, "inet6"); i >= 0 && i+1 < len(f) {
			if p, err := netip.ParsePrefix(f[i+1]); err == nil {
				addrs = append(addrs, p.Addr())
			}
		}
	}
	return addrs
}

func addrOn(ns, dev, scope string) netip.Addr {
	if a := addrsOn(ns, dev, scope); len(a) > 0 {
		return a[0]
	}
	return netip.Addr{}
}

func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(d); !ok(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
	}
}
