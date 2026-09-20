//go:build linux && integration

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// These tests need a kernel that accepts what the rule builder produces, which the unit tests
// cannot tell: an expression can marshal cleanly and still be rejected. They run as root in a
// network namespace of their own, so nothing on the host is touched:
//
//	docker run --rm --privileged -v "$PWD:/src" -w /src golang:1.27-alpine \
//	  go test -tags integration -run TestNATAgainstKernel ./...
func enterNetNS(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("writing nftables needs root")
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("cannot enter a network namespace of my own: %v", err)
	}
}

func mapeSnapshot(psid uint16) Snapshot {
	return Snapshot{Tunnel: &TunnelParams{
		Kind: "map-e", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		RuleMAPE: &mapeResult{IPv4: netip.MustParseAddr("203.0.113.9"), Ports: portSpans(4, 8, psid)},
	}}
}

func rulesIn(t *testing.T, c *nftables.Conn, chain string) []*nftables.Rule {
	t.Helper()
	r, err := c.GetRules(&nftables.Table{Family: nftables.TableFamilyINet, Name: natTable},
		&nftables.Chain{Name: chain})
	if err != nil {
		t.Fatalf("reading chain %s back: %v", chain, err)
	}
	return r
}

func TestNATAgainstKernel(t *testing.T) {
	enterNetNS(t)
	m := &natManager{dev: "sixup-test0", mtu: 1460, warned: true}
	t.Cleanup(m.remove)

	ports := portSpans(4, 8, 0x56)
	m.apply(mapeSnapshot(0x56))

	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	post := rulesIn(t, c, "postrouting")
	if len(post) != len(ports) {
		t.Fatalf("the kernel holds %d source NAT rules, one per port range would be %d", len(post), len(ports))
	}
	// The order rules come back in is the order they went in, so the ranges can be compared directly
	for i, r := range post {
		im := map[uint32][]byte{}
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Immediate); ok {
				im[v.Register] = v.Data
			}
		}
		start, end := binary.BigEndian.Uint16(im[3]), binary.BigEndian.Uint16(im[4])
		if start != ports[i].Start || end != ports[i].End {
			t.Fatalf("rule %d came back as %d-%d, want %s", i, start, end, ports[i])
		}
	}
	if n := len(rulesIn(t, c, "forward")); n != 1 {
		t.Fatalf("the MSS clamp should be one rule, got %d", n)
	}

	// A renumbering rewrites the set; the old ranges must not survive it
	m.apply(mapeSnapshot(0x57))
	post = rulesIn(t, c, "postrouting")
	if len(post) == 0 {
		t.Fatal("the table is empty after a renumbering")
	}
	for _, r := range post {
		for _, e := range r.Exprs {
			v, ok := e.(*expr.Immediate)
			if !ok || v.Register != 3 {
				continue
			}
			if got := binary.BigEndian.Uint16(v.Data); got == ports[0].Start {
				t.Fatalf("a port range from the previous prefix is still installed: %d", got)
			}
		}
	}

	m.remove()
	if tables, err := c.ListTables(); err == nil {
		for _, tb := range tables {
			if tb.Name == natTable {
				t.Fatal("the table outlived the daemon")
			}
		}
	}
}

// DS-Lite is translated by the AFTR, so the kernel should end up with the clamp and no source NAT.
func TestNATAgainstKernelDSLite(t *testing.T) {
	enterNetNS(t)
	m := &natManager{dev: "sixup-test0", mtu: 1460, warned: true}
	t.Cleanup(m.remove)
	m.apply(Snapshot{Tunnel: &TunnelParams{
		Kind: "ds-lite", Local: netip.MustParseAddr("2001:db8::1"), Remote: netip.MustParseAddr("2001:db8::2"),
		IPv4: netip.MustParseAddr("192.0.0.2"),
	}})
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	chains, err := c.ListChains()
	if err != nil {
		t.Fatalf("listing chains: %v", err)
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == natTable && ch.Name == "postrouting" {
			t.Fatal("DS-Lite must not translate here, the AFTR does")
		}
	}
	if n := len(rulesIn(t, c, "forward")); n != 1 {
		t.Fatalf("the clamp applies on DS-Lite too, got %d rules", n)
	}
}

// Another source NAT chain on the same hook decides the translation for whichever flow it sees
// first, which on a MAP-E line means a port the border relay does not route back. The operator has
// to be told; sixup neither removes it nor quietly outruns it.
func TestNATReportsAForeignSourceNATChain(t *testing.T) {
	enterNetNS(t)
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables: %v", err)
	}
	foreign := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "someone-else"})
	c.AddChain(&nftables.Chain{
		Name: "srcnat", Table: foreign, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
	})
	if err := c.Flush(); err != nil {
		t.Fatalf("installing the other table: %v", err)
	}
	t.Cleanup(func() {
		c.DelTable(foreign)
		c.Flush()
	})

	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)

	m := &natManager{dev: "sixup-test0", mtu: 1460}
	t.Cleanup(m.remove)
	m.apply(mapeSnapshot(0x56))

	if !bytes.Contains(logged.Bytes(), []byte("someone-else/srcnat")) {
		t.Fatalf("the other chain should be named in the warning:\n%s", logged.String())
	}
}
