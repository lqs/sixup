package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// tundevLoopback names the loopback interface, which carries 127.0.0.1 on every platform.
func tundevLoopback(t *testing.T) string {
	t.Helper()
	ifis, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

var tundevSpec = tunnelSpec{
	Local:  netip.MustParseAddr("2001:db8::1"),
	Remote: netip.MustParseAddr("2001:db8::2"),
	IPv4:   netip.MustParseAddr("192.0.2.1"),
	Kind:   tunnelMAPE,
}

func tundevSnapshot(spec tunnelSpec, mtu int, conflicts ...netip.Addr) Snapshot {
	return Snapshot{WANMTU: mtu, Tunnel: &TunnelParams{Local: spec.Local, Remote: spec.Remote, IPv4: spec.IPv4, Kind: spec.Kind, Conflicts: conflicts}}
}

// The manager skips snapshots without a tunnel or with nothing new, defers a local endpoint that
// lost DAD, and rebuilds when the spec or the WAN MTU changes.
func TestTunnelManagerRun(t *testing.T) {
	m := &tunnelManager{dev: "sixup-tt9", wan: "sixup-none0", cur: tundevSpec, applied: true}
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan Snapshot)
	done := make(chan struct{})
	go func() { m.run(ctx, ch); close(done) }()
	other := tundevSpec
	other.Remote = netip.MustParseAddr("2001:db8::3")
	ch <- Snapshot{}
	ch <- tundevSnapshot(tundevSpec, 0)
	ch <- tundevSnapshot(tundevSpec, 1500, tundevSpec.Local)
	ch <- tundevSnapshot(other, 1500) // the WAN interface is missing, so nothing is applied
	cancel()
	<-done
	if m.wanMTU != 1500 || m.cur != tundevSpec {
		t.Fatalf("%+v", m)
	}
	if conflicted(Snapshot{}, tundevSpec.Local) {
		t.Fatal("no tunnel, no conflict")
	}
}

// apply builds the device and, unless another interface holds the IPv4 already, its address and
// default route; dry-run lets it run through without touching the system.
func TestTunnelManagerApply(t *testing.T) {
	lo := tundevLoopback(t)
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()

	m := &tunnelManager{dev: "sixup-tt9", wan: lo, metric4: 300}
	m.apply(tundevSpec) // created; the default route finds no device in dry-run
	if !m.applied || m.cur != tundevSpec {
		t.Fatalf("%+v", m)
	}
	m.dev = lo
	m.apply(tundevSpec) // modified, with the route
	m.metric4 = 0
	m.apply(tundevSpec) // no route wanted

	m = &tunnelManager{dev: "sixup-tt9", wan: lo, metric4: 300}
	held := tundevSpec
	held.IPv4 = netip.MustParseAddr("127.0.0.1")
	m.apply(held)
	if m.applied {
		t.Fatal("an IPv4 held by another interface leaves the tunnel unfinished")
	}
	m.wan = "sixup-none0"
	m.apply(tundevSpec)
	if m.applied {
		t.Fatal("no WAN interface, no tunnel")
	}

	p, _ := planTunnel(tundevSnapshot(held, 1500), "sixup-tt9", lo, 0, 1500, 300)
	if !strings.Contains(p.Note, "already configured on "+lo) {
		t.Fatalf("the plan should name the holder: %q", p.Note)
	}
}
