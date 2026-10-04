//go:build linux && integration

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// aftrFakeDNS serves from [::1]:53 the AAAA record of each name in answers (fully qualified, with
// the trailing dot) and never answers about any other name.
func aftrFakeDNS(t *testing.T, answers map[string]netip.Addr) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("port 53 needs root")
	}
	pc, err := net.ListenPacket("udp6", "[::1]:53")
	if err != nil {
		t.Skipf("no DNS server of our own: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			a, ok := answers[q.Questions[0].Name.String()]
			if !ok {
				continue
			}
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true}, Questions: q.Questions}
			if q.Questions[0].Type == dnsmessage.TypeAAAA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AAAAResource{AAAA: a.As16()},
				}}
			}
			b, _ := resp.Pack()
			pc.WriteTo(b, from)
		}
	}()
}

// The AFTR name is resolved through the DNS servers the line hands out, not the system's, which on
// a DS-Lite line may only be reachable through the tunnel being set up (RFC 6334).
func TestAFTRResolvesThroughTheLineDNS(t *testing.T) {
	aftr := netip.MustParseAddr("2001:db8::a")
	aftrFakeDNS(t, map[string]netip.Addr{"aftr.sixup.invalid.": aftr})
	got := resolveAFTR(context.Background(), "aftr.sixup.invalid", []netip.Addr{netip.IPv6Loopback()}, "lo")
	if len(got) != 1 || got[0] != aftr {
		t.Fatalf("got %v, want %v from the line's server", got, aftr)
	}
}

// When names change faster than they resolve, every lookup but the latest is abandoned and only
// the latest result is stored; a lookup still running when the resolver stops ends with it.
func TestAFTRResolverKeepsTheLatest(t *testing.T) {
	aftr := netip.MustParseAddr("2001:db8::a")
	aftrFakeDNS(t, map[string]netip.Addr{"aftr.sixup.invalid.": aftr})
	st := &Store{aftrIn: make(chan aftrUpdate, 1)}
	r := &aftrResolver{store: st, retry: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan Snapshot)
	done := make(chan struct{})
	go func() { r.run(ctx, ch); close(done) }()
	dns := []netip.Addr{netip.IPv6Loopback()}
	for i := range 30 { // names the server never answers about
		ch <- Snapshot{DNS: dns, Tunnel: &TunnelParams{AFTRName: fmt.Sprintf("slow%d.sixup.invalid", i)}}
	}
	ch <- Snapshot{DNS: dns, Tunnel: &TunnelParams{AFTRName: "aftr.sixup.invalid"}}
	if u := <-st.aftrIn; u.name != "aftr.sixup.invalid" || len(u.addrs) != 1 || u.addrs[0] != aftr {
		t.Fatalf("%+v", u)
	}
	ch <- Snapshot{DNS: dns, Tunnel: &TunnelParams{AFTRName: "slow.sixup.invalid"}}
	cancel()
	<-done
	if len(st.aftrIn) != 0 {
		t.Fatalf("nothing but the latest result should be stored: %+v", <-st.aftrIn)
	}
}
