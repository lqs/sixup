//go:build linux && integration

package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The AFTR name is resolved through the DNS servers the line hands out, not the system's, which on
// a DS-Lite line may only be reachable through the tunnel being set up (RFC 6334).
func TestAFTRResolvesThroughTheLineDNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("port 53 needs root")
	}
	pc, err := net.ListenPacket("udp6", "[::1]:53")
	if err != nil {
		t.Skipf("no DNS server of our own: %v", err)
	}
	defer pc.Close()
	aftr := netip.MustParseAddr("2001:db8::a")
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
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true}, Questions: q.Questions}
			if q.Questions[0].Type == dnsmessage.TypeAAAA {
				resp.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AAAAResource{AAAA: aftr.As16()},
				}}
			}
			b, _ := resp.Pack()
			pc.WriteTo(b, from)
		}
	}()
	got := resolveAFTR(context.Background(), "aftr.sixup.invalid", []netip.Addr{netip.IPv6Loopback()}, "lo")
	if len(got) != 1 || got[0] != aftr {
		t.Fatalf("got %v, want %v from the line's server", got, aftr)
	}
}
