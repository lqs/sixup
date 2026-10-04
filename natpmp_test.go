package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func natpmpResult(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[2:]) }

// The refusals of a NAT-PMP mapping request.
func TestNATPMPRefusals(t *testing.T) {
	p := pcpServer4([]portSpan{{2000, 2000}})
	now := time.Now()
	if resp := p.handle([]byte{0, natpmpOpTCP, 0, 0}, pcpHost4, now); resp != nil {
		t.Fatalf("a truncated request is dropped: % x", resp)
	}
	if resp := p.handle(natpmpMap(natpmpOpTCP, 0, 0, 7200), pcpHost4, now); natpmpResult(resp) != natpmpRefused {
		t.Fatalf("no internal port: % x", resp)
	}
	// a PCP mapping under a nonce is not NAT-PMP's to renew
	p.handle(pcpReq4(pcpHost4, 3600, pcpProtoTCP, 8080, 0, "nonce-aaaaaa"), pcpHost4, now)
	if resp := p.handle(natpmpMap(natpmpOpTCP, 8080, 0, 7200), pcpHost4, now); natpmpResult(resp) != natpmpRefused {
		t.Fatalf("mapped by PCP: % x", resp)
	}
	other := netip.MustParseAddr("192.168.1.11")
	if resp := p.handle(natpmpMap(natpmpOpTCP, 8080, 0, 7200), other, now); natpmpResult(resp) != natpmpNoResources {
		t.Fatalf("no port left: % x", resp)
	}
	p.ipv4 = netip.Addr{}
	if resp := p.handle(natpmpMap(natpmpOpUDP, 5000, 0, 7200), pcpHost4, now); natpmpResult(resp) != natpmpNetworkFailure {
		t.Fatalf("no tunnel: % x", resp)
	}
}

// Without an IPv4 socket there is nothing to announce on.
func TestNATPMPAnnounceWithoutSocket(t *testing.T) {
	(&pcpServer{ipv4: netip.MustParseAddr("203.0.113.9")}).announceNATPMP(t.Context())
}
