//go:build linux && integration

package main

import (
	"net/netip"
	"testing"
	"time"
)

// The NAT-PMP announcement skips a missing LAN, goes on when sending on one fails, and repeats
// after a growing gap until stopped.
func TestNATPMPAnnounceAgainstKernel(t *testing.T) {
	pcpTestLinks(t)
	c4, _ := pcpTestConns(t)
	p := &pcpServer{lans: []string{"nope0", "pcp-down0", "lo"}, c4: c4, ipv4: netip.MustParseAddr("203.0.113.9"), start: time.Now()}
	p.announceNATPMP(pcpCancelAfter(400 * time.Millisecond))
}
