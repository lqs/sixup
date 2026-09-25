package main

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// stats holds process-wide packet counters, printed after dry-run to show where things stall.
var stats = struct {
	mu sync.Mutex
	m  map[string]int
}{m: map[string]int{}}

func statInc(key string) {
	stats.mu.Lock()
	stats.m[key]++
	stats.mu.Unlock()
}

func statSnapshot() map[string]int {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	out := make(map[string]int, len(stats.m))
	for k, v := range stats.m {
		out[k] = v
	}
	return out
}

func statKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// diagnose turns the counters into hints on what to check next.
func diagnose(m map[string]int) []string {
	var out []string
	if m["rs_sent"] == 0 && m["ra_recv"] == 0 {
		out = append(out, "No RS sent: the interface may lack a link-local address, or CAP_NET_RAW is missing")
	} else if m["ra_recv"] == 0 && m["ppp_default_route"] > 0 {
		out = append(out, "RS sent but no RA: PPP link, the default route already points at the device itself; address and prefix come from DHCPv6")
	} else if m["ra_recv"] == 0 {
		out = append(out, "RS sent but no RA: upstream does not send RA, or wrong interface (must be the WAN port directly on the ONU/ISP, not behind another router). Without RA on Ethernet there is no default route")
	}
	if m["solicit_sent"] == 0 {
		out = append(out, "No DHCPv6 SOLICIT sent: the interface has no link-local address, or port 546 is in use")
	} else if m["advertise_recv"] == 0 && m["reply_recv"] == 0 {
		out = append(out, "SOLICIT sent but no ADVERTISE: no DHCPv6 server on the link. Japanese IPoE lines usually have one; home router LAN ports, office networks and Wi-Fi mostly do not")
	} else if m["request_sent"] > 0 && m["reply_recv"] == 0 {
		out = append(out, "REQUEST sent but no REPLY: the request was ignored; check whether the server only accepts specific DUIDs")
	}
	if m["tunnel_pkt"] == 0 {
		out = append(out, "No IPv4-in-IPv6 tunnel packets captured: this host is not the tunnel endpoint (nothing is captured when the HGW or another tool holds the local address), or the line carries no tunnel traffic")
	}
	if m["pd_refused"] > 0 {
		out = append(out, "DHCPv6 server replied NoPrefixAvail: this line offers no prefix delegation; use the RA /64 (SLAAC line), or check whether the contract includes PD")
	}
	if m["ra_recv"] > 0 && m["ra_prefix"] == 0 {
		out = append(out, "RA received but without a prefix option: upstream only provides the default route; addresses come from DHCPv6")
	}
	return out
}

// diagnoseSnapshot reports what the parameters themselves say, which the packet counters cannot show.
// A point-to-point WAN never needs the NDP proxy, so it gets no advice about one.
func diagnoseSnapshot(s Snapshot, pointToPoint bool) []string {
	var out []string
	if reason, ask := s.proxyAdvice(); reason != "" && !pointToPoint {
		out = append(out, reason+", so sixup would proxy Neighbor Discovery as a workaround; ask your ISP: \""+ask+"\"")
	}
	if len(s.DNS) > 0 && len(routableDNS(s.DNS)) == 0 {
		out = append(out, "Upstream only offers link-local DNS servers ("+addrsString(s.DNS)+"): they are reachable on the WAN link alone, so they are dropped from the RA and the DHCPv6 server and LAN clients would get no DNS at all. Run a resolver on this router and point clients at it with -ra-dns")
	}
	return out
}

func addrsString(in []netip.Addr) string {
	var out []string
	for _, a := range in {
		out = append(out, a.String())
	}
	return strings.Join(out, ", ")
}
