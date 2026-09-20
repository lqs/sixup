package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

// dryOpts is what dry-run needs from the flags; grouped because the list had outgrown a signature.
type dryOpts struct {
	wan, stateDir, tunDev string
	dhcpMode              clientMode
	upRA, wantNA          bool
	pdLen, tunMTU         int
	metric4               uint32
	iid                   iidPolicy
	timeout               time.Duration
}

func runDry(ctx context.Context, store *Store, hub *linkHub, pkts *packetHub, o dryOpts) {
	if verbose == 0 {
		verbose = 1
	}
	if o.timeout > 0 {
		log.Printf("[dry-run] only requesting parameters, changing no configuration, running for %s and printing on every change", o.timeout)
	} else {
		log.Printf("[dry-run] only requesting parameters, changing no configuration, running until interrupted and printing on every change (renewals, prefix changes and tunnel inference all included)")
	}
	ch := store.Subscribe()
	var dhcp *dhcpClient
	if o.dhcpMode != clientOff {
		dhcp = newDHCPClient(o.wan, store, o.stateDir, o.pdLen, o.wantNA)
		dhcp.link = hub.Subscribe(o.wan)
		go dhcp.run(ctx, o.dhcpMode == clientAuto && o.upRA)
	}
	if o.upRA {
		// SLAAC still computes the address for the report; the address operations themselves are skipped under dry-run.
		go (&raClient{ifname: o.wan, store: store, dhcp: dhcp, slaac: true, iid: o.iid, secret: loadSecret(o.stateDir)}).run(ctx, hub)
	}
	// Capture tunnel traffic as usual: when DHCPv6 sends no tunnel option this is the only way to learn the BR, the local address and the IPv4.
	go (&tunnelWatcher{ifname: o.wan, store: store, pkts: pkts, maxRun: 2 * time.Minute}).run(ctx, store.Subscribe())
	// Name resolution changes nothing on the system, and without it a DS-Lite report has no remote endpoint.
	go (&aftrResolver{store: store}).run(ctx, store.Subscribe())
	var deadline <-chan time.Time
	if o.timeout > 0 {
		deadline = time.After(o.timeout)
	}
	var last Snapshot
	lastKey := ""
	first := true
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	for {
		select {
		case <-ctx.Done():
			log.Printf("[dry-run] interrupted, printing the final parameters")
			enc.Encode(dryReport(last, o))
			dryDiagnose(last)
			if dhcp != nil {
				dhcp.WaitDone()
			}
			return
		case <-deadline:
			log.Printf("[dry-run] deadline reached, printing the final parameters")
			enc.Encode(dryReport(last, o))
			dryDiagnose(last)
			return
		case s := <-ch:
			last = s
			// Print once whenever the prefix set, addresses, DNS or tunnel information change; a mere lifetime
			// refresh (renewal) is not reprinted, it is already visible in the [dhcpv6-client] / [prefix-store] logs.
			key := paramKey(s) + fmt.Sprint(s.DNS, s.DNSSL, s.PREF64)
			if s.Tunnel != nil {
				key += fmt.Sprint(s.Tunnel.Captured, s.Tunnel.Conflicts)
			}
			empty := len(s.WAN) == 0 && !s.WANAddr.IsValid() && s.Tunnel == nil && len(s.DNS) == 0
			if empty || (key == lastKey && s.Change != "revoke") {
				continue
			}
			lastKey = key
			label := s.Change
			if first {
				label = "initial parameters"
			} else if label == "none" {
				label = "update"
			}
			first = false
			log.Printf("[dry-run] parameters changed (%s), current report:", label)
			enc.Encode(dryReport(s, o))
		}
	}
}

// paramKey fingerprints the parameters without lifetimes, so a renewal does not look like a change.
func paramKey(s Snapshot) string {
	var parts []string
	for _, p := range s.WAN {
		if !p.Deprecated {
			parts = append(parts, p.Prefix.String())
		}
	}
	parts = append(parts, s.WANAddr.String(), string(s.Source))
	for _, name := range slices.Sorted(maps.Keys(s.LAN)) {
		for _, p := range s.LAN[name] {
			if !p.Deprecated {
				parts = append(parts, name+":"+p.Prefix.String())
			}
		}
	}
	if t := s.Tunnel; t != nil {
		parts = append(parts, string(t.Kind), string(t.Source), t.AFTRName, string(t.MAPESource),
			t.Local.String(), t.Remote.String(), t.IPv4.String())
	}
	return strings.Join(parts, "|")
}

func dryReport(s Snapshot, o dryOpts) map[string]any {
	now := time.Now()
	type pf struct {
		Prefix    string       `json:"prefix"`
		Source    prefixSource `json:"source"`
		Preferred int          `json:"preferred_lft"`
		Valid     int          `json:"valid_lft"`
	}
	var wan []pf
	for _, p := range s.WAN {
		wan = append(wan, pf{p.Prefix.String(), p.Source, int(p.preferredLeft(now) / time.Second), int(p.validLeft(now) / time.Second)})
	}
	lan := map[string][]string{}
	for k, v := range s.LAN {
		for _, p := range v {
			lan[k] = append(lan[k], p.Prefix.String())
		}
	}
	rep := map[string]any{
		"source": s.Source, "wan_addr": s.WANAddr.String(), "wan_prefixes": wan, "lan_split": lan,
		"dns": s.DNS, "dnssl": s.DNSSL, "tunnel": s.Tunnel,
	}
	// Show what the tunnel device would look like; the MTU needs the WAN interface, which may be gone
	ifMTU := 1500
	if ifi, err := net.InterfaceByName(o.wan); err == nil {
		ifMTU = ifi.MTU
	}
	if plan, ok := planTunnel(s, o.tunDev, o.wan, o.tunMTU, ifMTU, o.metric4); ok {
		rep["tunnel_device"] = plan
	}
	return rep
}

// dryDiagnose prints the packet counters and what to look at next.
func dryDiagnose(s Snapshot) {
	m := statSnapshot()
	fmt.Fprintln(os.Stderr, "packet counters:")
	for _, k := range statKeys(m) {
		fmt.Fprintf(os.Stderr, "  %-16s %d\n", k, m[k])
	}
	for _, hint := range diagnose(m) {
		fmt.Fprintln(os.Stderr, "hint: "+hint)
	}
	for _, hint := range diagnoseSnapshot(s) {
		fmt.Fprintln(os.Stderr, "hint: "+hint)
	}
}
