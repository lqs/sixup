package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Every option of sixup, declared here so that main reads as the order the components start in.
var (
	lans, statics, routes, ndStatic, ndExclude multiFlag

	wan        = flag.String("wan", "", "WAN interface name (required)")
	pdLen      = flag.Int("dhcp6c-pd-len", 56, "prefix length hint for IA_PD; 0 means do not request PD")
	wantNA     = flag.Bool("dhcp6c-ia-na", true, "request IA_NA (an address for the WAN interface itself)")
	dhcpMode   = flag.String("dhcp6c-mode", "auto", "DHCPv6 client: auto(follow the M/O bits of the upstream RA) / on / off")
	upRA       = flag.Bool("wan-ra", true, "listen to RA on the WAN side as a second prefix source and maintain the default route")
	wanSLAAC   = flag.Bool("wan-slaac", true, "run SLAAC on the WAN interface for upstream RA prefixes with the A bit set")
	wanIID     = flag.String("wan-iid", "", "suffix of the static SLAAC address on the WAN interface: empty for an RFC 7217 stable address, eui64 to derive it from the MAC, or a fixed suffix such as ::1 or ::1111:2222:3333:4444")
	wanTemp    = flag.Bool("wan-tempaddr", false, "besides the static SLAAC address, also rotate temporary addresses on the WAN interface according to -tempaddr-regen and friends")
	prefer     = flag.String("wan-prefer", "pd", "which prefix source wins when both are available: pd / ra")
	shared64   = flag.String("wan-shared64", "lan", "layout when upstream hands out only one /64: lan(RFC 7278 /64 sharing: /64 on the LAN, /128 routes for same-subnet hosts on the WAN side, default) / wan(/64 on the WAN, one /128 route per LAN host) / split(/128 on both sides, the router itself cannot reach hosts it has not learned); all /128 routes are added automatically once the NDP proxy probes them")
	hold       = flag.Duration("lan-deprecate-hold", 600*time.Second, "how long a revoked prefix keeps being advertised with preferred=0 (one RA cycle)")
	settle     = flag.Duration("settle", time.Second, "how long parameters must stay unchanged before they are pushed to the components (revocation does not wait); merges the RA, PD, DNS and capture results that arrive in batches at startup")
	dhcpRel    = flag.Bool("dhcp6c-release", false, "send RELEASE to the server on exit to give back the prefix and addresses. Off by default: a persisted DUID renews the same range after a restart and avoids prefix churn; dry-run always releases")
	pdGrace    = flag.Duration("dhcp6c-pd-grace", 10*time.Second, "how long to wait after startup for a PD result; meanwhile RA prefixes are only used as WAN information and not handed to the LAN, so no wrong prefix has to be revoked later")
	raMin      = flag.Duration("ra-min", 200*time.Second, "MinRtrAdvInterval")
	raMax      = flag.Duration("ra-max", 600*time.Second, "MaxRtrAdvInterval")
	raLifetime = flag.Duration("ra-lifetime", 1800*time.Second, "router lifetime of the RA")
	raMTU      = flag.Uint("ra-mtu", 0, "MTU advertised in the RA; 0 means automatic: advertised when the WAN path MTU (the MTU option of the upstream RA or the WAN interface MTU) is smaller than the LAN interface, so PPPoE 1492 and similar no longer depend on PMTU discovery")
	raDNS      = flag.String("ra-dns", "", "override the upstream DNS, comma separated")
	raPref64   = flag.String("ra-pref64", "", "NAT64 prefix advertised in the RA (RFC 8781), e.g. 64:ff9b::/96; empty passes through the value from the upstream RA. NAT64 itself is provided by external tools")
	srvMode    = flag.String("dhcp6s-mode", "off", "DHCPv6 server on the LAN side: off / stateless / stateful")
	srvPref    = flag.Duration("dhcp6s-lease-preferred", time.Hour, "IA_NA preferred lifetime")
	srvValid   = flag.Duration("dhcp6s-lease-valid", 2*time.Hour, "IA_NA valid lifetime")
	poolRange  = flag.String("dhcp6s-pool", "1000-ffff", "IID range of the address pool (hexadecimal, low 64 bits)")
	ndMode     = flag.String("ndproxy-mode", "auto", "NDP proxy: auto(enable forward mode when the obtained prefix is a /64) / off / static / prefix / forward; forward works in both directions and also proxies between same-subnet hosts on the LAN and WAN sides")
	ndTTL      = flag.Duration("ndproxy-ttl", 30*time.Second, "TTL of an NDP proxy session")
	tMode      = flag.String("tempaddr-mode", "off", "address mode of this host: off / stable / temporary / both")
	tRegen     = flag.Duration("tempaddr-regen", time.Hour, "temporary address generation interval")
	tPref      = flag.Duration("tempaddr-preferred", time.Hour, "preferred lifetime of a temporary address")
	tValid     = flag.Duration("tempaddr-valid", 24*time.Hour, "upper bound on the valid lifetime of a temporary address (the real value follows the in-use check)")
	tMax       = flag.Int("tempaddr-max", 8, "maximum number of temporary addresses kept at once")
	tDesync    = flag.Duration("tempaddr-desync", 10*time.Minute, "upper bound of the random jitter applied to rotation")
	tSkipDAD   = flag.Bool("tempaddr-skip-dad", false, "skip DAD (only on links known to be free of conflicts)")
	tGrace     = flag.Duration("tempaddr-drain-grace", 5*time.Second, "grace period between the two queries used to decide retirement")
	stateDir   = flag.String("state-dir", "/var/lib/sixup", "directory where the DUID, the secret and the leases are persisted")
	noSysctl   = flag.Bool("no-sysctl", false, "do not set forwarding / accept_ra and the other sysctls automatically, they are managed externally")
	ulaSpec    = flag.String("lan-ula", "", "ULA prefix advertised together with the GUA: auto generates a random /48 and persists it, or give one such as fd12:3456:789a::/48, comma separated for several")
	dryTO      = flag.Duration("dry-run-timeout", 0, "how long dry-run keeps running, 0 means until interrupted")
	tunRules   = flag.Bool("tunnel-mape-rules", true, "when DHCPv6 sends no MAP-E option, infer the MAP-E parameters from the user prefix using the Japanese IPoE (v6plus / BIGLOBE / OCN / NURO) rule table")
	tunDev     = flag.String("tunnel-dev", "sixup-ipv4", "name of the IPv4-in-IPv6 tunnel device to configure automatically: once the parameters are complete, create or modify the ip6tnl (equivalent to ip tunnel add/change), bring it up and assign the public IPv4; empty means no device. Not configured under dry-run")
	tunMTU     = flag.Int("tunnel-mtu", 0, "MTU of the tunnel device, 0 means the WAN interface MTU minus 40")
	tunMetric4 = flag.Uint("tunnel-route4-metric", 4096, "metric of the IPv4 default route added through the tunnel device once its IPv4 is known; the metric is high on purpose, so an existing IPv4 default route keeps winning and the tunnel only takes over when there is none. 0 adds no route")
	tunCap     = flag.Bool("tunnel-capture", true, "when running as a daemon and DHCPv6 sends no tunnel option, capture tunnel traffic to infer the parameters")
	tunCapMax  = flag.Duration("tunnel-capture-max", 2*time.Minute, "how long capture-based inference waits: it settles as soon as a tunnel packet is seen, otherwise it gives up at the deadline and retries when the prefix or the address changes")
	nat64      = flag.String("nat64", "off", "which NAT64 implementation to configure: jool uses the Jool kernel module (https://jool.mx, 4.1 or later, modprobe jool), creating an instance that translates the well-known prefix 64:ff9b::/96, advertising it in the RA and letting the source NAT above rewrite the result, so the port budget of a MAP-E line stays with one allocator; off configures none. DNS64 is not part of this and is left to a resolver of your choosing")
	joolIName  = flag.String("jool-instance", "sixup", "name of the Jool instance to create and remove")
	joolRanges = flag.Int("jool-port-ranges", 3, "how many of the port ranges a MAP-E line owns are given to the translator; netfilter keeps the rest, and neither hands out a port the other might. Ignored where the line owns every port of its address")
	tunNAT     = flag.String("tunnel-nat", "auto", "maintain the nftables table sixup for traffic leaving the tunnel device: auto configures the port-restricted source NAT a MAP-E customer edge is required to have (RFC 7597), an ordinary source NAT on a line with its own public IPv4, none on DS-Lite where the AFTR translates, and in every case an MSS clamp to the tunnel MTU; off writes no rules. Nothing outside that table is read or changed, and it is removed on exit")

	showVersion *bool
	showLicense *bool
)

// The options that need the address of an existing variable, or that accumulate repeated values.
func init() {
	flag.BoolVar(&dryRun, "dry-run", false, "trial run: walk through the whole flow of requesting parameters from upstream, renewing and identifying tunnel parameters, printing continuously, but change no system configuration and send no RA to the LAN")
	flag.Var(&lans, "lan", "LAN interface, repeatable, format name[:subnet-id], e.g. eth1:0; the id is the one this /64 takes out of the delegated prefix and has nothing to do with an IPv4 alias label of the same shape, which the kernel does not accept as an interface name anyway")
	flag.Var(&statics, "dhcp6s-static", "DHCPv6 static binding, repeatable: mac=..,addr=::100 or duid=hex,addr=2001:db8::5")
	flag.Var(&routes, "ra-route", "Route Information carried in the RA, repeatable")
	flag.Var(&ndStatic, "ndproxy-static", "static address or prefix for the NDP proxy, repeatable")
	flag.Var(&ndExclude, "ndproxy-exclude", "prefix excluded from the NDP proxy, repeatable")
	flag.IntVar(&verbose, "v", 0, "log level, 1 prints debug information")
	showVersion = flag.Bool("version", false, "print the version and exit")
	showLicense = flag.Bool("license", false, "print the licence of sixup and of the work it derives from, and exit")
}

// multiFlag lets the same option be repeated.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func parseLans(list []string) []lanDef {
	var out []lanDef
	for i, s := range list {
		name, idx := s, i
		if k := strings.IndexByte(s, ':'); k >= 0 {
			name = s[:k]
			v, err := strconv.Atoi(s[k+1:])
			if err != nil {
				log.Fatalf("-lan %q has an invalid subnet id", s)
			}
			idx = v
		}
		out = append(out, lanDef{iface: name, index: idx})
	}
	return out
}

func parseStatics(list []string) []staticBind {
	var out []staticBind
	for _, s := range list {
		var b staticBind
		for _, kv := range strings.Split(s, ",") {
			k, v, _ := strings.Cut(kv, "=")
			switch strings.TrimSpace(k) {
			case "mac":
				b.mac = strings.TrimSpace(v)
			case "duid":
				b.duid = strings.ToLower(strings.TrimSpace(v))
			case "addr":
				a, err := netip.ParseAddr(strings.TrimSpace(v))
				if err != nil {
					log.Fatalf("-dhcp6s-static %q has an invalid address: %v", s, err)
				}
				b.addr = a
			}
		}
		if !b.addr.IsValid() || (b.mac == "" && b.duid == "") {
			log.Fatalf("-dhcp6s-static %q needs mac or duid, plus addr", s)
		}
		out = append(out, b)
	}
	return out
}

func parsePool(s string) (uint64, uint64) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		log.Fatalf("-dhcp6s-pool %q must have the form start-end", s)
	}
	start, err1 := strconv.ParseUint(a, 16, 64)
	end, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil || start > end {
		log.Fatalf("-dhcp6s-pool %q is invalid", s)
	}
	return start, end
}

func parsePrefixOrAddr(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		log.Fatalf("%q is not a valid address or prefix", s)
	}
	return netip.PrefixFrom(a, 128)
}

// serverDUID shares one DUID with the client, since a device has a single DUID. It generates its own when the client is disabled.
// usageGroups sets the grouping and order of -h; flags not listed here fall under "Other".
var usageGroups = []struct {
	title string
	names []string
}{
	{"Interfaces and prefixes", []string{"wan", "lan", "lan-ula", "lan-deprecate-hold"}},
	{"WAN side: DHCPv6 client", []string{"dhcp6c-mode", "dhcp6c-pd-len", "dhcp6c-ia-na", "dhcp6c-pd-grace", "dhcp6c-release"}},
	{"WAN side: upstream RA and addresses", []string{"wan-ra", "wan-slaac", "wan-iid", "wan-tempaddr", "wan-prefer", "wan-shared64"}},
	{"LAN side: RA advertisement", []string{"ra-min", "ra-max", "ra-lifetime", "ra-mtu", "ra-dns", "ra-pref64", "ra-route"}},
	{"LAN side: DHCPv6 server", []string{"dhcp6s-mode", "dhcp6s-pool", "dhcp6s-static", "dhcp6s-lease-preferred", "dhcp6s-lease-valid"}},
	{"NDP proxy", []string{"ndproxy-mode", "ndproxy-static", "ndproxy-exclude", "ndproxy-ttl"}},
	{"Local address rotation", []string{"tempaddr-mode", "tempaddr-regen", "tempaddr-preferred", "tempaddr-valid", "tempaddr-max", "tempaddr-desync", "tempaddr-skip-dad", "tempaddr-drain-grace"}},
	{"Tunnel", []string{"tunnel-dev", "tunnel-mtu", "tunnel-route4-metric", "tunnel-nat", "tunnel-mape-rules", "tunnel-capture", "tunnel-capture-max"}},
	{"NAT64", []string{"nat64", "jool-instance", "jool-port-ranges"}},
	{"Runtime", []string{"state-dir", "no-sysctl", "settle", "dry-run", "dry-run-timeout", "v", "version", "license"}},
}

func printUsage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "usage: %s -wan <interface> -lan <interface> [options]\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(w, "       %s -wan <interface> -dry-run\n", filepath.Base(os.Args[0]))
	listed := map[string]bool{}
	printFlag := func(f *flag.Flag) {
		def := f.DefValue
		if def == "" || def == "false" || def == "0" {
			def = ""
		} else {
			def = " (default " + def + ")"
		}
		fmt.Fprintf(w, "  -%s\n        %s%s\n", f.Name, f.Usage, def)
	}
	for _, g := range usageGroups {
		fmt.Fprintf(w, "\n%s\n", g.title)
		for _, n := range g.names {
			if f := flag.Lookup(n); f != nil {
				listed[n] = true
				printFlag(f)
			}
		}
	}
	first := true
	flag.VisitAll(func(f *flag.Flag) {
		if listed[f.Name] {
			return
		}
		if first {
			fmt.Fprintf(w, "\nOther\n")
			first = false
		}
		printFlag(f)
	})
}
