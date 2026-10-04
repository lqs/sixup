package main

import (
	"flag"
	"fmt"
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

	wan         = flag.String("wan", "", "WAN interface name (required)")
	pdLen       = flag.Int("dhcp6c-pd-len", 56, "prefix length hint for IA_PD, retried once without a hint if refused; 0 means do not request PD")
	wantNA      = flag.Bool("dhcp6c-ia-na", true, "request IA_NA (an address for the WAN interface itself)")
	dhcpMode    = flag.String("dhcp6c-mode", "auto", "DHCPv6 client: auto(follow the M/O bits of the upstream RA) / on / off")
	upRA        = flag.Bool("wan-ra", true, "listen to RA on the WAN side as a second prefix source and maintain the default route")
	wanSLAAC    = flag.Bool("wan-slaac", true, "run SLAAC on the WAN interface for upstream RA prefixes with the A bit set")
	wanIID      = flag.String("wan-iid", "", "comma-separated suffixes of the static SLAAC addresses on the WAN interface, one address each: empty or stable for an RFC 7217 stable address, eui64 to derive it from the MAC, or a fixed suffix such as ::1 or ::1111:2222:3333:4444; the first one is reported as the WAN address")
	prefer      = flag.String("wan-prefer", "pd", "which prefix source wins when both are available: pd / ra")
	wanPrefix   = flag.String("wan-prefix", "", "comma-separated prefixes the upstream routes to this router when neither RA nor DHCPv6-PD tells it, such as a static prefix routed to the line by contract, or the /64 of a VPS; the DHCPv6 client then asks only for DNS and the like. A /64 is taken as the WAN link's on-link prefix and shared with the LAN as RFC 7278 describes; a shorter one as a delegation")
	shared64    = flag.String("wan-shared64", "lan", "layout when upstream hands out only one /64: lan(RFC 7278 /64 sharing: /64 on the LAN, /128 routes for same-subnet hosts on the WAN side, default) / wan(/64 on the WAN, one /128 route per LAN host) / split(/128 on both sides, the router itself cannot reach hosts it has not learned); all /128 routes are added automatically once the NDP proxy probes them")
	lanIIDSpec  = flag.String("lan-iid", "", "comma-separated suffixes of this host's static addresses on each LAN prefix, one address each, same syntax as -wan-iid; empty means an RFC 7217 stable address")
	hold        = flag.Duration("lan-deprecate-hold", ndValidLimit, "how long a prefix the line took away, or one advertised before a restart that the line did not hand out again, is advertised with lifetimes 0 so that hosts drop it (RFC 9096). Hosts hold a prefix for at most the 90 minutes its advertised valid lifetime is capped at, so a shorter hold may leave some behind")
	settle      = flag.Duration("settle", time.Second, "how long parameters must stay unchanged before they are pushed to the components (revocation does not wait); merges the RA, PD, DNS and capture results that arrive in batches at startup")
	dhcpRel     = flag.Bool("dhcp6c-release", false, "send RELEASE to the server on exit to give back the prefix and addresses. Off by default: a persisted DUID renews the same range after a restart and avoids prefix churn; dry-run always releases")
	pdGrace     = flag.Duration("dhcp6c-pd-grace", 10*time.Second, "longest wait after startup for a PD result, which ends as soon as PD succeeds or is refused; meanwhile RA prefixes are not handed to the LAN, so no wrong prefix has to be revoked later, and when the RA sets M or O the WAN takes no address in them yet, since its prefix length depends on the result")
	raMin       = flag.Duration("ra-min", 200*time.Second, "MinRtrAdvInterval")
	raMax       = flag.Duration("ra-max", 600*time.Second, "MaxRtrAdvInterval")
	raSLAAC     = flag.Bool("ra-slaac", true, "set the A flag in the RA's prefixes, so hosts form addresses by SLAAC; off with -dhcp6s-mode stateful hands out addresses by DHCPv6 only")
	raOnLink    = flag.Bool("ra-onlink", true, "set the L flag in the RA's prefixes, so hosts reach each other directly; off sends all their traffic through this router")
	raLifetime  = flag.Duration("ra-lifetime", ndPreferredLimit, "router lifetime of the RA, 45 minutes by default as RFC 9096 recommends; it is 0 while the WAN has no default router")
	raMTU       = flag.Uint("ra-mtu", 0, "MTU advertised in the RA; 0 means automatic: advertised when the WAN path MTU (the MTU option of the upstream RA or the WAN interface MTU) is smaller than the LAN interface, so PPPoE 1492 and similar no longer depend on PMTU discovery")
	raDNS       = flag.String("ra-dns", "upstream", "DNS servers announced on the LAN: off, or a comma-separated list, in order, of upstream (the servers the upstream hands out), self (this router's address on that LAN, in the ULA when there is one) and IPv6 addresses")
	raPref64    = flag.String("ra-pref64", "auto", "PREF64 advertised in the RA (RFC 8781): auto advertises this router's NAT64 prefix while it translates and otherwise passes on the upstream RA's; off advertises none; a prefix advertises that one, for a NAT64 elsewhere, and cannot be combined with -nat64")
	srvMode     = flag.String("dhcp6s-mode", "off", "DHCPv6 server on the LAN side: off / stateless / stateful")
	srvPref     = flag.Duration("dhcp6s-lease-preferred", 45*time.Minute, "preferred lifetime of IA_NA addresses and IA_PD prefixes, capped by the upstream's (RFC 9096)")
	srvValid    = flag.Duration("dhcp6s-lease-valid", 90*time.Minute, "valid lifetime of IA_NA addresses and IA_PD prefixes, capped by the upstream's (RFC 9096)")
	srvPDLen    = flag.Int("dhcp6s-pd-len", 60, "shortest prefix delegated to a downstream router; a longer hint is honoured, a shorter one cut down; 0 disables downstream PD")
	poolRange   = flag.String("dhcp6s-pool", "1000-ffff", "IID range of the address pool (hexadecimal, low 64 bits)")
	ndMode      = flag.String("ndproxy-mode", "auto", "NDP proxy: auto(enable forward mode when a LAN /64 is also the on-link /64 of a broadcast WAN) / off / static / prefix / forward; forward works in both directions and also proxies between same-subnet hosts on the LAN and WAN sides")
	ndTTL       = flag.Duration("ndproxy-ttl", 30*time.Second, "TTL of an NDP proxy session")
	tEnable     = flag.Bool("tempaddr", false, "besides the static addresses, rotate temporary addresses (RFC 8981) on the WAN interface; only traffic the router itself starts uses them")
	tRegen      = flag.Duration("tempaddr-regen", time.Hour, "temporary address generation interval")
	tPref       = flag.Duration("tempaddr-preferred", time.Hour, "preferred lifetime of a temporary address")
	tValid      = flag.Duration("tempaddr-valid", 24*time.Hour, "upper bound on the valid lifetime of a temporary address (the real value follows the in-use check)")
	tMax        = flag.Int("tempaddr-max", 8, "maximum number of temporary addresses kept at once")
	tSkipDAD    = flag.Bool("tempaddr-skip-dad", false, "skip DAD (only on links known to be free of conflicts)")
	tGrace      = flag.Duration("tempaddr-drain-grace", 5*time.Second, "grace period between the two queries used to decide retirement")
	stateDir    = flag.String("state-dir", "/var/lib/sixup", "directory where the DUID, the secret and the leases are persisted")
	noSysctl    = flag.Bool("no-sysctl", false, "do not set forwarding / accept_ra and the other sysctls automatically, they are managed externally")
	ulaSpec     = flag.String("ula", "", "ULA prefix of this site, either auto (a random /48, kept in -state-dir) or prefixes such as fd12:3456:789a::/48. Each LAN gets the /64 of its subnet id")
	dryTO       = flag.Duration("dry-run-timeout", 0, "how long dry-run keeps running, 0 means until interrupted")
	tunRules    = flag.Bool("tunnel-mape-rules", true, "when DHCPv6 sends no MAP-E option, infer the MAP-E parameters from the user prefix using the Japanese IPoE (v6plus / BIGLOBE / OCN / NURO) rule table")
	tunDev      = flag.String("tunnel-dev", "sixup-ipv4", "name of the IPv4-in-IPv6 tunnel device to configure automatically: once the parameters are complete, create or modify the ip6tnl (equivalent to ip tunnel add/change), bring it up and assign the public IPv4; empty means no device. Not configured under dry-run")
	tunMTU      = flag.Int("tunnel-mtu", 0, "MTU of the tunnel device, 0 means the WAN interface MTU minus 40")
	tunMetric4  = flag.Uint("tunnel-route4-metric", 4096, "metric of the IPv4 default route added through the tunnel device once its IPv4 is known; the metric is high on purpose, so an existing IPv4 default route keeps winning and the tunnel only takes over when there is none. 0 adds no route")
	tunCap      = flag.Bool("tunnel-capture", true, "when running as a daemon and DHCPv6 sends no tunnel option, capture tunnel traffic to infer the parameters")
	tunCapMax   = flag.Duration("tunnel-capture-max", 2*time.Minute, "how long capture-based inference waits: it settles as soon as a tunnel packet is seen, otherwise it gives up at the deadline and retries when the prefix or the address changes")
	nat64       = flag.String("nat64", "off", "which NAT64 implementation to configure: jool uses the Jool kernel module (https://jool.mx, 4.1 or later; when it is not loaded, sixup runs /sbin/modprobe jool once), run in a network namespace of its own behind the veth sixup-nat64, translating -nat64-prefix for the LAN and this router alike. The namespace exists, and the prefix is advertised in the RA unless -ra-pref64 is off, only while the module is loaded, which is checked every minute. The IPv4 output leaves by this host's IPv4 route, through the tunnel's source NAT or any other, so a MAP-E line's ports have one allocator. A firewall has to let traffic through sixup-nat64: the LAN's, forwarded, and the answers to this router's own, arriving on it. off configures none. DNS64 is not part of this and is left to a resolver of your choosing")
	nat64Prefix = flag.String("nat64-prefix", nat64WKP.String(), "prefix the NAT64 translates (RFC 6052), advertised in the RA while it does (see -ra-pref64). Reaching private IPv4 addresses needs a network-specific prefix such as fd00:64::/96, and one carved from the delegated prefix would change with it")
	joolIPv4    = flag.String("jool-ipv4", "192.168.255.254/31", "the IPv4 /31 between this namespace and Jool's: the lower address is the gateway on this side, the upper one Jool's pool4. It must not overlap any address or route of this host")
	unsolicited = flag.String("unsolicited", "request", "unsolicited IPv6 from the WAN to the LAN (RFC 6092): request lets in only what the LAN started, endpoints that recently sent out, ports opened with PCP (UDP 5351), and the ICMPv6 and IPsec that must pass; deny does the same without PCP; allow lets it all in. PCP, and NAT-PMP for programs that know only it, also forward ports of the tunnel's IPv4 while sixup does its NAT. The RFC 7084 border for ULA and LAN prefixes holds in every mode")
	srcFilter   = flag.Bool("source-filter", true, "let the LAN send to the WAN only from its own and the delegated prefixes, answering others with ICMPv6 code 5 (BCP 38), and the WAN reach only those; turn it off when another prefix is routed into the LAN")
	tunNAT      = flag.String("tunnel-nat", "auto", "maintain the nftables table sixup for traffic leaving the tunnel device: auto configures the port-restricted source NAT a MAP-E customer edge is required to have (RFC 7597), an ordinary source NAT on a line with its own public IPv4, none on DS-Lite where the AFTR translates, and in every case an MSS clamp to the tunnel MTU; off writes no rules. Nothing outside that table is read or changed, and it is removed on exit")

	logLevelName = flag.String("log-level", "info", "minimum level printed: debug / info / warn / error")

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
	flag.BoolVar(&verbose, "v", false, "shorthand for -log-level debug")
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
				fatalf("-lan %q has an invalid subnet id", s)
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
					fatalf("-dhcp6s-static %q has an invalid address: %v", s, err)
				}
				b.addr = a
			}
		}
		if !b.addr.IsValid() || (b.mac == "" && b.duid == "") {
			fatalf("-dhcp6s-static %q needs mac or duid, plus addr", s)
		}
		out = append(out, b)
	}
	return out
}

func parsePool(s string) (uint64, uint64) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		fatalf("-dhcp6s-pool %q must have the form start-end", s)
	}
	start, err1 := strconv.ParseUint(a, 16, 64)
	end, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil || start > end {
		fatalf("-dhcp6s-pool %q is invalid", s)
	}
	return start, end
}

func parsePrefixOrAddr(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		fatalf("%q is not a valid address or prefix", s)
	}
	return netip.PrefixFrom(a, 128)
}

// serverDUID shares one DUID with the client, since a device has a single DUID. It generates its own when the client is disabled.
// usageGroups sets the grouping and order of -h; flags not listed here fall under "Other".
var usageGroups = []struct {
	title string
	names []string
}{
	{"Interfaces and prefixes", []string{"wan", "lan", "ula", "lan-iid", "lan-deprecate-hold"}},
	{"WAN side: DHCPv6 client", []string{"dhcp6c-mode", "dhcp6c-pd-len", "dhcp6c-ia-na", "dhcp6c-pd-grace", "dhcp6c-release"}},
	{"WAN side: upstream RA and addresses", []string{"wan-ra", "wan-slaac", "wan-iid", "wan-prefer", "wan-prefix", "wan-shared64"}},
	{"LAN side: RA advertisement", []string{"ra-min", "ra-max", "ra-lifetime", "ra-slaac", "ra-onlink", "ra-mtu", "ra-dns", "ra-pref64", "ra-route"}},
	{"LAN side: DHCPv6 server", []string{"dhcp6s-mode", "dhcp6s-pool", "dhcp6s-static", "dhcp6s-lease-preferred", "dhcp6s-lease-valid", "dhcp6s-pd-len"}},
	{"NDP proxy", []string{"ndproxy-mode", "ndproxy-static", "ndproxy-exclude", "ndproxy-ttl"}},
	{"Temporary addresses", []string{"tempaddr", "tempaddr-regen", "tempaddr-preferred", "tempaddr-valid", "tempaddr-max", "tempaddr-skip-dad", "tempaddr-drain-grace"}},
	{"Tunnel", []string{"tunnel-dev", "tunnel-mtu", "tunnel-route4-metric", "tunnel-nat", "tunnel-mape-rules", "tunnel-capture", "tunnel-capture-max"}},
	{"NAT64", []string{"nat64", "nat64-prefix", "jool-ipv4"}},
	{"Unsolicited traffic", []string{"unsolicited", "source-filter"}},
	{"Runtime", []string{"state-dir", "no-sysctl", "settle", "dry-run", "dry-run-timeout", "log-level", "v", "version", "license"}},
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

// flagGiven reports whether the option was actually passed on the command line.
func flagGiven(name string) bool {
	given := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}
