package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"time"
)

var (
	verbose bool
	dryRun  bool
	version = "dev" // injected by build.sh via -ldflags -X
)

// A release is a bare binary, and both licences ask for their text to accompany it. Carrying them
// inside means that holds however the binary was obtained.
//
//go:embed LICENSE
var licenseText string

//go:embed NOTICE
var noticeText string

// joolNAT64 is the well-known prefix of RFC 6052. Carving one out of the delegated prefix instead
// would tie the translator to a prefix that changes, and every client would have to be told again.
var joolNAT64 = netip.MustParsePrefix("64:ff9b::/96")

func main() {
	flag.Usage = printUsage
	flag.Parse()
	if *showVersion {
		fmt.Println("sixup", version)
		return
	}
	if *showLicense {
		fmt.Printf("sixup %s\n\n%s\n%s", version, licenseText, noticeText)
		return
	}

	setupLogging(*logLevelName)
	// -v and dry-run both mean "show everything", but an explicit -log-level still wins.
	if verbose || (dryRun && !flagGiven("log-level")) {
		setDebug()
	}
	if *wan == "" {
		fatalf("-wan is required")
	}
	if runtime.GOOS != "linux" && !dryRun {
		fatalf("only -dry-run is supported on %s: configuring addresses, routes, sysctls and tunnel devices needs Linux netlink, so run for real on Linux", runtime.GOOS)
	}
	if len(lans) == 0 && !dryRun {
		fatalf("at least one -lan is required")
	}
	if len(lans) == 0 {
		lans = multiFlag{"lan"}
	}
	lanDefs := parseLans(lans)
	// A prefix learned from RA is only a /64, which cannot be split across LANs.
	mode := clientMode(*dhcpMode)
	pdEnabled := mode != clientOff && *pdLen > 0
	if len(lanDefs) > 1 && (!pdEnabled || *prefer == "ra") {
		fatalf("multiple LAN interfaces need a PD prefix; a /64 from RA cannot be split, so enable PD and set -wan-prefer pd")
	}
	srv := serverMode(*srvMode)
	if srv != serverOff && srv != serverStateless && srv != serverStateful {
		fatalf("-dhcp6s-mode must be off / stateless / stateful")
	}
	if *tMode != "off" && *tMode != "stable" && *tMode != "temporary" && *tMode != "both" {
		fatalf("-tempaddr-mode must be off / stable / temporary / both")
	}
	if *tunNAT != "auto" && *tunNAT != "off" {
		fatalf("-tunnel-nat must be auto / off")
	}
	// The two translators divide one port set, so the ruleset has to know what was lent out.
	joolShare := 0
	if *nat64 == "jool" {
		joolShare = *joolRanges
	}
	if *nat64 != "jool" && *nat64 != "off" {
		fatalf("-nat64 must be jool / off")
	}
	layout := shared64Layout(*shared64)
	switch layout {
	case "wan", "lan", "split":
	default:
		fatalf("-wan-shared64 must be wan / lan / split")
	}
	switch *ndMode {
	case "auto", "off", "static", "prefix", "forward":
	default:
		fatalf("-ndproxy-mode must be auto / off / static / prefix / forward")
	}
	if *srvPDLen < 0 || *srvPDLen > 64 {
		fatalf("-dhcp6s-pd-len must be between 0 and 64")
	}
	if *raMin > *raMax || *raMin < 3*time.Second {
		fatalf("-ra-min must be at least 3 seconds and no larger than -ra-max")
	}
	if mode == clientOff && !*upRA {
		fatalf("at least one of the DHCPv6 client and the upstream RA must be enabled")
	}
	iids, err := parseIIDPolicies(*wanIID)
	if err != nil {
		fatalf("-wan-iid: %v", err)
	}
	lanIIDs, err := parseIIDPolicies(*lanIIDSpec)
	if err != nil {
		fatalf("-lan-iid: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ula, err := loadULA(*stateDir, *ulaSpec)
	if err != nil {
		fatalf("-lan-ula: %v", err)
	}
	grace := *pdGrace
	if mode == clientOff || *pdLen == 0 {
		grace = 0
	}
	store := newStore(prefixSource(*prefer), lanDefs, *hold, ula, *tunRules, grace, *settle)
	if !dryRun {
		names := []string{*wan}
		for _, l := range lanDefs {
			names = append(names, l.iface)
		}
		if *tunDev != "" {
			names = append(names, *tunDev)
		}
		slices.Sort(names)
		claims, err := claimInterfaces(slices.Compact(names))
		if err != nil {
			fatalf("%v", err)
		}
		defer closeAll(claims)
	}
	if !*noSysctl && !dryRun {
		applySysctl(*wan, lanDefs)
	}
	hub := newLinkHub(ctx)
	pkts := newPacketHub(ctx, *wan)

	if dryRun {
		runDry(ctx, store, hub, pkts, dryOpts{wan: *wan, dhcpMode: mode, stateDir: *stateDir, tunDev: *tunDev, upRA: *upRA, wantNA: *wantNA, pdLen: *pdLen, tunMTU: *tunMTU, metric4: uint32(*tunMetric4), iid: iids[0], timeout: *dryTO})
		return
	}

	// DS-Lite hands out a name, not an address; resolving it is what completes the tunnel parameters.
	go (&aftrResolver{store: store}).run(ctx, store.Subscribe())

	secret := loadSecret(*stateDir)
	var dhcp *dhcpClient
	if mode != clientOff {
		dhcp = newDHCPClient(*wan, store, *stateDir, *pdLen, *wantNA)
		dhcp.link = hub.Subscribe(*wan)
		dhcp.releaseOn = *dhcpRel
		go dhcp.run(ctx, mode == clientAuto && *upRA)
		go holdDelegations(ctx, store.Subscribe())
	}
	if *upRA {
		go (&raClient{ifname: *wan, store: store, dhcp: dhcp, slaac: *wanSLAAC, iid: iids[0], layout: layout, secret: secret}).run(ctx, hub)
	} else {
		// Without RA there is no source for a default route, so point it at the device on a point-to-point link.
		go hub.supervise(ctx, *wan, func(cctx context.Context, ifi *net.Interface) {
			pppDefaultRoute(ifi)
			<-cctx.Done()
		})
	}
	if *tunDev != "" {
		go (&tunnelManager{dev: *tunDev, wan: *wan, mtu: *tunMTU, metric4: uint32(*tunMetric4), store: store}).run(ctx, store.Subscribe())
		// A tunnel carries IPv4, which the kernel will not forward on a system that has never been a
		// router; the IPv6 switches alone leave the tunnel built and the LAN unable to use it.
		if !*noSysctl && !dryRun {
			if err := sysctlWrite("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
				warnf("[sysctl] ipv4/ip_forward=1 failed: %v", err)
			}
		}
		if *tunNAT == "auto" {
			go (&natManager{dev: *tunDev, mtu: *tunMTU, joolRanges: joolShare}).run(ctx, store.Subscribe())
		}
	}
	if *nat64 == "jool" {
		go (&joolManager{iname: *joolIName, ranges: *joolRanges}).run(ctx, store.Subscribe())
	}
	if *tunCap && dhcp != nil {
		go (&tunnelWatcher{ifname: *wan, store: store, pkts: pkts, maxRun: *tunCapMax}).run(ctx, store.Subscribe())
	}

	dnsOverride := lanDNS{iid: lanIIDs[0], secret: secret}
	if dnsOverride.list, err = parseLANDNS(*raDNS); err != nil {
		fatalf("-ra-dns: %v", err)
	}
	var pref64 netip.Prefix
	if *raPref64 == "" && *nat64 != "off" {
		// Clients that do their own translation (RFC 8781 with a CLAT) need the prefix announced;
		// the others reach it through DNS64, which is configured elsewhere.
		pref64 = joolNAT64
	}
	if *raPref64 != "" {
		p, err := netip.ParsePrefix(*raPref64)
		if err != nil {
			fatalf("-ra-pref64: %v", err)
		}
		switch p.Bits() {
		case 32, 40, 48, 56, 64, 96:
		default:
			fatalf("-ra-pref64 length must be 32/40/48/56/64/96")
		}
		pref64 = p.Masked()
	}
	var rios []netip.Prefix
	for _, r := range routes {
		rios = append(rios, netip.MustParsePrefix(r))
	}
	tcfg := tempConfig{mode: tempMode(*tMode), regenInterval: *tRegen, preferredLft: *tPref, validLft: *tValid, maxConcurrent: *tMax, desync: *tDesync, skipDAD: *tSkipDAD, grace: *tGrace}
	if *upRA && *wanSLAAC {
		// The static SLAAC address and the optional temporary addresses coexist on the WAN interface.
		wcfg := tcfg
		wcfg.mode = tempStable
		if *wanTemp {
			wcfg.mode = "both"
		}
		go (&addrManager{ifname: *wan, secret: secret, cfg: wcfg, iids: iids, pick: Snapshot.wanSLAAC, side: sideWAN, layout: layout, extra: Snapshot.tunnelEndpoints}).run(ctx, hub, store, store.Subscribe())
	}
	poolStart, poolEnd := parsePool(*poolRange)
	var pd *pdPool
	if *srvMode != "off" && *srvPDLen > 0 {
		pd = newPDPool(*srvPDLen, filepath.Join(*stateDir, "pd-leases.json"))
	}
	for _, l := range lanDefs {
		iface := l.iface
		go (&addrManager{ifname: iface, secret: secret, cfg: tcfg, iids: lanIIDs, pick: func(s Snapshot) []Prefix { return s.LAN[iface] }, side: sideLAN, layout: layout}).run(ctx, hub, store, store.Subscribe())
		go (&raServer{
			ifname: l.iface, minI: *raMin, maxI: *raMax, lifetime: *raLifetime, mtu: uint32(*raMTU),
			managed: srv == serverStateful, other: srv != serverOff, routes: rios, dns: dnsOverride, pref64: pref64,
		}).run(ctx, hub, store, store.Subscribe())
		if *srvMode != "off" {
			s := &dhcpServer{
				ifname: l.iface, stateful: *srvMode == "stateful", leaseFile: filepath.Join(*stateDir, "leases-"+l.iface+".json"),
				statics: parseStatics(statics), poolStart: poolStart, poolEnd: poolEnd, preferred: *srvPref, valid: *srvValid, dns: dnsOverride, pd: pd,
			}
			go func(s *dhcpServer) {
				s.duid = serverDUID(ctx, dhcp, *stateDir, *wan)
				if s.duid == nil {
					return
				}
				s.run(ctx, hub, store, store.Subscribe())
			}(s)
		}
	}
	var proxy *ndProxy
	if *ndMode != "off" {
		proxy = &ndProxy{mode: proxyMode(*ndMode), wanIf: *wan, lanIf: lanDefs[0].iface, ttl: *ndTTL, layout: layout}
		for _, s := range ndStatic {
			proxy.static = append(proxy.static, parsePrefixOrAddr(s))
		}
		for _, s := range ndExclude {
			proxy.exclude = append(proxy.exclude, parsePrefixOrAddr(s))
		}
		go proxy.run(ctx, hub, store, store.Subscribe())
	}

	infof("[sixup] version %s", version)
	infof("[sixup] starting: wan=%s lan=%v dhcpv6-client=%s dhcpv6-server=%s ndp-proxy=%s tempaddr=%s", *wan, lans, *dhcpMode, *srvMode, *ndMode, *tMode)
	<-ctx.Done()
	infof("[sixup] got a termination signal, advertising RA with lifetime=0 and releasing the DHCPv6 bindings before exit")
	if dhcp != nil {
		dhcp.WaitDone()
	}
	time.Sleep(500 * time.Millisecond)
}

// claimInterfaces binds one abstract Unix socket per interface, so a second sixup touching any of
// them fails at startup instead of fighting over addresses and routes. Abstract sockets belong to
// the network namespace, as interfaces do, and the kernel drops them however the process exits.
func claimInterfaces(names []string) ([]net.Listener, error) {
	var claims []net.Listener
	for _, name := range names {
		l, err := net.Listen("unix", "@sixup/"+name)
		if err != nil {
			closeAll(claims)
			if errors.Is(err, syscall.EADDRINUSE) {
				return nil, fmt.Errorf("another sixup is already using %s", name)
			}
			return nil, fmt.Errorf("claim %s: %w", name, err)
		}
		claims = append(claims, l)
	}
	return claims, nil
}

func closeAll(ls []net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}
