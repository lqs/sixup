package main

// applySysctl turns on the kernel switches a bare system needs: global forwarding, and no RA on the LAN interfaces.
// IPv6 forwarding is decided by conf/all/forwarding, so a per-interface setting alone has no effect.
// Without a LAN there is nothing to forward, and only the WAN's own RA handling is turned off.
func applySysctl(wan string, lans []lanDef) {
	set := func(iface, key, val string) {
		if err := sysctlSet(iface, key, val); err != nil {
			warnf("[sysctl] %s/%s=%s failed: %v", iface, key, val, err)
		}
	}
	// A host that forwards nothing would take the RA itself beside sixup, addresses and default
	// route alike; a router ignores it already
	if len(lans) == 0 {
		set(wan, "accept_ra", "0")
		return
	}
	set("all", "forwarding", "1")
	for _, l := range lans {
		set(l.iface, "accept_ra", "0")
		set(l.iface, "forwarding", "1")
	}
	set(wan, "forwarding", "1")
}
