package main

import "log"

// applySysctl turns on the kernel switches a bare system needs: global forwarding, and no RA on the LAN interfaces.
// IPv6 forwarding is decided by conf/all/forwarding, so a per-interface setting alone has no effect.
func applySysctl(wan string, lans []lanDef) {
	set := func(iface, key, val string) {
		if err := sysctlSet(iface, key, val); err != nil {
			log.Printf("[sysctl] %s/%s=%s failed: %v", iface, key, val, err)
		}
	}
	set("all", "forwarding", "1")
	for _, l := range lans {
		set(l.iface, "accept_ra", "0")
		set(l.iface, "forwarding", "1")
	}
	set(wan, "forwarding", "1")
}
