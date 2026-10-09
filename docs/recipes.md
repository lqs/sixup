# Recipes

<strong>English</strong> | <a href="recipes.zh.md" lang="zh-Hans">简体中文</a> | <a href="recipes.ja.md" lang="ja">日本語</a>

sixup works out on its own what the line provides, so most setups need nothing beyond the WAN
and LAN interfaces.

```sh
sudo sixup -wan eth0 -lan eth1
```

The recipes below are for needs beyond that. Find yours in the table, then read its section for
the command and what it changes. `eth0` faces the ISP and `eth1` and `eth2` are LAN ports in
every example. Recipes combine. To have both a resolver on the router and NAT64, give the flags of
both.

| Need | Flags |
|---|---|
| [Reaching LAN hosts from the Internet](#reaching-lan-hosts-from-the-internet) | `-unsolicited allow`, or `deny` to close it further |
| [Several LAN segments](#several-lan-segments) | `-lan eth1:0 -lan eth2:1` |
| [Only one /64 from the line](#only-one-64-from-the-line) | `-wan-shared64 wan`, `-ndproxy-mode` |
| [Adjusting how the prefix is obtained](#adjusting-how-the-prefix-is-obtained) | `-dhcp6c-pd-len 60`, `-wan-prefer ra` |
| [SoftBank Hikari](#softbank-hikari) | `-wan-iid ::1111:1111:1111:1111` |
| [A prefix nobody announces](#a-prefix-nobody-announces) | `-routed-prefix 2001:db8:100::/48` |
| [Your own firewall rules for the tunnel](#your-own-firewall-rules-for-the-tunnel) | `-tunnel-nat off` |
| [Adjusting the IPv4 tunnel](#adjusting-the-ipv4-tunnel) | `-tunnel-mtu 1460`, `-tunnel-dev ""` |
| [Fixed WAN addresses for the router](#fixed-wan-addresses-for-the-router) | `-wan-iid ::1` |
| [A ULA for the LAN](#a-ula-for-the-lan) | `-ula auto` |
| [Rotating addresses for the router's own traffic](#rotating-addresses-for-the-routers-own-traffic) | `-tempaddr` |
| [Choosing the DNS servers](#choosing-the-dns-servers) | `-ra-dns self`, or the servers' addresses |
| [Addresses handed out by DHCPv6](#addresses-handed-out-by-dhcpv6) | `-dhcp6s-mode stateful` |
| [A router behind this one](#a-router-behind-this-one) | `-dhcp6s-mode stateless` on the upstream router |
| [An IPv6-only or IPv6-mostly LAN](#an-ipv6-only-or-ipv6-mostly-lan) | `-nat64 jool` |
| [Another network behind a LAN host](#another-network-behind-a-lan-host) | `-ra-route`, `-source-filter=false` |
| [Running in a container](#running-in-a-container) | `-no-sysctl`, `-state-dir` |

Every option, with its default, is listed by `sixup -h`; this page shows them by need.

On a new line, start with a dry run. It talks to the ISP, prints what the line provides and
changes nothing.

```sh
sudo sixup -wan eth0 -dry-run
```

## What needs no flags

- **A firewall for the LAN.** Connections the Internet starts are dropped before they reach the LAN
  (RFC 6092). Replies to the LAN's own connections pass, and so does traffic to a LAN endpoint that
  sent something out in the last 5 minutes, which keeps peer-to-peer programs such as Tailscale
  working. IPsec (AH, ESP and IKE) and HIP pass as RFC 6092 requires. A program that needs a port opened can ask for it with PCP, or NAT-PMP for IPv4, which over IPv4 also
  forwards a port of the tunnel's address to the host.
- **A delegated prefix.** sixup requests a /56 with DHCPv6-PD, puts a /64 of it on the LAN and
  advertises it with its own RA. The rest of the delegation is held by an unreachable route, so
  traffic for an unassigned part is dropped here instead of looping back to the ISP.
- **No address of the router on the LAN.** The LAN holds only an on-link route for each of its
  prefixes (`proto 66` in `ip -6 route`); the router's global addresses are on the WAN, and one of
  them that falls in a LAN prefix is answered for on the LAN. Hosts reach the router by its
  link-local address, and with a ULA by `::1` in it.
- **A prefix the line takes away.** The LAN is told at once, with both lifetimes 0, for 90 minutes
  (`-lan-deprecate-hold`), so hosts drop it. The LAN prefixes are recorded in the state directory,
  so one advertised before a restart that the line does not hand out again goes the same way.
- **Only a /64.** When nothing is delegated, the /64 from the upstream RA moves to the LAN
  (RFC 7278). On an Ethernet WAN the upstream router still resolves LAN addresses on the WAN
  link, so sixup answers Neighbor Discovery for them there, and logs a warning with what to ask
  the ISP for.
- **PPPoE.** Give the PPP device as the WAN, `-wan ppp0`. A point-to-point WAN has no address
  resolution, so a shared /64 needs no proxy, and without an RA the default route points at the
  device. The RA tells the LAN the smaller MTU of the line, 1492, so hosts do not depend on path
  MTU discovery; `-ra-mtu` gives another.
- **MAP-E.** When DHCPv6 carries a MAP-E option, or the prefix matches the rule tables of the
  Japanese IPoE providers (v6plus, BIGLOBE, OCN, NURO), sixup builds the tunnel `sixup-ipv4`,
  gives it the shared IPv4 address, adds an IPv4 default route through it with a high metric,
  and keeps an nftables table `inet sixup` that restricts source ports to the line's port set
  and clamps the TCP MSS.
- **DS-Lite.** When DHCPv6 names the AFTR, sixup resolves it and builds the tunnel. The AFTR
  translates, so only the MSS clamp is installed here.
- **A tunnel DHCPv6 does not describe**, such as a static 4in6 tunnel. When tunnel traffic reaches
  the WAN, sixup captures it and infers the endpoints and the IPv4 address.

## Reaching LAN hosts from the Internet

By default a host on the LAN is reachable from the Internet only where it asked to be, through
PCP. To let every host be reached at its own address, as IPv6 was meant to allow, for instance on
a network of servers that have firewalls of their own, let unsolicited traffic through.

```sh
sudo sixup -wan eth0 -lan eth1 -unsolicited allow
```

To keep the LAN closed even to programs that ask, for instance in an office, turn PCP off as well.
Peer-to-peer programs still connect, since an endpoint that sends out can be reached for a while.

```sh
sudo sixup -wan eth0 -lan eth1 -unsolicited deny
```

The default follows RFC 6092, which describes simple security for home gateways. Its default mode
drops traffic nobody on the LAN asked for, since a home network holds devices that nobody manages
and that were never meant to face the Internet. It recommends a protocol that lets programs ask
for inbound traffic (REC-48), which is what PCP does, and filtering that does not depend on the
remote endpoint (REC-11, REC-17, REC-33), so that anyone can reach a port a host has just used and
peer-to-peer programs still find each other. RFC 7084, the requirements for home routers, asks
for RFC 6092 support and takes no position on the default (S-1). RFC 6092 itself allows the open
mode as the default and requires only that it be easy to select (REC-49), which is `allow`.

In every case only traffic forwarded to the LAN is filtered. Services on the router itself are yours
to protect.

## Several LAN segments

Give each LAN interface a subnet number inside the delegation.

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1
```

A line that gives only a /64 covers one segment. Subnet 0 gets it and the others get no global
prefix. Give the segments a ULA if they need to reach each other.

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1 -ula auto
```

## Only one /64 from the line

When the line delegates nothing, the /64 of the upstream RA goes to the LAN, and the router answers
Neighbor Discovery on the WAN for the LAN hosts (RFC 7278). That is `-wan-shared64 lan`, the
default. Other layouts keep the /64 elsewhere:

- `wan` keeps the /64 on the WAN, and each LAN host gets a /128 route. It is chosen on its own
  when a /64 the LAN would share holds an address configured by hand.
- `split` puts /128 routes on both sides, and the router itself cannot reach a host it has not
  learned yet.

```sh
sudo sixup -wan eth0 -lan eth1 -wan-shared64 wan
```

The proxy follows `-ndproxy-mode`. `auto` turns `forward` on for a shared /64 on a broadcast WAN,
which probes the other side before answering, both ways. `prefix` answers every WAN solicitation
for an address in the LAN prefix without probing, `static` puts only the `-ndproxy-static`
entries into the kernel proxy table, and `off` answers nothing. `-ndproxy-exclude` keeps a prefix
out of the proxy.

```sh
sudo sixup -wan eth0 -lan eth1 -ndproxy-mode static -ndproxy-static 2001:db8:1:1::100
```

Routers behind one another can each share the /64 again, every one answering for the hosts
behind it.

## Adjusting how the prefix is obtained

sixup asks for a /56 and takes whatever length the ISP delegates, asking again without the hint
when it is refused. To ask for another length, such as the one the contract names, give it.

```sh
sudo sixup -wan eth0 -lan eth1 -dhcp6c-pd-len 60
```

The DHCPv6 client starts when the RA sets M or O, and tries PD when neither is set. `-dhcp6c-mode
on` runs it regardless, and `off` never, for a line that gives everything by RA. It also asks
for an address of the WAN interface itself (IA_NA); `-dhcp6c-ia-na=false` stops that.
`-dhcp6c-pd-len 0` asks for no prefix.

When both a delegation and an RA prefix are available, the delegation feeds the LAN.
`-wan-prefer ra` makes it the RA prefix instead. `-wan-slaac=false` gives the WAN no SLAAC
address, and `-wan-ra=false` ignores the upstream RA altogether, for a WAN configured by hand.

```sh
sudo sixup -wan eth0 -lan eth1 -wan-prefer ra
```

The prefix is kept across restarts: the DUID stays in the state directory, and nothing is
released on exit, so the ISP renews the same one. `-dhcp6c-release` gives it back on exit instead.

## SoftBank Hikari

On SoftBank Hikari (ソフトバンク光), the prefix for the LAN comes from the RA or DHCPv6-PD,
whichever the NTT line under the service gives, and IPv4 comes over a 4in6 tunnel that DHCPv6
does not describe. The border relay sends that tunnel to the address the rented Hikari BB Unit
takes on the WAN. sixup finds the tunnel from that traffic, but without the address of its own it
does not answer Neighbor Discovery for it, and the tunnel does not come up. Give the BB Unit's
interface identifier with `-wan-iid`. On the 1 Gbps service it is usually
`::1111:1111:1111:1111`; otherwise the BB Unit's status page should show the address.

```sh
sudo sixup -wan eth0 -wan-iid ::1111:1111:1111:1111 -lan eth1
```

sixup then takes the place of the BB Unit.

## A prefix nobody announces

Some upstreams route a prefix to the router without saying so by RA or DHCPv6-PD, such as a
dedicated line or a data center's transit, which routes a static prefix to the WAN address.
Configure the WAN address and the default route in the system's network configuration first, such
as 2001:db8:ffff::2/126 with the gateway 2001:db8:ffff::1, then give the prefix. The provider
gives these values when it hands the line over:

```sh
sudo sixup -wan eth0 -routed-prefix 2001:db8:100::/48 -lan eth1
```

sixup leaves the address on the WAN as it is and adds no SLAAC or IA_NA address beside it; an
address counts as configured by hand when both its lifetimes are infinite, and the first one is
the WAN address. The prefix is split
across the LAN segments and delegated to downstream routers, as a delegation is. The DHCPv6
client then asks only for DNS servers and the like; if it gets none, give them with `-ra-dns`.

A /64 that is on the WAN link rather than routed, such as that of a VPS, goes in `-wan-prefix`
instead and is shared with the LAN as when an RA gives one. When the address in it is already
configured by hand, `-wan-prefix auto` reads the /64 from it; the /64 then stays on the WAN, and
the router takes a /128 of it on the LAN and answers Neighbor Discovery on the WAN for the LAN
hosts.

An upstream that puts a prefix shorter than /64 on the link is not supported: ask it to route the
prefix to the WAN address instead.

To give the /64 of a VPS to a LAN at home through WireGuard, which carries no Neighbor Discovery,
put a GRETAP tunnel over it, run sixup on the VPS with `-wan-prefix` and the GRETAP device as the LAN, and
run sixup at home with that device as the WAN.

## Your own firewall rules for the tunnel

An existing firewall that also masquerades traffic leaving the tunnel would, on a MAP-E line,
hand out source ports outside the line's port set, and only some connections would work; sixup
warns about such chains. To leave the tunnel's source NAT and MSS clamp to your own rules, turn them off.

```sh
sudo sixup -wan eth0 -lan eth1 -tunnel-nat off
```

## Adjusting the IPv4 tunnel

The DS-Lite, MAP-E or IPIP6 tunnel is the device `sixup-ipv4`, with the WAN MTU less 40. A line
whose path is narrower needs a smaller MTU.

```sh
sudo sixup -wan eth0 -lan eth1 -tunnel-mtu 1460
```

`-tunnel-dev` names the device, and `-tunnel-dev ""` builds none, for a tunnel you set up yourself
from the parameters sixup prints. The IPv4 default route through the tunnel has metric 4096, so an
existing IPv4 default route keeps winning; `-tunnel-route4-metric` changes it, and `0` adds none.

```sh
sudo sixup -wan eth0 -lan eth1 -tunnel-route4-metric 100
```

When DHCPv6 gives no MAP-E option, sixup reads the parameters from the rule tables of the Japanese
IPoE providers; `-tunnel-mape-rules=false` stops that on a line the tables get wrong. When DHCPv6
gives no tunnel at all, sixup looks for tunnel traffic on the WAN; `-tunnel-capture=false` stops
that.

## NAT66 for containers

Docker hands its containers fixed addresses, which cannot follow a prefix that changes, so a
Docker network with a ULA and a NAT66 of your own is the practical choice. sixup refuses a ULA
that leaves its LAN interfaces, but checks what other interfaces send only after source NAT: what
your NAT translated goes out, and what would leave with a ULA untranslated is dropped. Likewise
a port published with destination NAT is reached from the Internet, whether Docker or your own
rules set it up.

```nft
table ip6 docker-nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" ip6 saddr fd00:dead:beef::/48 masquerade
    }
}
```

## Fixed WAN addresses for the router

Interface identifiers that stay the same across renumbering make the router easy to find. The
first WAN one is the address sixup reports as the WAN address. When neither SLAAC nor IA_NA
gives the WAN an address, its static addresses go in the first LAN's /64, so keep `-wan-iid`
clear of the addresses of LAN hosts.

```sh
sudo sixup -wan eth0 -wan-iid ::1 -lan eth1
```

## A ULA for the LAN

A ULA gives the LAN addresses of its own beside the ISP's prefix. Each LAN gets a /64 of it, and
hosts take an address there that stays the same when the ISP renumbers and works when the WAN is
down. The router takes `::1` of each such /64, its only address on the LAN besides the
link-local one. `auto` generates a random /48 and keeps it in `/var/lib/sixup/ula`.

```sh
sudo sixup -wan eth0 -lan eth1 -ula auto
```

## Rotating addresses for the router's own traffic

With `-tempaddr` the WAN gets temporary addresses (RFC 8981) beside its static ones. Connections
the router itself opens, such as those of a resolver or a proxy running on it, leave from the
newest of them, and a new one replaces it every hour. An address stays while connections still
use it, for a day at most, and is removed once they end. Traffic forwarded from the LAN is not
affected: LAN hosts keep their own addresses, which most systems already rotate.

```sh
sudo sixup -wan eth0 -lan eth1 -tempaddr
```

To rotate faster, shorten `-tempaddr-regen`. Every address still in use counts towards
`-tempaddr-max`. At the limit the oldest one is removed and its connections break, so raise the
limit to cover the longest connections.

```sh
sudo sixup -wan eth0 -lan eth1 -tempaddr -tempaddr-regen 5m -tempaddr-max 32
```

With a delegation, the temporary addresses go in the first LAN's /64, and the upstream router sees
only the router's link-local address however many there are. Without one they go in the SLAAC
prefix, where each is one more neighbor the upstream router keeps. Some ISPs limit their number
per line, and on some equipment too many of them break IPv6 on the line altogether. On such a
line, ask the ISP before raising `-tempaddr-max` or shortening the interval.

Only the interface identifier changes. The prefix the ISP assigned stays the same, and it still
identifies the line.

## Choosing the DNS servers

By default the LAN gets the DNS servers the upstream hands out. `-ra-dns` replaces them in the RA
and in the DHCPv6 server, with a list of entries used in order.

A resolver running on the router itself is `self`, the router's address in each LAN's ULA, which
stays reachable when the ISP renumbers or the WAN is down. Without a ULA it is the router's WAN
address.

```sh
sudo sixup -wan eth0 -lan eth1 -ula auto -ra-dns self
```

A resolver on another host of the LAN is given by its address. Give that host a fixed address in
the ULA, for the same reason.

```sh
sudo sixup -wan eth0 -lan eth1 -ula fd12:3456:789a::/48 -ra-dns fd12:3456:789a::53
```

Public resolvers are given by their addresses too.

```sh
sudo sixup -wan eth0 -lan eth1 -ra-dns 2606:4700:4700::1111,2001:4860:4860::8888
```

Entries combine. `-ra-dns self,upstream` puts the upstream servers after the router's own, and
`-ra-dns off` announces none.

## Addresses handed out by DHCPv6

For hosts that should get an address from a pool, or a fixed one, run a stateful DHCPv6 server.

```sh
sudo sixup -wan eth0 -lan eth1 -dhcp6s-mode stateful \
  -dhcp6s-static mac=aa:bb:cc:00:00:01,addr=::100
```

The RA sets M, so hosts ask DHCPv6 for addresses. Addresses come from the interface identifiers
`1000` to `ffff`; `-dhcp6s-pool 100-1ff` picks another range. `-dhcp6s-mode stateless` hands out
no addresses, only options such as DNS, and prefixes to downstream routers.

## A router behind this one

The DHCPv6 server delegates prefixes to downstream routers out of the upstream delegation, clear
of the LAN subnets, sized by default from what the upstream delegated. Another sixup behind this
one works without configuration.

```sh
# upstream router
sudo sixup -wan eth0 -lan eth1 -dhcp6s-mode stateless
# downstream router, its WAN on the upstream's LAN
sudo sixup -wan eth0 -lan eth1
```

The downstream one asks for a /56, gets at most what the upstream one can spare, such as a /60
out of a /56, and splits it across its own LANs. `-dhcp6s-pd-len` sets the size instead. This needs
a delegation shorter than /64 upstream, since a /64 has no room left once the LAN has it.
`-dhcp6s-pd-len 0` turns delegation off.

With a ULA upstream, each downstream router also gets a part of it in the same delegation, and
uses it unless it has `-ula` of its own. Hosts behind every router of the site then reach each
other and each router by ULA, while the ULA of another site stays out.

The upstream firewall lets traffic for a delegated prefix through and leaves it to the downstream
router's own, so ports opened with PCP on the downstream router can be reached.

## An IPv6-only or IPv6-mostly LAN

A LAN can run on IPv6 alone, with no IPv4 addresses, no DHCPv4, and no second protocol to keep
in step. Clients still reach the IPv4 internet through NAT64, which translates their IPv6
packets at the router. Going IPv6-only is one of the most useful things a network can do for
IPv6, since every such network is one less reason for anyone to keep IPv4 around; if that is
your plan, this section is for you.

Install the Jool module and start sixup with NAT64. If the module is not loaded, sixup loads it with `/sbin/modprobe jool`.
The namespace is reached through the IPv4 /31 `192.168.255.254/31`; when that overlaps an address
or a route of the host, sixup refuses to start, and `-jool-ipv4` gives another.

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool
```

Jool runs in a network namespace of its own behind the veth `sixup-nat64` and translates
`64:ff9b::/96`, for the LAN and for the router itself. While it translates, the RA announces the
prefix (PREF64, RFC 8781). The translated IPv4 leaves by the router's IPv4 route. Through a MAP-E
tunnel it shares the line's port set with everything else, and without a tunnel it takes
whatever IPv4 uplink is configured. A firewall has to let traffic through `sixup-nat64`.

Clients reach IPv4 in one of two ways.

- **A CLAT on the client** (464XLAT, RFC 6877) takes the prefix from the RA and translates the
  client's own IPv4 traffic, so every application works, including those that use IPv4 literals.
- **DNS64** answers IPv4-only names with addresses inside the prefix. It needs a resolver of your
  choice, which sixup does not provide, and it does not help applications that connect to IPv4
  addresses directly.

Built-in CLAT support that follows the PREF64 in the RA, as far as known at the time of writing;
check the vendors' current notes, since this moves quickly.

| System | CLAT |
|---|---|
| iOS, iPadOS 16 and later, macOS 13 and later | Built in; turns on when the network has no IPv4 |
| Android 11 and later | Built in; Android has had a CLAT for mobile networks much longer |
| Windows 11 | [Public preview](https://techcommunity.microsoft.com/blog/networkingblog/announcing-windows-clat-public-preview/4506046) since Insider Canary build 29599, off by default, turned on with `netsh interface clat set global permit=enabled pref64fromra=enabled`; needs SLAAC, so not with `-ra-slaac=false` |
| Linux | None built in; a CLAT daemon such as clatd is needed |

A network does not have to drop IPv4 at once. An IPv6-mostly network keeps IPv4 for the clients
that need it, and lets the others go without. A DHCPv4 server that sends option 108, IPv6-Only Preferred (RFC 8925),
tells capable clients to give up their IPv4 address and rely on NAT64 instead. sixup does not
run DHCPv4; set the option on the DHCPv4 server you use.

To reach private IPv4 addresses through NAT64, which the well-known prefix may not carry
(RFC 6052), use a network-specific prefix.

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool -nat64-prefix fd00:64::/96
```

To offer NAT64 through DNS64 only, without clients turning on their CLAT, keep the prefix out of
the RA.

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool -ra-pref64 off
```

## Another network behind a LAN host

A host on the LAN may route a network of its own, such as a VPN server with a prefix for its
clients. `-ra-route` tells the LAN hosts to send that prefix to the router, which needs a route to
the host itself, and the source filter has to let the prefix out.

```sh
sudo ip -6 route add 2001:db8:200::/64 via fe80::1234 dev eth1
sudo sixup -wan eth0 -lan eth1 -ra-route 2001:db8:200::/64 -source-filter=false
```

The source filter lets the LAN send out only from its own and the delegated prefixes, and answers
other sources with ICMPv6 code 5 (BCP 38). Turning it off lets the routed prefix out; it then has
to be routed to this router upstream too. `-ra-onlink=false` goes further the other way: hosts
then send even traffic for each other through the router.

## Running in a container

sixup needs the host network, and sets `forwarding`, `accept_ra`, `proxy_ndp` and `proxy_delay`
itself. Where `/proc/sys` is read-only, as in a container without `privileged`, set them on the
host and pass `-no-sysctl`: forwarding 1, `accept_ra` 0 on the LAN, `proxy_ndp` 1 and
`proxy_delay` 0 on the LAN. Keep the state directory on a volume, or a new container gets a new
DUID and the ISP may hand out a different prefix. [`docker-compose.yml`](../docker-compose.yml)
shows both.

```sh
docker run -d --network host --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  -v sixup-state:/var/lib/sixup ghcr.io/lqs/sixup -wan eth0 -lan eth1 -no-sysctl \
  -state-dir /var/lib/sixup
```
