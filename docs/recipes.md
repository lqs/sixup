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
| [SoftBank Hikari](#softbank-hikari) | `-wan-iid ::1111:1111:1111:1111` |
| [A prefix nobody announces](#a-prefix-nobody-announces) | `-wan-prefix 2001:db8:100::/48` |
| [Your own firewall rules for the tunnel](#your-own-firewall-rules-for-the-tunnel) | `-tunnel-nat off` |
| [Fixed addresses for the router](#fixed-addresses-for-the-router) | `-wan-iid ::1 -lan-iid ::1` |
| [Rotating addresses for the router's own traffic](#rotating-addresses-for-the-routers-own-traffic) | `-tempaddr` |
| [Choosing the DNS servers](#choosing-the-dns-servers) | `-ra-dns self`, or the servers' addresses |
| [Addresses handed out by DHCPv6](#addresses-handed-out-by-dhcpv6) | `-dhcp6s-mode stateful` |
| [A router behind this one](#a-router-behind-this-one) | `-dhcp6s-mode stateless` on the upstream router |
| [An IPv6-only or IPv6-mostly LAN](#an-ipv6-only-or-ipv6-mostly-lan) | `-nat64 jool` |

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
- **Only a /64.** When nothing is delegated, the /64 from the upstream RA moves to the LAN
  (RFC 7278). On an Ethernet WAN the upstream router still resolves LAN addresses on the WAN
  link, so sixup answers Neighbor Discovery for them there, and logs a warning with what to ask
  the ISP for.
- **PPPoE.** Give the PPP device as the WAN, `-wan ppp0`. A point-to-point WAN has no address
  resolution, so a shared /64 needs no proxy, and without an RA the default route points at the
  device.
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
static prefix an ISP routes to the line by contract, or the single /64 of a VPS. Give it by hand.

```sh
sudo sixup -wan eth0 -wan-prefix 2001:db8:100::/48 -lan eth1
```

The DHCPv6 client then asks only for DNS servers and the like. Without an RA on the line, the
default route is set up otherwise, as a VPS usually has it, and the DNS servers are given with
`-ra-dns` if DHCPv6 gives none.

A /64, such as that of a VPS, is shared with the LAN as when an RA gives one. The router keeps a
/128 of it on the WAN and answers Neighbor Discovery there for the LAN hosts. A shorter prefix is split across the LAN
segments and delegated to downstream routers, as a delegation is.

To give the /64 of a VPS to a LAN at home through WireGuard, which carries no Neighbor Discovery,
put a GRETAP tunnel over it, run this command on the VPS with the GRETAP device as the LAN, and
run sixup at home with that device as the WAN.

## Your own firewall rules for the tunnel

An existing firewall that also masquerades traffic leaving the tunnel would, on a MAP-E line,
hand out source ports outside the line's port set, and only some connections would work; sixup
warns about such chains. To leave the tunnel's source NAT and MSS clamp to your own rules, turn them off.

```sh
sudo sixup -wan eth0 -lan eth1 -tunnel-nat off
```

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

## Fixed addresses for the router

Interface identifiers that stay the same across renumbering make the router easy to find. The
first WAN one is the address sixup reports as the WAN address.

```sh
sudo sixup -wan eth0 -wan-iid ::1 -lan eth1 -lan-iid ::1
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

A resolver running on the router itself is `self`, the router's address on each LAN. A ULA keeps
that address valid when the ISP renumbers.

```sh
sudo sixup -wan eth0 -lan eth1 -ula auto -lan-iid ::1 -ra-dns self
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

The RA sets M, so hosts ask DHCPv6 for addresses. `-dhcp6s-mode stateless` hands out no
addresses, only options such as DNS, and prefixes to downstream routers.

## A router behind this one

The DHCPv6 server delegates prefixes to downstream routers out of the upstream delegation, clear
of the LAN subnets, a /60 by default. Another sixup behind this one works without configuration.

```sh
# upstream router
sudo sixup -wan eth0 -lan eth1 -dhcp6s-mode stateless
# downstream router, its WAN on the upstream's LAN
sudo sixup -wan eth0 -lan eth1
```

The downstream one asks for a /56 and gets a /60, which it splits across its own LANs. This needs
a delegation shorter than /64 upstream, since a /64 has no room left once the LAN has it.
`-dhcp6s-pd-len 0` turns delegation off.

The upstream firewall lets traffic for a delegated prefix through and leaves it to the downstream
router's own, so ports opened with PCP on the downstream router can be reached.

## An IPv6-only or IPv6-mostly LAN

A LAN can run on IPv6 alone, with no IPv4 addresses, no DHCPv4, and no second protocol to keep
in step. Clients still reach the IPv4 internet through NAT64, which translates their IPv6
packets at the router. Going IPv6-only is one of the most useful things a network can do for
IPv6, since every such network is one less reason for anyone to keep IPv4 around; if that is
your plan, this section is for you.

Install the Jool module and start sixup with NAT64. If the module is not loaded, sixup loads it with `/sbin/modprobe jool`.

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
