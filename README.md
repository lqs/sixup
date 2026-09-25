# sixup: IPv6 routing, fully automatic

<strong>English</strong> | <a href="README.zh.md" lang="zh-Hans">简体中文</a> | <a href="README.ja.md" lang="ja">日本語</a>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

In the past, setting up IPv6 routing on Linux took a number of programs. `odhcp6c`
obtained the prefix, `radvd` sent the Router Advertisements, `odhcpd` served DHCPv6,
`ndppd` proxied Neighbor Discovery, and a few scripts passed parameters between them and
restarted whatever had to be restarted.

sixup does all of it in one program, the state and the parameters of each stage passing
inside it rather than through scripts. When the line hands out a different prefix, the
interface addresses, the Router Advertisements, the DHCPv6 leases, the proxy entries and
the tunnel endpoints all follow from that one event. No manual step, no restart.

## Features

- Handles the whole job of an IPv6 router, with no other daemon to configure
- Detects how the prefix arrives, DHCPv6-PD or an RA, and hands clients their addresses and configuration through its own RA and DHCPv6 services
- When the ISP hands out a new prefix, addresses, RAs, leases, proxy entries and tunnel endpoints follow
- Shares a single upstream /64 with the LAN (RFC 7278), with a Neighbor Discovery proxy on broadcast WANs, splits a shorter prefix across the segments
- Builds a DS-Lite, MAP-E or IPIP6 tunnel as needed, and keeps MAP-E source ports inside the assigned port set
- One static binary under 5 MiB, dependent on no external command and no system service

## Quick start

> [!WARNING]
> sixup is under development and has not been released yet. Parts of it have never run on
> a real line, so it may not work at all, and options change from one commit to the next.

Pick the package for your distribution (`.deb`, `.rpm`, `.apk` or Arch Linux
`.pkg.tar.zst`) or a static binary from the
[releases page](https://github.com/lqs/sixup/releases). There is no formal release yet,
only the `dev` pre-release.

Check what the line provides, without changing anything:

```sh
sudo sixup -wan eth0 -dry-run
```

Obtain the prefix from the WAN interface and configure one LAN interface from it:

```sh
sudo sixup -wan eth0 -lan eth1
```

The prefix is obtained by whichever method the line supports. No further options are
needed.

To divide a delegated prefix across several LAN segments, give each interface a subnet
id:

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1
```

Note: a single /64 covers one LAN segment. On a line that delegates nothing, subnet id 0
gets the prefix and the other segments get none; give them a ULA with `-lan-ula auto` if
they need to reach each other.

Note: on a MAP-E line the source port has to stay inside the port set the line was given,
or return traffic never arrives. sixup maintains those nftables rules in a table of its
own, `inet sixup`, removed when it exits. Pass `-tunnel-nat off` to write them yourself.

## Options

> [!WARNING]
> sixup has not been released yet, so options may be renamed or removed without notice.

`sixup -h` lists every option in the groups below.

- A boolean option is turned off with `=false`, for example `-wan-ra=false`.
- A duration takes Go syntax: `30s`, `10m`, `1h30m`.
- A repeatable option is given once per value: `-lan eth1 -lan eth2`.

### Interfaces and prefixes

| Option | Default | Description |
|---|---|---|
| `-wan` | | WAN interface. Required. |
| `-lan` | | LAN interface, repeatable, as `name[:subnet-id]`. The subnet id, in decimal, picks which /64 of the delegated prefix goes to this interface; without one, the interfaces take 0, 1, 2 in the order given. Several LAN interfaces need a delegated prefix. |
| `-lan-ula` | | ULA prefix advertised next to the global prefix. `auto` generates a random /48 and keeps it in the state directory; a prefix such as `fd12:3456:789a::/48` is used as given. Comma separated for several. |
| `-lan-iid` | | Interface identifiers of the router's own addresses on each LAN prefix, comma separated, one address each, same syntax as `-wan-iid`. Empty means one RFC 7217 stable address. |
| `-lan-deprecate-hold` | `10m` | How long a withdrawn prefix keeps being advertised with a preferred lifetime of 0, so clients stop using it. |

### WAN side: DHCPv6 client

| Option | Default | Description |
|---|---|---|
| `-dhcp6c-mode` | `auto` | `auto` follows the M and O flags of the upstream RA, `on` always runs the client, `off` never does. |
| `-dhcp6c-pd-len` | `56` | Prefix length hinted when requesting a delegated prefix (IA_PD). The server decides the length it delegates; if it refuses the hint, sixup asks once more without one. `0` requests none. |
| `-dhcp6c-ia-na` | `true` | Also request an address for the WAN interface itself (IA_NA). |
| `-dhcp6c-pd-grace` | `10s` | How long to wait for a delegated prefix after startup. Until then an RA prefix only serves the WAN side and is not handed to the LAN, so it never has to be withdrawn again. |
| `-dhcp6c-release` | `false` | Send RELEASE on exit to give back the prefix and addresses. Off by default: the DUID is kept, so a restart renews the same prefix. A dry run always releases. |

### WAN side: upstream RA and addresses

| Option | Default | Description |
|---|---|---|
| `-wan-ra` | `true` | Listen to upstream RAs as a second prefix source, and maintain the default route from them. |
| `-wan-slaac` | `true` | Configure SLAAC addresses on the WAN interface for RA prefixes with the A flag set. |
| `-wan-iid` | | Interface identifiers of the static SLAAC addresses on the WAN interface, comma separated, one address each. Each is `stable` or empty for an RFC 7217 stable address, `eui64` to derive it from the MAC address, or a fixed suffix such as `::1` or `::1111:2222:3333:4444`. The first one is reported as the WAN address. |
| `-wan-tempaddr` | `false` | Also rotate temporary addresses on the WAN interface, following the `-tempaddr-*` options. |
| `-wan-prefer` | `pd` | Which prefix wins when both a delegated prefix and an RA prefix are available: `pd` or `ra`. |
| `-wan-shared64` | `lan` | Layout when the upstream gives only one /64. `lan`: the /64 goes to the LAN, and hosts on the WAN link get /128 routes (RFC 7278). `wan`: the /64 stays on the WAN, and each LAN host gets a /128 route. `split`: /128 routes on both sides; the router itself cannot reach a host it has not learned yet. The /128 routes are added as the NDP proxy finds the hosts. |

### LAN side: RA advertisement

| Option | Default | Description |
|---|---|---|
| `-ra-min` | `3m20s` | Minimum interval between unsolicited RAs (MinRtrAdvInterval). |
| `-ra-max` | `10m` | Maximum interval between unsolicited RAs (MaxRtrAdvInterval). |
| `-ra-lifetime` | `30m` | Router lifetime carried in the RA. |
| `-ra-mtu` | `0` | MTU advertised in the RA. `0` advertises the WAN path MTU when it is smaller than the LAN interface MTU, taken from the upstream RA or the WAN interface, so a PPPoE line with 1492 no longer depends on path MTU discovery. |
| `-ra-dns` | | DNS servers to advertise instead of the upstream ones, comma separated. Also used by the DHCPv6 server. |
| `-ra-pref64` | | NAT64 prefix to advertise (RFC 8781), such as `64:ff9b::/96`. Empty passes on the one from the upstream RA. The length must be 32, 40, 48, 56, 64 or 96. |
| `-ra-route` | | Prefix to advertise as a Route Information option, repeatable. |

### LAN side: DHCPv6 server

| Option | Default | Description |
|---|---|---|
| `-dhcp6s-mode` | `off` | `stateless` answers only with options such as DNS; `stateful` also assigns addresses; `off` runs no server. The RA flags follow this choice. |
| `-dhcp6s-pool` | `1000-ffff` | Range of interface identifiers to assign from, in hexadecimal, as the low 64 bits. |
| `-dhcp6s-static` | | Fixed assignment, repeatable: `mac=<MAC>,addr=::100`, or `duid=<hex>,addr=2001:db8::5`. |
| `-dhcp6s-lease-preferred` | `1h` | Preferred lifetime of an assigned address. |
| `-dhcp6s-lease-valid` | `2h` | Valid lifetime of an assigned address. |

### NDP proxy

| Option | Default | Description |
|---|---|---|
| `-ndproxy-mode` | `auto` | `auto` turns `forward` on when a LAN /64 is also the on-link /64 of a broadcast WAN, and stays off otherwise, since a delegated prefix or a point-to-point WAN needs no proxy. `forward` probes the other side before answering, in both directions, so hosts on the WAN link and on the LAN reach each other too. `prefix` answers every WAN solicitation for an address in the LAN prefix without probing. `static` only puts the `-ndproxy-static` entries into the kernel proxy table. `off` disables the proxy. |
| `-ndproxy-static` | | Address or prefix to proxy in `static` mode, repeatable. |
| `-ndproxy-exclude` | | Prefix never proxied, repeatable. |
| `-ndproxy-ttl` | `30s` | How long a learned proxy entry lives. |

### Local address rotation

These options govern the router's own addresses on the LAN, and on the WAN with `-wan-tempaddr`.

| Option | Default | Description |
|---|---|---|
| `-tempaddr-mode` | `off` | `temporary` and `both` add rotating temporary addresses (RFC 8981) next to the static ones; `off` and `stable` keep only the static addresses. |
| `-tempaddr-regen` | `1h` | How often a new temporary address is created. |
| `-tempaddr-preferred` | `1h` | Preferred lifetime of a temporary address. |
| `-tempaddr-valid` | `24h` | Upper limit of the valid lifetime of a temporary address. An address still in use is kept up to this limit, an unused one is removed earlier. |
| `-tempaddr-max` | `8` | Maximum number of temporary addresses at once. |
| `-tempaddr-desync` | `10m` | Upper limit of the random offset applied to each rotation. |
| `-tempaddr-skip-dad` | `false` | Skip duplicate address detection. Only for links known to be free of conflicts. |
| `-tempaddr-drain-grace` | `5s` | Interval between the two checks that decide an address is no longer in use. |

### Tunnel

| Option | Default | Description |
|---|---|---|
| `-tunnel-dev` | `sixup-ipv4` | Name of the IPv4-in-IPv6 tunnel device. Once the tunnel parameters are known, sixup creates or updates it, brings it up and assigns the IPv4 address. Empty creates no device. |
| `-tunnel-mtu` | `0` | MTU of the tunnel device. `0` means the WAN interface MTU minus 40. |
| `-tunnel-route4-metric` | `4096` | Metric of the IPv4 default route through the tunnel. It is high on purpose: an existing IPv4 default route keeps winning, and the tunnel takes over only when there is none. `0` adds no route. |
| `-tunnel-nat` | `auto` | Maintain the nftables table `inet sixup` for traffic leaving the tunnel. `auto` configures the port-restricted source NAT required on MAP-E (RFC 7597), an ordinary source NAT on a line with its own IPv4 address, and none on DS-Lite, where the provider translates; in every case it clamps the TCP MSS to the tunnel MTU. `off` writes no rules. Nothing outside the table is touched, and the table is removed on exit. |
| `-tunnel-mape-rules` | `true` | When DHCPv6 carries no MAP-E option, derive the MAP-E parameters from the delegated prefix using the rule tables of the Japanese IPoE providers (v6plus, BIGLOBE, OCN, NURO). |
| `-tunnel-capture` | `true` | When DHCPv6 carries no tunnel option, capture tunnel traffic to find the parameters. Needs `-dhcp6c-mode` other than `off`, and is not done in a dry run. |
| `-tunnel-capture-max` | `2m` | How long the capture waits. It ends at the first tunnel packet; if none arrives, it gives up and tries again when the prefix or the address changes. |

### NAT64

| Option | Default | Description |
|---|---|---|
| `-nat64` | `off` | `jool` configures NAT64 with the [Jool](https://jool.mx) kernel module (4.1 or later, loaded with `modprobe jool`): an instance translating `64:ff9b::/96`, advertised in the RA, whose output goes through the source NAT above, so the ports of a MAP-E line have one owner. `off` configures none. DNS64 is left to a resolver of your choice. |
| `-jool-instance` | `sixup` | Name of the Jool instance sixup creates and removes. |
| `-jool-port-ranges` | `3` | How many of the port ranges of a MAP-E line go to the translator; netfilter keeps the rest, and the two never hand out the same port. Ignored when the line owns every port of its address. |

### Runtime

| Option | Default | Description |
|---|---|---|
| `-state-dir` | `/var/lib/sixup` | Directory for the DUID, the secret behind the stable addresses, the ULA and the leases. Keep it across restarts, or the provider may hand out a different prefix. |
| `-no-sysctl` | `false` | Leave `forwarding`, `accept_ra` and the other sysctls alone, for setups that manage them elsewhere. |
| `-settle` | `1s` | How long the parameters must stay unchanged before they are applied, so the RA, the delegated prefix, DNS and the capture result arriving one after another at startup are applied together. Withdrawals are applied at once. |
| `-dry-run` | `false` | Go through obtaining and renewing the parameters and finding the tunnel, printing as it goes, without changing the system or sending RAs to the LAN. |
| `-dry-run-timeout` | `0` | How long a dry run lasts. `0` runs until interrupted. |
| `-log-level` | `info` | Lowest level printed: `debug`, `info`, `warn` or `error`. |
| `-v` | `false` | Same as `-log-level debug`. |
| `-version` | | Print the version and exit. |
| `-license` | | Print the licence of sixup and of the work it derives from, and exit. |
