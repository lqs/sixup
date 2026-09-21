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
- Shares a single upstream /64 with the LAN as RFC 7278 prescribes, Neighbor Discovery proxy included, splits a shorter prefix across the segments
- Builds a DS-Lite, MAP-E or IPIP6 tunnel as needed, and keeps MAP-E source ports inside the assigned port set
- One static binary under 5 MiB, dependent on no external command and no system service

## Quick start

> [!WARNING]
> sixup is under development and has not been released yet. Parts of it have never run on
> a real line, so it may not work at all, and options change from one commit to the next.

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

`sixup -h` lists every option, grouped by function.
