# sixup: IPv6 routing, fully automatic

<strong>English</strong> | <a href="README.zh.md" lang="zh-Hans">简体中文</a> | <a href="README.ja.md" lang="ja">日本語</a>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lqs/sixup/graph/badge.svg)](https://codecov.io/gh/lqs/sixup)
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
- Built to the RFCs for home routers, RFC 7084 for the router as a whole and RFC 6092 for its firewall, with [each requirement and its status](docs/standards.md) listed
- Detects how the prefix arrives, DHCPv6-PD or an RA, and hands clients their addresses and configuration through its own RA and DHCPv6 services
- When the ISP hands out a new prefix, addresses, RAs, leases, proxy entries and tunnel endpoints follow
- Shares a single upstream /64 with the LAN (RFC 7278), with a Neighbor Discovery proxy on broadcast WANs, splits a shorter prefix across the segments
- Delegates prefixes to downstream routers, so one sixup can sit behind another
- Keeps unsolicited IPv6 out of the LAN, and lets programs open ports with PCP
- Builds a DS-Lite, MAP-E or IPIP6 tunnel as needed, and keeps MAP-E source ports inside the assigned port set
- One static binary under 6 MiB, dependent on no external command and no system service

## Quick start

Pick the package for your distribution (`.deb`, `.rpm`, `.apk` or Arch Linux
`.pkg.tar.zst`) or a static binary from the
[releases page](https://github.com/lqs/sixup/releases). The `dev` pre-release is built from
every commit on main and untested; a router in daily use should run a numbered release.

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
gets the prefix and the other segments get none; give them a ULA with `-ula auto` if
they need to reach each other.

Note: on a MAP-E line the source port has to stay inside the port set the line was given,
or return traffic never arrives. sixup maintains those nftables rules in a table of its
own, `inet sixup`, removed when it exits. Pass `-tunnel-nat off` to write them yourself.

For other needs, such as several LAN segments, fixed addresses, DNS servers or NAT64, see the
[recipes](docs/recipes.md). Which RFCs sixup follows, item by item and gaps included, is listed in
[standards](docs/standards.md).

## Options

`sixup -h` lists every option with its default, and the [recipes](docs/recipes.md) show them by
need. Only the options for running sixup itself are listed here.

- A boolean option is turned off with `=false`, for example `-wan-ra=false`.
- A duration takes Go syntax: `30s`, `10m`, `1h30m`.
- A repeatable option is given once per value: `-lan eth1 -lan eth2`.

| Option | Default | Description |
|---|---|---|
| `-state-dir` | `/var/lib/sixup` | Directory for the DUID, the secret behind the stable addresses, the ULA and the leases. Keep it across restarts, or the provider may hand out a different prefix. |
| `-no-sysctl` | `false` | Leave `forwarding`, `accept_ra` and the other sysctls alone, for setups that manage them elsewhere. The LAN then needs `proxy_ndp` 1 and `proxy_delay` 0. |
| `-dry-run` | `false` | Go through obtaining and renewing the parameters and finding the tunnel, printing as it goes, without changing the system or sending RAs to the LAN. |
| `-dry-run-timeout` | `0` | How long a dry run lasts. `0` runs until interrupted. |
| `-log-level` | `info` | Lowest level printed: `debug`, `info`, `warn` or `error`. |
| `-v` | `false` | Same as `-log-level debug`. |
| `-version` | | Print the version and exit. |
| `-license` | | Print the licence of sixup and of the work it derives from, and exit. |
