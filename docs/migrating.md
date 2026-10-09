# Migrating to sixup

<strong>English</strong> | <a href="migrating.zh.md" lang="zh-Hans">简体中文</a> | <a href="migrating.ja.md" lang="ja">日本語</a>

On many Linux routers, several programs and scripts set up IPv6. sixup does all of this in one
program. This page shows how to move an existing router to sixup, step by step.

During the move, the router has no IPv6 for a few minutes. On a MAP-E or DS-Lite line, IPv4 is
also down, because it runs over IPv6.

## 1. Do a dry run

First check that sixup works on your line. A dry run does not change anything on the router, so
you can run it while your current setup is still running. Use the flags you plan to use.

```sh
sudo sixup -wan eth0 -lan eth1 -dry-run
```

A dry run talks to the ISP and prints the prefix, the DNS servers and the tunnel it finds. It
sends no RA to the LAN. When it ends, it releases what the ISP gave it. It uses a DUID made from
the MAC address, not the one in `/var/lib/sixup/duid`. To stop it, press Ctrl+C, or set a time
with `-dry-run-timeout`.

The dry run needs UDP port 546, the DHCPv6 client port. If your current DHCPv6 client uses this
port, the dry run cannot start its DHCPv6 client. In that case, stop your client during the dry
run, and start it again after. Some clients release the prefix when they stop, so the ISP may give
a new prefix after that.

Check the output.

- sixup gets a prefix, and its length is what your ISP gives.
- On a MAP-E, DS-Lite or 4in6 line, sixup finds the tunnel, and the tunnel type is correct.
- There are no errors, and you understand every warning.

If something is not as you expect, stop here and do not go on to the next steps. Your router is
still unchanged. Check the options in the [recipes](recipes.md) and `sixup -h`, or
[open an issue](https://github.com/lqs/sixup/issues) with the output of the dry run.

## 2. Make a checklist

Write down what your router does for IPv6 now, and which program does it. sixup does the jobs in
the first rows of this table. The jobs in the last row stay with your current programs.

| Job | Usually done by | With sixup |
|---|---|---|
| Getting the prefix from the ISP | odhcp6c, dhcpcd, wide-dhcpv6-client, `dhclient -6`, systemd-networkd, ifupdown | Built in |
| Router Advertisements on the LAN | radvd, odhcpd, dnsmasq (`enable-ra`), systemd-networkd (`IPv6SendRA`) | Built in |
| DHCPv6 server on the LAN | odhcpd, dnsmasq, Kea | Built in, `-dhcp6s-mode` |
| Neighbor Discovery proxy for a shared /64 | ndppd | Built in |
| MAP-E, DS-Lite or 4in6 tunnel, with its NAT and MSS rules | scripts | Built in |
| IPv6 filter for traffic to the LAN | ip6tables, nftables | Built in, see `-unsolicited` |
| DHCPv4, native IPv4 NAT, DNS resolver, filter for the router itself | dnsmasq, Unbound, nftables | Not changed |

Now find everything that does one of the sixup jobs, and write down where it is. Then step 5 is
only a matter of working through this list.

**Services to stop.** List the services that start at boot, and note the ones from the table,
such as radvd, odhcpd, odhcp6c, ndppd and wide-dhcpv6-client.

```sh
systemctl list-unit-files --state=enabled   # systemd
rc-update show default                      # OpenRC, such as Alpine
```

**Settings to change in programs that keep running.** Note the file and the line.

- **dnsmasq**, in `/etc/dnsmasq.conf` and `/etc/dnsmasq.d/`. The lines `enable-ra`, `ra-param`,
  and `dhcp-range` with an IPv6 range.
- **systemd-networkd**, in `/etc/systemd/network/*.network` for the WAN and the LANs. The
  settings `IPv6AcceptRA`, `IPv6SendRA`, `DHCPPrefixDelegation` and `DHCP`.
- **NetworkManager.** The connections of the WAN and the LANs, from `nmcli connection show`, and
  their `ipv6.method`.
- **dhcpcd**, in `/etc/dhcpcd.conf`. The options `ia_pd`, `ipv6rs` and `ipv6only`.
- **ifupdown**, in `/etc/network/interfaces`. The `inet6` sections of the WAN and the LANs.

**Scripts and leftovers.** These commands help you find them.

```sh
crontab -l; ls /etc/cron.d
grep -rlE 'ip -6|ip6tables|ip6tnl|inet6|radvd' /etc/network /etc/ppp /etc/dhcpcd* /etc/cron* 2>/dev/null
grep -rE 'accept_ra|autoconf|forwarding' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
ip -d link show type ip6tnl
nft list ruleset | grep -n masquerade
iptables -t nat -S 2>/dev/null | grep MASQUERADE
```

- Cron jobs, `if-up.d` scripts, PPP `ip-up` scripts and dhcpcd hooks that add IPv6 addresses,
  routes or tunnels.
- Files in `/etc/sysctl.d` that set `accept_ra`, `autoconf` or `forwarding`. sixup sets these
  values when it starts. If such a file stays, reloading the sysctls changes them back.
- Tunnel devices that scripts created.
- nftables or iptables rules that masquerade traffic going out through the tunnel. On MAP-E, these
  rules use ports outside the port set of the line. sixup warns when it finds such a rule.
- Your own IPv6 filter for traffic to the LAN. Keep it only if you will run sixup with
  `-unsolicited allow`.

**Save the current state.** You can use it later to compare, or to go back.

```sh
ip -6 addr > before-addr.txt
ip -6 route > before-route.txt
ip -4 route >> before-route.txt
nft list ruleset > before-nft.txt
sysctl -a 2>/dev/null | grep -E 'ipv6\.conf\..*\.(forwarding|accept_ra|autoconf)' > before-sysctl.txt
crontab -l > before-crontab.txt
```

**Keep the prefix, if you want.** The ISP knows your router by its DHCPv6 DUID. sixup creates a
new DUID. Many ISPs give a new prefix to a new DUID, and then every address on the LAN changes
once.

To keep your prefix, find the DUID of your old DHCPv6 client. Look in its state files or its log.
Before you start sixup for the first time, write the DUID to `/var/lib/sixup/duid` as hex, with no
separators, for example `000100012a3b4c5d001122334455`. The ISP may still give a new prefix,
because it can also check the IAID. sixup makes the IAID from the last four bytes of the WAN MAC
address.

## 3. Plan how to go back

Do not delete the old services. Only stop and disable them, and keep a copy of every file you
change. Then you can go back with a few commands.

```sh
# systemd
sudo systemctl disable --now sixup
sudo systemctl enable --now radvd odhcp6c   # the services you stopped in step 5

# OpenRC
sudo rc-service sixup stop && sudo rc-update del sixup default
sudo rc-update add radvd default && sudo rc-service radvd start   # and so on for each service
```

When sixup stops, it sends a Router Advertisement with a Router Lifetime of 0, so hosts stop
using it at once. It also removes its nftables tables `inet sixup` and `inet sixup-filter` and
its unreachable routes.

The addresses that sixup added stay until their lifetimes end, at most 90 minutes on the LAN. To
remove them at once, flush them or reboot. If the tunnel device `sixup-ipv4` is still there, you
can delete it.

```sh
sudo ip -6 addr flush dev eth1 scope global
sudo ip link del sixup-ipv4
```

Before you start, make sure you can reach the router without IPv6 and without the LAN you are
changing. For example, use the console, or IPv4 on another port.

## 4. Choose a maintenance window

Choose a time. 15 minutes is enough. Tell everyone who uses the network, including pets with
online feeders, robots, and AI agents that are working on a task. If an AI agent does the
migration for you, it needs a connection that still works after step 5.

Before you start, check three things.

- **Things that cannot be offline for 15 minutes.** For example, smart locks that need the cloud,
  alarms, medical devices that send data, and phones that use the Internet. Find another way for
  each of them.
- **Places where the old prefix is written.** For example, dynamic DNS, static addresses, and
  allowlists on remote services. Update them if the ISP gives you a new prefix.
- **You are next to the router.** Have a phone with a mobile hotspot, and enough time to go back
  if needed. Do not migrate a router in another country, such as your parents' router, from where
  you are. Do not migrate your home router while you travel to Mars.

## 5. Stop the old IPv6 setup

Work through the list from step 2. If two programs send RAs on one LAN, or two DHCPv6 clients run
on one WAN, you get problems that are hard to find, so do not skip anything.

Stop and disable the services.

```sh
# systemd
sudo systemctl disable --now radvd odhcpd odhcp6c ndppd

# OpenRC
for s in radvd odhcpd odhcp6c ndppd; do sudo rc-service $s stop; sudo rc-update del $s default; done
```

Change the settings of the programs that keep running, then restart them.

- **dnsmasq.** Remove the IPv6 lines. Keep DHCPv4 and DNS.
- **systemd-networkd.** Set `IPv6AcceptRA=no` and `IPv6SendRA=no`, remove
  `DHCPPrefixDelegation`, and set `DHCP=` to `ipv4` or `no`.
- **NetworkManager.** Set `ipv6.method` to `link-local`, or stop managing these interfaces.
- **dhcpcd.** Add `noipv6rs` and `ipv6ra_noautoconf` and remove `ia_pd`, or run it with `-4`.
- **ifupdown.** Remove the `inet6` sections of the WAN and the LANs.

Remove the scripts, the sysctl files and the masquerade rules you found. Delete the old tunnel
devices with `ip link del`.

Check that nothing is still running.

```sh
pgrep -a 'radvd|odhcpd|odhcp6c|ndppd|dhcp6c'
sudo ss -ulpn 'sport = :546 or sport = :547'
```

## 6. Switch to sixup

Put your flags in the configuration file and start the service.

```sh
# systemd
echo 'SIXUP_OPTS="-wan eth0 -lan eth1"' | sudo tee /etc/default/sixup
sudo systemctl enable --now sixup
journalctl -u sixup -f

# OpenRC
echo 'SIXUP_OPTS="-wan eth0 -lan eth1"' | sudo tee /etc/conf.d/sixup
sudo rc-update add sixup default && sudo rc-service sixup start
tail -f /var/log/sixup.log
```

Then check the following, on the router and on a host in the LAN.

- The log shows the prefix and the LAN routes. On a tunnel line, it also shows the tunnel.
- A LAN host gets an address in the new prefix and can reach IPv6 sites. test-ipv6.com tests IPv4
  and IPv6 at the same time.
- On a MAP-E or DS-Lite line, IPv4 works through the tunnel.
- `nft list table inet sixup-filter` shows the filter, and its counters go up.

Keep the old configuration for a few days. Wait until the prefix has been renewed at least once,
then delete it.
