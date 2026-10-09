# 迁移到 sixup

<a href="migrating.md" lang="en">English</a> | <strong>简体中文</strong> | <a href="migrating.ja.md" lang="ja">日本語</a>

在很多 Linux 路由器上，IPv6 由好几个程序和脚本共同配置。sixup 用一个程序完成所有这些工作。本文一步一步地说明如何把现有的路由器迁移到 sixup。

迁移期间，路由器会有几分钟没有 IPv6。在 MAP-E 或 DS-Lite 线路上，IPv4 也会中断，因为它运行在 IPv6 之上。

## 1. 试运行

先确认 sixup 在你的线路上能正常工作。试运行不会改变路由器上的任何东西，所以可以在现有配置运行的同时进行。请使用你打算正式使用的参数。

```sh
sudo sixup -wan eth0 -lan eth1 -dry-run
```

试运行会和运营商通信，输出它找到的前缀、DNS 服务器和隧道。它不向内网发送 RA。结束时，它会释放运营商分配的资源。它使用由 MAC 地址生成的 DUID，而不是 `/var/lib/sixup/duid` 中的 DUID。要停止它，按 Ctrl+C，或者用 `-dry-run-timeout` 设定时间。

试运行需要 UDP 546 端口，也就是 DHCPv6 客户端端口。如果现有的 DHCPv6 客户端占用了这个端口，试运行就无法启动它的 DHCPv6 客户端。这时请在试运行期间停止现有客户端，结束后再启动。有些客户端停止时会释放前缀，所以之后运营商可能会分配新的前缀。

检查输出。

- sixup 获得了前缀，长度与运营商分配的一致。
- 在 MAP-E、DS-Lite 或 4in6 线路上，sixup 找到了隧道，隧道类型正确。
- 没有错误，并且你理解每一条警告。

如果有与预期不符的地方，请到此为止，不要继续后面的步骤。此时路由器仍然没有任何改变。请查看 [recipes](recipes.zh.md) 和 `sixup -h` 的参数说明，或者附上试运行的输出[提交 issue](https://github.com/lqs/sixup/issues)。

## 2. 列出清单

写下路由器现在为 IPv6 做了哪些工作，分别由哪个程序完成。下表前几行的工作由 sixup 完成，最后一行的工作仍由现有程序负责。

| 工作 | 通常由谁完成 | 使用 sixup 后 |
|---|---|---|
| 从运营商获取前缀 | odhcp6c、dhcpcd、wide-dhcpv6-client、`dhclient -6`、systemd-networkd、ifupdown | 内置 |
| 在内网发送路由器通告 | radvd、odhcpd、dnsmasq（`enable-ra`）、systemd-networkd（`IPv6SendRA`） | 内置 |
| 内网 DHCPv6 服务器 | odhcpd、dnsmasq、Kea | 内置，`-dhcp6s-mode` |
| 共享 /64 时的邻居发现代理 | ndppd | 内置 |
| MAP-E、DS-Lite 或 4in6 隧道，以及相关的 NAT 和 MSS 规则 | 脚本 | 内置 |
| 发往内网流量的 IPv6 过滤 | ip6tables、nftables | 内置，见 `-unsolicited` |
| DHCPv4、原生 IPv4 NAT、DNS 解析器、路由器自身的过滤 | dnsmasq、Unbound、nftables | 不变 |

然后找出所有承担 sixup 工作的东西，记下它们的位置。这样第 5 步只需要按清单逐项处理。

**要停止的服务。** 列出开机启动的服务，记下表中出现的那些，比如 radvd、odhcpd、odhcp6c、ndppd 和 wide-dhcpv6-client。

```sh
systemctl list-unit-files --state=enabled   # systemd
rc-update show default                      # OpenRC, such as Alpine
```

**继续运行的程序中要修改的设置。** 记下文件和行。

- **dnsmasq**，在 `/etc/dnsmasq.conf` 和 `/etc/dnsmasq.d/` 中。`enable-ra`、`ra-param`，以及带 IPv6 范围的 `dhcp-range`。
- **systemd-networkd**，在 WAN 和内网的 `/etc/systemd/network/*.network` 中。`IPv6AcceptRA`、`IPv6SendRA`、`DHCPPrefixDelegation` 和 `DHCP` 这几项设置。
- **NetworkManager。** `nmcli connection show` 中 WAN 和内网的连接，以及它们的 `ipv6.method`。
- **dhcpcd**，在 `/etc/dhcpcd.conf` 中。`ia_pd`、`ipv6rs` 和 `ipv6only` 这几个选项。
- **ifupdown**，在 `/etc/network/interfaces` 中。WAN 和内网的 `inet6` 部分。

**脚本和残留。** 下面的命令可以帮你找到它们。

```sh
crontab -l; ls /etc/cron.d
grep -rlE 'ip -6|ip6tables|ip6tnl|inet6|radvd' /etc/network /etc/ppp /etc/dhcpcd* /etc/cron* 2>/dev/null
grep -rE 'accept_ra|autoconf|forwarding' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
ip -d link show type ip6tnl
nft list ruleset | grep -n masquerade
iptables -t nat -S 2>/dev/null | grep MASQUERADE
```

- 添加 IPv6 地址、路由或隧道的 cron 任务、`if-up.d` 脚本、PPP 的 `ip-up` 脚本和 dhcpcd 钩子。
- `/etc/sysctl.d` 中设置 `accept_ra`、`autoconf` 或 `forwarding` 的文件。sixup 启动时会设置这些值。如果这类文件还在，重新加载 sysctl 时会把它们改回去。
- 脚本创建的隧道设备。
- 对经隧道出去的流量做伪装（masquerade）的 nftables 或 iptables 规则。在 MAP-E 上，这些规则会使用线路端口集之外的端口。sixup 发现这类规则时会发出警告。
- 你自己为发往内网的流量设置的 IPv6 过滤。只有在使用 `-unsolicited allow` 运行 sixup 时才保留它。

**保存当前状态。** 以后可以用来对比，或者用来回退。

```sh
ip -6 addr > before-addr.txt
ip -6 route > before-route.txt
ip -4 route >> before-route.txt
nft list ruleset > before-nft.txt
sysctl -a 2>/dev/null | grep -E 'ipv6\.conf\..*\.(forwarding|accept_ra|autoconf)' > before-sysctl.txt
crontab -l > before-crontab.txt
```

**如果想保留前缀。** 运营商通过 DHCPv6 DUID 识别你的路由器。sixup 会生成新的 DUID。很多运营商会给新的 DUID 分配新的前缀，这样内网所有地址都会变一次。

要保留前缀，请找到旧 DHCPv6 客户端的 DUID，可以在它的状态文件或日志中查找。在第一次启动 sixup 之前，把 DUID 以不带分隔符的十六进制写入 `/var/lib/sixup/duid`，例如 `000100012a3b4c5d001122334455`。运营商仍然可能分配新的前缀，因为它还可能检查 IAID。sixup 用 WAN MAC 地址的最后四个字节生成 IAID。

## 3. 准备回退方案

不要删除旧的服务，只停止并禁用它们，并且备份每一个修改过的文件。这样用几条命令就能回退。

```sh
# systemd
sudo systemctl disable --now sixup
sudo systemctl enable --now radvd odhcp6c   # the services you stopped in step 5

# OpenRC
sudo rc-service sixup stop && sudo rc-update del sixup default
sudo rc-update add radvd default && sudo rc-service radvd start   # and so on for each service
```

sixup 停止时会发送 Router Lifetime 为 0 的路由器通告，让主机立即停止使用它。它还会删除自己的 nftables 表 `inet sixup` 和 `inet sixup-filter`，以及它添加的不可达路由。

sixup 添加的地址会保留到生存期结束，在内网上最多 90 分钟。要立即删除，可以清空地址或者重启。如果隧道设备 `sixup-ipv4` 还在，可以删除它。

```sh
sudo ip -6 addr flush dev eth1 scope global
sudo ip link del sixup-ipv4
```

开始之前，请确认不依靠 IPv6、也不经过正在修改的内网，仍然能够访问路由器。例如使用串口控制台，或者通过另一个端口的 IPv4。

## 4. 选择维护时间

选一个时间，15 分钟就够了。通知所有使用这个网络的人，包括用着联网喂食器的宠物、机器人，以及正在执行任务的 AI 智能体。如果由 AI 智能体替你迁移，它需要一个在第 5 步之后仍然可用的连接。

开始之前，检查三件事。

- **不能断网 15 分钟的东西。** 比如依赖云端的智能门锁、报警器、上传数据的医疗设备，以及正在使用网络的手机。为每一样找到替代办法。
- **写有旧前缀的地方。** 比如动态 DNS、静态地址，以及远程服务上的白名单。如果运营商分配了新前缀，要更新它们。
- **你就在路由器旁边。** 准备一部能开热点的手机，并且留出必要时回退的时间。不要在异地迁移另一个国家的路由器，比如父母家的路由器。也不要在前往火星的途中迁移家里的路由器。

## 5. 停止旧的 IPv6 配置

按照第 2 步的清单逐项处理。如果一个内网上有两个程序发送 RA，或者一个 WAN 上运行着两个 DHCPv6 客户端，就会出现很难排查的问题，所以不要遗漏任何一项。

停止并禁用服务。

```sh
# systemd
sudo systemctl disable --now radvd odhcpd odhcp6c ndppd

# OpenRC
for s in radvd odhcpd odhcp6c ndppd; do sudo rc-service $s stop; sudo rc-update del $s default; done
```

修改继续运行的程序的设置，然后重启它们。

- **dnsmasq。** 删除 IPv6 相关的行，保留 DHCPv4 和 DNS。
- **systemd-networkd。** 设置 `IPv6AcceptRA=no` 和 `IPv6SendRA=no`，删除 `DHCPPrefixDelegation`，把 `DHCP=` 设为 `ipv4` 或 `no`。
- **NetworkManager。** 把 `ipv6.method` 设为 `link-local`，或者不再让它管理这些接口。
- **dhcpcd。** 添加 `noipv6rs` 和 `ipv6ra_noautoconf` 并删除 `ia_pd`，或者用 `-4` 运行它。
- **ifupdown。** 删除 WAN 和内网的 `inet6` 部分。

删除找到的脚本、sysctl 文件和伪装规则。用 `ip link del` 删除旧的隧道设备。

确认没有残留的程序在运行。

```sh
pgrep -a 'radvd|odhcpd|odhcp6c|ndppd|dhcp6c'
sudo ss -ulpn 'sport = :546 or sport = :547'
```

## 6. 切换到 sixup

把参数写入配置文件，然后启动服务。

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

然后在路由器和内网主机上检查以下几点。

- 日志中显示了前缀和内网路由。在隧道线路上，还显示了隧道。
- 内网主机获得了新前缀中的地址，并且能访问 IPv6 网站。test-ipv6.com 可以同时测试 IPv4 和 IPv6。
- 在 MAP-E 或 DS-Lite 线路上，IPv4 能通过隧道正常工作。
- `nft list table inet sixup-filter` 显示了过滤规则，并且计数器在增加。

旧的配置保留几天。等前缀至少续期一次之后，再删除它。
