# 配置速查

<a href="recipes.md" lang="en">English</a> | <strong>简体中文</strong> | <a href="recipes.ja.md" lang="ja">日本語</a>

sixup 会自己判断线路提供了什么，所以大多数情况下，只需要指定 WAN 和内网接口。

```sh
sudo sixup -wan eth0 -lan eth1
```

下面的配方针对超出这个范围的需求。先在表中找到自己的需求，再看对应的一节，了解命令和它改变了什么。所有例子中，`eth0` 连接运营商，`eth1` 和 `eth2` 是内网接口。配方可以组合使用。比如既要用路由器上的解析器，又要 NAT64，就把两节的参数都写上。

| 需求 | 参数 |
|---|---|
| [让外部访问内网主机](#让外部访问内网主机) | `-unsolicited allow`，更严格时用 `deny` |
| [多个内网网段](#多个内网网段) | `-lan eth1:0 -lan eth2:1` |
| [SoftBank 光](#softbank-光) | `-wan-iid ::1111:1111:1111:1111` |
| [上游不通告前缀，手动指定](#上游不通告前缀手动指定) | `-routed-prefix 2001:db8:100::/48` |
| [自己管理隧道的防火墙规则](#自己管理隧道的防火墙规则) | `-tunnel-nat off` |
| [给路由器固定地址](#给路由器固定地址) | `-wan-iid ::1 -lan-iid ::1` |
| [路由器自己的流量使用轮换地址](#路由器自己的流量使用轮换地址) | `-tempaddr` |
| [指定 DNS 服务器](#指定-dns-服务器) | `-ra-dns self`，或服务器的地址 |
| [用 DHCPv6 分配地址](#用-dhcpv6-分配地址) | `-dhcp6s-mode stateful` |
| [下级路由器](#下级路由器) | 上级路由器加 `-dhcp6s-mode stateless` |
| [IPv6 单栈或 IPv6-mostly 内网](#ipv6-单栈或-ipv6-mostly-内网) | `-nat64 jool` |

在一条新线路上，先做一次试运行。它会与运营商交互，打印线路提供的参数，不改动系统。

```sh
sudo sixup -wan eth0 -dry-run
```

## 不需要参数的情况

- **内网的防火墙。** 由外部发起的连接到达内网之前就会被丢弃（RFC 6092）。回复内网自己发起的连接的流量照常通过，发往 5 分钟内向外发过包的内网端点的流量也会通过，所以 Tailscale 等点对点程序照常可用。按照 RFC 6092 的要求，IPsec（AH、ESP 和 IKE）和 HIP 也会通过。需要开放端口的程序可以用 PCP 申请，IPv4 也可以用 NAT-PMP，在 IPv4 上，PCP 还会把隧道地址的一个端口转发给这台主机。
- **线路委派前缀。** sixup 用 DHCPv6-PD 请求一个 /56，把其中一个 /64 放到内网上，由内置的 RA 通告。委派前缀中其余的部分由一条 unreachable 路由兜住，发往未分配部分的流量在这里丢弃，不会再回到运营商那里形成环路。
- **只有一个 /64。** 线路不做委派时，上游 RA 中的 /64 移到内网上（RFC 7278）。在以太网 WAN 上，上游路由器仍会在 WAN 链路上解析内网地址，所以 sixup 在 WAN 上替它们应答邻居发现，并打出一条警告，说明应该向运营商申请什么。
- **PPPoE。** 把 PPP 设备作为 WAN，即 `-wan ppp0`。点对点的 WAN 没有地址解析，共享的 /64 不需要代理；收不到 RA 时，默认路由直接指向这个设备。
- **MAP-E。** DHCPv6 带有 MAP-E 选项，或者前缀符合日本 IPoE 运营商（v6plus、BIGLOBE、OCN、NURO）的规则表时，sixup 建立隧道 `sixup-ipv4`，配置共享的 IPv4 地址，经隧道添加一条 metric 较高的 IPv4 默认路由，并维护 nftables 表 `inet sixup`，把源端口限制在线路分到的端口集内，同时钳制 TCP MSS。
- **DS-Lite。** DHCPv6 给出 AFTR 名称时，sixup 解析它并建立隧道。转换由 AFTR 完成，这里只设置 MSS 钳制。
- **DHCPv6 没有描述的隧道**，例如固定的 4in6 隧道。隧道流量到达 WAN 时，sixup 抓包推断出两端地址和 IPv4 地址。

## 让外部访问内网主机

默认情况下，内网主机只有通过 PCP 申请过的端口，才能从外部访问。如果希望每台主机都能在自己的地址上被访问，就像 IPv6 本来设想的那样，比如一个由自带防火墙的服务器组成的网络，就放行未经请求的流量。

```sh
sudo sixup -wan eth0 -lan eth1 -unsolicited allow
```

如果连程序自己申请也不允许，比如在办公室里，就连 PCP 一起关闭。点对点程序仍然能够连接，因为向外发过包的端点在一段时间内可以被访问。

```sh
sudo sixup -wan eth0 -lan eth1 -unsolicited deny
```

默认设置依据 RFC 6092，它描述了家用网关的简单安全机制。在它的默认模式下，内网没有请求过的流量会被丢弃，因为家庭网络里有许多无人管理、本来就不打算直接面对互联网的设备。它建议提供一种让程序申请入站流量的协议（REC-48），PCP 就是这样的协议；还建议过滤不依赖远端地址（REC-11、REC-17、REC-33），这样主机刚用过的端口任何人都能访问，点对点程序仍然能互相找到。家用路由器的要求 RFC 7084 要求支持 RFC 6092，但对默认设置不作规定（S-1）。RFC 6092 本身也允许以开放模式为默认，只要求它容易选择（REC-49），这就是 `allow`。

无论哪种设置，过滤的都只是转发到内网的流量。路由器自身的服务需要你自己保护。

## 多个内网网段

给每个内网接口指定一个委派前缀中的子网号。

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1
```

线路只给一个 /64 时，只够一个网段，子网号 0 拿到它，其余网段没有全局前缀。这些网段之间需要互访，就给它们配一个 ULA。

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1 -ula auto
```

## SoftBank 光

SoftBank 光（ソフトバンク光）给内网的前缀来自 RA 或 DHCPv6-PD，取决于这项服务下面的 NTT 线路给的是哪一种；IPv4 走一条 DHCPv6 没有描述的 4in6 隧道。边界中继把这条隧道发往租用的 Hikari BB Unit 在 WAN 上使用的地址。sixup 能从这些流量中找出隧道，但自己没有这个地址时，不会为它应答邻居发现，隧道也就建立不起来。用 `-wan-iid` 指定 BB Unit 的接口标识。1G 的服务通常是 `::1111:1111:1111:1111`；如果不是，BB Unit 的状态页面上应该能看到这个地址。

```sh
sudo sixup -wan eth0 -wan-iid ::1111:1111:1111:1111 -lan eth1
```

这样 sixup 就可以代替 BB Unit。

## 上游不通告前缀，手动指定

有些上游把前缀路由给路由器，却不通过 RA 或 DHCPv6-PD 告知，比如专线或数据中心的 transit 线路，会把固定前缀静态路由到 WAN 地址上。先在系统的网络配置里配置 WAN 地址和默认路由，比如地址 2001:db8:ffff::2/126、网关 2001:db8:ffff::1，再给出前缀。这些参数由运营商在线路开通时书面告知：

```sh
sudo sixup -wan eth0 -routed-prefix 2001:db8:100::/48 -lan eth1
```

sixup 不改动 WAN 上的这个地址，也不在 WAN 上添加自己的地址。前缀按委派前缀处理，切分给各个内网网段，也委派给下级路由器。这时 DHCPv6 客户端只请求 DNS 服务器等配置；拿不到 DNS 服务器时，用 `-ra-dns` 指定。

不是路由过来、而是在 WAN 链路上的 /64，比如 VPS 的 /64，改用 `-wan-prefix`，处理方式和 RA 给出的一样，与内网共享。如果其中的地址已经手动配置好，用 `-wan-prefix auto` 从这个地址读取 /64；这时 /64 留在 WAN 上，路由器在内网上取其中一个 /128，并在 WAN 上替内网主机应答邻居发现。

上游把比 /64 更短的前缀直接放在链路上的情况不受支持，请让上游改为把前缀路由到 WAN 地址。

要通过 WireGuard 把 VPS 的 /64 给家里的内网用，由于 WireGuard 不传递邻居发现，就在它上面再套一层 GRETAP 隧道。VPS 上用 `-wan-prefix` 运行 sixup，以 GRETAP 设备为内网；家里也运行 sixup，以这个设备为 WAN。

## 自己管理隧道的防火墙规则

在 MAP-E 线路上，如果已有的防火墙也对经隧道出去的流量做 masquerade，它分出的源端口会落在线路的端口集之外，结果只有一部分连接能通；sixup 发现这样的链时会警告。要把隧道的源地址转换和 MSS 钳制交给自己的规则，就关闭这项功能。

```sh
sudo sixup -wan eth0 -lan eth1 -tunnel-nat off
```

## 给容器做 NAT66

Docker 给容器分配固定地址，跟不上会变的前缀，所以给 Docker 网络配 ULA，再自己做 NAT66，是实际可行的做法。sixup 拒绝从它的 LAN 接口发出的 ULA，但对其他接口发出的流量，要等源地址转换之后才检查：经过你的 NAT 转换的可以出去，没有转换、仍带着 ULA 的会被丢弃。同样，用目的地址转换发布的端口可以从外网访问，不管规则是 Docker 写的还是你自己写的。

```nft
table ip6 docker-nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" ip6 saddr fd00:dead:beef::/48 masquerade
    }
}
```

## 给路由器固定地址

运营商换前缀时接口标识不变，路由器就容易找到。WAN 的第一个接口标识对应的地址，就是 sixup 报告的 WAN 地址。

```sh
sudo sixup -wan eth0 -wan-iid ::1 -lan eth1 -lan-iid ::1
```

## 路由器自己的流量使用轮换地址

加上 `-tempaddr` 后，WAN 在静态地址之外还会有临时地址（RFC 8981）。路由器自己发起的连接，例如路由器上运行的 DNS 解析器或代理程序发起的连接，使用其中最新的一个，每小时换一个新地址。仍有连接在使用的地址会保留，最长一天，连接结束后删除。从内网转发出去的流量不受影响：内网设备使用自己的地址，大多数系统已经会自行轮换。

```sh
sudo sixup -wan eth0 -lan eth1 -tempaddr
```

要更快地轮换，就缩短 `-tempaddr-regen`。仍在使用的地址都计入 `-tempaddr-max`。达到上限时会删除最旧的地址，上面的连接随之中断，所以上限要足够容纳最长的连接。

```sh
sudo sixup -wan eth0 -lan eth1 -tempaddr -tempaddr-regen 5m -tempaddr-max 32
```

有委派前缀时，临时地址放在第一个内网 /64 里，不管有多少个，上游都只看到路由器的链路本地地址。没有委派前缀时，临时地址放在 SLAAC 前缀里，每个都让上游路由器多维护一个邻居。有的运营商会限制每条线路的邻居数量，个别设备在邻居太多时甚至会让整条线路的 IPv6 完全不通。这种线路上，调大 `-tempaddr-max` 或缩短轮换间隔之前，请先咨询运营商。

变化的只是接口标识。运营商分配的前缀保持不变，仍然能识别出这条线路。

## 指定 DNS 服务器

默认情况下，内网拿到的是上游下发的 DNS 服务器。`-ra-dns` 在 RA 和 DHCPv6 服务器中替换它们，按顺序列出各项。

路由器上运行的解析器写作 `self`，也就是路由器在各个内网上的地址。用 ULA，运营商换前缀后这个地址仍然有效。

```sh
sudo sixup -wan eth0 -lan eth1 -ula auto -lan-iid ::1 -ra-dns self
```

内网中另一台主机上的解析器，直接写它的地址。出于同样的原因，给这台主机一个 ULA 中的固定地址。

```sh
sudo sixup -wan eth0 -lan eth1 -ula fd12:3456:789a::/48 -ra-dns fd12:3456:789a::53
```

公共 DNS 同样直接写地址。

```sh
sudo sixup -wan eth0 -lan eth1 -ra-dns 2606:4700:4700::1111,2001:4860:4860::8888
```

各项可以组合。`-ra-dns self,upstream` 在路由器自己的地址后面附上上游的服务器，`-ra-dns off` 不通告任何 DNS。

## 用 DHCPv6 分配地址

主机需要从地址池分配地址，或者需要固定地址时，运行有状态的 DHCPv6 服务器。

```sh
sudo sixup -wan eth0 -lan eth1 -dhcp6s-mode stateful \
  -dhcp6s-static mac=aa:bb:cc:00:00:01,addr=::100
```

RA 会设置 M 标志，主机因此向 DHCPv6 请求地址。`-dhcp6s-mode stateless` 不分配地址，只回答 DNS 等选项，并向下级路由器委派前缀。

## 下级路由器

DHCPv6 服务器从上游委派的前缀中划出前缀，避开内网子网，委派给下级路由器，默认是 /60。在这台 sixup 下面再接一台 sixup，不需要任何配置。

```sh
# 上级路由器
sudo sixup -wan eth0 -lan eth1 -dhcp6s-mode stateless
# 下级路由器，WAN 接在上级路由器的内网上
sudo sixup -wan eth0 -lan eth1
```

下级路由器请求 /56，拿到一个 /60，再切分给自己的内网。这要求上游委派的前缀短于 /64，因为一个 /64 分给内网以后，就没有剩余的空间了。`-dhcp6s-pd-len 0` 关闭下游委派。

上级路由器的防火墙放行发往委派前缀的流量，交给下级路由器自己的防火墙处理，所以在下级路由器上用 PCP 打开的端口可以从外部访问。

## IPv6 单栈或 IPv6-mostly 内网

内网可以只用 IPv6，没有 IPv4 地址，没有 DHCPv4，也不用同时维护两套协议。客户端仍然可以通过 NAT64 访问 IPv4 互联网，由路由器把它们的 IPv6 包转换成 IPv4。改用 IPv6 单栈，是一个网络能为 IPv6 做的最有意义的事情之一，因为每多一个这样的网络，大家继续保留 IPv4 的理由就少一个。如果你打算这样做，这一节就是为你写的。

安装 Jool 模块，再启用 NAT64。如果模块没有加载，sixup 会用 `/sbin/modprobe jool` 加载它。

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool
```

Jool 运行在独立的网络命名空间里，经 veth `sixup-nat64` 相连，转换 `64:ff9b::/96`，内网和路由器自身都能使用。转换期间，RA 会通告这个前缀（PREF64，RFC 8781）。转换出的 IPv4 按路由器的 IPv4 路由出去。走 MAP-E 隧道时，它和其他流量共用线路的端口集；没有隧道时，从已配置的其他 IPv4 出口出去。防火墙需要放行经过 `sixup-nat64` 的流量。

客户端访问 IPv4 有两种方式。

- **客户端上的 CLAT**（464XLAT，RFC 6877）从 RA 中取得前缀，把客户端自己的 IPv4 流量转换成 IPv6，所以所有应用都能用，包括直接写 IPv4 地址的应用。
- **DNS64** 为只有 IPv4 的域名返回这个前缀内的地址。它需要你自己选择的解析器，sixup 不提供；对直接连接 IPv4 地址的应用无效。

根据 RA 中的 PREF64 启用 CLAT 的内置支持情况，以撰写时所知为准；这方面变化很快，请以各厂商的最新说明为准。

| 系统 | CLAT |
|---|---|
| iOS、iPadOS 16 及以后，macOS 13 及以后 | 内置；网络中没有 IPv4 时启用 |
| Android 11 及以后 | 内置；Android 在移动网络上支持 CLAT 的时间要早得多 |
| Windows 11 | Insider Canary build 29599 起为[公开预览](https://techcommunity.microsoft.com/blog/networkingblog/announcing-windows-clat-public-preview/4506046)，默认关闭，用 `netsh interface clat set global permit=enabled pref64fromra=enabled` 开启；需要 SLAAC，所以不能配合 `-ra-slaac=false` |
| Linux | 没有内置；需要 clatd 这类 CLAT 程序 |

网络不必一下子去掉 IPv4。IPv6-mostly 网络让需要 IPv4 的客户端继续用 IPv4，其余的不用。DHCPv4 服务器发送 option 108，也就是 IPv6-Only Preferred（RFC 8925），支持它的客户端就会放弃 IPv4 地址，改用 NAT64。sixup 不运行 DHCPv4，这个选项请在你使用的 DHCPv4 服务器上设置。

要通过 NAT64 访问私有 IPv4 地址，需要用网络专用前缀，因为知名前缀可能不能用于私有地址（RFC 6052）。

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool -nat64-prefix fd00:64::/96
```

只想通过 DNS64 提供 NAT64，不让客户端启用 CLAT，就不在 RA 中通告前缀。

```sh
sudo sixup -wan eth0 -lan eth1 -nat64 jool -ra-pref64 off
```
