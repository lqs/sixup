<div lang="zh-Hans">

# sixup：全自动配置 IPv6 路由

<a href="README.md" lang="en">English</a> | <strong>简体中文</strong> | <a href="README.ja.md" lang="ja">日本語</a>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

过去在 Linux 上搭 IPv6 路由，要许多程序配合。`odhcp6c` 取前缀，`radvd` 发 RA，
`odhcpd` 做 DHCPv6，`ndppd` 做代理，再用几个脚本在它们之间传递参数、必要时重启。

sixup 一个程序做完这些，各环节的状态和参数在内部流转，不再经过脚本。运营商换发前缀
时，接口地址、RA 的内容、DHCPv6 租约、代理表项和隧道端点都从同一个事件更新，不需要手工
干预，也不需要重启。

## 功能

- 内置 IPv6 路由器所需的完整功能，无需再配置其他守护进程
- 自动检测前缀获取方式（DHCPv6-PD 或 RA），由内置的 RA 与 DHCPv6 服务向客户端分发地址与配置
- 运营商换发前缀时，地址、RA、租约、代理表项与隧道端点随之更新
- 上游仅有 /64 时按 RFC 7278 与内网共享并启动 NDP 代理，前缀更短则切分至各网段
- 按需建立 DS-Lite、MAP-E 或 IPIP6 隧道，并维护 MAP-E 端口集约束
- 静态链接的单个二进制，小于 5 MiB，不依赖外部命令与系统服务

## 快速开始

</div>

> [!WARNING]
> <span lang="zh-Hans">项目仍在开发中，尚未发布。部分功能从未在真实线路上跑过，可能根本不能用，
> 参数也随时会变。</span>

<div lang="zh-Hans">

从 [Releases 页面](https://github.com/lqs/sixup/releases) 下载适合自己发行版的包（`.deb`、
`.rpm`、`.apk` 或 Arch Linux 的 `.pkg.tar.zst`），或者直接下载静态二进制。目前还没有正式
版本，只有 `dev` 预发布版。

查看线路提供了什么，不改动系统：

```sh
sudo sixup -wan eth0 -dry-run
```

从 WAN 接口获取前缀，并据此配置一个内网接口：

```sh
sudo sixup -wan eth0 -lan eth1
```

前缀按线路支持的方式获取，不需要指定其他选项。

把一个委派前缀分给多个内网网段时，给每个接口指定子网号：

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1
```

注意：一个 /64 只够一个内网网段使用。线路不做委派时，子网号 0 拿到该前缀，其余网段
没有前缀；这些网段之间需要互访，用 `-lan-ula auto` 下发一个 ULA。

注意：MAP-E 线路上，源端口必须落在该线路分到的端口段内，否则回程流量到不了。
这组 nftables 规则由 sixup 维护，只写 `inet sixup` 这一张表，退出时自动删除；自己写
规则就加 `-tunnel-nat off`。

## 选项

`sixup -h` 按下面的分组列出全部选项。

- 布尔选项用 `=false` 关闭，例如 `-wan-ra=false`。
- 时长采用 Go 的写法：`30s`、`10m`、`1h30m`。
- 可重复的选项，每个值写一次：`-lan eth1 -lan eth2`。

### 接口与前缀

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-wan` | | WAN 接口，必填。 |
| `-lan` | | 内网接口，可重复，格式为 `名称[:子网号]`。子网号是十进制数，决定这个接口分到委派前缀里的哪一个 /64；不写时，各接口按书写顺序依次取 0、1、2。多个内网接口需要有委派前缀。 |
| `-lan-ula` | | 与全局前缀一起通告的 ULA 前缀。`auto` 随机生成一个 /48 并保存在状态目录；写成 `fd12:3456:789a::/48` 这样的前缀则直接使用。多个用逗号分隔。 |
| `-lan-iid` | | 本机在每个内网前缀上的地址所用的接口标识，逗号分隔，每项一个地址，写法同 `-wan-iid`。留空表示一个 RFC 7217 稳定地址。 |
| `-lan-deprecate-hold` | `10m` | 撤回的前缀继续以首选生存期 0 通告多久，让客户端停止使用它。 |

### WAN 侧：DHCPv6 客户端

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-dhcp6c-mode` | `auto` | `auto` 按上游 RA 的 M、O 标志决定，`on` 总是运行客户端，`off` 不运行。 |
| `-dhcp6c-pd-len` | `56` | 请求委派前缀（IA_PD）时提示的前缀长度。`0` 表示不请求。 |
| `-dhcp6c-ia-na` | `true` | 同时为 WAN 接口本身请求一个地址（IA_NA）。 |
| `-dhcp6c-pd-grace` | `10s` | 启动后等待委派前缀的时间。在此期间，RA 前缀只用于 WAN 侧，不分给内网，因此以后不必再撤回。 |
| `-dhcp6c-release` | `false` | 退出时发送 RELEASE，归还前缀和地址。默认关闭：DUID 会保存下来，重启后续租的仍是同一个前缀。试运行总会归还。 |

### WAN 侧：上游 RA 与地址

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-wan-ra` | `true` | 监听上游 RA，作为第二个前缀来源，并据此维护默认路由。 |
| `-wan-slaac` | `true` | 对带 A 标志的 RA 前缀，在 WAN 接口上配置 SLAAC 地址。 |
| `-wan-iid` | | WAN 接口上静态 SLAAC 地址的接口标识，逗号分隔，每项一个地址。每项可以是 `stable` 或留空，表示 RFC 7217 稳定地址；`eui64`，表示由 MAC 地址生成；或者固定后缀，如 `::1`、`::1111:2222:3333:4444`。第一个作为 WAN 地址报告。 |
| `-wan-tempaddr` | `false` | 在 WAN 接口上也轮换临时地址，参数按 `-tempaddr-*` 各选项。 |
| `-wan-prefer` | `pd` | 委派前缀和 RA 前缀同时存在时以哪个为准：`pd` 或 `ra`。 |
| `-wan-shared64` | `lan` | 上游只给一个 /64 时的布局。`lan`：/64 给内网，WAN 链路上的主机用 /128 路由（RFC 7278）。`wan`：/64 留在 WAN 侧，每台内网主机一条 /128 路由。`split`：两侧都用 /128 路由，路由器本身访问不到尚未学到的主机。/128 路由在 NDP 代理发现主机时自动添加。 |

### 内网侧：RA 通告

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-ra-min` | `3m20s` | 主动发送 RA 的最小间隔（MinRtrAdvInterval）。 |
| `-ra-max` | `10m` | 主动发送 RA 的最大间隔（MaxRtrAdvInterval）。 |
| `-ra-lifetime` | `30m` | RA 中的路由器生存期。 |
| `-ra-mtu` | `0` | RA 中通告的 MTU。`0` 表示当 WAN 路径 MTU 小于内网接口 MTU 时通告前者，WAN 路径 MTU 取自上游 RA 或 WAN 接口。这样 PPPoE 的 1492 等情况不必再依赖路径 MTU 发现。 |
| `-ra-dns` | | 代替上游 DNS 通告的 DNS 服务器，逗号分隔。DHCPv6 服务器也使用它。 |
| `-ra-pref64` | | 通告的 NAT64 前缀（RFC 8781），如 `64:ff9b::/96`。留空则转发上游 RA 中的值。长度必须是 32、40、48、56、64 或 96。 |
| `-ra-route` | | 以路由信息选项（Route Information）通告的前缀，可重复。 |

### 内网侧：DHCPv6 服务器

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-dhcp6s-mode` | `off` | `stateless` 只回答 DNS 等选项；`stateful` 还分配地址；`off` 不运行服务器。RA 中的标志随之设置。 |
| `-dhcp6s-pool` | `1000-ffff` | 分配地址所用的接口标识范围，十六进制，指低 64 位。 |
| `-dhcp6s-static` | | 固定分配，可重复：`mac=<MAC>,addr=::100` 或 `duid=<十六进制>,addr=2001:db8::5`。 |
| `-dhcp6s-lease-preferred` | `1h` | 分配地址的首选生存期。 |
| `-dhcp6s-lease-valid` | `2h` | 分配地址的有效生存期。 |

### NDP 代理

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-ndproxy-mode` | `auto` | `auto` 在前缀为 /64 时启用 `forward`，否则关闭。`forward` 先到另一侧探测再应答，双向进行，因此 WAN 链路上的主机和内网主机之间也能互访。`prefix` 对 WAN 侧询问内网前缀内任意地址的请求一律应答，不做探测。`static` 只把 `-ndproxy-static` 的条目写进内核代理表。`off` 关闭代理。 |
| `-ndproxy-static` | | `static` 模式下代理的地址或前缀，可重复。 |
| `-ndproxy-exclude` | | 不做代理的前缀，可重复。 |
| `-ndproxy-ttl` | `30s` | 学到的代理条目的存活时间。 |

### 本机地址轮换

这组选项控制路由器自己在内网上的地址；加上 `-wan-tempaddr` 时也控制 WAN 侧。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-tempaddr-mode` | `off` | `temporary` 和 `both` 在静态地址之外再加上轮换的临时地址（RFC 8981）；`off` 和 `stable` 只保留静态地址。 |
| `-tempaddr-regen` | `1h` | 生成新临时地址的间隔。 |
| `-tempaddr-preferred` | `1h` | 临时地址的首选生存期。 |
| `-tempaddr-valid` | `24h` | 临时地址有效生存期的上限。仍在使用的地址最多保留到这个上限，不再使用的会提前删除。 |
| `-tempaddr-max` | `8` | 同时存在的临时地址数量上限。 |
| `-tempaddr-desync` | `10m` | 每次轮换所加随机偏移的上限。 |
| `-tempaddr-skip-dad` | `false` | 跳过重复地址检测。只用于确定不会冲突的链路。 |
| `-tempaddr-drain-grace` | `5s` | 判断地址不再使用时，两次检查之间的间隔。 |

### 隧道

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-tunnel-dev` | `sixup-ipv4` | IPv4-in-IPv6 隧道设备的名称。隧道参数确定后，sixup 创建或更新这个设备，启用它并配置 IPv4 地址。留空则不创建设备。 |
| `-tunnel-mtu` | `0` | 隧道设备的 MTU。`0` 表示 WAN 接口 MTU 减 40。 |
| `-tunnel-route4-metric` | `4096` | 经隧道的 IPv4 默认路由的 metric。故意设得较高：已有的 IPv4 默认路由仍然优先，没有时才由隧道接管。`0` 表示不添加路由。 |
| `-tunnel-nat` | `auto` | 为离开隧道的流量维护 nftables 表 `inet sixup`。`auto` 在 MAP-E 上配置规定必须有的端口受限源地址转换（RFC 7597），在有独立 IPv4 地址的线路上配置普通的源地址转换，在由运营商做转换的 DS-Lite 上不配置；所有情况下都把 TCP MSS 限制到隧道 MTU。`off` 不写规则。表外的内容一概不动，退出时删除这张表。 |
| `-tunnel-mape-rules` | `true` | DHCPv6 没有携带 MAP-E 选项时，按日本 IPoE 运营商（v6plus、BIGLOBE、OCN、NURO）的规则表，从委派前缀推算 MAP-E 参数。 |
| `-tunnel-capture` | `true` | DHCPv6 没有携带隧道选项时，抓取隧道流量来确定参数。需要 `-dhcp6c-mode` 不为 `off`，试运行时不进行。 |
| `-tunnel-capture-max` | `2m` | 抓包等待的时长。收到第一个隧道包就结束；一直收不到则放弃，等前缀或地址变化时再试。 |

### NAT64

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-nat64` | `off` | `jool` 用 [Jool](https://jool.mx) 内核模块（4.1 或更新版本，用 `modprobe jool` 加载）配置 NAT64：创建一个转换 `64:ff9b::/96` 的实例，在 RA 中通告，转换结果再经过上面的源地址转换，这样 MAP-E 线路的端口只由一方分配。`off` 不配置。DNS64 不在其中，由你选择的解析器提供。 |
| `-jool-instance` | `sixup` | sixup 创建和删除的 Jool 实例名。 |
| `-jool-port-ranges` | `3` | MAP-E 线路的端口段中分给转换器的段数，其余留给 netfilter，两者不会分出相同的端口。线路独占整个地址的全部端口时忽略此项。 |

### 运行

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-state-dir` | `/var/lib/sixup` | 保存 DUID、稳定地址所用的密钥、ULA 和租约的目录。重启前后要保留它，否则运营商可能分配另一个前缀。 |
| `-no-sysctl` | `false` | 不自动设置 `forwarding`、`accept_ra` 等 sysctl，适用于由其他方式管理它们的环境。 |
| `-settle` | `1s` | 参数保持不变多久后才应用。启动时 RA、委派前缀、DNS 和抓包结果陆续到达，这样可以一起应用。撤回会立即应用。 |
| `-dry-run` | `false` | 完整走一遍获取、续租参数和识别隧道的流程，边运行边打印，但不改动系统，也不向内网发送 RA。 |
| `-dry-run-timeout` | `0` | 试运行的时长。`0` 表示一直运行到被中断。 |
| `-log-level` | `info` | 打印的最低级别：`debug`、`info`、`warn` 或 `error`。 |
| `-v` | `false` | 等同于 `-log-level debug`。 |
| `-version` | | 打印版本号后退出。 |
| `-license` | | 打印 sixup 及其所衍生作品的许可证后退出。 |

</div>
