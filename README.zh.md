<div lang="zh-Hans">

# sixup：全自动配置 IPv6 路由

<a href="README.md" lang="en">English</a> | <strong>简体中文</strong> | <a href="README.ja.md" lang="ja">日本語</a>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lqs/sixup/graph/badge.svg)](https://codecov.io/gh/lqs/sixup)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

过去在 Linux 上搭 IPv6 路由，要许多程序配合。`odhcp6c` 取前缀，`radvd` 发 RA，
`odhcpd` 做 DHCPv6，`ndppd` 做代理，再用几个脚本在它们之间传递参数、必要时重启。

sixup 一个程序做完这些，各环节的状态和参数在内部流转，不再经过脚本。运营商换发前缀
时，接口地址、RA 的内容、DHCPv6 租约、代理表项和隧道端点都从同一个事件更新，不需要手工
干预，也不需要重启。

## 功能

- 内置 IPv6 路由器所需的完整功能，无需再配置其他守护进程
- 按照 RFC 对家用路由器的要求设计，整体依据 RFC 7084，防火墙依据 RFC 6092，[各项要求和实现情况](docs/standards.md)逐条列出
- 自动检测前缀获取方式（DHCPv6-PD 或 RA），由内置的 RA 与 DHCPv6 服务向客户端分发地址与配置
- 运营商换发前缀时，地址、RA、租约、代理表项与隧道端点随之更新
- 上游仅有 /64 时按 RFC 7278 与内网共享，广播型 WAN 上另启动 NDP 代理，前缀更短则切分至各网段
- 向下游路由器委派前缀，sixup 下面可以再接 sixup
- 阻止未经请求的 IPv6 流量进入内网，程序可以用 PCP 开放端口
- 按需建立 DS-Lite、MAP-E 或 IPIP6 隧道，并维护 MAP-E 端口集约束
- 静态链接的单个二进制，小于 6 MiB，不依赖外部命令与系统服务

## 快速开始

从 [Releases 页面](https://github.com/lqs/sixup/releases) 下载适合自己发行版的包（`.deb`、
`.rpm`、`.apk` 或 Arch Linux 的 `.pkg.tar.zst`），或者直接下载静态二进制。`dev` 预发布版由
main 上的每次提交构建，未经测试；实际使用的路由器请选带版本号的正式版。

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
没有前缀；这些网段之间需要互访，用 `-ula auto` 下发一个 ULA。

注意：MAP-E 线路上，源端口必须落在该线路分到的端口段内，否则回程流量到不了。
这组 nftables 规则由 sixup 维护，只写 `inet sixup` 这一张表，退出时自动删除；自己写
规则就加 `-tunnel-nat off`。

其他需求，比如多个内网网段、固定地址、指定 DNS 服务器或 NAT64，见[配置速查](docs/recipes.zh.md)。sixup 遵循哪些 RFC，
逐条的实现情况和尚未做到的地方，见 [Standards](docs/standards.md)（英文）。

## 选项

`sixup -h` 列出全部选项及其默认值，[配置速查](docs/recipes.zh.md)按需求介绍它们的用法。这里只列出运行 sixup 本身的选项。

- 布尔选项用 `=false` 关闭，例如 `-wan-ra=false`。
- 时长采用 Go 的写法：`30s`、`10m`、`1h30m`。
- 可重复的选项，每个值写一次：`-lan eth1 -lan eth2`。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-state-dir` | `/var/lib/sixup` | 保存 DUID、稳定地址所用的密钥、ULA 和租约的目录。重启前后要保留它，否则运营商可能分配另一个前缀。 |
| `-no-sysctl` | `false` | 不自动设置 `forwarding`、`accept_ra` 等 sysctl，适用于由其他方式管理它们的环境。此时内网接口需要设置 `proxy_ndp` 为 1、`proxy_delay` 为 0。 |
| `-dry-run` | `false` | 完整走一遍获取、续租参数和识别隧道的流程，边运行边打印，但不改动系统，也不向内网发送 RA。 |
| `-dry-run-timeout` | `0` | 试运行的时长。`0` 表示一直运行到被中断。 |
| `-log-level` | `info` | 打印的最低级别：`debug`、`info`、`warn` 或 `error`。 |
| `-v` | `false` | 等同于 `-log-level debug`。 |
| `-version` | | 打印版本号后退出。 |
| `-license` | | 打印 sixup 及其所衍生作品的许可证后退出。 |

</div>
