<div lang="zh-Hans">

# sixup

<a href="README.md" lang="en">English</a> | <strong>简体中文</strong> | <a href="README.ja.md" lang="ja">日本語</a>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

过去在 Linux 上搭 IPv6 路由，要许多程序配合。`odhcp6c` 取前缀，`radvd` 发 RA，
`odhcpd` 做 DHCPv6，`ndppd` 做代理，再用几个脚本在它们之间传递参数、必要时重启。

sixup 一个程序做完这些，各环节的状态和参数在内部流转，不再经过脚本。运营商换发前缀
时，接口地址、RA 的内容、DHCPv6 租约、代理表项和隧道端点都从同一个事件更新，不需要手工
干预，也不需要重启。

## 功能

- 支持从 DHCPv6-PD 或 RA 获取前缀
- 自动切分给各个内网网段，下发地址与 DNS，可另配 ULA 供内网互访
- 线路只给一个 /64 时，按 RFC 7278 的共享布局配置并开启 NDP 代理，内网照样拿到全球地址
- 建立日本 NGN 线路的 IPv4 隧道，包括 DS-Lite、MAP-E，以及从流量识别的 SoftBank 光 IPIP6
- 把上游 MTU 和真正可达的 DNS 服务器带给内网客户端
- 单个静态二进制，小于 5 MiB，不依赖 iproute2 等外部命令和系统服务，直接操作 netlink 与 /proc

## 快速开始

</div>

> [!WARNING]
> <span lang="zh-Hans">项目仍在开发中，尚未发布。部分功能从未在真实线路上跑过，可能根本不能用，
> 参数也随时会变。</span>

<div lang="zh-Hans">

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

`sixup -h` 按功能分组列出全部选项。

</div>
