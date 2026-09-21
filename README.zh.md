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
