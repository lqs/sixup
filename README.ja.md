<div lang="ja">

# sixup

<a href="README.md" lang="en">English</a> | <a href="README.zh.md" lang="zh-Hans">简体中文</a> | <strong>日本語</strong>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

かつて Linux で IPv6 ルーティングを組むには、いくつものプログラムが必要でした。
プレフィックス取得に `odhcp6c`、RA の送信に `radvd`、DHCPv6 に `odhcpd`、代理応答に
`ndppd`、さらにその間でパラメータを受け渡し、必要に応じて再起動をかけるスクリプト。

sixup はこれを 1 つのプログラムで行います。各段階の状態とパラメータはプロセスの内部で
受け渡され、スクリプトを介しません。回線がプレフィックスを変更すれば、インターフェイスの
アドレス、RA の内容、DHCPv6 リース、代理応答のエントリ、トンネルのエンドポイントが
同じ一つのイベントから更新され、手作業も再起動も必要ありません。

## 機能

- IPv6 ルーターに必要な機能を一通り内蔵し、他のデーモンの設定は不要
- プレフィックスの取得方式（DHCPv6-PD / RA）を自動で判別し、内蔵の RA と DHCPv6 サーバーがアドレスと設定を配布
- 事業者がプレフィックスを変更すると、アドレス、RA、リース、代理応答エントリ、トンネルのエンドポイントが追従
- 上流が /64 のみなら RFC 7278 に従って LAN と共有し NDP 代理応答を有効化、より短いプレフィックスなら各セグメントへ分割
- 必要に応じて DS-Lite、MAP-E、IPIP6 のトンネルを構築し、MAP-E では割り当てられたポートセットを維持
- 単一の静的バイナリで 5 MiB 未満。外部コマンドにもシステムサービスにも依存しない

## クイックスタート

</div>

> [!WARNING]
> <span lang="ja">本プロジェクトは開発中で、まだリリースしていません。実回線で一度も
> 動かしていない部分があり、まったく動かない可能性があります。オプションも随時変わります。</span>

<div lang="ja">

回線が何を提供しているかを、システムを変更せずに確認する：

```sh
sudo sixup -wan eth0 -dry-run
```

WAN インターフェイスからプレフィックスを取得し、LAN インターフェイスを構成する：

```sh
sudo sixup -wan eth0 -lan eth1
```

プレフィックスは回線が対応している方式で取得します。他のオプションは必要ありません。

一つの委任プレフィックスを複数の LAN セグメントへ分けるときは、インターフェイスごとに
サブネット番号を指定します：

```sh
sudo sixup -wan eth0 -lan eth1:0 -lan eth2:1
```

注意：/64 が一つでは LAN セグメント一つ分にしかなりません。委任のない回線では、サブ
ネット番号 0 のセグメントがそのプレフィックスを受け取り、残りには割り当てられません。
セグメント同士で通信する必要があれば `-lan-ula auto` で ULA を配布してください。

注意：MAP-E 回線では、送信元ポートが回線に割り当てられたポートセットの内側に収まって
いなければ、戻りの通信が届きません。この nftables ルールは sixup が維持します。書き込む
のは `inet sixup` テーブルだけで、終了時に自動で削除します。自分で書く場合は `-tunnel-nat off`
を指定してください。

`sixup -h` で全オプションを機能別に一覧表示します。

</div>
