<div lang="ja">

# sixup: IPv6 ルーティングを全自動で設定

<a href="README.md" lang="en">English</a> | <a href="README.zh.md" lang="zh-Hans">简体中文</a> | <strong>日本語</strong>

[![CI](https://github.com/lqs/sixup/actions/workflows/ci.yml/badge.svg)](https://github.com/lqs/sixup/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/lqs/sixup/graph/badge.svg)](https://codecov.io/gh/lqs/sixup)
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
- 家庭用ルーターについての RFC に基づいて設計し、全体は RFC 7084、ファイアウォールは RFC 6092 に従う。[各要件と対応状況](docs/standards.md)を一覧にしている
- プレフィックスの取得方式（DHCPv6-PD / RA）を自動で判別し、内蔵の RA と DHCPv6 サーバーがアドレスと設定を配布
- 事業者がプレフィックスを変更すると、アドレス、RA、リース、代理応答エントリ、トンネルのエンドポイントが追従
- 上流が /64 のみなら RFC 7278 に従って LAN と共有し、ブロードキャスト型の WAN では NDP 代理応答も有効化、より短いプレフィックスなら各セグメントへ分割
- 下流のルーターにプレフィックスを委任し、sixup の下にさらに sixup を置ける
- 要求されていない IPv6 の着信を LAN に入れず、プログラムは PCP でポートを開ける
- 必要に応じて DS-Lite、MAP-E、IPIP6 のトンネルを構築し、MAP-E では割り当てられたポートセットを維持
- 単一の静的バイナリで 6 MiB 未満。外部コマンドにもシステムサービスにも依存しない

## クイックスタート

</div>

> [!WARNING]
> <span lang="ja">本プロジェクトは開発中で、まだリリースしていません。実回線で一度も
> 動かしていない部分があり、まったく動かない可能性があります。オプションも随時変わります。</span>

<div lang="ja">

[Releases ページ](https://github.com/lqs/sixup/releases) から、ディストリビューションに合った
パッケージ（`.deb`、`.rpm`、`.apk`、Arch Linux の `.pkg.tar.zst`）か静的バイナリを入手して
ください。正式版はまだなく、`dev` プレリリースのみです。

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
セグメント同士で通信する必要があれば `-ula auto` で ULA を配布してください。

注意：MAP-E 回線では、送信元ポートが回線に割り当てられたポートセットの内側に収まって
いなければ、戻りの通信が届きません。この nftables ルールは sixup が維持します。書き込む
のは `inet sixup` テーブルだけで、終了時に自動で削除します。自分で書く場合は `-tunnel-nat off`
を指定してください。

複数の LAN セグメント、固定アドレス、DNS サーバーの指定、NAT64 など、ほかの用途については
[設定レシピ](docs/recipes.ja.md)を参照してください。sixup が従う RFC と、項目ごとの対応状況や未対応の点は [Standards](docs/standards.md)
（英語）にまとめています。

## オプション

</div>

> [!WARNING]
> <span lang="ja">まだリリースしていないため、オプションは予告なく名前が変わったり削除されたりすることがあります。</span>

<div lang="ja">

`sixup -h` は全オプションを既定値とともに一覧表示し、[レシピ](docs/recipes.ja.md)は用途ごとに使い方を示します。ここでは sixup 自体の実行に関するオプションだけを挙げます。

- 真偽値のオプションは `=false` で無効にします。例：`-wan-ra=false`。
- 時間は Go の書式で指定します：`30s`、`10m`、`1h30m`。
- 繰り返し指定できるオプションは、値ごとに一回ずつ書きます：`-lan eth1 -lan eth2`。

| オプション | 既定値 | 説明 |
|---|---|---|
| `-state-dir` | `/var/lib/sixup` | DUID、安定アドレスの元になる秘密値、ULA、リースを保存するディレクトリ。再起動をまたいで残してください。消えると事業者が別のプレフィックスを割り当てることがあります。 |
| `-no-sysctl` | `false` | `forwarding`、`accept_ra` などの sysctl を自動で設定しません。他の方法で管理している環境向けです。このとき LAN インターフェイスには `proxy_ndp` を 1、`proxy_delay` を 0 に設定する必要があります。 |
| `-dry-run` | `false` | パラメータの取得、更新、トンネルの特定を一通り行い、経過を表示しますが、システムは変更せず、LAN に RA も送りません。 |
| `-dry-run-timeout` | `0` | ドライランを続ける時間。`0` は中断されるまで続けます。 |
| `-log-level` | `info` | 表示する最低レベル：`debug`、`info`、`warn`、`error`。 |
| `-v` | `false` | `-log-level debug` と同じ。 |
| `-version` | | バージョンを表示して終了します。 |
| `-license` | | sixup と、その派生元の作品のライセンスを表示して終了します。 |

</div>
