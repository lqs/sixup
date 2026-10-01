<div lang="ja">

# sixup への移行

<a href="migrating.md" lang="en">English</a> | <a href="migrating.zh.md" lang="zh-Hans">简体中文</a> | <strong>日本語</strong>

多くの Linux ルーターでは、IPv6 の設定を複数のプログラムやスクリプトが分担しています。sixup はこれを一つのプログラムで行います。このページでは、既存のルーターを sixup に移行する手順を順番に説明します。

移行中、ルーターは数分間 IPv6 が使えなくなります。MAP-E や DS-Lite の回線では、IPv4 も IPv6 の上で動いているため、同じく止まります。

## 1. ドライランをする

まず、sixup が自分の回線で動くことを確かめます。ドライランはルーターに何も変更を加えないので、今の設定を動かしたまま実行できます。本番で使う予定のオプションを指定してください。

```sh
sudo sixup -wan eth0 -lan eth1 -dry-run
```

ドライランは ISP と通信し、見つけたプレフィックス、DNS サーバー、トンネルを表示します。LAN には RA を送りません。終了時には、ISP から受け取ったものを解放します。DUID は `/var/lib/sixup/duid` のものではなく、MAC アドレスから作ったものを使います。止めるには Ctrl+C を押すか、`-dry-run-timeout` で時間を指定します。

ドライランには DHCPv6 クライアントのポートである UDP 546 番が必要です。今の DHCPv6 クライアントがこのポートを使っていると、ドライランは DHCPv6 クライアントを起動できません。その場合は、ドライランの間だけ今のクライアントを止め、終わったら再び起動してください。停止時にプレフィックスを解放するクライアントもあるので、その後 ISP から新しいプレフィックスが割り当てられることがあります。

出力を確認します。

- sixup がプレフィックスを取得し、その長さが ISP から割り当てられるものと一致している。
- MAP-E、DS-Lite、4in6 の回線では、sixup がトンネルを見つけ、トンネルの種類が正しい。
- エラーがなく、すべての警告の意味が分かる。

予想と違う点があれば、ここで止めて、次の手順には進まないでください。ルーターはまだ何も変わっていません。README のオプションを確認するか、ドライランの出力を添えて [issue を作成](https://github.com/lqs/sixup/issues)してください。

## 2. チェックリストを作る

ルーターが今 IPv6 のために何をしていて、それをどのプログラムが担当しているかを書き出します。下の表のうち、最後の行以外は sixup が行う仕事です。最後の行の仕事は、今のプログラムがそのまま担当します。

| 仕事 | 主な担当 | sixup 導入後 |
|---|---|---|
| ISP からプレフィックスを取得する | odhcp6c、dhcpcd、wide-dhcpv6-client、`dhclient -6`、systemd-networkd、ifupdown | 内蔵 |
| LAN にルーター広告を送る | radvd、odhcpd、dnsmasq（`enable-ra`）、systemd-networkd（`IPv6SendRA`） | 内蔵 |
| LAN の DHCPv6 サーバー | odhcpd、dnsmasq、Kea | 内蔵、`-dhcp6s-mode` |
| /64 を共有するときの近隣探索プロキシ | ndppd | 内蔵 |
| MAP-E、DS-Lite、4in6 のトンネルと、その NAT および MSS のルール | スクリプト | 内蔵 |
| LAN 宛て通信の IPv6 フィルター | ip6tables、nftables | 内蔵、`-unsolicited` を参照 |
| DHCPv4、ネイティブ IPv4 の NAT、DNS リゾルバ、ルーター自身のフィルター | dnsmasq、Unbound、nftables | 変更なし |

次に、sixup の仕事をしているものをすべて探し、その場所を書き留めます。そうすれば、手順 5 はこのリストを順に片付けるだけになります。

**止めるサービス。** 起動時に立ち上がるサービスを一覧にし、表に出てくるもの、たとえば radvd、odhcpd、odhcp6c、ndppd、wide-dhcpv6-client を書き留めます。

```sh
systemctl list-unit-files --state=enabled   # systemd
rc-update show default                      # OpenRC, such as Alpine
```

**動かし続けるプログラムで変更する設定。** ファイル名と行を書き留めます。

- **dnsmasq**。`/etc/dnsmasq.conf` と `/etc/dnsmasq.d/` にある、`enable-ra`、`ra-param`、IPv6 の範囲を持つ `dhcp-range` の行。
- **systemd-networkd**。WAN と LAN の `/etc/systemd/network/*.network` にある、`IPv6AcceptRA`、`IPv6SendRA`、`DHCPPrefixDelegation`、`DHCP` の設定。
- **NetworkManager**。`nmcli connection show` で表示される WAN と LAN の接続と、その `ipv6.method`。
- **dhcpcd**。`/etc/dhcpcd.conf` にある、`ia_pd`、`ipv6rs`、`ipv6only` のオプション。
- **ifupdown**。`/etc/network/interfaces` にある、WAN と LAN の `inet6` セクション。

**スクリプトと残骸。** 次のコマンドで探せます。

```sh
crontab -l; ls /etc/cron.d
grep -rlE 'ip -6|ip6tables|ip6tnl|inet6|radvd' /etc/network /etc/ppp /etc/dhcpcd* /etc/cron* 2>/dev/null
grep -rE 'accept_ra|autoconf|forwarding' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
ip -d link show type ip6tnl
nft list ruleset | grep -n masquerade
iptables -t nat -S 2>/dev/null | grep MASQUERADE
```

- IPv6 のアドレス、経路、トンネルを追加する cron ジョブ、`if-up.d` スクリプト、PPP の `ip-up` スクリプト、dhcpcd のフック。
- `/etc/sysctl.d` にあって `accept_ra`、`autoconf`、`forwarding` を設定するファイル。sixup は起動時にこれらの値を設定します。こうしたファイルが残っていると、sysctl を再読み込みしたときに値が元に戻ります。
- スクリプトが作ったトンネルデバイス。
- トンネルから出ていく通信をマスカレードする nftables や iptables のルール。MAP-E では、これらのルールは回線のポートセット外のポートを使ってしまいます。sixup はこうしたルールを見つけると警告を出します。
- LAN 宛て通信のために自分で書いた IPv6 フィルター。sixup を `-unsolicited allow` で動かす場合に限り残してください。

**今の状態を保存する。** 後で比べたり、元に戻したりするときに使えます。

```sh
ip -6 addr > before-addr.txt
ip -6 route > before-route.txt
ip -4 route >> before-route.txt
nft list ruleset > before-nft.txt
sysctl -a 2>/dev/null | grep -E 'ipv6\.conf\..*\.(forwarding|accept_ra|autoconf)' > before-sysctl.txt
crontab -l > before-crontab.txt
```

**プレフィックスを維持したい場合。** ISP は DHCPv6 の DUID でルーターを識別します。sixup は新しい DUID を作ります。多くの ISP は新しい DUID に新しいプレフィックスを割り当てるので、LAN のアドレスがすべて一度変わります。

プレフィックスを維持するには、古い DHCPv6 クライアントの DUID を探します。状態ファイルやログを見てください。sixup を初めて起動する前に、その DUID を区切り文字なしの 16 進数で `/var/lib/sixup/duid` に書き込みます。たとえば `000100012a3b4c5d001122334455` のようにします。ISP は IAID も確認することがあるため、それでも新しいプレフィックスが割り当てられる場合があります。sixup は WAN の MAC アドレスの末尾 4 バイトから IAID を作ります。

## 3. 元に戻す方法を決めておく

古いサービスは削除せず、停止して無効にするだけにします。変更するファイルはすべてコピーを取っておきます。そうすれば、数個のコマンドで元に戻せます。

```sh
# systemd
sudo systemctl disable --now sixup
sudo systemctl enable --now radvd odhcp6c   # the services you stopped in step 5

# OpenRC
sudo rc-service sixup stop && sudo rc-update del sixup default
sudo rc-update add radvd default && sudo rc-service radvd start   # and so on for each service
```

sixup は停止するときに Router Lifetime が 0 のルーター広告を送るので、ホストはすぐに sixup を使うのをやめます。また、自分の nftables テーブル `inet sixup` と `inet sixup-filter`、および追加した到達不能経路も削除します。

sixup が追加したアドレスは、有効期間が切れるまで残ります。LAN では最長 90 分です。すぐに消すには、アドレスを flush するか再起動します。トンネルデバイス `sixup-ipv4` が残っていれば、削除できます。

```sh
sudo ip -6 addr flush dev eth1 scope global
sudo ip link del sixup-ipv4
```

始める前に、IPv6 を使わず、変更中の LAN も通らずにルーターに入れることを確かめてください。たとえばシリアルコンソールや、別のポートの IPv4 を使います。

## 4. メンテナンスの時間を決める

時間を決めます。15 分あれば十分です。ネットワークを使う全員に知らせてください。オンラインの給餌器を使っているペット、ロボット、タスクを実行中の AI エージェントも含みます。AI エージェントに移行を任せる場合は、手順 5 の後も使える接続が必要です。

始める前に、三つのことを確認します。

- **15 分間オフラインにできないもの。** たとえば、クラウドに依存するスマートロック、警報装置、データを送信する医療機器、インターネットを使っているスマートフォン。それぞれ別の手段を用意してください。
- **古いプレフィックスが書かれている場所。** たとえば、ダイナミック DNS、固定アドレス、リモートのサービスの許可リスト。ISP から新しいプレフィックスが割り当てられたら更新します。
- **ルーターのそばにいること。** モバイルホットスポットが使えるスマートフォンを用意し、必要なら元に戻せるだけの時間を取っておきます。実家のルーターのように別の国にあるルーターを、離れた場所から移行しないでください。火星に向かう途中で自宅のルーターを移行するのもやめてください。

## 5. 古い IPv6 の設定を止める

手順 2 のリストを順に片付けます。一つの LAN で二つのプログラムが RA を送ったり、一つの WAN で二つの DHCPv6 クライアントが動いたりすると、原因を見つけにくい問題が起きるので、一つも飛ばさないでください。

サービスを停止して無効にします。

```sh
# systemd
sudo systemctl disable --now radvd odhcpd odhcp6c ndppd

# OpenRC
for s in radvd odhcpd odhcp6c ndppd; do sudo rc-service $s stop; sudo rc-update del $s default; done
```

動かし続けるプログラムの設定を変更し、再起動します。

- **dnsmasq**。IPv6 の行を削除します。DHCPv4 と DNS は残します。
- **systemd-networkd**。`IPv6AcceptRA=no` と `IPv6SendRA=no` を設定し、`DHCPPrefixDelegation` を削除して、`DHCP=` を `ipv4` か `no` にします。
- **NetworkManager**。`ipv6.method` を `link-local` にするか、これらのインターフェイスを管理対象から外します。
- **dhcpcd**。`noipv6rs` と `ipv6ra_noautoconf` を追加して `ia_pd` を削除するか、`-4` を付けて動かします。
- **ifupdown**。WAN と LAN の `inet6` セクションを削除します。

見つけたスクリプト、sysctl のファイル、マスカレードのルールを削除します。古いトンネルデバイスは `ip link del` で削除します。

何も動いていないことを確認します。

```sh
pgrep -a 'radvd|odhcpd|odhcp6c|ndppd|dhcp6c'
sudo ss -ulpn 'sport = :546 or sport = :547'
```

## 6. sixup に切り替える

オプションを設定ファイルに書き、サービスを起動します。

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

次に、ルーターと LAN 内のホストで以下を確認します。

- ログにプレフィックスと LAN のアドレスが出ている。トンネルの回線では、トンネルも出ている。
- LAN のホストが新しいプレフィックスのアドレスを取得し、IPv6 のサイトにつながる。test-ipv6.com では IPv4 と IPv6 を同時に確認できます。
- MAP-E や DS-Lite の回線では、トンネル経由で IPv4 が使える。
- `nft list table inet sixup-filter` でフィルターが表示され、カウンターが増えている。

古い設定は数日間残しておきます。プレフィックスが少なくとも一度更新されるのを待ってから削除してください。

</div>
