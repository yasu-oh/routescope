# RouteScope

Cisco `show ip route` / `show ipv6 route` の出力を、VRF・prefix・protocol・next-hop 単位で比較するための diff ツールです。

単純なテキスト diff では見づらい経路表の差分を、ネットワークエンジニアが確認しやすい形に整理します。

## Site

https://yasu-oh.github.io/routescope/

## Features

* Cisco `show ip route` / `show ipv6 route` 出力の意味的 diff
* VRF 単位の比較
* prefix 単位の追加・削除・変更検出
* ECMP next-hop の集合比較
* connected / local / static / OSPF / BGP の基本形式に対応
* 完全クライアントサイド処理
* GitHub Pages で静的ホスティング可能

## Supported input

* Cisco IOS / IOS-XE / NX-OS / XR-OS / ASA の基本的な経路情報
* `show ip route` / `show ipv6 route`
* `show ip route vrf <VRF名>` / `show ipv6 route vrf <VRF名>`
* `show ip route vrf all` / `show ipv6 route vrf all`
* `show ip route vrf *` / `show ipv6 route vrf *`
* `DEVICE#show ip route vrf *` のようなプロンプト付き出力
* `DEVICE#show p ip route vrf *` のような省略コマンドのプロンプト付き出力
* IPv4 / IPv6 経路（基本的な一行形式）
* Cisco IOS の `x.x.x.x/<len> is subnetted` 親行に続く `/prefixlen` 省略経路

## Not supported

現時点では、以下は主な対象外です。

* MPLS / VPNv4 / VPNv6 経路
* multicast routing table
* platform 固有の詳細属性すべての完全解析
* vendor 横断の route table diff
* IPv6 のあらゆる出力形式の網羅（基本行のみを想定）

## Privacy and security

RouteScope はブラウザ内だけで処理を行う静的 Web アプリです。

* 入力された経路表をサーバへ送信しません
* 外部 API を使用しません
* analytics を入れていません
* CDN を使用していません
* `localStorage` へ自動保存しません

貼り付けた経路表データは、利用中のブラウザ上でのみ解析されます。

## Use cases

* 作業前後の routing table 比較
* VRF ごとの経路差分確認
* OSPF / BGP / static / connected 経路の変化確認
* ECMP next-hop の増減確認
* 障害対応時の経路変化の整理
* config 変更・メンテナンス後の確認
