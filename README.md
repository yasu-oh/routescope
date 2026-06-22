# RouteScope

Cisco `show ip route` の意味的 diff ツールです。

このツールは GitHub Pages で公開できる完全クライアントサイド Web アプリです。貼り付けた経路表データを外部へ送信・保存・解析しません。

## Supported

- Cisco IOS / IOS-XE の基本的な `show ip route`
- `show ip route vrf <VRF名>`
- `show ip route vrf all`
- `show ip route vrf *` and prompted captures such as `DEVICE#show ip route vrf *`
- Prompted `show p ip route vrf *` captures, such as `DEVICE#show p ip route vrf *`
- NX-OS 風の `IP Route Table for VRF "<name>"` ヘッダ
- IPv4
- VRF 単位の diff
- ECMP next-hop の集合比較
- connected / local / static / OSPF / BGP の基本形式
- Cisco IOS の `x.x.x.x/<len> is subnetted` 親行に続く `/prefixlen` 省略経路

## Privacy and security

- 入力された `show ip route` はブラウザ内だけで処理します
- サーバへ送信しません
- 外部 API を使いません
- analytics を入れていません
- CDN を使っていません
- `localStorage` へ自動保存しません
