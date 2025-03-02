---
title: OpShieldWall-1
description: 🛜 Forensic réseau d'un WiFi compromis
slug: opshieldwall-1
date: 2024-05-07 08:00:05+0000
tags: ["Sherlock", "Network Forensic", "Easy"]
# weight: 1       # You can add weight to some posts to override the default sorting (date descending)
---

## シナリオ
> お電話にご対応いただき、ありがとうございます。ヴェロリアン国防省は切実な支援を必要としています...
>
> この件は内密に扱う必要がありますが、ヴェロリアン国防省オフィス内のパブリックWiFiが侵害された疑いがあります。被害は最小限のようですが、ネットワーク図からは実質的なセグメンテーションが実施されておらず、デバイス間の直接通信が許可されていることが分かります。政府大臣はBYoD（Bring Your Own Device）機器とヴェロリアンMoDNetホストを用いてこのネットワークを利用しています。提供されたpcapファイルを解析し、どのように、またいつこの事象が発生したのかを確認してください。なお、本調査はTLP Amberに分類されています。

## ファイル
- `opshieldwall1.zip` （ネットワークキャプチャ「VELORIA-NETWORK.pcap」を含む）

## セットアップ
このチャレンジはシンプルなため、`tshark` / `wireshark` のみを用いて解析を行います。

## 質問

### 質問 1
**当社のWiFiネットワークのSSIDを確認してください。**

まず、キャプチャデータに慣れるため、以下のコマンドを使用して統計情報を収集します:
```shell
$ tshark -r traffic.pcapng -qz
```
- `-r` はファイルの読み込みを許可するオプション
- `-q` は出力を抑制し、グローバルな統計情報のみを表示するためのオプション
- `-z` は統計情報の表示を有効にします

考えられる統計項目は多岐に渡ります（``tshark -z help`` で確認可能）が、ここでは主に以下を把握したいです:
- パケット数
- キャプチャ時間
- パケット数の多いIPv4アドレス
- 通信量の多いIPv4エンドポイント
- 最も利用されたプロトコル

**パケット数とキャプチャ時間**: 106; 31.6秒

```shell
$ tshark -r VELORIA-NETWORK.pcap -qz io,stat,0

===================================
| IO Statistics                   |
|                                 |
| Duration: 31.6 secs             |
| Interval: 31.6 secs             |
|                                 |
| Col 1: Frames and bytes         |
|---------------------------------|
|              |1               | |
| Interval     | Frames | Bytes | |
|-------------------------------| |
|  0.0 <> 31.6 |    106 | 20759 | |
===================================
```

**IPv4エンドポイント:**
- パケット数が最も多いもの: 
```shell
$ tshark -r VELORIA-NETWORK.pcap -qz endpoints,ip       
================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
0.0.0.0                        3          1044          3            1044           0               0   
255.255.255.255                3          1044          0               0           3            1044   
10.0.3.1                       3          1048          3            1048           0               0   
10.0.3.52                      3          1048          0               0           3            1048   
================================================================================
```

- 通信量が最も多いもの: 
```shell
tshark -r VELORIA-NETWORK.pcap -qz conv,ip              
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
0.0.0.0              <-> 255.255.255.255            0 0 bytes         3 1044 bytes       3 1044 bytes    23.256576000         8.3680
10.0.3.1             <-> 10.0.3.52                  0 0 bytes         3 1048 bytes       3 1048 bytes    23.256959000         8.3693
================================================================================
```

**最も使用されたプロトコル:**
```bash
tshark -r VELORIA-NETWORK.pcap -qz io,phs        

===================================================================
Protocol Hierarchy Statistics
Filter: 

sll                                      frames:106 bytes:20759
  radiotap                               frames:92 bytes:17572
    wlan_radio                           frames:92 bytes:17572
      wlan                               frames:92 bytes:17572
        wlan.mgt                         frames:92 bytes:17572
  eapol                                  frames:6 bytes:999
    eap                                  frames:6 bytes:999
  ip                                     frames:6 bytes:2092
    udp                                  frames:6 bytes:2092
      dhcp                               frames:6 bytes:2092
  arp                                    frames:2 bytes:96
===================================================================

```

回答するために、以下のコマンドを実行します:
```shell
$ tshark -r VELORIA-NETWORK.pcap  -T fields -e wlan.ssid | head -n 1 | xxd -r -p

VELORIA-MoD-AP012
```

**解説** :
(https://www.wireshark.org/docs/dfref/w/wlan.html)
- `-t` はユーザー指定のフィールドのみを表示するため（従って ``-e`` オプションでフィールドを指定する必要があります）
- `-e wlan.ssid` は無線ネットワークのSSIDを抽出・表示するために指定
- `-xxd -r -p` は出力を16進数から可読テキストに変換します

**回答** : 
``VELORIA-MoD-AP012``	

### 質問 2
**AP（アクセスポイント）のMACアドレスを確認してください。**

```shell
tshark -r VELORIA-NETWORK.pcap  -T fields -e wlan.sa | head -n 1
02:00:00:00:01:00
```

**回答** : 
``02:00:00:00:01:00``	

### 質問 3
**APの認証状態／認証方式と攻撃ベクトルを確認してください。**

Wiresharkに切り替えます。

![EAP Sequence (Extensible Authentication Protocol)](pictures/image.png)

**回答** : 
``WPS``	

### 質問 4
**攻撃が開始されたパケット番号は何ですか?**

キャプチャ内で唯一の接続試行である最初の試行から容易に推測できます。

**回答** : 
``93``	


### 質問 5
**攻撃が終了したパケット番号は何ですか?**

認証に失敗した時点で終了していることが明らかです。

**回答** : 
``8``	
