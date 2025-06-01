---
title: OpShieldWall-1
description: 🛜 Forensic réseau d'un WiFi compromis
slug: opshieldwall-1
date: 2024-05-07 08:00:05+0000
tags: ["Sherlock", "Network Forensic", "Easy", "Writeup"]
# weight: 1       # You can add weight to some posts to override the default sorting (date descending)
---

## Scenario
> Thank you for responding to our call. The Ministry of Defense of Velorian is in desperate need of assistance...
>
> We need to keep this discreet, but we believe that the public WiFi at the Ministry of Defense offices in Velorian has been compromised. The impact seems minimal, but network diagrams show that no real segmentation of the network has been implemented and that device-to-device traffic is allowed. Government ministers use this network with BYoD equipment and Velorian MoDNet hosts. Please analyze the provided pcap file and confirm how and when this occurred. Remember that this investigation is classified as TLP Amber.

## Files
- `opshieldwall1.zip` containing the network capture "VELORIA-NETWORK.pcap"

## Setup
Given the simplicity of this challenge, we can limit ourselves to `tshark` / `wireshark`.

## Questions

### Question 1
**Please confirm the SSID of our WiFi network.**

First, let’s get familiar with the capture. We’ll use the following command to gather some statistics:
```shell
$ tshark -r traffic.pcapng -qz
```
- `-r` allows reading a file
- `-q` makes the output quieter (useful for stats as it displays global statistics, not per packet)
- `-z` enables statistics display

There are many possible values (`tshark -z help` to display them), but here we primarily want to know:
- the packet count
- the capture duration
- the IPv4 addresses with the most packets
- the IPv4 endpoints exchanging the most
- the most used protocols

**Packet count and duration**: 106; 31.6 sec

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

**IPv4 endpoints:**
- with the most packets: 
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

- exchanging the most: 
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

**Most used protocols:**
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

To answer, we can simply use the command:
```shell
$ tshark -r VELORIA-NETWORK.pcap  -T fields -e wlan.ssid | head -n 1 | xxd -r -p

VELORIA-MoD-AP012
```

**Explication** :
(https://www.wireshark.org/docs/dfref/w/wlan.html)
- `-t` displays only user-specified fields (thus requiring the use of the `-e` option to specify fields)
- `-e wlan.ssid` specifies that the `wlan.ssid` field (SSID of wireless networks) should be extracted and displayed
- `-xxd -r -p` converts the output from hexadecimal to readable text

**Answer** : 
``VELORIA-MoD-AP012``	

### Question 2
**Please confirm the MAC address of the access point (AP).**

```shell
tshark -r VELORIA-NETWORK.pcap  -T fields -e wlan.sa | head -n 1
02:00:00:00:01:00
```

**Answer** : 
``02:00:00:00:01:00``	

### Question 3
**Please confirm the AP’s authentication state/mechanism and attack vector.**

Switching to Wireshark.

![EAP Sequence (Extensible Authentication Protocol)](pictures/image.png)

**Answer** : 
``WPS``	

### Question 4
**What is the packet number where the attack began?**

We can easily deduce that it’s at the first connection attempt (the only one in the capture).

**Answer** : 
``93``	


### Question 5
**What is the packet number where the attack ended?**

It’s clear that it ends when the authentication fails.

**Answer** : 
``8``	
