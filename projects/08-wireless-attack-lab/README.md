# 📡 Wireless Attack Lab — 802.11 Security Research

> Authorized CTF/lab project covering passive wireless reconnaissance, client identification, and deauthentication attack execution — with a focus on how defenders detect these techniques.

![Tools](https://img.shields.io/badge/tools-Kismet%20%2B%20airodump--ng%20%2B%20Python-1f6feb?style=flat-square)
![Type](https://img.shields.io/badge/type-Authorized%20CTF%20%2F%20Lab-2ea043?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

> ⚠️ **Disclaimer:** All work documented here was performed in an authorized CTF environment targeting a dedicated test network. Deauthentication attacks on networks you do not own or have explicit written permission to test are illegal under the Computer Fraud and Abuse Act and equivalent laws. This project is documented for educational purposes only.

---

## 🎯 Overview

802.11 wireless security is a critical topic for SOC analysts — wireless attacks are quiet, hard to attribute, and can bypass perimeter defenses entirely. This lab covers the attacker's methodology end-to-end (passive recon → target identification → frame injection → result analysis) while building the defensive intuition to detect these patterns.

The CTF scenario: identify target AP BSSID and connected client, force client reconnection via deauthentication flood, capture the WPA handshake, and analyze the resulting traffic.

---

## 🧰 Skills & Technologies

- Kismet — passive 802.11 scanning and monitoring mode capture
- airodump-ng (aircrack-ng suite) — targeted packet capture, client enumeration
- aireplay-ng — deauthentication frame injection
- Python (Scapy) — custom frame crafting and automated scanning
- Wireshark — packet analysis and handshake verification
- 802.11 protocol: frame types (management/control/data), BSSID/SSID/ESSID, beacon frames, authentication/deauth frames

---

## ⚙️ Methodology

```
PHASE 1: Passive Reconnaissance
    ↓
    Monitor mode enabled on wireless adapter
    Kismet / airodump-ng to enumerate nearby APs
    Record: BSSID, channel, ESSID, encryption type, signal strength, connected clients

PHASE 2: Target Identification
    ↓
    Lock onto target BSSID + channel
    Enumerate associated client MAC addresses
    Identify active client (high data transfer rate)

PHASE 3: Deauthentication Attack
    ↓
    Craft 802.11 deauthentication frames spoofing AP BSSID
    Flood target client, forcing disconnection
    Client reconnects → 4-way WPA handshake captured in airodump

PHASE 4: Analysis
    ↓
    Verify handshake in Wireshark
    Document frame structure and timing
    Map to defensive detection opportunities
```

### Key commands (authorized lab only)

```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Passive scan — enumerate APs and clients
sudo airodump-ng wlan0mon

# Lock onto target AP and capture
sudo airodump-ng -c <CHANNEL> --bssid <TARGET_BSSID> -w capture wlan0mon

# Deauth attack (authorized lab only)
sudo aireplay-ng -0 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Phase |
|-----------|----|-|
| Network Sniffing | T1040 | Passive recon — capturing all visible 802.11 frames |
| Network Denial of Service | T1498 | Deauth flood forcing client disconnect |
| Adversary-in-the-Middle | T1557 | Positioning during reconnect (extended scenarios) |

---

## 🛡️ Detection & Defensive Relevance

This is the core reason to document the attack: understanding what it looks like to a defender.

### What defenders see during a deauth attack

| Observable | Where | Description |
|------------|-------|-------------|
| Deauth frame flood | Wireless IDS (WIDS) / RF sensor | Sudden spike in 802.11 deauth frames from an AP's BSSID — especially frames with reason code 6/7 (class 2/3 not yet authenticated) |
| Client disconnect + reconnect | RADIUS / AP logs | Client repeatedly drops association and reconnects in short windows |
| Spoofed BSSID | WIDS correlation | Deauth frames source MAC doesn't match physical AP MAC in AP database |
| Channel anomalies | RF spectrum monitor | Monitor-mode adapters on adjacent channels during recon phase |

### Detection logic (conceptual Sigma rule)

```yaml
title: 802.11 Deauthentication Flood Detected
description: Excessive deauth frames targeting a single client — indicates deauth attack or WIDS evasion attempt
tags:
  - attack.network_denial_of_service
  - attack.t1498
detection:
  selection:
    frame_type: 'deauth'
    reason_code:
      - 6    # Class 2 frame received from nonauthenticated STA
      - 7    # Class 3 frame received from nonassociated STA
  threshold:
    field: source_mac
    count: '> 20'
    timeframe: 10s
  condition: selection | threshold
level: high
```

### Hardening recommendations

- **Enable 802.11w (Management Frame Protection / MFP)** — cryptographically authenticates management frames including deauth, making spoofed frames ineffective on supporting clients.
- **Deploy a WIDS** (Cisco WLC / Aruba, or open-source tools like Kismet in IDS mode) to detect deauth floods and rogue APs.
- **Disable WPA2-only TKIP** — use WPA3 or WPA2-AES where possible.
- **Monitor AP association logs** for clients repeatedly cycling disconnect/reconnect.

---

## 📁 Contents

```
scripts/
├── scan_aps.py         ← Scapy-based passive AP scanner (authorized lab use)
├── client_enum.py      ← Parse airodump-ng CSV output to identify active clients
└── handshake_check.py  ← Validate captured handshake completeness in pcap
```

---

## 📚 What I Learned

- **The 802.11 management plane is unauthenticated by default.** Deauth attacks work because the AP and clients have no way to verify that management frames are genuine — MFP fixes this but requires hardware support on both sides.
- **Passive recon leaves no trace.** Monitor mode captures are completely invisible to the target — defenders can't see you unless they have RF sensors looking for monitor-mode behavior.
- **Wireless attacks require physical proximity.** This limits scale but also gives defenders a geographic constraint for investigation — anomalous RF patterns point to a physical location.
