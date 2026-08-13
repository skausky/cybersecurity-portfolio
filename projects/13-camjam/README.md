# CamJam — Wi-Fi Security Monitoring & Deauth Lab

> A wireless network monitoring and deauthentication testing tool built to understand 802.11 attack techniques from the inside — so defenders know exactly what to look for.

[![Language](https://img.shields.io/badge/language-Python%20%2F%20Bash-3776ab?style=flat-square)](.)
[![Type](https://img.shields.io/badge/type-Authorized%20Lab%20Tool-2ea043?style=flat-square)](.)
[![Interface](https://img.shields.io/badge/interface-Web%20UI%20%2B%20CLI-1f6feb?style=flat-square)](.)

> ⚠️ **Authorized use only.** This tool is for security research and authorized penetration testing on networks you own or have explicit written permission to assess. Deauthentication attacks against third-party networks are illegal under the CFAA and equivalent laws. The author assumes no liability for misuse.

---

## What This Demonstrates

Building a tool like this requires understanding the 802.11 protocol at a level that makes you a more effective analyst. You can't write a deauth detection rule if you don't understand what a deauth frame looks like, where it comes from, and what a flood of them indicates.

**Skills demonstrated:**

| Skill | How |
|-------|-----|
| 802.11 protocol knowledge | Management frame types, BSSID/SSID structure, monitor mode, client-AP association mechanics |
| Attack technique research | Iteratively tested deauth variations — broadcast vs. unicast, burst vs. sustained, single-BSSID vs. multi-BSSID |
| Device fingerprinting | OUI-based manufacturer identification; keyword filtering to isolate camera clients from general traffic |
| Python development | Async web backend (FastAPI), WebSockets for live event feed, SQLite for persistent intel, modular architecture |
| Bash scripting | Monitor mode setup, airodump-ng CSV parsing, process management, cleanup traps |
| Network recon methodology | Passive AP enumeration, client identification, channel tracking, signal analysis |
| Web security basics | Session token auth, localhost-only binding, bearer token enforcement on all routes |
| Defensive awareness | Understanding what deauth attacks generate in WIDS logs, why 802.11w (MFP) defeats this technique |

---

## Overview

CamJam evolved from a single Bash script (`multi.sh`) into a full web platform (v2). The two versions are preserved side-by-side as a record of how the tool matured:

| Version | Description |
|---------|-------------|
| [`versions/camjam_v1/`](versions/camjam_v1/) | Original CLI — Bash-driven multi-BSSID deauth loop with client verification |
| [`camjam_v2/`](camjam_v2/) | Web-first platform with real-time dashboard, persistent database, and multi-target queue |

---

## Attack Techniques Explored

The project wasn't built in one pass — each technique was tested, observed, and iterated on before moving to the next. That iteration is what produced real understanding of how the attack behaves and how it fails.

### 1. Broadcast Deauth

The simplest approach: send a single deauth frame with the broadcast destination (`FF:FF:FF:FF:FF:FF`) spoofing the AP's BSSID. This tells every client on the AP to disconnect simultaneously.

```
aireplay-ng --deauth 5 -a <BSSID> <interface>
```

**Observed behavior:** effective against legacy clients; modern devices with 802.11w enabled ignore it entirely. Fast to execute but noisy — generates a visible spike on any WIDS that monitors frame counts by reason code.

### 2. Unicast Deauth (Targeted)

Sending deauth frames directly to a specific client MAC rather than broadcasting. More surgical — only the targeted device disconnects. Useful when the goal is to knock a specific device offline without disturbing others on the same AP.

```
aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> <interface>
```

**Observed behavior:** more reliable against clients that partially implement MFP (honor unicast management frames but not broadcast). Requires knowing the client's MAC first, which comes from the passive recon phase.

### 3. Multi-BSSID Deauth Loop

Most networks have multiple access points — a single-AP deauth just pushes the client to roam to a neighbor AP. Multi-BSSID mode loops through all APs on the target network, channel-hopping between each deauth, so clients have nowhere to roam.

```bash
declare -A BSSID_CHAN=(
  ["AA:BB:CC:DD:EE:F1"]="6"    # AP 1 — 2.4 GHz ch 6
  ["AA:BB:CC:DD:EE:F2"]="1"    # AP 2 — 2.4 GHz ch 1
  ["AA:BB:CC:DD:EE:F3"]="36"   # AP 3 — 5 GHz ch 36
  ["AA:BB:CC:DD:EE:F4"]="40"   # AP 4 — 5 GHz ch 40
)
```

**Observed behavior:** dramatically more effective on mesh networks and enterprise Wi-Fi with roaming. A client that reconnects to AP2 after being deauthed from AP1 gets deauthed from AP2 on the next loop iteration. Sustaining this across all APs keeps targeted devices offline indefinitely.

### 4. Verified Deauth with Before/After Client Count

Rather than fire-and-forget, CamJam captures an airodump-ng client snapshot before and after each deauth burst. The difference in associated client count determines a confidence level: **high** (client count dropped), **medium** (count unchanged but RSSI dropped), **low** / **inconclusive** (no observable change).

This matters for two reasons: some clients reconnect faster than the sampling interval, and some clients (with MFP enabled) never disconnect at all. The verifier tells you which case you're in.

### 5. Device-Type Targeting by OUI and Keyword

An attacker doesn't need to blindly deauth everything on a network. By looking up the OUI (the first three octets of a MAC address), tools can identify the manufacturer of each associated device — distinguishing cameras from laptops from phones. CamJam's intel module cross-references OUI prefixes against a manufacturer keyword list to flag camera-class devices.

**How it works:**

```
airodump-ng output (client section):
  Station MAC        | BSSID              | Signal | Notes
  D8:3A:DD:xx:xx:xx  | AA:BB:CC:DD:EE:F1  | -62    | Hikvision (camera)
  00:17:88:xx:xx:xx  | AA:BB:CC:DD:EE:F1  | -55    | Philips Hue (IoT)
  F0:18:98:xx:xx:xx  | AA:BB:CC:DD:EE:F1  | -48    | Apple (phone)
```

OUI lookups flag `D8:3A:DD` as Hikvision — a camera manufacturer. The tool queues that client for deauth while leaving the phone untouched. Camera keyword matches include Hikvision, Dahua, Reolink, Amcrest, Axis, Hanwha, Vivotek, and others.

**Why this matters for defenders:** an attacker targeting your camera system doesn't need to know which devices are cameras ahead of time. The OUI tells them. Any camera on your network using its factory-assigned MAC is trivially identifiable and targetable.

---

## How It Works

```
1. Adapter set to monitor mode (captures all 802.11 frames, no association required)
        ↓
2. Passive scan — enumerate APs (BSSID, channel, SSID, encryption, signal strength)
        ↓
3. Client enumeration — identify devices associated with target AP
        ↓
4. OUI lookup — cross-reference client MACs against manufacturer database; flag camera-class devices
        ↓
5. Deauth — craft 802.11 deauthentication frames spoofing the AP's BSSID → flood target client
        ↓
6. Verify — before/after client snapshot confirms whether disconnect succeeded
        ↓
7. Log to SQLite — AP fingerprints, client associations, deauth events, success rates
```

The v2 web dashboard shows this pipeline live via WebSocket events.

---

## v2 Features

- **Responsive web dashboard** — real-time AP/client table, deauth queue controls, live event feed
- **Multi-target mode** — select multiple APs/clients, per-target deauth configuration
- **Device classification** — OUI-based manufacturer tagging; camera-class devices flagged automatically
- **Persistent intel DB** — SQLite stores AP fingerprints, client associations, and deauth history across sessions
- **Deauth verifier** — confidence levels (high / medium / low / inconclusive) based on before/after client counts
- **Session security** — randomized localhost port + bearer token; no external exposure
- **CLI fallback** — `--cli` flag for headless/scripted use

---

## Installation

**Requirements:** Linux, `aircrack-ng` suite (`airodump-ng`, `aireplay-ng`), monitor-mode capable Wi-Fi adapter, Python 3.10+, root/sudo

```bash
git clone https://github.com/skausky/camjam.git
cd camjam
python3 -m venv venv && source venv/bin/activate
pip install -r camjam_v2/requirements.txt
```

### 5 GHz adapter setup (Alfa 8812AU)

If your adapter finds 2.4 GHz APs but no 5 GHz targets, the wrong driver may be bound:

```bash
sudo ./scripts/fix-alfa-5ghz.sh
sudo ./scripts/fix-alfa-5ghz.sh --verify-only   # after replug or reboot
```

See [`scripts/alfa-5ghz-driver.md`](scripts/alfa-5ghz-driver.md) for details.

---

## Usage

```bash
# Web UI (default — open the URL printed to stderr)
./run.sh

# CLI mode
./run.sh --cli

# v1 reference (frozen Bash version)
./run.sh --v1
```

**Configure your target** before running — edit the `CONFIGURATION` block in [`multi.sh`](multi.sh):

```bash
INTERFACE="wlan1"           # your monitor-mode adapter
ESSID="YOUR_NETWORK_NAME"   # SSID you own / have permission to test

declare -A BSSID_CHAN=(
  ["AA:BB:CC:DD:EE:F1"]="6"   # BSSID → channel
)
```

---

## The Key Lesson: Use a Private MAC Address

**This is the single most actionable takeaway from building this tool.**

Every IP camera, IoT device, and wireless client ships with a globally unique MAC address assigned by the manufacturer. The first three octets (the OUI) publicly identify who made the device. When a camera connects to your Wi-Fi, its OUI is visible to anyone running a passive scan — no association, no credentials, no packets sent to them.

An attacker running a tool like this can:
1. Passively scan the air and enumerate every client on a target network
2. Look up each client's OUI and identify cameras by manufacturer
3. Queue those clients for sustained deauth — knocking cameras offline on demand
4. Do all of this without ever connecting to the network or triggering standard IDS alerts

**The defense:** configure devices to use a **private (randomized) MAC address** when connecting to Wi-Fi.

| Device | How to enable |
|--------|---------------|
| iOS 14+ | Settings → Wi-Fi → (network) → Private Wi-Fi Address → On |
| Android 10+ | Settings → Wi-Fi → (network) → Privacy → Use randomized MAC |
| Windows 10/11 | Settings → Wi-Fi → (network) → Random hardware addresses → On |
| IP cameras | Varies by firmware — many do not support MAC randomization at all |

**The hard reality for cameras:** most IP cameras — especially budget Hikvision/Dahua/Reolink units — have no MAC randomization support. Their factory MAC is fixed, their OUI is published, and there is no firmware option to change it. Until manufacturers build this in, the realistic mitigations are:

- **802.11w (Management Frame Protection):** forces deauth frames to be cryptographically authenticated — the single most effective technical control against this attack
- **Network segmentation:** put cameras on a dedicated VLAN/SSID so even a successful deauth doesn't affect other devices
- **WIDS monitoring:** alert on deauth frame floods, reason code anomalies, and clients cycling through associate/deauth rapidly
- **Wired cameras where possible:** a camera on ethernet is immune to wireless deauth entirely

**MITRE ATT&CK:** T1498 (Network Denial of Service), T1040 (Network Sniffing — passive recon phase), T1592.001 (Gather Victim Host Information — OUI-based device fingerprinting)

---

## Defensive Relevance

Understanding this tool makes you better at catching it in production.

**What a SOC analyst sees during a deauth attack:**

| Signal | Source | Notes |
|--------|--------|-------|
| Spike in 802.11 deauth frames | Wireless IDS / RF sensor | Deauth reason codes 6 or 7, high volume from one source MAC |
| Spoofed BSSID | WIDS correlation | Frame source MAC doesn't match AP's physical MAC in asset inventory |
| Client repeatedly drops/reconnects | RADIUS logs / AP association log | Same client cycling through authenticate → associate → deauth in seconds |
| Camera feed interruptions correlating with deauth events | NVR / camera management platform | Physical security breach — attacker can blind specific cameras on demand |

---

## Project Structure

```
camjam_v2/
├── camjam/
│   ├── radio/          ← monitor mode, scanning, deauth engine
│   ├── intel/          ← AP fingerprinting, OUI lookup, client classification
│   ├── engine/         ← session management, multi-target logic, verifier
│   ├── store/          ← SQLite models and DB layer
│   └── api/            ← FastAPI routes, WebSocket, session security
├── web/static/         ← dashboard HTML/CSS/JS
└── requirements.txt

versions/camjam_v1/     ← original Bash + Python CLI (frozen reference)
multi.sh                ← standalone multi-BSSID deauth script (configurable)
scripts/                ← adapter setup and driver tooling
```

---

## What I Learned

- **802.11 management frames are unauthenticated by default.** Deauth works because neither the AP nor client can verify the frame is genuine. This is a protocol-level flaw, not a misconfiguration — and it's why MFP exists.
- **Broadcast deauth and unicast deauth behave differently.** Broadcast hits everything on the AP but is easier to ignore with partial MFP implementations. Unicast is more surgical but requires a known client MAC. Testing both revealed which clients were actually protected and which just thought they were.
- **Multi-AP networks require multi-BSSID deauth.** A client that roams from AP1 to AP2 after a single deauth is still online. Looping across all BSSIDs on the target network is what makes the attack actually effective — and that's what made mesh networks so interesting to test against.
- **OUI lookup is trivially easy for an attacker.** The manufacturer database is public. Any camera connecting to Wi-Fi with its factory MAC is advertising what it is to anyone within radio range. This was the most practically significant finding from the whole project.
- **Monitor mode vs. managed mode** — capturing all frames versus only frames addressed to your MAC. The difference in what you can see is dramatic.
- **v1 → v2 rewrite taught more than v1 did.** Decomposing a monolithic Bash script into a modular Python application with a persistent store forced a clean separation between collection, analysis, and presentation layers — a pattern that appears in every production security platform.
