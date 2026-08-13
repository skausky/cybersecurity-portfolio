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

## How It Works

```
1. Adapter set to monitor mode (captures all 802.11 frames, no association required)
        ↓
2. Passive scan — enumerate APs (BSSID, channel, SSID, encryption, signal strength)
        ↓
3. Client enumeration — identify devices associated with target AP
        ↓
4. Deauth — craft 802.11 deauthentication frames spoofing the AP's BSSID → flood target client
        ↓
5. Verify — before/after client snapshot confirms whether disconnect succeeded
        ↓
6. Log to SQLite — AP fingerprints, client associations, deauth events, success rates
```

The v2 web dashboard shows this pipeline live via WebSocket events.

---

## v2 Features

- **Responsive web dashboard** — real-time AP/client table, deauth queue controls, live event feed
- **Multi-target mode** — select multiple APs/clients, per-target deauth configuration
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
INTERFACE="wlan1"          # your monitor-mode adapter
ESSID="YOUR_NETWORK_NAME"  # SSID you own / have permission to test

declare -A BSSID_CHAN=(
  ["AA:BB:CC:DD:EE:F1"]="6"   # BSSID → channel
)
```

---

## Defensive Relevance

Understanding this tool makes you better at catching it in production.

**What a SOC analyst sees during a deauth attack:**

| Signal | Source | Notes |
|--------|--------|-------|
| Spike in 802.11 deauth frames | Wireless IDS / RF sensor | Deauth reason codes 6 or 7, high volume from one source MAC |
| Spoofed BSSID | WIDS correlation | Frame source MAC doesn't match AP's physical MAC in asset inventory |
| Client repeatedly drops/reconnects | RADIUS logs / AP association log | Same client cycling through authenticate → associate → deauth in seconds |

**Mitigation:** Enable **802.11w (Management Frame Protection)** on the AP. Cryptographically authenticated management frames make spoofed deauth frames ineffective on supporting clients — this single control defeats the technique entirely.

**MITRE ATT&CK:** T1498 (Network Denial of Service), T1040 (Network Sniffing — passive recon phase)

---

## Project Structure

```
camjam_v2/
├── camjam/
│   ├── radio/          ← monitor mode, scanning, deauth engine
│   ├── intel/          ← AP fingerprinting, client classification
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
- **Monitor mode vs. managed mode** — capturing all frames versus only frames addressed to your MAC. The difference in what you can see is dramatic.
- **Building a web dashboard** for a real-time security tool required thinking about session isolation, concurrent state, and event streaming — the same concerns that come up in SIEM frontend work.
- **v1 → v2 rewrite taught more than v1 did.** Decomposing a monolithic Bash script into a modular Python application with a persistent store forced a clean separation between collection, analysis, and presentation layers — a pattern that appears in every production security platform.
