# rtsp-camera-scanner — IP Camera Security Assessment Tool

> A network scanner for identifying exposed, unauthenticated, or weakly-secured RTSP IP cameras — built to understand how attackers find vulnerable devices so defenders can find them first.

[![Language](https://img.shields.io/badge/language-Python-3776ab?style=flat-square)](.)
[![Type](https://img.shields.io/badge/type-Authorized%20Assessment%20Tool-2ea043?style=flat-square)](.)
[![CVEs](https://img.shields.io/badge/CVE%20research-Hikvision%20%2F%20Dahua-c5283d?style=flat-square)](.)

> ⚠️ **Authorized use only.** This tool is for security professionals assessing networks and devices they own or have explicit written permission to test. Scanning or accessing systems without authorization is illegal in most jurisdictions. The author assumes no liability for misuse.

---

## What This Demonstrates

IP cameras are among the most commonly exploited devices on enterprise and home networks — default credentials, unpatched firmware, and unauthenticated RTSP streams are routine findings in network security assessments. Building this tool required understanding how those vulnerabilities work at the protocol level.

**Skills demonstrated:**

| Skill | How |
|-------|-----|
| Python development | Async pipeline, modular architecture (`cam_scan/` package), structured logging, optional web deps |
| Network scanning methodology | masscan for discovery, targeted RTSP probing, credential testing, result correlation |
| RTSP protocol | OPTIONS/DESCRIBE handshake, authentication negotiation, stream URL path enumeration |
| Vulnerability assessment | CVE-2017-7921 (Hikvision unauthenticated config download), Dahua authentication bypass, default credential cataloguing |
| Structured output / reporting | JSONL + CSV per-run output, per-IP findings folder, severity classification (critical/high/medium) |
| Web development | FastAPI dashboard with Server-Sent Events for live scan results, optional dependency isolation |
| Security research | CVE analysis, PoC testing, understanding root cause vs. symptom for each vulnerability class |

---

## Overview

The scanner runs in two modes:

**Presence detection (`rtsp_finder.py`)** — lightweight single-target RTSP path enumerator. Given an IP and port, probes common RTSP URL paths and reports which return `200 OK` or `401 Unauthorized` (both confirm the stream exists).

**Full assessment (`cam-scan.py`)** — production-grade pipeline:
1. masscan discovers hosts with port 554 open at scale
2. RTSP client probes each host for valid stream URLs
3. Credential engine tests unauthenticated access and common default passwords
4. Vulnerability checks run against known CVEs (Hikvision, Dahua, generic)
5. Every verified hit is recorded immediately to multiple outputs (JSONL, CSV, per-IP folder)
6. Optional web dashboard shows live results via Server-Sent Events

---

## Vulnerability Coverage

| Vulnerability | CVE | What it detects |
|---------------|-----|-----------------|
| Unauthenticated RTSP stream | — | Empty credentials accepted on RTSP OPTIONS/DESCRIBE |
| Weak default credentials | — | Common manufacturer defaults (admin/admin, admin/12345, etc.) |
| Hikvision config download | CVE-2017-7921 | Unauthenticated access to `/System/configurationFile` — exposes credentials in plaintext |
| Dahua authentication bypass | CVE-2021-33044 | Magic packet bypass on older firmware |

Each finding is tagged with `severity` (critical / high / medium), `unauth` flag, `vulns[]` list, and ready-to-use verification commands.

---

## Quick Start

**Requirements:** Linux, Python 3.10+, `masscan` (for full scan), `ffmpeg` (optional, for snapshots)

```bash
git clone https://github.com/skausky/rtsp-camera-scanner.git
cd rtsp-camera-scanner
bash setup.sh           # creates venv, installs deps, checks masscan/ffmpeg
```

### Single target — path enumeration

```bash
# Edit rtsp_finder.py: set IP = "your.target.ip"
python3 rtsp_finder.py
```

### Full network scan (headless)

```bash
./run.sh --range 192.168.1.0/24 --rate 1000 --snapshots
```

### Web dashboard

```bash
./run.sh --web --port 8080
# Open http://127.0.0.1:8080
```

---

## Output

Every scan run produces:

```
output/
├── <run_id>.jsonl           ← full result rows with all fields
├── <run_id>-hits.jsonl      ← verified hits only
├── <run_id>.csv             ← spreadsheet-ready summary
└── <ip>/
    ├── stream_<id>.txt      ← human-readable: URL, creds, severity, ffplay/ffmpeg commands
    └── stream_<id>.json     ← machine-readable: all vuln fields
```

---

## Architecture

```
cam_scan/
├── cli.py          ← argument parsing and run entry point
├── config.py       ← scan parameters and defaults
├── discovery.py    ← masscan wrapper and result parsing
├── rtsp_client.py  ← RTSP OPTIONS/DESCRIBE/path enumeration
├── creds.py        ← default credential database
├── verifier.py     ← stream verification and auth probing
├── vulns.py        ← CVE checks and severity classification
├── pipeline.py     ← core: discovery → verify → record (immediate, no lost hits)
├── results.py      ← Result dataclass with all vuln fields
├── database.py     ← SQLite persistence layer
├── logging_setup.py← structured JSON logging (no silent drops)
└── web.py          ← FastAPI dashboard with SSE live feed (optional)
```

---

## Defensive Relevance

The same methodology attackers use to find exposed cameras is the methodology defenders should use to audit their own networks before attackers do.

**For a SOC analyst or network defender:**

- **Asset inventory:** a scanner like this will find cameras on your network that IT doesn't know are exposed to the internet — shadow IoT is a real problem in enterprise environments
- **Default credential detection:** any camera responding to `admin/admin` is a critical finding that should trigger immediate remediation
- **CVE-2017-7921 (Hikvision):** patched in 2017, still found in production in 2024. Running this against internal ranges identifies unpatched devices before attackers do
- **RTSP exposure:** cameras that expose unauthenticated streams to the LAN (or worse, the internet) are a physical security breach and a network pivot point

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1078.001 (Default Accounts), T1190 (Exploit Public-Facing Application — for CVE checks)

---

## Research References

The `research/` directory (local only, not tracked) contains cloned PoC repos for the CVEs studied:

| Repo | CVE | Purpose |
|------|-----|---------|
| CVE-2017-7921 | Hikvision config download | Root cause analysis and detection development |
| CVE-2021-36260 | Hikvision RCE | Understanding post-exploit chain |
| DahuaLoginBypass | Dahua auth bypass | Default cred and bypass pattern research |

These external repos are gitignored — they're study material, not part of this codebase.

---

## What I Learned

- **Default credentials are the most common finding, not complex exploits.** `admin/admin` still works on a disturbing percentage of deployed cameras. Patch management and default credential rotation are unglamorous but high-impact controls.
- **The RTSP protocol has no mandatory authentication.** Many manufacturers implement auth as optional, and it defaults to off. This is a design choice that survives into production because it makes setup easier — the same tradeoff that creates most IoT security debt.
- **CVE-2017-7921 is a lesson in how authentication bypasses work.** The Hikvision flaw wasn't a buffer overflow or memory corruption — it was a path that the developer forgot to add to the authentication middleware. Understanding root causes like this is what lets you write detection rules that catch the behavior, not just the specific exploit.
- **Structured output matters.** Building reliable JSONL output with fsync on every write — so no hit is lost if the process is interrupted — is the same reliability concern that drives log pipeline design in SIEM infrastructure.
