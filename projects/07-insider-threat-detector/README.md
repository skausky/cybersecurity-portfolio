# 🔍 Insider Threat Detector

> A lightweight SIEM prototype that ingests user activity logs and flags anomalous behavior patterns associated with insider threats — data exfiltration, off-hours access, and privilege abuse.

![Language](https://img.shields.io/badge/language-Python-3776ab?style=flat-square)
![Type](https://img.shields.io/badge/type-Detection%20Tool-2ea043?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

---

## 🎯 Overview

Insider threats — malicious, negligent, or compromised employees — are among the hardest threat actors to detect because they use legitimate credentials and access patterns. Commercial SIEMs (Splunk, Microsoft Sentinel, QRadar) handle this through user behavior analytics (UEBA), but building one from scratch is the best way to understand what's happening under the hood.

This tool ingests structured log data (authentication events, file access, process execution) and applies rule-based and statistical detection logic to surface anomalous patterns. The architecture parallels real SIEM pipelines: ingest → parse → enrich → correlate → alert.

---

## 🧰 Skills & Technologies

- Python (log parsing, data structures, alerting)
- Log formats: Windows Security Event Logs (EVTX), syslog, CSV
- Detection logic: threshold rules, time-window correlation, baseline deviation
- Alert generation and triage output
- Concepts: UEBA, behavioral baselining, insider threat indicators

---

## ⚙️ How It Works

```
Log Sources (CSV / EVTX / syslog)
        │
        ▼
   Ingest & Parse
   (normalize to common schema)
        │
        ▼
   Enrich
   (add user baseline, time context, asset sensitivity)
        │
        ▼
   Detection Engine
   (rule evaluation → anomaly scoring)
        │
        ▼
   Alert Output
   (console / JSON / log file)
```

### Indicator Categories

| Category | What it looks for | Example indicators |
|----------|-------------------|-------------------|
| **Data staging / exfiltration** | Large file copies, access to sensitive paths, unusual outbound | >500MB written in <10 min, access to HR/finance paths |
| **Off-hours access** | Login or file activity outside the user's normal window | Authentication at 2 AM when baseline is 8 AM–6 PM |
| **Privilege abuse** | Accessing resources outside normal job function | Finance user querying IT admin shares |
| **Anomalous logon behavior** | Failed attempts, new workstations, source IP changes | 5+ failed logins followed by success, RDP from new host |
| **Lateral movement signals** | Auth events across multiple systems in short windows | Same user authenticating to 8 hosts in 30 minutes |

### Detection Rules (examples)

```python
# Off-hours logon
def check_off_hours_logon(event, user_baseline):
    hour = event.timestamp.hour
    normal_start = user_baseline['logon_window']['start']   # e.g. 7
    normal_end   = user_baseline['logon_window']['end']     # e.g. 19
    return not (normal_start <= hour < normal_end)

# Spike in file writes
def check_file_write_spike(events, window_minutes=10, threshold_mb=500):
    windowed = filter_by_time_window(events, window_minutes)
    total_mb = sum(e.bytes_written for e in windowed) / 1_048_576
    return total_mb > threshold_mb
```

---

## 🗺️ MITRE ATT&CK Coverage

| Technique | ID | What we detect |
|-----------|----|-|
| Valid Accounts (insider using legit creds) | T1078 | Baseline deviation on known-good accounts |
| Data Staged | T1074 | Bulk file writes / unusual staging directories |
| Exfiltration Over Web Service | T1567 | Large outbound data (if network logs available) |
| Account Discovery | T1087 | LDAP/AD enumeration outside normal job function |
| Lateral Movement | T1021 | Multi-host auth in short time windows |

---

## 📁 Source Layout

```
src/
├── ingest/
│   ├── evtx_parser.py      ← Windows Security Event Log reader
│   ├── syslog_parser.py
│   └── csv_parser.py
├── detection/
│   ├── rules.py            ← threshold and correlation rules
│   ├── baseline.py         ← per-user behavioral baseline building
│   └── scoring.py          ← risk score aggregation
├── alert/
│   └── output.py           ← alert formatting and output
├── config/
│   └── rules.yaml          ← rule thresholds (externalized)
└── main.py
```

---

## 🚀 Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run against a sample log directory
python main.py --logs ./sample-logs/ --output alerts.json

# Build a baseline from clean historical data first
python main.py --baseline ./historical-logs/ --save-baseline baseline.json

# Run detection using saved baseline
python main.py --logs ./sample-logs/ --baseline baseline.json
```

---

## 🔗 Real-World Parallels

| This Tool | Commercial Equivalent |
|-----------|-----------------------|
| Rule-based detection engine | Splunk correlation searches, Sentinel analytics rules |
| User behavioral baseline | CrowdStrike Falcon Identity, Darktrace, Splunk UBA |
| Alert output | SIEM alert queue / ticketing integration (ServiceNow, Jira) |
| Log ingest/normalization | Logstash, Cribl, Splunk Heavy Forwarder |

---

## 📚 What I Learned

- **Baselining is harder than rules.** Static thresholds produce noisy alerts. Building a per-user behavioral model dramatically reduces false positives — and this is exactly what UEBA platforms do.
- **Log normalization is 60% of the work.** Getting auth logs, file events, and network events into a common schema before correlation is where most real SIEM projects spend their time.
- **Context is everything in insider threat.** A 2 AM login from a sysadmin on-call is normal; the same login from a departing employee is a red flag. Enrichment (HR data, role context) is what separates a good UEBA from a bad one.
