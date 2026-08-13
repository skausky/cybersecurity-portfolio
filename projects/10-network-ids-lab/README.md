# 🌐 Network IDS Lab — Suricata & Zeek

> Hands-on network intrusion detection: writing and tuning Suricata rules, analyzing Zeek logs, and building detection logic against real captured traffic.

![Tools](https://img.shields.io/badge/tools-Suricata%20%2B%20Zeek-1f6feb?style=flat-square)
![Type](https://img.shields.io/badge/type-Detection%20Engineering-2ea043?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

---

## 🎯 Overview

Network-based detection is a foundational SOC skill. Host-based telemetry (Sysmon, auditd) tells you what happened *on* an endpoint; network telemetry tells you what happened *between* them. This lab covers two complementary tools:

- **Suricata** — signature-based IDS/IPS with a rule language similar to Snort; catches known-bad patterns in live or captured traffic.
- **Zeek** — protocol-aware network analysis framework that generates structured connection logs rather than firing on specific signatures; excellent for hunting and anomaly detection.

Together they form a layered detection capability: Suricata catches what it knows, Zeek logs everything for humans to hunt in.

---

## 🧰 Skills & Technologies

- **Suricata** — rule syntax, alert modes, pcap replay, EVE JSON output
- **Zeek** — conn.log, dns.log, http.log, ssl.log, files.log, custom scripts
- **Wireshark / tcpdump** — initial packet capture and inspection
- **jq / Bash** — querying and pivoting through Zeek JSON logs
- **Python** — log parsing and correlation scripts

---

## ⚙️ Lab Architecture

```
[Traffic Generator]        [Analysis Host]
Kali Linux / attack VM     Ubuntu 22.04
       │                        │
       └──── span/mirror ────►  eth1 (monitor-only, no IP)
                                 │
                          Suricata (IDS mode)
                          Zeek (JSON log output)
                                 │
                           ./logs/
                           ├── suricata/eve.json
                           └── zeek/
                               ├── conn.log
                               ├── dns.log
                               ├── http.log
                               └── ssl.log
```

---

## 📋 Suricata Rules

### Rule syntax overview

```
action  proto  src_ip  src_port  direction  dst_ip  dst_port  (options)
alert   tcp    any     any       ->         $HOME_NET  any    (msg:"..."; sid:9000001; rev:1;)
```

### Detection rules written in this lab

| Rule | Detects | ATT&CK |
|------|---------|--------|
| [`nmap_syn_scan.rules`](./suricata-rules/nmap_syn_scan.rules) | Nmap SYN port scan pattern | T1046 Network Service Discovery |
| [`http_suspicious_ua.rules`](./suricata-rules/http_suspicious_ua.rules) | Curl/Python/Nmap User-Agent on HTTP | T1071.001 Web Protocols |
| [`dns_high_volume.rules`](./suricata-rules/dns_high_volume.rules) | DNS flood / potential DGA activity | T1568 Dynamic Resolution |
| [`smb_eternal_blue.rules`](./suricata-rules/smb_eternal_blue.rules) | MS17-010 EternalBlue exploit attempt | T1210 Exploitation of Remote Services |
| [`icmp_tunnel.rules`](./suricata-rules/icmp_tunnel.rules) | Oversized ICMP payloads (potential tunnel) | T1095 Non-Application Layer Protocol |

### Example — Nmap SYN scan detection

```suricata
# Detect Nmap SYN scan: large number of SYN packets, no established connections
alert tcp any any -> $HOME_NET any (
    msg:"SCAN Nmap SYN scan detected";
    flags:S,12;                        # SYN only (no ACK)
    detection_filter:track by_src, count 30, seconds 10;
    classtype:network-scan;
    sid:9000001;
    rev:1;
    metadata:attack_target Client_and_Server,
              created_at 2025_01_01,
              mitre_tactic_id TA0007,
              mitre_technique_id T1046;
)
```

### Example — EternalBlue SMBv1 detection

```suricata
alert tcp any any -> $HOME_NET 445 (
    msg:"EXPLOIT EternalBlue MS17-010 SMBv1 attempt";
    content:"|00 00 00 00|";
    content:"|FF|SMB";
    content:"|73 00 00 00 00 00 00 00|";  # negotiate request signature
    classtype:attempted-admin;
    sid:9000010;
    rev:2;
    reference:cve,2017-0144;
    metadata:mitre_technique_id T1210;
)
```

---

## 📊 Zeek Log Analysis

Zeek doesn't fire alerts — it writes structured logs of *everything*. The analyst brings the questions.

### Log fields used most in hunting

**conn.log** — every TCP/UDP/ICMP flow:
```
ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
```

**dns.log** — every DNS query:
```
ts  uid  id.orig_h  id.resp_h  query  qtype_name  answers  TTLs
```

**http.log** — every HTTP transaction:
```
ts  uid  id.orig_h  id.resp_h  method  host  uri  user_agent  status_code  response_body_len
```

### Hunting queries (Bash / jq)

```bash
# Find all hosts making > 100 DNS queries in a 5-minute window (potential DGA/beacon)
jq -s 'group_by(.["id.orig_h"]) | map({host: .[0]["id.orig_h"], count: length}) | sort_by(.count) | reverse' \
    zeek/dns.log | head -20

# Find connections with unusual byte ratios (small request, huge response = possible exfil destination OR C2 download)
jq 'select(.orig_bytes < 500 and .resp_bytes > 1000000)' zeek/conn.log

# Find HTTP requests with suspicious user agents
jq 'select(.user_agent | test("curl|python|nmap|zgrab"; "i"))' zeek/http.log

# Find long-duration connections to new external IPs (beacon detection)
jq 'select(.duration > 3600 and .conn_state == "S1")' zeek/conn.log
```

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | Detection method |
|--------|-----------|-----------------|
| Reconnaissance | T1046 Network Service Discovery | Suricata SYN scan rule |
| Initial Access | T1190 Exploit Public-Facing App | Suricata EternalBlue rule |
| Command & Control | T1071.001 Web Protocols | Zeek http.log UA analysis |
| Command & Control | T1571 Non-Standard Port | Zeek conn.log service field mismatches |
| Exfiltration | T1048 Over Alternative Protocol | Suricata ICMP tunnel rule + Zeek oversized ICMP |
| Discovery | T1018 Remote System Discovery | Zeek conn.log fan-out pattern per source IP |

---

## 🔬 Lab Exercises Completed

1. **Replay a known-malicious pcap** (from Malware Traffic Analysis) through Suricata — compare alerts to known ground truth
2. **Write a custom rule** to detect the exact attack technique, tune it down to zero false positives
3. **Hunt in Zeek conn.log** for beaconing behavior using connection regularity analysis
4. **Correlate Suricata alert UID with Zeek logs** to pivot from alert → full connection context → related HTTP/DNS

---

## 📚 What I Learned

- **Suricata and Zeek are complementary, not redundant.** Suricata says "this is bad" (signature); Zeek says "here's everything that happened" (context). Together you can alert and then pivot through context without re-examining raw packets.
- **Rule tuning is where skill lives.** My first Nmap detection rule fired on every SYN packet. Getting it precise enough to detect scans without firing on normal browsing took several iterations and a solid understanding of TCP state.
- **Zeek logs unlock hypothesis-driven hunting.** Without Zeek, you can only detect what you've written a rule for. With it, you can ask questions like "which host is making connections to the most unique IPs?" and find things you didn't know to look for.
- **pcap replay is the best way to test rules.** `suricata -r capture.pcap` gives you a deterministic, repeatable test environment — much better than hoping an attack happens while you're watching.
