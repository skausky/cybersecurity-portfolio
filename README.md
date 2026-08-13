<div align="center">

# Sean — Cybersecurity Portfolio

**B.S. Cybersecurity · 2026**

Blue Team · SOC · Detection Engineering · Incident Response

📧

![Last Commit](https://img.shields.io/github/last-commit/skausky/skausky)
![Security+](https://img.shields.io/badge/CompTIA-Security%2B%20In%20Progress-red)
![Open to Work](https://img.shields.io/badge/Status-Open%20to%20Entry--Level%20SOC-blue)

</div>

---

I learn by building. This portfolio is a record of hands-on security work — detection rules mapped to real ATT&CK techniques, incident response playbooks built from simulated incidents, and offensive research done to understand what defenders actually see. Alongside that sits a home lab of custom sensors and automation generating live telemetry I use to test against. Everything here was built, broken, and fixed by me.

> **Start here:** [Home SOC Lab](./projects/01-home-soc-lab/) — Wazuh + ELK, Sysmon, Atomic Red Team simulation, full detection loop end-to-end. Or if you're looking at the offensive side: [AMSI & Defender Bypass](./projects/06-amsi-defender-bypass/) — capstone project with full detection analysis.

---

## Projects

### Blue Team

| Project | What it shows |
|---------|---------------|
| [Home SOC Lab](./projects/01-home-soc-lab/) | Wazuh + ELK stack, Sysmon, Atomic Red Team simulation — full detection loop end-to-end |
| [SIEM Detection Rules](./projects/02-siem-detection-rules/) | Sigma and Wazuh rules mapped to ATT&CK; tuning notes and FP reduction |
| [Incident Response Playbooks](./projects/03-incident-response-playbooks/) | NIST 800-61 playbooks for phishing, ransomware, and compromised accounts |
| [Threat Hunting & Log Analysis](./projects/04-threat-hunting-log-analysis/) | Hypothesis-driven hunt writeups with KQL and SPL queries |
| [System Hardening](./projects/05-system-hardening/) | CIS-aligned hardening scripts for Windows and Linux with audit output |
| [Network IDS Lab](./projects/10-network-ids-lab/) | Suricata rule writing and Zeek log analysis for network intrusion detection |
| [Home Security Monitoring Lab](./projects/12-home-lab/) | Physical IoT sensor stack: Frigate NVR, MQTT, AdGuard DNS, ESP32 radar sensors |

### Offensive Research (Defense-Informed)

*Attacker technique research, each documented with the defender-side view: what logs it generates, what rules catch it, what hardening eliminates it.*

| Project | What it shows |
|---------|---------------|
| [AMSI & Defender Bypass](./projects/06-amsi-defender-bypass/) | C# AMSI memory patching and AV evasion — capstone; includes detection analysis |
| [Insider Threat Detector](./projects/07-insider-threat-detector/) | Python SIEM prototype: log normalization, behavioral baselining, anomaly detection |
| [Wireless Attack Lab](./projects/08-wireless-attack-lab/) | 802.11 deauth lab: passive recon, client enumeration, frame injection, WIDS detection |
| [Cross-Platform Loader](./projects/09-cross-platform-loader/) | Linux → Windows C# payload staging and delivery detection |
| [Privilege Escalation Research](./projects/11-privesc-research/) | Linux and Windows privesc methodology with ATT&CK mapping and detection opportunities |
| [CamJam — Deauth & Camera Targeting](https://github.com/skausky/camjam) ↗ | Multi-BSSID deauth tool with OUI-based camera fingerprinting; private MAC address lab |
| [RTSP Camera Scanner](https://github.com/skausky/rtsp-camera-scanner) ↗ | Network scanner for exposed IP cameras; CVE-2017-7921, Dahua auth bypass, default creds |

### Writeups

| | |
|---|---|
| [TryHackMe & CTF Writeups](./writeups/) | Defensive-framed room writeups mapped to ATT&CK |
| [CVE Research](./writeups/cve-research/) | Root cause → exploitation → detection → patch for specific CVEs |

---

## Skills

**SIEM / Monitoring** — Wazuh · Elastic/ELK · Splunk · Security Onion · Sysmon · Suricata · Zeek

**Detection & Hunting** — Sigma · KQL · Splunk SPL · MITRE ATT&CK · Atomic Red Team · YARA

**Network & Wireless** — Wireshark · Kismet · aircrack-ng · Scapy · tcpdump · 802.11 protocol

**Platforms** — Windows / Active Directory · Linux · CIS Benchmarks · Group Policy

**Scripting** — Python · PowerShell · Bash · C# · Regex

**Frameworks** — MITRE ATT&CK · NIST CSF · NIST 800-61 · Cyber Kill Chain

---

## Education & Certifications

**B.S. Cybersecurity** — 2026 · [details](./docs/education.md)

**CompTIA Security+** — in progress · [certifications](./docs/certifications.md)

---

<div align="center">

*Actively expanding · 2026 · Open to entry-level SOC and security analyst roles*

</div>
