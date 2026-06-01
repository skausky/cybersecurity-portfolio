# TryHackMe — Blue (EternalBlue)

| | |
|---|---|
| **Platform** | TryHackMe |
| **Difficulty** | Easy |
| **Category** | Blue team fundamentals / Windows exploitation |
| **Date** | 2026-06-01 |
| **ATT&CK** | T1210, T1059.001, T1003, T1543.003 |

> ⚠️ **No flags or full solution steps below** — this is a defensive writeup, per TryHackMe's content policy. The goal is to understand the attack well enough to *catch and stop it*.

---

## 🎯 Objective
A beginner room built around **MS17-010 (EternalBlue)** — a remote code execution flaw in Microsoft's SMBv1 implementation, famously used by WannaCry. Great for connecting an offensive technique to the defensive signals it generates.

## 🧠 Approach (high level)
- The target exposed **SMBv1**, which is both deprecated and vulnerable to MS17-010.
- Exploitation yields a SYSTEM-level shell; from there a Meterpreter session is established and migrated into a stable process.
- Post-exploitation involves dumping credential hashes from memory.

I focused less on running the exploit and more on the question: *what would each of these stages look like in my SIEM?*

## 🗺️ MITRE ATT&CK Mapping
| Technique | ID | Where it showed up |
|-----------|----|--------------------|
| Exploitation of Remote Services | T1210 | Initial access via vulnerable SMBv1 |
| Command & Scripting Interpreter: PowerShell | T1059.001 | Post-exploitation tooling |
| OS Credential Dumping | T1003 | Hash dumping from LSASS/memory |
| Create or Modify System Process: Windows Service | T1543.003 | Payload often installs as a service |

## 🛡️ Detection & Defense

- **Detect:**
  - SMBv1 usage itself is an anomaly — alert on SMBv1 negotiation at the network layer (Suricata/Zeek) and on hosts still permitting it.
  - The payload commonly installs a service → my [**New Windows Service** Sigma rule](../../../projects/02-siem-detection-rules/sigma/windows_new_service.yml) (Event ID 7045) would fire.
  - Post-exploitation PowerShell maps to my [**PowerShell download cradle** rule](../../../projects/02-siem-detection-rules/sigma/powershell_download_cradle.yml).
  - LSASS access for credential dumping → a known gap in my [coverage map](../../../projects/02-siem-detection-rules/#-coverage-map) (T1003) — this room is a good prompt to close it.
- **Prevent / harden:**
  - **Disable SMBv1 entirely** and **patch MS17-010** — both are checked by my [Windows audit script](../../../projects/05-system-hardening/windows/Invoke-WindowsAudit.ps1).
  - Network segmentation to limit SMB exposure between hosts.
- **Respond:** SYSTEM-level RCE on a host → treat as a major incident; the spread/persistence pattern aligns with my [ransomware playbook](../../../projects/03-incident-response-playbooks/ransomware.md) containment steps (isolate, preserve, eradicate).

## 💡 Lessons Learned
The biggest takeaway: **one deprecated protocol (SMBv1) created the entire attack surface.** A single hardening control — disabling SMBv1 — would have prevented the whole chain. It also exposed a real gap in my lab: I have no detection for credential dumping (T1003) yet, so that's my next detection-engineering task.
