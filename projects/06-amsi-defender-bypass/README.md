# 🔴 AMSI & Windows Defender Bypass Research

> C# tooling demonstrating how Antimalware Scan Interface (AMSI) and Windows Defender signature detection can be evaded — built to understand what attackers do so defenders can catch it.

![Language](https://img.shields.io/badge/language-C%23-178600?style=flat-square)
![Type](https://img.shields.io/badge/type-Red%20Team%20Education-c5283d?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

> ⚠️ **Disclaimer:** This project was developed as part of academic coursework (ISU capstone) in authorized, isolated lab environments. All techniques are documented for educational and defensive purposes only. Do not use against systems you do not own or have explicit written permission to test.

---

## 🎯 Overview

AMSI (Antimalware Scan Interface) is a Windows API that allows security products to inspect scripts and in-memory content before execution. Modern attackers bypass it before running offensive tooling — understanding that bypass is essential for defenders who need to detect it.

This project covers two layers of evasion:
1. **AMSI bypass** — preventing `amsi.dll` from scanning in-memory PowerShell/C# content
2. **Defender signature evasion** — avoiding static pattern detection of known-bad strings and byte sequences

I was the primary developer on this as a capstone team project; it gave me direct experience with the offensive side of the detection problem.

---

## 🧰 Skills & Technologies

- C# (.NET / .NET Framework)
- Windows Antimalware Scan Interface (AMSI) internals
- Reflection and runtime memory patching
- PowerShell Script Block Logging bypass techniques
- Payload obfuscation (string splitting, encoding, runtime assembly)
- AV/EDR signature analysis and evasion concepts

---

## ⚙️ How It Works

### AMSI Internals (Brief)

```
PowerShell/C# execution
        │
        ▼
    amsi.dll loaded into process
        │
        ▼
    AmsiScanBuffer() called on content
        │
        ├─► AMSI_RESULT_CLEAN     → execution proceeds
        └─► AMSI_RESULT_DETECTED  → block + alert
```

### Bypass Technique 1 — AmsiScanBuffer Patch

The most common technique patches `AmsiScanBuffer` in memory at runtime to always return `AMSI_RESULT_CLEAN`:

```csharp
// Simplified pseudocode — actual implementation in src/
var amsi = LoadLibrary("amsi.dll");
var scanPtr = GetProcAddress(amsi, "AmsiScanBuffer");
// Write a 'ret 0' stub to the function entry point via VirtualProtect + Marshal.Copy
// This makes the function return immediately with a clean result
```

### Bypass Technique 2 — Reflection-based Assembly Loading

Loading shellcode or payloads via `Assembly.Load(byte[])` from a byte array avoids touching disk entirely, bypassing file-based scanning.

### Defender Evasion — Obfuscation Patterns

- String concatenation and runtime building of flagged terms (avoids static signature hits)
- Base64/XOR encoding of payload bytes, decoded at runtime
- GUID-based or random variable naming in generated code

---

## 🛡️ Detection & Defensive Relevance

This is the reason to build it: understanding the attack makes you better at catching it.

### What a SOC analyst sees when this runs

| Defensive Signal | Log Source | ATT&CK |
|-----------------|------------|--------|
| PowerShell process spawned with encoded `-EncodedCommand` | Sysmon Event ID 1 / Windows Event 4688 | T1059.001 |
| `VirtualProtect` called on `amsi.dll` address range | Sysmon Event ID 8 (CreateRemoteThread) / ETW | T1562.001 |
| `Assembly.Load` called with byte array (no file path) | .NET ETW provider / AMSI telemetry | T1620 |
| AMSI result overridden — telemetry gap | Windows Defender alert (pre-bypass) | T1562.001 |
| Encoded or obfuscated PowerShell | PowerShell Script Block Logging (Event 4104) | T1027 |

### Key defensive takeaways

1. **Behavioral detection beats signatures.** Signature-based AV loses once the attacker changes one byte. EDR tools (CrowdStrike, Defender for Endpoint) that hook at the kernel/ETW layer are much harder to fully blind.
2. **Script Block Logging is your friend.** Even if AMSI is patched, PowerShell Script Block Logging (Event ID 4104) captures the decoded script content *before* execution — many AMSI bypasses don't address this.
3. **Patch attempts leave artifacts.** `VirtualProtect` on `amsi.dll` memory ranges is a detectable behavior — CrowdStrike and similar EDRs alert on this pattern regardless of whether the patch succeeds.
4. **Process lineage matters.** `powershell.exe` spawned by `winword.exe` or `outlook.exe` is suspicious; spawned by a C# binary is even more so.

### Sigma rule concept for AMSI patch detection

```yaml
title: Suspicious VirtualProtect on AMSI DLL
status: experimental
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetObject|contains: 'amsi.dll'
    GrantedAccess|contains: '0x40'    # PAGE_EXECUTE_READWRITE
  condition: selection
level: high
```

---

## 📁 Source Layout

```
src/
├── AmsiPatch/
│   ├── AmsiPatch.cs        ← AmsiScanBuffer memory patch
│   └── ReflectionLoader.cs ← in-memory assembly loading
├── ObfuscationSamples/
│   └── StringObfuscation.cs
└── AmsiBypass.sln
```

> **Note:** Source files are intentionally omitted from the public repo. The techniques documented here are covered in public research (ired.team, S3cur3Th1sSh1t, etc.). This README documents the educational outcome, not a deployment-ready tool.

---

## 📚 What I Learned

- **How AMSI works at the API level** — not just "it scans things" but specifically which functions are called and when.
- **Why memory patching works and why it's increasingly detectable** — EDRs monitor for exactly this pattern using kernel callbacks.
- **The difference between signature evasion and behavioral evasion** — signature changes are a cat-and-mouse game; behavioral detections are much stickier.
- **How to write detections for evasion attempts** — the attacker has to *do something* to bypass AMSI, and that something is detectable.

---

## 🔗 References

- [AMSI Internals — Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK T1620 — Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
