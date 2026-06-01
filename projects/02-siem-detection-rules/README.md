# 📡 SIEM Detection Rules

> Custom detection content written in **Sigma** (vendor-agnostic) and translated to Wazuh / KQL, each mapped to MITRE ATT&CK and validated against my [Home SOC Lab](../01-home-soc-lab/).

![Format](https://img.shields.io/badge/format-Sigma-1f6feb?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

---

## 🎯 Philosophy

A good detection is more than a keyword match. For each rule I aim to document:

- **What adversary behavior** it catches (ATT&CK technique)
- **Why** that behavior is suspicious
- **Known false positives** and how I tuned them out
- **How I validated it** (which Atomic test fired it)

## 📁 Rules in this repo

| Rule | ATT&CK | Detects | File |
|------|--------|---------|------|
| Suspicious PowerShell download cradle | T1059.001 | `IEX (New-Object Net.WebClient).DownloadString` style execution | [`sigma/powershell_download_cradle.yml`](./sigma/powershell_download_cradle.yml) |
| New service installed | T1543.003 | Service creation often used for persistence | [`sigma/windows_new_service.yml`](./sigma/windows_new_service.yml) |
| Linux SSH brute force | T1110 | Repeated failed SSH auth from a single source | [`sigma/linux_ssh_bruteforce.yml`](./sigma/linux_ssh_bruteforce.yml) |

## 🔬 Example: PowerShell Download Cradle

A classic initial-access / execution technique. The Sigma rule below keys on `powershell.exe` spawning with download-and-execute patterns in the command line:

```yaml
title: Suspicious PowerShell Download Cradle
status: experimental
description: Detects PowerShell download cradles commonly used to pull and execute remote payloads in memory.
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_cmd:
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection_img and selection_cmd
falsepositives:
  - Legitimate admin scripts that pull modules from internal repos (allowlist by signing/path)
level: high
```

### How I validated it
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```
The test fired the rule in Wazuh; I then added an allowlist exception for our internal module repo path to clear the recurring false positive.

## 🔄 Sigma → your SIEM

Sigma is intentionally vendor-neutral. To deploy these:

```bash
# Convert to your backend with sigma-cli (pySigma)
sigma convert -t lucene -p ecs_windows sigma/powershell_download_cradle.yml   # Elastic
sigma convert -t kusto sigma/powershell_download_cradle.yml                    # Microsoft Sentinel/KQL
```

## 🧭 Coverage Map

I track coverage against ATT&CK tactics so gaps are visible:

| Tactic | Coverage |
|--------|----------|
| Execution | 🟢 PowerShell |
| Persistence | 🟡 Service creation (expanding) |
| Credential Access | 🔴 Planned (T1003) |
| Lateral Movement | 🔴 Planned |

> 🟢 covered · 🟡 partial · 🔴 gap — honest gaps are part of the story.
