# ⬆️ Privilege Escalation Research

> Methodology-first research into local privilege escalation techniques on Linux and Windows — each technique mapped to MITRE ATT&CK and paired with the detection it leaves behind.

![Platforms](https://img.shields.io/badge/platforms-Linux%20%2B%20Windows-1f6feb?style=flat-square)
![Type](https://img.shields.io/badge/type-Offensive%20Research-c5283d?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

> ⚠️ **Disclaimer:** All techniques documented here were practiced in isolated lab environments (TryHackMe, personal VMs). Privilege escalation against systems you don't own is illegal. This research is documented to support defensive awareness and SOC detection development.

---

## 🎯 Overview

Privilege escalation is how an attacker moves from "I have a foothold" to "I own this machine." For a SOC analyst, understanding what escalation looks like — the commands that get run, the files that get touched, the processes that get spawned — is essential for building detections that catch it.

This research covers the major escalation categories on both Linux and Windows, using a consistent methodology: **enumerate → identify → exploit → document → detect.**

---

## 🔍 Enumeration Tools

| Tool | Platform | What it finds |
|------|----------|--------------|
| **LinPEAS** | Linux | SUID/SGID files, sudo misconfigs, writable cron jobs, kernel version, PATH injection opportunities |
| **WinPEAS** | Windows | Service misconfigs, unquoted paths, AlwaysInstallElevated, token privileges, scheduled tasks |
| **sudo -l** | Linux | Manual check — what the current user can run as root |
| **accesschk.exe** | Windows | Granular service and file permission analysis |
| **PowerUp.ps1** | Windows | Automated Windows privilege escalation checks |

---

## 🐧 Linux Techniques

### SUID/SGID Abuse (T1548.001)

When a binary has the SUID bit set, it executes with the file owner's privileges (often root) regardless of who runs it.

```bash
# Enumerate SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Common SUID escalation paths (GTFOBins)
# If 'find' is SUID:
find . -exec /bin/bash -p \; -quit

# If 'vim' is SUID:
vim -c ':!/bin/bash'
```

**Detection:** Execution of binaries from `/tmp` or user home directories with effective UID = 0; SUID execution outside `/bin`, `/usr/bin`, `/sbin`.

### Sudo Misconfiguration (T1548.003)

```bash
# Check what current user can sudo
sudo -l

# Example vulnerable config in /etc/sudoers:
# user ALL=(ALL) NOPASSWD: /usr/bin/find
# Exploit:
sudo find . -exec /bin/bash \; -quit
```

**Detection:** Syslog / auth.log entries for `sudo` commands; auditd rules on execve for commands run via sudo.

### Writable Cron Jobs / PATH Injection

```bash
# Find world-writable cron scripts
ls -la /etc/cron*
cat /etc/crontab

# If a cron job calls a script without full path and a writable dir precedes it in PATH:
# Place malicious script with same name in writable directory
```

**Detection:** New or modified files in `/etc/cron.*` (auditd -w file watches); unexpected script executions originating from cron.

### Weak File Permissions

```bash
# World-writable /etc/passwd (legacy systems)
echo 'backdoor:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd

# Writable /etc/shadow or /etc/sudoers
```

**Detection:** File Integrity Monitoring (Wazuh FIM, AIDE, auditd) on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.

---

## 🪟 Windows Techniques

### Unquoted Service Path (T1574.009)

If a service binary path contains spaces and is not quoted, Windows attempts to execute each space-delimited segment:

```
C:\Program Files\Vulnerable Service\service.exe
→ Windows tries: C:\Program.exe, C:\Program Files\Vulnerable.exe, ...
```

```powershell
# Find unquoted service paths
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch '"' -and $_.PathName -match '\s'
} | Select-Object Name, PathName, StartMode

# If C:\Program Files\Vulnerable\ is writable:
# Drop malicious 'Vulnerable.exe' there and restart the service
```

**Detection:** Service creation/modification events (Windows Event 7045, 4697); unexpected binary execution from paths containing spaces.

### DLL Hijacking (T1574.001)

```powershell
# Identify DLLs loaded from writable paths using Process Monitor
# Filter: Operation=LoadImage, Result=NAME NOT FOUND, Path ends in .dll

# Drop a malicious DLL in the searched path
# When the application loads, it executes attacker's DLL
```

**Detection:** Sysmon Event ID 7 (ImageLoaded) — unusual DLL load paths; DLLs loaded from user writable directories (`%APPDATA%`, `%TEMP%`).

### Token Impersonation — SeImpersonatePrivilege (T1134.001)

Common after service account compromise (SQL Server, IIS, etc.). The service account has `SeImpersonatePrivilege`, allowing impersonation of any user who connects:

```
Tools: PrintSpoofer, RoguePotato, JuicyPotato (Windows build-dependent)
```

**Detection:** `whoami /priv` in command history (Sysmon cmd/PowerShell events); unusual parent processes spawning `cmd.exe` or `powershell.exe` with elevated token.

### AlwaysInstallElevated (T1548.002)

```powershell
# Check registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Both must be 1 for exploitation
# Generate malicious MSI with msfvenom, install as normal user → runs as SYSTEM
```

**Detection:** MSI installations from unexpected locations (Sysmon Event ID 11 file create + Event ID 1 msiexec); Windows Event 1040/1042 (MSI installation begin/end).

---

## 🗺️ MITRE ATT&CK Coverage

| Technique | ID | Platform |
|-----------|----|-|
| Abuse Elevation Control Mechanism: SUID/SGID | T1548.001 | Linux |
| Abuse Elevation Control Mechanism: Sudo/Sudoers Abuse | T1548.003 | Linux |
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | Windows |
| Hijack Execution Flow: DLL Hijacking | T1574.001 | Windows |
| Hijack Execution Flow: Unquoted Service Path | T1574.009 | Windows |
| Access Token Manipulation: Token Impersonation/Theft | T1134.001 | Windows |

---

## 📁 Contents

```
methodology/
├── linux-privesc-checklist.md   ← Systematic enumeration checklist
├── windows-privesc-checklist.md ← Systematic enumeration checklist
└── mitre-mapping.md             ← ATT&CK technique cross-reference
```

---

## 📚 What I Learned

- **Enumeration is 90% of privilege escalation.** The techniques themselves are often simple once you've found the misconfiguration. Tools like LinPEAS/WinPEAS automate enumeration, but understanding what they're looking for lets you search manually when they're blocked by AV.
- **Every escalation technique leaves a detection opportunity.** SUID execution leaves a process with effective UID 0 and a suspicious parent. Unquoted paths leave file creation events in predictable locations. The question is whether the defender has the logging configured to catch it.
- **MITRE ATT&CK mappings changed how I read this material.** Seeing "sudo abuse → T1548.003" forces you to think about the technique class, not just the specific command, which is how you build detections that catch *variations* of the technique, not just the exact tool.
