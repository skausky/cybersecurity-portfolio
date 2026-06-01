# 🔒 System Hardening

> Auditable hardening scripts for Windows and Linux, aligned to **CIS Benchmark** guidance. Each script *reports* before it *changes*, so the security posture is measurable.

![Standard](https://img.shields.io/badge/aligned-CIS%20Benchmarks-2ea043?style=flat-square)

---

## 🎯 Approach

Hardening is only useful if it's **measurable and reversible**. My scripts:

1. **Audit first** — report current state against the benchmark.
2. **Apply** changes only with an explicit flag.
3. **Log** every change so it can be reviewed or rolled back.

> ⚠️ **Always test in a lab (or with a snapshot) before running against anything you care about.** These are learning artifacts, not a drop-in production baseline.

## 📁 Scripts

| Script | Platform | What it does |
|--------|----------|--------------|
| [`windows/Invoke-WindowsAudit.ps1`](./windows/Invoke-WindowsAudit.ps1) | Windows (PowerShell) | Audits key CIS controls (firewall, SMBv1, RDP NLA, audit policy, etc.) and reports PASS/FAIL |
| [`linux/harden-ssh.sh`](./linux/harden-ssh.sh) | Linux (Bash) | Audits & optionally hardens the SSH daemon to CIS-aligned settings |

## 🧩 Controls Covered (sample)

**Windows**
- SMBv1 disabled
- Windows Firewall enabled on all profiles
- RDP requires Network Level Authentication (NLA)
- PowerShell Script Block Logging enabled
- Guest account disabled

**Linux (SSH)**
- Root login disabled
- Password authentication disabled (keys only)
- Protocol 2, modern ciphers/MACs
- Idle timeout configured
- Max auth tries limited

## 🔁 Closing the Loop

After hardening, I re-run the relevant [Atomic Red Team](../01-home-soc-lab/) tests to confirm the change actually reduces the attack surface or the generated signal — hardening you can't verify is just hope.
