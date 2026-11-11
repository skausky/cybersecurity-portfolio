# System Hardening

> **Study notes.** I wrote these while studying this topic. They describe how I'd set it up and what to look for; they are not a record of a lab I ran myself.

> Auditable hardening scripts for Windows and Linux, aligned to **CIS Benchmark** guidance. Each script *reports* before it *changes*, so the security posture is measurable.

## Approach

Hardening is only useful if it's **measurable and reversible**. The scripts here:

1. **Audit first** — report current state against the benchmark.
2. **Apply** changes only with an explicit flag.
3. **Log** every change so it can be reviewed or rolled back.

> **Always test in a lab (or with a snapshot) before running against anything you care about.** These are learning artifacts, not a drop-in production baseline.

## Scripts

| Script | Platform | What it does |
|--------|----------|--------------|
| [`windows/Invoke-WindowsAudit.ps1`](./windows/Invoke-WindowsAudit.ps1) | Windows (PowerShell) | Audits key CIS controls (firewall, SMBv1, RDP NLA, audit policy, etc.) and reports PASS/FAIL |
| [`linux/harden-ssh.sh`](./linux/harden-ssh.sh) | Linux (Bash) | Audits & optionally hardens the SSH daemon to CIS-aligned settings |

## Controls Covered (sample)

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

## Closing the Loop

After hardening, re-run the relevant [Atomic Red Team](../01-home-soc-lab/) tests to confirm the change actually reduces the attack surface or the signal it generates. Hardening you can't verify is just hope.
