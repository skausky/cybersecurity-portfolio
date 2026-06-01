# 🧬 Playbook: Ransomware

**Aligned to:** NIST SP 800-61 · **Severity:** Critical

> ⚠️ Speed and containment matter most. **Isolate, don't power off** where possible — powering off can destroy volatile evidence and, for some variants, corrupt recoverable data.

---

## Triggers / Detection Signals
- Mass file modification/rename events (FIM / EDR) with unusual extensions
- Ransom note files (`README.txt`, `.html`) appearing across shares
- Spike in `vssadmin delete shadows`, `bcdedit`, or backup deletion activity
- EDR alert on known ransomware family behavior

## Severity & Escalation
**Critical — invoke the major incident process immediately.** Notify IR lead, management, and (per policy) legal and the cyber insurer.

---

## 1. Detection & Analysis
- [ ] Confirm it's ransomware vs. a noisy false positive.
- [ ] Identify patient zero and the encryption start time.
- [ ] Determine the variant (note extension, ransom note) for known decryptors / TTPs.
- [ ] Scope: which hosts, shares, and accounts are affected?

## 2. Containment
- [ ] **Isolate** affected hosts from the network (disable switch port / EDR network containment) — keep them powered on for forensics.
- [ ] Disable compromised accounts and the spreading mechanism (e.g. SMB, admin shares).
- [ ] Protect backups — verify they are offline/immutable and not yet encrypted.

## 3. Eradication
- [ ] Remove the malware and any persistence across all affected hosts.
- [ ] Close the initial access vector (patch, reset creds, disable exposed service).

## 4. Recovery
- [ ] Rebuild from known-good images; restore data from verified-clean backups.
- [ ] Stagger reconnection and monitor for reinfection.
- [ ] **Do not pay** without leadership/legal/law-enforcement consultation — payment is a business/legal decision, not a technical one.

## 5. Lessons Learned
- [ ] Root cause and dwell time.
- [ ] Backup/segmentation/EDR gaps to fix.

## Evidence to Preserve
- Memory and disk images of patient zero (if forensics resourced)
- Ransom note, sample encrypted files, malware sample
- Network and authentication logs around the encryption window

## Communications
- Internal: IR lead, IT, leadership. External (per policy): legal, cyber insurance, law enforcement, regulators if data was exfiltrated.
