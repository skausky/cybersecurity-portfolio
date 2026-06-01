# 🔐 Playbook: Compromised User Account

**Aligned to:** NIST SP 800-61 · **Severity:** High

---

## Triggers / Detection Signals
- Impossible travel (logins from geographically distant locations in a short window)
- Login from anonymizing infrastructure (Tor/VPN) inconsistent with the user
- MFA fatigue / push bombing alerts
- Inbox rules created to auto-forward or hide mail
- Anomalous data access or mass downloads

## Severity & Escalation
Treat as **High** by default. Escalate to IR lead immediately if the account is privileged, has access to sensitive data, or shows lateral movement.

---

## 1. Detection & Analysis
- [ ] Review sign-in logs: source IPs, ASN, device, user agent, MFA status.
- [ ] Check for newly created inbox rules, OAuth app grants, or mailbox delegations.
- [ ] Determine first confirmed malicious login timestamp (the "patient zero" moment).
- [ ] Identify what the account can access (blast radius).

## 2. Containment
- [ ] **Disable the account or force sign-out of all sessions** (revoke tokens — a password reset alone won't kill active sessions).
- [ ] Reset password; require re-registration of MFA if MFA may be attacker-controlled.
- [ ] Remove malicious inbox rules / OAuth grants.

## 3. Eradication
- [ ] Revoke any persistence (app passwords, OAuth tokens, delegated access).
- [ ] Hunt for lateral movement from the account to other systems.

## 4. Recovery
- [ ] Re-enable the account with fresh credentials + MFA once clean.
- [ ] Monitor closely for 7–14 days for re-compromise.

## 5. Lessons Learned
- [ ] Root cause (phishing? password reuse? infostealer?).
- [ ] Conditional access / MFA policy improvements?

## Evidence to Preserve
- Sign-in / authentication logs
- Mailbox audit logs and any malicious rules
- Timeline of access

## Communications
- Notify the user, their manager, and security leadership. Coordinate with legal/privacy if sensitive data was accessed.
