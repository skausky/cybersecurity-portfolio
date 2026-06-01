# 🎣 Playbook: Phishing Email

**Aligned to:** NIST SP 800-61 · **Severity:** Medium → High (depends on click/credential entry)

---

## Triggers / Detection Signals
- User-reported suspicious email (report button / abuse mailbox)
- Secure email gateway alert
- SIEM alert on a click to a newly-registered or known-bad domain
- Multiple recipients of the same lure

## Severity & Escalation
| Condition | Severity | Escalate? |
|-----------|----------|-----------|
| Email reported, not clicked | Low | No — document & block |
| Link clicked, no creds entered | Medium | Notify IR lead |
| Credentials entered / attachment opened | High | Escalate immediately, treat as account compromise |

---

## 1. Detection & Analysis
- [ ] Pull the original email (headers + body) from the abuse mailbox — **do not** forward live links.
- [ ] Analyze headers: sender domain, SPF/DKIM/DMARC results, Reply-To mismatch.
- [ ] Detonate URLs/attachments in a sandbox (e.g. urlscan.io, any.run) — never on a production host.
- [ ] Extract IOCs: sender address, URLs, domains, attachment hashes.
- [ ] Identify scope — query the mail gateway/SIEM for all recipients of the campaign.

## 2. Containment
- [ ] Block sender address, domains, and URLs at the email gateway and web proxy/DNS.
- [ ] Quarantine/purge the message from all recipient mailboxes.
- [ ] If links were clicked → pivot to the [Compromised Account playbook](./compromised-account.md).

## 3. Eradication
- [ ] Remove delivered messages org-wide.
- [ ] Add IOCs to blocklists / threat intel platform.

## 4. Recovery
- [ ] Confirm affected users regained safe state (password resets if creds entered).
- [ ] Monitor for follow-on activity from extracted IOCs.

## 5. Lessons Learned
- [ ] Was detection timely? Any gateway gap to close?
- [ ] Consider targeted awareness training if a user clicked.

## Evidence to Preserve
- Original `.eml` with full headers
- Sandbox reports
- List of recipients and click events

## Communications
- Notify the affected user(s), IT, and (if widespread) security leadership.
