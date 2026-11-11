# Incident Response Playbooks

> **Study notes.** I wrote these while studying this topic. They describe how I'd set it up and what to look for; they are not a record of a lab I ran myself.

> Practical, repeatable response playbooks aligned to the **NIST SP 800-61** incident handling lifecycle. Written to be usable by a tier-1 analyst under pressure.

## The Lifecycle These Follow

```mermaid
flowchart LR
    P["1. Preparation"] --> D["2. Detection &\nAnalysis"]
    D --> C["3. Containment"]
    C --> E["4. Eradication"]
    E --> R["5. Recovery"]
    R --> L["6. Lessons\nLearned"]
    L -.feeds back.-> P
```

## Playbooks

| Playbook | Scenario | File |
|----------|----------|------|
| 🎣 Phishing | User reports / clicks a suspicious email | [`phishing.md`](./phishing.md) |
| 🔐 Compromised Account | Anomalous logins, impossible travel, MFA fatigue | [`compromised-account.md`](./compromised-account.md) |
| 🧬 Ransomware | Mass file encryption, ransom note detected | [`ransomware.md`](./ransomware.md) |

## What each playbook contains

- **Trigger / detection signals** — how this lands in the queue
- **Severity & escalation criteria** — when to wake someone up
- **Step-by-step actions** mapped to NIST phases
- **Containment decisions** — isolate vs. monitor, and the tradeoffs
- **Evidence to preserve** — for forensics and post-incident review
- **Communication notes** — who to notify

> Written from a tier-1 analyst's point of view as study material.
