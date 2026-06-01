# 📝 Writeups

> Lab and CTF writeups — framed from a **defender's** perspective. Each one focuses on *what the technique was, how I'd detect it, and how I'd defend against it*, not step-by-step solutions.

![Approach](https://img.shields.io/badge/framing-defensive-1f6feb?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

---

## ⚠️ Responsible Disclosure

These writeups deliberately **avoid full step-by-step solutions and flags** for active rooms/challenges, in line with platform terms of service (e.g. TryHackMe). The value here is the **detection and defense takeaway** — the part a SOC actually cares about — which I tie back to the detections, hunts, and hardening in my [projects](../projects/).

## 📚 Index

| Platform | Room / Challenge | Difficulty | Key Techniques | ATT&CK | Defensive Takeaway | Link |
|----------|------------------|------------|----------------|--------|--------------------|------|
| TryHackMe | Blue (EternalBlue) | Easy | SMBv1 RCE, Meterpreter | T1210, T1059 | Disable SMBv1, patch MS17-010, detect on EID 7045 | [writeup](./tryhackme/blue/) |

> _Add a row per writeup as you go. Keep the "Defensive Takeaway" column sharp — it's the column hiring managers read._

## 🗂️ Structure

```
writeups/
├── README.md          ← this index
├── TEMPLATE.md        ← copy this for each new writeup
└── tryhackme/
    └── <room-name>/
        └── README.md
```

## ➕ Adding a new writeup

1. Copy [`TEMPLATE.md`](./TEMPLATE.md) to `tryhackme/<room-name>/README.md`.
2. Fill it in — emphasize the **Detection & Defense** section.
3. Add a row to the index table above.
4. Where relevant, link the technique to a concrete detection in [SIEM Detection Rules](../projects/02-siem-detection-rules/) or a hunt in [Threat Hunting](../projects/04-threat-hunting-log-analysis/).
