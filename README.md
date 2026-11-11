# Security projects

I finished my B.S. in Cybersecurity in May 2026 and I'm looking for an entry-level SOC or security analyst role.

Most of what I know I learned by building things and then working out how a defender would catch them. A lot of it is wireless and embedded work: ESP32 boards, 802.11 frames, cameras on my own network. Each project says what I built, what went wrong, and what a SOC would actually see.

## Projects I built

| Project | What it is |
|---|---|
| [ackwave](./projects/15-ackwave/) | An ESP32-S3 that detects people moving by measuring the Wi-Fi signal from a router it never connects to. C firmware, detection on the board, tested overnight against a mmWave radar. [Code](https://github.com/skausky/ackwave) |
| [Insider Threat Detector](./projects/07-insider-threat-detector/) | A Windows agent in C (processes, USB, clipboard, window titles, uploads) that reports to a Flask server with risk scoring, alerts and a live dashboard. [Code](https://github.com/skausky/InsiderThreatDetector) |
| [CamJam](./projects/13-camjam/) | A Wi-Fi monitoring and deauthentication lab tool that picks out cameras by vendor, built so I'd know exactly what a deauth attack looks like before writing detections for it. [Code](https://github.com/skausky/camjam) |
| [RTSP Camera Scanner](./projects/14-rtsp-camera-scanner/) | Finds IP cameras on a network and checks them for default logins, open streams and known CVEs (CVE-2017-7921, Dahua auth bypass). [Code](https://github.com/skausky/rtsp-camera-scanner) |
| [Home monitoring lab](./projects/12-home-lab/) | Home Assistant on a Raspberry Pi with mmWave radar sensors on ESP32 boards, Frigate for cameras, MQTT and AdGuard DNS. The radar data is what I used to check ackwave. |

## School and lab research

| Project | What it is |
|---|---|
| [AMSI and Defender bypass](./projects/06-amsi-defender-bypass/) | Team capstone. I wrote the C# that patches AMSI in memory; we then documented how Defender and logging can still catch it. |
| [Wireless attack lab](./projects/08-wireless-attack-lab/) | A CTF lab: passive recon, finding the client, deauthenticating it to capture the WPA handshake, and the alerts a wireless IDS raises. |
| [Cross-platform loader](./projects/09-cross-platform-loader/) | Building a C# payload on Linux and staging it to a Windows lab VM, and where each step shows up in logs. |
| [Privilege escalation research](./projects/11-privesc-research/) | Linux and Windows privilege escalation practised on TryHackMe and my own VMs, mapped to ATT&CK with how to detect each one. |

## Writeups

- [CVE research](./writeups/cve-research/): root cause, exploitation, detection and patch for specific CVEs.
- [TryHackMe: Blue](./writeups/tryhackme/blue/): EternalBlue from the defender's side.

## Study notes

Notes I wrote while studying for SOC work. They're reference material, not labs I ran myself:
[SOC lab design](./projects/01-home-soc-lab/) ·
[detection rules](./projects/02-siem-detection-rules/) ·
[IR playbooks](./projects/03-incident-response-playbooks/) ·
[threat hunting](./projects/04-threat-hunting-log-analysis/) ·
[hardening](./projects/05-system-hardening/) ·
[network IDS](./projects/10-network-ids-lab/)

## Skills

- **Languages:** C, Python, C#, PowerShell, Bash
- **Wireless and embedded:** 802.11 frame injection, Wi-Fi CSI, ESP32 / ESP-IDF / FreeRTOS, aircrack-ng, Wireshark
- **Security:** MITRE ATT&CK, CVE analysis, AMSI and Defender internals, privilege escalation, detection write-ups
- **Infrastructure:** Linux, Windows, Home Assistant, MQTT, Raspberry Pi, Flask, Git

## Education

B.S. Cybersecurity, Illinois State University, May 2026 ([coursework](./docs/education.md)). Studying for CompTIA Security+ ([certifications](./docs/certifications.md)).
