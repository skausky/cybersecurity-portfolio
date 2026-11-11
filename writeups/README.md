# Writeups

Lab and CTF writeups written from the defender's side: what the technique was, how I'd detect it, and how to stop it. I leave out flags and full step-by-step solutions for active rooms, per the platforms' rules.

| Platform | Room | What it covers | Defensive takeaway |
|---|---|---|---|
| TryHackMe | [Blue](./tryhackme/blue/) | EternalBlue (MS17-010) over SMBv1, Meterpreter | Disable SMBv1, patch MS17-010, watch for new services (event 7045) |

The [CVE research](./cve-research/) notes follow the same pattern for specific CVEs: root cause, exploitation, detection, patch.
