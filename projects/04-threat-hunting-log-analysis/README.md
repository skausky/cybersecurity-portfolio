# Threat Hunting & Log Analysis

> **Study notes.** I wrote these while studying this topic. They describe how I'd set it up and what to look for; they are not a record of a lab I ran myself.

> Hypothesis-driven hunt plans for the kind of telemetry described in my [SOC lab notes](../01-home-soc-lab/). Each one ends with the detection it would lead to, or what "no findings" would tell you.

## My Hunting Method

```mermaid
flowchart LR
    H["Hypothesis\n(ATT&CK informed)"] --> Q["Query the data"]
    Q --> A["Analyze\n& pivot"]
    A --> F{"Findings?"}
    F -->|Yes| DET["Create / tune\ndetection"]
    F -->|No| DOC["Document coverage\n+ refine hypothesis"]
    DET --> H
    DOC --> H
```

I lean on the **Pyramid of Pain** — hunting on *behaviors and TTPs* rather than easily-changed indicators like hashes and IPs.

## Hunt Writeups

| Hunt | Hypothesis | ATT&CK | Writeup |
|------|-----------|--------|---------|
| Living-off-the-land binaries | Adversaries abuse signed Windows binaries (LOLBins) to evade detection | T1218 | [`hunt-lolbins.md`](./hunt-lolbins.md) |

## Query Library

Reusable hunting queries kept in [`queries/`](./queries/):

| File | Platform | Purpose |
|------|----------|---------|
| [`lolbin_execution.kql`](./queries/lolbin_execution.kql) | KQL (Sentinel/Defender) | Surface suspicious LOLBin process activity |
| [`failed_logons.spl`](./queries/failed_logons.spl) | Splunk SPL | Spot password-spray / brute-force patterns |

## Log Analysis Skills Demonstrated
- Parsing and normalizing noisy Windows Event Logs and Sysmon
- Pivoting from a single suspicious process to parent/child lineage and network connections
- Baselining "normal" to make outliers visible
- Translating findings into durable detections (see [SIEM Detection Rules](../02-siem-detection-rules/))
