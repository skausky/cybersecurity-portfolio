# 🔎 Hunt: Living-off-the-Land Binaries (LOLBins)

**ATT&CK:** T1218 (System Binary Proxy Execution) · **Data:** Sysmon Event ID 1 (Process Creation)

---

## 1. Hypothesis
> An adversary with a foothold will prefer signed, built-in Windows binaries (`certutil`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`) to download or execute payloads, because they blend in with normal activity and may be allowlisted. If this is happening in my environment, I'll see these binaries spawning with network-facing or script-execution arguments, often from unusual parent processes.

## 2. Data & Scope
- **Source:** Sysmon process creation events from the lab Windows hosts.
- **Window:** 7 days of telemetry, including a deliberate Atomic Red Team run.

## 3. The Hunt

I started broad — every execution of the usual LOLBins — then pivoted on the suspicious arguments:

```kql
// See queries/lolbin_execution.kql for the full version
DeviceProcessEvents
| where FileName in~ ("certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe","bitsadmin.exe")
| where ProcessCommandLine has_any ("http","https","-urlcache","javascript:","scrobj.dll")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Pivot
For each hit, I examined:
- **Parent process** — was `certutil` spawned by Office, a browser, or a script? (Office → `certutil` is highly suspicious.)
- **Command line** — download URL? Decoding a base64 blob?
- **Subsequent network connections** (Sysmon Event ID 3) from the same process.

## 4. Findings
The Atomic test `T1218.010 (regsvr32)` and a `certutil -urlcache -f http://...` download both surfaced clearly. Normal admin activity did **not** match the argument filters — meaning the behavioral filter (binary + suspicious args + unusual parent) was specific enough to be low-noise.

## 5. Outcome
- ✅ Promoted the query into a **scheduled detection** (added to [SIEM Detection Rules](../02-siem-detection-rules/) backlog as a Sigma rule).
- 📌 Documented that `rundll32` is too noisy to alert on by command line alone — it needs parent-process context to avoid false positives.

## 6. Reflection
The biggest lesson: **hunting on behavior beats hunting on indicators.** I never needed a hash or an IP — the *combination* of a known LOLBin + suspicious arguments + abnormal parent is what made the activity stand out, and that's much harder for an adversary to change.
