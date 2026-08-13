# rtsp-camera-scanner — IP Camera Recon & Vulnerability Assessment

> Concise, high-signal scanner for RTSP IP cameras on authorized networks. Surfaces open/unauthenticated streams and weak default credentials — built for authorized security assessments and network audits.

> ⚠️ **Authorized use only.** This tool is for security research, penetration testing, and defensive security purposes on networks and devices you own or have explicit written permission to assess. Scanning systems without authorization is illegal. The author assumes no liability for misuse.

**Features**: zero lost hits, durable persistence, hardened logging, and first-class vulnerability output (unauth + weak default creds). Web UI deps are optional — pure headless use never requires fastapi/uvicorn.

## Why this version
- **No lost hits**: masscan "hit" always leads to full brute (probe is advisory only). Verified hits are recorded *immediately* (before any slow snapshot) to:
  - run `*-hits.jsonl`
  - global `output/hits.jsonl` (with fsync)
  - per-IP folder + .txt/.json
  - live web UI (SSE)
  - main run .jsonl/.csv
- **Vuln & exploitation first-class**:
  - Every verified hit gets `unauth`, `weak_auth`, `vulns[]`, `severity`, `fingerprint`.
  - Common wins auto-tagged: `unauth_rtsp_access`, `weak_default_creds`.
  - Severity: critical (unauth) / high (weak) / medium.
  - Human .txt + machine .json in per-IP folder include ready-to-run `ffplay` / `ffmpeg` record / snapshot commands.
  - Web dashboard cards show red CRITICAL badges + UNAUTH/WEAK indicators + vuln list.
- **Durable + observable**: fsync on all hit writes, hardened structured logging (no silent drops), per-run + global artifacts.
- **Concise & professional**: ~single-file web UI, clean CLI, minimal deps. Web UI is optional (headless never pulls fastapi/uvicorn).
- **Robust imports**: `import cam_scan.web` (and pipeline's internal use of register_hit) always succeeds.

## Quick start

```bash
# Headless (recommended for scale)
python3 cam-scan.py --unlimited --rate 5000 --concurrency 300 --us-only --snapshots

# Web dashboard (localhost, beautiful live view + controls)
python3 cam-scan.py --web --port 8080
# then open http://127.0.0.1:8080
```

Speed presets in web UI: slow/medium/fast/insane. Mullvad rotation optional.

## Key outputs (per run)
- `output/<run_id>.jsonl` + `.csv` — full Result rows (now with vuln fields)
- `output/<run_id>-hits.jsonl` — clean verified hits only (with vulns)
- `output/hits.jsonl` — global (web mode, fsynced)
- `output/<ip>/stream_*.txt` + `.json` — human + machine per-hit (exploitation commands + vuln tags)
- `output/<ip>/snapshot_*.jpg` (best-effort)
- `logs/<run_id>.jsonl` + console (rich or plain)

## Vuln / exploitation fields (new in this version)
On every verified hit:
- `unauth`: true if empty creds succeeded
- `weak_auth`: true for common short/default passwords
- `vulns`: ["unauth_rtsp_access", "weak_default_creds", ...]
- `severity`: "critical" | "high" | "medium"
- `fingerprint`: "rtsp-camera-default"

These appear in:
- all JSON/CSV/hits files
- per-IP .txt (human readable + copy-paste commands)
- per-IP .json
- live web cards (red severity + UNAUTH/WEAK badges)

## Legal / ethics
**Authorized use only.** This tool is for security research, authorized testing, and defensive purposes. Scanning or accessing systems without explicit permission is illegal in most jurisdictions. The authors assume no liability. Use responsibly and at your own risk.

## External dependencies
- `masscan` (required for discovery)
- `ffmpeg` (optional, for snapshots + record commands in output)
- For `--web` UI only: `fastapi` + `uvicorn` (optional; core scanner works without them)

Install on Debian/Ubuntu:
```bash
sudo apt install masscan ffmpeg
pip install -r requirements.txt   # includes web deps; safe to use for headless too
```

## Architecture notes (for contributors)
- `cam_scan/pipeline.py` — core (immediate hit record + vuln tagging + best-effort snapshot)
- `cam_scan/results.py` — Result dataclass (vuln fields added)
- `cam_scan/web.py` — single-file dashboard + durable global hits; web deps optional
- `cam_scan/logging_setup.py` — no-silent-drop JsonLineHandler
- `cam_scan/creds.py` + `targets.py` — excellent defaults + smart public/US targeting

Legacy `paused.conf` and `archives/` are from the old shell/masscan version and are ignored by the Python code (header comment added).

## Value
Reliable (you will not miss hits), high-signal (every hit comes with exploitation metadata and ready commands), concise, and professional. Built to be something you'd proudly show a serious buyer.

Run it. Trust the outputs. Act on the vulns.