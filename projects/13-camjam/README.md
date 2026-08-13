# CamJam

Wi-Fi monitor-mode scanner and deauth orchestration tool. **Authorized testing on networks you own or have written permission to assess only.**

## Versions

| Path | Description |
|------|-------------|
| [`versions/camjam_v1/`](versions/camjam_v1/) | Frozen full mirror of the original CLI + `multi.sh` (read-only reference) |
| [`camjam_v2/`](camjam_v2/) | Current web-first platform (v2.0.0) |

## Requirements

- Linux with `aircrack-ng` (`airodump-ng`, `aireplay-ng`), `iw`, `ip`
- Compatible adapter with monitor mode (e.g. Alfa 8812AU — see [scripts/alfa-5ghz-driver.md](scripts/alfa-5ghz-driver.md))
- **root/sudo** for radio operations

### Alfa / 8812AU and 5 GHz

If the Alfa adapter finds 2.4 GHz APs but **no 5 GHz targets**, Linux may bind **`rtw88_8821au`** instead of **`88XXau`**. Run the fix script (builds DKMS driver, blacklists rtw88, rebinds USB):

```bash
cd .
sudo ./scripts/fix-alfa-5ghz.sh
sudo ./scripts/fix-alfa-5ghz.sh --verify-only   # after replug or reboot
```

Details: [scripts/alfa-5ghz-driver.md](scripts/alfa-5ghz-driver.md). CamJam shows adapter warnings under **Monitor** in the UI.

## Install

```bash
cd .
python3 -m venv venv
source venv/bin/activate
pip install -r camjam_v2/requirements.txt
```

## Run (default: web UI)

```bash
./run.sh
```

Open the URL printed to stderr (random localhost port + session token). The UI works on phone or desktop browsers on the same machine.

## Run (CLI, optional)

```bash
./run.sh --cli
```

## Run (frozen v1 reference)

```bash
./run.sh --v1
```

## CamJam v2 features

- Responsive web dashboard (localhost-only, bearer token)
- Multi-target deauth queue (select by SSID/BSSID, per-target mode)
- SQLite fingerprinting and history (APs, clients, associations, deauth events)
- Deauth verification via before/after client snapshots (from v1 `multi.sh` logic)
- Live WebSocket event feed and statistics panel

## Changelog v1 → v2

- Web UI is the default entrypoint; CLI is opt-in (`--cli`)
- Multi-AP targeting with per-AP deauth mode
- Persistent intel DB and success-rate stats
- Documented verifier confidence levels (high / medium / low / inconclusive)