# Alfa 8812AU / 8821AU — 5 GHz monitor mode

## What we see on this machine

- USB: `0bda:0811` Realtek 8812AU/8821AU (Alfa-class dual-band AC adapter)
- Interface: `<YOUR_ADAPTER>` (e.g. `wlx...` — shown by `ip link` or `iw dev`)
- **Current driver:** `rtw88_8821au` (in-kernel rtw88)
- **Bundled in repo:** `rtl8812au/` builds **`88XXau`** (aircrack-ng DKMS) — **not loaded by default**

`iw phy` shows Band 2 (5 GHz) frequencies, but in monitor mode the iface often stays on **2.4 GHz** (e.g. channel 8). With **rtw88**, many users see **no 5 GHz APs** in `airodump-ng` even when `--band a` or `abg` is used.

## Kernel 6.14+ (including 6.17 on Mint)

The bundled `rtl8812au` tree includes patches for newer kernels (from [aircrack-ng PR #1253](https://github.com/aircrack-ng/rtl8812au/pull/1253)): `ccflags-y` for include paths, timer shims, and cfg80211 API updates. Without these, `make dkms_install` fails with `drv_types.h: No such file or directory`.

## Recommended fix: automated script

```bash
cd /path/to/camjam   # or just run from the repo root
sudo ./scripts/fix-alfa-5ghz.sh
```

This installs **`88XXau`** via DKMS from [`rtl8812au/`](../rtl8812au/), writes `/etc/modprobe.d/camjam-alfa-88xxau.conf`, unloads **rtw88**, and verifies channel 36 (5 GHz).

After reboot or replug:

```bash
sudo ./scripts/fix-alfa-5ghz.sh --verify-only
```

Soft check only (regulatory domain, no driver swap):

```bash
sudo ./scripts/fix-alfa-5ghz.sh --soft-only
```

## Manual steps (if you prefer)

1. Build/install from this repo — same as `make dkms_install` inside `rtl8812au/`.
2. Blacklist `rtw88_8812au` and `rtw88_8821au` in modprobe.d.
3. Replug the Alfa adapter or reboot.

4. Confirm:

   ```bash
   ethtool -i <YOUR_ADAPTER> | grep driver
   # expect: driver: 88XXau

   sudo iw dev <YOUR_ADAPTER> set channel 36 HT20
   iw dev <YOUR_ADAPTER> info | grep channel
   # expect: 5180 MHz (5 GHz)

   sudo airodump-ng --band a <YOUR_ADAPTER>
   ```

## Regulatory domain

```bash
sudo iw reg set US   # or your country
iw reg get
```

DFS channels (52–144) need radar detection; try **36–48** or **149–165** first.

## CamJam

After enabling monitor mode, the UI shows driver + 5 GHz capability warnings under **INTERFACE**. Use band chip **5 GHz only** for a dedicated pass if **2.4 + 5 GHz** still looks empty on rtw88.