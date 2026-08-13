"""Probe interface PHY/driver capabilities (5 GHz monitor, driver family)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class RadioCapabilities:
    interface: str
    driver: str = ""
    driver_version: str = ""
    usb_model: str = ""
    phy_name: str = ""
    has_5ghz: bool = False
    has_2ghz: bool = False
    monitor_mode: bool = False
    current_channel: Optional[int] = None
    current_freq_mhz: Optional[int] = None
    five_ghz_channel_count: int = 0
    recommended_driver: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "driver": self.driver,
            "driver_version": self.driver_version,
            "usb_model": self.usb_model,
            "phy_name": self.phy_name,
            "has_5ghz": self.has_5ghz,
            "has_2ghz": self.has_2ghz,
            "monitor_mode": self.monitor_mode,
            "current_channel": self.current_channel,
            "current_freq_mhz": self.current_freq_mhz,
            "five_ghz_channel_count": self.five_ghz_channel_count,
            "recommended_driver": self.recommended_driver,
            "warnings": self.warnings,
        }


def _run(cmd: List[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def _iface_phy_name(interface: str) -> str:
    wiphy_path = Path(f"/sys/class/net/{interface}/phy80211/name")
    if wiphy_path.exists():
        return wiphy_path.read_text().strip()
    info = _run(["iw", "dev", interface, "info"])
    m = re.search(r"wiphy\s+(\d+)", info)
    return f"phy{m.group(1)}" if m else ""


def _parse_bands(phy_info: str) -> tuple[bool, bool, int]:
    has_2 = False
    has_5 = False
    five_ch = 0
    band_num: Optional[int] = None
    for line in phy_info.splitlines():
        m = re.match(r"\s*Band\s+(\d+)", line)
        if m:
            band_num = int(m.group(1))
            continue
        if band_num == 1 and "MHz" in line and "[" in line and "disabled" not in line:
            has_2 = True
        if band_num == 2 and "MHz" in line and "[" in line and "disabled" not in line:
            has_5 = True
            five_ch += 1
    return has_2, has_5, five_ch


def _parse_current_channel(info: str) -> tuple[Optional[int], Optional[int]]:
    m = re.search(r"channel\s+(\d+)\s+\((\d+)\s+MHz\)", info)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None, None


def probe_interface(interface: str) -> RadioCapabilities:
    cap = RadioCapabilities(interface=interface)
    ethtool = _run(["ethtool", "-i", interface])
    for line in ethtool.splitlines():
        if line.startswith("driver:"):
            cap.driver = line.split(":", 1)[1].strip()
        elif line.startswith("version:"):
            cap.driver_version = line.split(":", 1)[1].strip()

    props = _run(["udevadm", "info", "-q", "property", "-p", f"/sys/class/net/{interface}"])
    for line in props.splitlines():
        if line.startswith("ID_MODEL_FROM_DATABASE="):
            cap.usb_model = line.split("=", 1)[1].strip()
        elif line.startswith("ID_MODEL=") and not cap.usb_model:
            cap.usb_model = line.split("=", 1)[1].strip()

    info = _run(["iw", "dev", interface, "info"])
    cap.monitor_mode = "type monitor" in info
    cap.current_channel, cap.current_freq_mhz = _parse_current_channel(info)

    cap.phy_name = _iface_phy_name(interface)
    if cap.phy_name:
        phy_info = _run(["iw", "phy", cap.phy_name, "info"])
        cap.has_2ghz, cap.has_5ghz, cap.five_ghz_channel_count = _parse_bands(phy_info)

    # Alfa / Realtek USB AC adapters: aircrack-ng 88XXau is usually better for monitor + 5 GHz
    if cap.driver.startswith("rtw88") and ("8812" in cap.usb_model or "8821" in cap.usb_model or "0bda" in props):
        cap.recommended_driver = "88XXau (aircrack-ng rtl8812au DKMS)"
        cap.warnings.append(
            f"Interface uses mainline driver '{cap.driver}'. Many Alfa 8812AU/8821AU adapters "
            "see poor or no 5 GHz networks in monitor mode with rtw88; install the "
            "88XXau driver from rtl8812au/ and blacklist rtw88_8812au / rtw88_8821au for this USB device."
        )

    if cap.has_5ghz and cap.monitor_mode and cap.current_freq_mhz and cap.current_freq_mhz < 3000:
        cap.warnings.append(
            f"Monitor mode is on 2.4 GHz (ch {cap.current_channel}) but adapter supports 5 GHz. "
            "Use band '5 GHz only' scan or dual-pass scan; ensure airodump hops Band 2."
        )

    if not cap.has_5ghz:
        cap.warnings.append("PHY reports no usable 5 GHz frequencies — adapter may be 2.4-only or blocked by regdom.")

    return cap