import csv
from pathlib import Path
from typing import Optional

_OUI_TABLE: dict[str, str] = {}
_LOADED = False

# Prefer system IEEE data; fall back to bundled copy in data/
_SYSTEM_OUI = Path("/usr/share/ieee-data/oui.csv")
_BUNDLED_OUI = Path(__file__).resolve().parents[2] / "data" / "oui.csv"


def _load() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    for candidate in (_SYSTEM_OUI, _BUNDLED_OUI):
        if candidate.exists():
            _parse_ieee_csv(candidate)
            return


def _parse_ieee_csv(path: Path) -> None:
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            for row in reader:
                if len(row) >= 3:
                    prefix = row[1].strip().replace("-", "").replace(":", "").upper()
                    vendor = row[2].strip()
                    if len(prefix) >= 6 and vendor:
                        _OUI_TABLE[prefix[:6]] = vendor
    except OSError:
        pass


def vendor_from_mac(mac: str) -> str:
    _load()
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) < 6:
        return "unknown"
    return _OUI_TABLE.get(clean[:6], clean[:8])


def is_randomized_mac(mac: str) -> bool:
    clean = mac.replace(":", "").replace("-", "")
    if len(clean) < 2:
        return False
    try:
        second = int(clean[1], 16)
    except ValueError:
        return False
    return bool(second & 0x2)
