from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "camjam.db"
WEB_DIR = ROOT / "web" / "static"

DEFAULT_BAND = "abg"
NETWORK_SCAN_DURATION = 45
CLIENT_SCAN_DURATION = 15
WRITE_INTERVAL = 1
DEAUTH_DEFAULT_SECONDS = 10
DEAUTH_PACKETS = 10
DEAUTH_VERIFY_SLEEP = 2.0
VALID_BANDS = frozenset({"a", "b", "g", "ab", "ag", "bg", "abg"})

REQUIRED_TOOLS = ("airodump-ng", "iw", "ip", "aireplay-ng")
OPTIONAL_TOOLS = ("airmon-ng",)