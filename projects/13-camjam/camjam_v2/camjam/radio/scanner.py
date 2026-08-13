import csv
import glob
import os
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

from camjam import config


class Scanner:
    def __init__(self, interface: str):
        self.interface = interface

    def wait_for_csv(self, prefix: str, retries: int = 6, delay: float = 1.5) -> str:
        for _ in range(retries):
            matches = sorted(glob.glob(f"{prefix}*.csv"))
            if matches:
                return matches[0]
            time.sleep(delay)
        return ""

    def run_scan(
        self,
        name: str,
        duration: int,
        *,
        channel: str | None = None,
        bssid: str | None = None,
        band: str | None = config.DEFAULT_BAND,
        cancel: Optional[threading.Event] = None,
    ) -> Tuple[str, str]:
        timestamp = int(time.time())
        prefix = f"/tmp/camjam_{name}_{timestamp}"
        cmd = [
            "airodump-ng",
            self.interface,
            "--output-format",
            "csv",
            "--write",
            prefix,
            "--write-interval",
            str(config.WRITE_INTERVAL),
        ]
        band_arg = config.DEFAULT_BAND if band is None else band.strip()
        if band_arg:
            cmd += ["--band", band_arg]
        if channel:
            cmd += ["--channel", str(channel)]
        if bssid:
            cmd += ["--bssid", bssid]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elapsed = 0.0
        step = 0.5
        while elapsed < duration:
            if cancel and cancel.is_set():
                break
            time.sleep(step)
            elapsed += step
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        csv_path = self.wait_for_csv(prefix)
        return csv_path, prefix

    def cleanup(self, prefix: str) -> None:
        for path in glob.glob(f"{prefix}*"):
            try:
                os.remove(path)
            except OSError:
                pass

    @staticmethod
    def parse_csv(csv_path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        networks: List[Dict[str, str]] = []
        clients: List[Dict[str, str]] = []
        section = "networks"
        try:
            with open(csv_path, newline="") as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    if not row or all(not cell.strip() for cell in row):
                        continue
                    first = row[0].strip()
                    if first.startswith("BSSID"):
                        section = "networks"
                        continue
                    if first.startswith("Station MAC"):
                        section = "clients"
                        continue
                    if section == "networks" and len(row) >= 14:
                        networks.append(
                            {
                                "bssid": row[0].strip(),
                                "first_seen": row[1].strip(),
                                "last_seen": row[2].strip(),
                                "channel": row[3].strip(),
                                "speed": row[4].strip(),
                                "encryption": row[5].strip(),
                                "cipher": row[6].strip(),
                                "auth": row[7].strip(),
                                "power": row[8].strip(),
                                "beacons": row[9].strip(),
                                "iv": row[10].strip(),
                                "lan_ip": row[11].strip(),
                                "essid_len": row[12].strip(),
                                "ssid": row[13].strip(),
                            }
                        )
                    elif section == "clients" and len(row) >= 6:
                        clients.append(
                            {
                                "station_mac": row[0].strip(),
                                "power": row[3].strip(),
                                "packets": row[4].strip(),
                                "bssid": row[5].strip(),
                                "probes": row[6].strip() if len(row) > 6 else "",
                            }
                        )
        except FileNotFoundError:
            return [], []

        cleaned = []
        for net in networks:
            if not net.get("bssid"):
                continue
            if net.get("ssid") in ("", "(not associated)"):
                net["ssid"] = "<hidden>"
            cleaned.append(net)
        return cleaned, clients

    @staticmethod
    def sort_by_power(entries: List[Dict[str, str]], key: str = "power") -> List[Dict[str, str]]:
        def power_val(entry: Dict[str, str]) -> int:
            try:
                return int(entry.get(key, "-1000"))
            except ValueError:
                return -1000

        return sorted(entries, key=power_val, reverse=True)

    def scan_networks(
        self,
        duration: int = config.NETWORK_SCAN_DURATION,
        band: str = config.DEFAULT_BAND,
        cancel: Optional[threading.Event] = None,
    ):
        csv_path, prefix = self.run_scan("nets", duration, band=band, cancel=cancel)
        if not csv_path:
            self.cleanup(prefix)
            return []
        networks, _ = self.parse_csv(csv_path)
        self.cleanup(prefix)
        return self.sort_by_power(networks)

    def scan_clients(
        self,
        target: Dict[str, str],
        duration: int = config.CLIENT_SCAN_DURATION,
        cancel: Optional[threading.Event] = None,
    ):
        csv_path, prefix = self.run_scan(
            "clients",
            duration,
            channel=target.get("channel"),
            bssid=target.get("bssid"),
            band=None,
            cancel=cancel,
        )
        if not csv_path:
            self.cleanup(prefix)
            return []
        _, clients = self.parse_csv(csv_path)
        self.cleanup(prefix)
        return self.sort_by_power(clients)

    def clients_for_bssid(self, csv_path: str, bssid: str) -> List[str]:
        _, clients = self.parse_csv(csv_path)
        want = bssid.lower()
        macs = []
        for c in clients:
            if c.get("bssid", "").lower() == want and c.get("station_mac"):
                macs.append(c["station_mac"].lower())
        return sorted(set(macs))