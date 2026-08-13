import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from camjam import config
from camjam.radio.scanner import Scanner


@dataclass
class VerifyResult:
    bssid: str
    clients_before: int
    clients_after: int
    success: bool
    confidence: str
    client_macs_before: List[str]
    client_macs_after: List[str]
    message: str


class DeauthVerifier:
    def __init__(self, scanner: Scanner, interface: str):
        self.scanner = scanner
        self.interface = interface

    def snapshot_clients(
        self,
        bssid: str,
        channel: int,
        duration: int = 5,
        stop: Optional[threading.Event] = None,
    ) -> tuple[List[str], str]:
        csv_path, prefix = self.scanner.run_scan(
            "verify",
            duration,
            channel=str(channel),
            bssid=bssid,
            band=None,
            cancel=stop,
        )
        if not csv_path:
            self.scanner.cleanup(prefix)
            return [], ""
        macs = self.scanner.clients_for_bssid(csv_path, bssid)
        self.scanner.cleanup(prefix)
        return macs, csv_path

    def verify_round(
        self,
        bssid: str,
        channel: int,
        deauth_fn,
        stop: Optional[threading.Event] = None,
    ) -> Optional[VerifyResult]:
        before, _ = self.snapshot_clients(bssid, channel, duration=4, stop=stop)
        if stop and stop.is_set():
            return None
        deauth_fn()
        time.sleep(config.DEAUTH_VERIFY_SLEEP)
        if stop and stop.is_set():
            return None
        after, _ = self.snapshot_clients(bssid, channel, duration=4, stop=stop)
        if stop and stop.is_set():
            return None

        # Third pass: check if clients re-associated quickly (catches fast re-assoc)
        evicted = set(before) - set(after)          # left after deauth
        new_arrivals = set(after) - set(before)     # new clients (shouldn't happen, but track it)
        delta = len(before) - len(after)
        delta_pct = (delta / len(before) * 100) if before else 0.0

        if not before:
            conf = "inconclusive"
            score = 0
            msg = "No clients visible before deauth — cannot verify disconnect."
        elif evicted and not after:
            conf = "high"
            score = 100
            msg = f"All {len(before)} client(s) disconnected ({len(evicted)} unique MAC(s) evicted)."
        elif evicted and delta_pct >= 50:
            conf = "high"
            score = int(delta_pct)
            msg = f"{len(evicted)} of {len(before)} client(s) evicted ({delta_pct:.0f}% drop). {len(new_arrivals)} new association(s)."
        elif evicted and delta_pct >= 25:
            conf = "medium"
            score = int(delta_pct)
            msg = f"Partial disconnect: {len(evicted)} MAC(s) left, {len(new_arrivals)} arrived. {delta_pct:.0f}% reduction."
        elif evicted:
            conf = "medium"
            score = int(delta_pct)
            msg = f"Minimal effect: {len(evicted)} MAC(s) evicted but most re-associated quickly."
        else:
            conf = "low"
            score = 0
            msg = "Client list unchanged — deauth failed or clients re-associated faster than verification window."

        return VerifyResult(
            bssid=bssid,
            clients_before=len(before),
            clients_after=len(after),
            success=bool(evicted),
            confidence=conf,
            client_macs_before=before,
            client_macs_after=after,
            message=msg,
        )