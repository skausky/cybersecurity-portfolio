import asyncio
import os
import shutil
import threading
from typing import Any, Callable, Dict, List, Optional

from camjam import config
from camjam.engine.multi_target import MultiTargetScheduler
from camjam.intel.presence import PresenceTracker
from camjam.intel.rogue import detect_rogues
from camjam.radio.deauth import DeauthRunner
from camjam.radio.interface import RadioInterface
from camjam.radio.scanner import Scanner
from camjam.store.db import Database
from camjam.store.models import DeauthMode, DeauthTarget


class AppSession:
    """Shared runtime state for web and CLI."""

    def __init__(self, broadcast: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.radio = RadioInterface()
        self.db = Database()
        self.physical_iface: Optional[str] = None
        self.monitor_iface: Optional[str] = None
        self.scanner: Optional[Scanner] = None
        self.deauth: Optional[DeauthRunner] = None
        self.networks: List[Dict[str, str]] = []
        self.clients_cache: Dict[str, List[Dict[str, str]]] = {}
        self.session_id: int = 0
        self._broadcast = broadcast
        self._deauth_thread: Optional[threading.Thread] = None
        self._deauth_stop = threading.Event()
        self._scan_cancel: Optional[threading.Event] = None
        self._presence_stop = threading.Event()
        self._presence_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.presence_tracker = PresenceTracker(self.db)

    def emit(self, event: str, payload: Dict[str, Any]) -> None:
        if self._broadcast:
            self._broadcast({"event": event, **payload})

    def ensure_root(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("Root required for Wi-Fi monitor/deauth operations (run with sudo).")

    def ensure_tools(self) -> None:
        missing = [t for t in config.REQUIRED_TOOLS if not shutil.which(t)]
        if missing:
            raise RuntimeError(f"Missing tools: {', '.join(missing)}")

    def setup_interface(self, iface: str) -> str:
        self.ensure_root()
        self.ensure_tools()
        self.physical_iface = iface
        self.monitor_iface = self.radio.set_monitor_mode(iface)
        if not self.monitor_iface:
            raise RuntimeError("Failed to enter monitor mode")
        self.scanner = Scanner(self.monitor_iface)
        self.deauth = DeauthRunner(self.monitor_iface)
        return self.monitor_iface

    async def scan_networks(self, band: str = config.DEFAULT_BAND, duration: int = config.NETWORK_SCAN_DURATION):
        if not self.scanner:
            raise RuntimeError("Interface not configured")
        self._scan_cancel = threading.Event()
        self.emit("scan:start", {"band": band, "duration": duration})

        task = asyncio.create_task(
            asyncio.to_thread(self.scanner.scan_networks, duration, band, self._scan_cancel)
        )
        elapsed = 0
        while not task.done():
            await asyncio.sleep(1)
            elapsed += 1
            if not task.done():
                self.emit("scan:progress", {
                    "elapsed": elapsed,
                    "total": duration,
                    "pct": min(100, elapsed * 100 // duration),
                })
        nets = await task

        self.networks = nets
        if not self.session_id:
            self.session_id = await self.db.start_session(self.monitor_iface or "", band)
        await self.db.ingest_scan(nets, [], self.session_id)
        self.emit("scan:done", {"count": len(nets), "networks": nets})

        # Rogue AP detection after each network scan
        rogues = detect_rogues(nets)
        if rogues:
            await self.db.save_rogue_alerts(rogues)
            self.emit("scan:rogues", {"rogues": rogues, "count": len(rogues)})

        return nets

    async def scan_clients_for(self, bssid: str) -> List[Dict[str, str]]:
        if not self.scanner:
            raise RuntimeError("Interface not configured")
        target = next((n for n in self.networks if n["bssid"] == bssid), None)
        if not target:
            raise ValueError(f"Unknown BSSID: {bssid}")
        clients = await asyncio.to_thread(self.scanner.scan_clients, target)
        self.clients_cache[bssid] = clients
        await self.db.ingest_scan([], clients, self.session_id)
        # Presence tracking
        await self.presence_tracker.process_scan_result(clients, emit=self.emit)
        self.emit("clients:done", {"bssid": bssid, "count": len(clients), "clients": clients})
        return clients

    def stop_deauth(self) -> None:
        self._deauth_stop.set()
        # Don't join — thread checks stop at 0.5s granularity and exits on its own (daemon=True)

    def start_deauth(self, targets: List[DeauthTarget], packets: int = 3, loop: bool = False) -> None:
        if not self.scanner or not self.deauth or not self.monitor_iface:
            raise RuntimeError("Interface not configured")
        self.stop_deauth()
        self._deauth_stop.clear()

        scheduler = MultiTargetScheduler(
            interface=self.monitor_iface,
            scanner=self.scanner,
            deauth=self.deauth,
            db=self.db,
            session_id=self.session_id,
            emit=self.emit,
            radio=self.radio,
        )

        def _run():
            try:
                if loop:
                    while not self._deauth_stop.is_set():
                        scheduler.run_round(targets, packets, self._deauth_stop)
                else:
                    scheduler.run_round(targets, packets, self._deauth_stop)
            finally:
                self.emit("deauth:stopped", {})

        self._deauth_thread = threading.Thread(target=_run, daemon=True)
        self._deauth_thread.start()

    def start_presence_watch(self, interval: int = 120, bssids: Optional[List[str]] = None) -> None:
        self.stop_presence_watch()
        self._presence_stop.clear()

        def _watch():
            import time
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            targets = (bssids or []) or [n["bssid"] for n in self.networks]
            self.emit("presence:watching", {"active": True, "interval": interval, "watched_count": len(targets)})
            while not self._presence_stop.is_set():
                if not self.scanner:
                    self._presence_stop.wait(timeout=interval)
                    continue
                for bssid in targets:
                    if self._presence_stop.is_set():
                        break
                    target = next((n for n in self.networks if n["bssid"] == bssid), None)
                    if not target:
                        continue
                    cancel = threading.Event()
                    clients = self.scanner.scan_clients(target, duration=8, cancel=cancel)
                    if self._presence_stop.is_set():
                        break
                    loop.run_until_complete(self.db.ingest_scan([], clients, self.session_id))
                    loop.run_until_complete(
                        self.presence_tracker.process_scan_result(clients, emit=self.emit)
                    )
                self._presence_stop.wait(timeout=interval)
            self.emit("presence:watching", {"active": False, "interval": interval, "watched_count": 0})
            loop.close()

        self._presence_thread = threading.Thread(target=_watch, daemon=True)
        self._presence_thread.start()

    def stop_presence_watch(self) -> None:
        self._presence_stop.set()

    def shutdown(self) -> None:
        self.stop_deauth()
        self.stop_presence_watch()
        if self.physical_iface:
            self.radio.restart_network_manager()
            if self.monitor_iface and self.monitor_iface.endswith("_mon"):
                self.radio.reset_interface(self.physical_iface)