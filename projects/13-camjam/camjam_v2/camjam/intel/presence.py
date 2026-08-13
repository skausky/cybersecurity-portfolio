import time
from typing import Callable, Dict, List, Optional

HOME_TIMEOUT = 300  # seconds without being seen = away


class PresenceTracker:
    def __init__(self, db):
        self.db = db

    async def process_scan_result(
        self,
        clients: List[Dict],
        emit: Optional[Callable] = None,
    ) -> List[Dict]:
        """Compare visible clients against watched MACs. Returns state-change list."""
        watched = await self.db.get_watched_macs()
        if not watched:
            return []

        now = time.time()
        visible = {c.get("station_mac", "").lower() for c in clients if c.get("station_mac")}

        changes = []
        for mac in watched:
            mac_lower = mac.lower()
            was_status = await self.db.get_presence_state(mac)

            if mac_lower in visible:
                assoc = next(
                    (c for c in clients if c.get("station_mac", "").lower() == mac_lower), {}
                )
                await self.db.update_presence(
                    mac, "home", assoc.get("bssid") or None, assoc.get("power")
                )
                if was_status != "home":
                    change = {"mac": mac, "status": "home", "prev": was_status}
                    changes.append(change)
                    if emit:
                        label = await self.db.get_label_for_mac(mac)
                        emit("presence:change", {
                            "mac": mac,
                            "label": label or mac,
                            "status": "home",
                            "prev": was_status,
                            "ap_bssid": assoc.get("bssid"),
                        })
            else:
                last_home = await self.db.get_last_home_ts(mac)
                timed_out = last_home is None or (now - last_home) > HOME_TIMEOUT
                if timed_out and was_status != "away":
                    await self.db.update_presence(mac, "away", None, None)
                    change = {"mac": mac, "status": "away", "prev": was_status}
                    changes.append(change)
                    if emit:
                        label = await self.db.get_label_for_mac(mac)
                        emit("presence:change", {
                            "mac": mac,
                            "label": label or mac,
                            "status": "away",
                            "prev": was_status,
                            "ap_bssid": None,
                        })

        return changes
