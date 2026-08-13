import csv
import io
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

from camjam import config
from camjam.intel.fingerprint import ap_record, client_record

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    iface TEXT,
    band TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS access_points (
    bssid TEXT PRIMARY KEY,
    ssid TEXT,
    channel TEXT,
    encryption TEXT,
    cipher TEXT,
    auth TEXT,
    vendor_oui TEXT,
    first_seen REAL,
    last_seen REAL,
    observation_count INTEGER DEFAULT 0,
    last_power TEXT,
    last_beacons TEXT
);
CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    vendor_oui TEXT,
    is_randomized INTEGER,
    first_seen REAL,
    last_seen REAL,
    traits_json TEXT
);
CREATE TABLE IF NOT EXISTS associations (
    client_mac TEXT,
    ap_bssid TEXT,
    last_power TEXT,
    last_probes TEXT,
    last_seen REAL,
    PRIMARY KEY (client_mac, ap_bssid)
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,
    ref_id TEXT,
    power TEXT,
    extra_json TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS deauth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    target_bssid TEXT,
    mode TEXT,
    clients_before INTEGER,
    clients_after INTEGER,
    success INTEGER,
    delta INTEGER,
    duration_ms INTEGER,
    ts REAL,
    detail_json TEXT
);
CREATE TABLE IF NOT EXISTS device_labels (
    mac TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    notes TEXT,
    color TEXT DEFAULT '#5b9dff',
    watch INTEGER DEFAULT 0,
    created_at REAL,
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS presence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    ap_bssid TEXT,
    status TEXT NOT NULL,
    power TEXT,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_presence_mac ON presence_events(mac);
CREATE TABLE IF NOT EXISTS presence_state (
    mac TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    last_seen_home REAL,
    ap_bssid TEXT,
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS probe_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_mac TEXT NOT NULL,
    ssid TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probe_ssid ON probe_history(ssid);
CREATE INDEX IF NOT EXISTS idx_probe_mac ON probe_history(client_mac);
CREATE TABLE IF NOT EXISTS rogue_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT,
    suspect_bssid TEXT,
    trusted_bssid TEXT,
    reasons TEXT,
    severity TEXT,
    ts REAL,
    dismissed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS selected_targets (
    bssid TEXT PRIMARY KEY,
    added_at REAL
);
"""


class Database:
    def __init__(self, path: Path | None = None):
        self.path = path or config.DB_PATH

    @asynccontextmanager
    async def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.path) as conn:
            await conn.executescript(SCHEMA)
            await conn.commit()
            yield conn

    # ── Sessions ────────────────────────────────────────────────────────────

    async def start_session(self, iface: str, band: str) -> int:
        async with self.connect() as conn:
            cur = await conn.execute(
                "INSERT INTO scan_sessions (started_at, iface, band) VALUES (?, ?, ?)",
                (time.time(), iface, band),
            )
            await conn.commit()
            return cur.lastrowid or 0

    async def list_sessions(self, limit: int = 50) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    """
                    SELECT s.id, s.started_at, s.iface, s.band,
                           COUNT(DISTINCT o.ref_id) AS ap_count
                    FROM scan_sessions s
                    LEFT JOIN observations o ON o.kind='ap'
                        AND json_extract(o.extra_json,'$.session_id')=s.id
                    GROUP BY s.id ORDER BY s.started_at DESC LIMIT ?
                    """,
                    (limit,),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scan ingestion ───────────────────────────────────────────────────────

    async def ingest_scan(self, networks: List[Dict[str, str]], clients: List[Dict[str, str]], session_id: int):
        now = time.time()
        async with self.connect() as conn:
            for net in networks:
                rec = ap_record(net)
                await conn.execute(
                    """
                    INSERT INTO access_points (bssid, ssid, channel, encryption, cipher, auth,
                        vendor_oui, first_seen, last_seen, observation_count, last_power, last_beacons)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid=excluded.ssid, channel=excluded.channel,
                        encryption=excluded.encryption, cipher=excluded.cipher, auth=excluded.auth,
                        last_seen=excluded.last_seen,
                        observation_count=observation_count+1,
                        last_power=excluded.last_power, last_beacons=excluded.last_beacons
                    """,
                    (
                        rec["bssid"], rec["ssid"], rec["channel"], rec["encryption"],
                        rec["cipher"], rec["auth"], rec["vendor_oui"],
                        now, now, rec["power"], rec["beacons"],
                    ),
                )
                await conn.execute(
                    "INSERT INTO observations (kind, ref_id, power, extra_json, ts) VALUES (?, ?, ?, ?, ?)",
                    ("ap", rec["bssid"], rec["power"], json.dumps({"session_id": session_id}), now),
                )
            for client in clients:
                rec = client_record(client)
                await conn.execute(
                    """
                    INSERT INTO clients (mac, vendor_oui, is_randomized, first_seen, last_seen, traits_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        last_seen=excluded.last_seen, traits_json=excluded.traits_json
                    """,
                    (
                        rec["mac"], rec["vendor_oui"], 1 if rec["is_randomized"] else 0,
                        now, now, rec["traits_json"],
                    ),
                )
                if rec["bssid"] and rec["bssid"] not in ("", "(not associated)"):
                    await conn.execute(
                        """
                        INSERT INTO associations (client_mac, ap_bssid, last_power, last_probes, last_seen)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(client_mac, ap_bssid) DO UPDATE SET
                            last_power=excluded.last_power, last_probes=excluded.last_probes,
                            last_seen=excluded.last_seen
                        """,
                        (rec["mac"], rec["bssid"], rec["power"], rec["probes"], now),
                    )
                # Record probe history
                if rec.get("probes"):
                    for ssid in (p.strip() for p in rec["probes"].split(",") if p.strip()):
                        await conn.execute(
                            "INSERT INTO probe_history (client_mac, ssid, ts) VALUES (?, ?, ?)",
                            (rec["mac"], ssid, now),
                        )
            await conn.commit()

    # ── Deauth ──────────────────────────────────────────────────────────────

    async def record_deauth(
        self,
        session_id: int,
        bssid: str,
        mode: str,
        before: int,
        after: int,
        detail: Optional[Dict[str, Any]] = None,
    ) -> int:
        success = 1 if after < before else 0
        delta = before - after
        now = time.time()
        async with self.connect() as conn:
            cur = await conn.execute(
                """
                INSERT INTO deauth_events
                (session_id, target_bssid, mode, clients_before, clients_after, success, delta, duration_ms, ts, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, bssid, mode, before, after, success, delta,
                    int(config.DEAUTH_VERIFY_SLEEP * 1000), now, json.dumps(detail or {}),
                ),
            )
            await conn.commit()
            return cur.lastrowid or 0

    # ── Stats ────────────────────────────────────────────────────────────────

    async def stats_summary(self) -> Dict[str, Any]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            total  = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events")).fetchone()
            ok     = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events WHERE success=1")).fetchone()
            hi     = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events WHERE json_extract(detail_json,'$.confidence')='high'")).fetchone()
            med    = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events WHERE json_extract(detail_json,'$.confidence')='medium'")).fetchone()
            lo     = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events WHERE json_extract(detail_json,'$.confidence')='low'")).fetchone()
            incon  = await (await conn.execute("SELECT COUNT(*) AS c FROM deauth_events WHERE json_extract(detail_json,'$.confidence')='inconclusive'")).fetchone()
            aps    = await (await conn.execute("SELECT COUNT(*) AS c FROM access_points")).fetchone()
            clients= await (await conn.execute("SELECT COUNT(*) AS c FROM clients")).fetchone()
            labeled= await (await conn.execute("SELECT COUNT(*) AS c FROM device_labels")).fetchone()
            watched= await (await conn.execute("SELECT COUNT(*) AS c FROM device_labels WHERE watch=1")).fetchone()
            avg_delta = await (await conn.execute("SELECT AVG(delta) AS a FROM deauth_events WHERE success=1")).fetchone()
            by_mode= await (await conn.execute(
                "SELECT mode, COUNT(*) AS cnt, SUM(success) AS wins FROM deauth_events GROUP BY mode"
            )).fetchall()
            top_targets = await (await conn.execute(
                "SELECT target_bssid, COUNT(*) AS cnt, SUM(success) AS wins FROM deauth_events GROUP BY target_bssid ORDER BY cnt DESC LIMIT 10"
            )).fetchall()
            recent = await (await conn.execute("SELECT * FROM deauth_events ORDER BY ts DESC LIMIT 30")).fetchall()
        t = total["c"] if total else 0
        s = ok["c"] if ok else 0
        return {
            "deauth_total": t,
            "deauth_success": s,
            "deauth_success_rate": round((s / t) if t else 0.0, 3),
            "confidence_high": hi["c"] if hi else 0,
            "confidence_medium": med["c"] if med else 0,
            "confidence_low": lo["c"] if lo else 0,
            "confidence_inconclusive": incon["c"] if incon else 0,
            "avg_clients_evicted": round(avg_delta["a"] or 0, 2),
            "access_points": aps["c"] if aps else 0,
            "clients": clients["c"] if clients else 0,
            "labeled_devices": labeled["c"] if labeled else 0,
            "watched_devices": watched["c"] if watched else 0,
            "by_mode": [dict(r) for r in by_mode],
            "top_targets": [dict(r) for r in top_targets],
            "recent_events": [dict(r) for r in recent],
        }

    async def list_aps(self, limit: int = 200) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute("SELECT * FROM access_points ORDER BY last_seen DESC LIMIT ?", (limit,))
            ).fetchall()
        return [dict(r) for r in rows]

    async def ap_power_history(self, bssid: str, hours: int = 24) -> List[Dict]:
        cutoff = time.time() - hours * 3600
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    "SELECT power, ts FROM observations WHERE kind='ap' AND ref_id=? AND ts>? ORDER BY ts",
                    (bssid, cutoff),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Device labels ─────────────────────────────────────────────────────────

    async def upsert_device_label(
        self,
        mac: str,
        label: str,
        notes: Optional[str] = None,
        color: str = "#5b9dff",
        watch: bool = False,
    ) -> None:
        now = time.time()
        async with self.connect() as conn:
            await conn.execute(
                """
                INSERT INTO device_labels (mac, label, notes, color, watch, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    label=excluded.label, notes=excluded.notes, color=excluded.color,
                    watch=excluded.watch, updated_at=excluded.updated_at
                """,
                (mac, label, notes, color, 1 if watch else 0, now, now),
            )
            await conn.commit()

    async def delete_device_label(self, mac: str) -> None:
        async with self.connect() as conn:
            await conn.execute("DELETE FROM device_labels WHERE mac=?", (mac,))
            await conn.commit()

    async def get_label_for_mac(self, mac: str) -> Optional[str]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            row = await (await conn.execute("SELECT label FROM device_labels WHERE mac=?", (mac,))).fetchone()
        return row["label"] if row else None

    async def list_devices_enriched(self, limit: int = 500) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    """
                    SELECT c.mac, c.vendor_oui, c.is_randomized, c.first_seen, c.last_seen,
                           c.traits_json,
                           dl.label, dl.notes, dl.color, dl.watch,
                           a.ap_bssid, a.last_power, a.last_probes, a.last_seen AS assoc_seen,
                           ap.ssid AS ap_ssid,
                           ps.status AS presence_status, ps.last_seen_home
                    FROM clients c
                    LEFT JOIN device_labels dl ON c.mac = dl.mac
                    LEFT JOIN associations a ON c.mac = a.client_mac
                        AND a.last_seen = (
                            SELECT MAX(last_seen) FROM associations WHERE client_mac = c.mac
                        )
                    LEFT JOIN access_points ap ON a.ap_bssid = ap.bssid
                    LEFT JOIN presence_state ps ON c.mac = ps.mac
                    ORDER BY c.last_seen DESC LIMIT ?
                    """,
                    (limit,),
                )
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get("traits_json"):
                try:
                    d["traits"] = json.loads(d["traits_json"])
                except (json.JSONDecodeError, TypeError):
                    d["traits"] = {}
            results.append(d)
        return results

    # ── Presence ─────────────────────────────────────────────────────────────

    async def get_watched_macs(self) -> List[str]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute("SELECT mac FROM device_labels WHERE watch=1")
            ).fetchall()
        return [r["mac"] for r in rows]

    async def get_presence_state(self, mac: str) -> Optional[str]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            row = await (
                await conn.execute("SELECT status FROM presence_state WHERE mac=?", (mac,))
            ).fetchone()
        return row["status"] if row else None

    async def get_last_home_ts(self, mac: str) -> Optional[float]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            row = await (
                await conn.execute("SELECT last_seen_home FROM presence_state WHERE mac=?", (mac,))
            ).fetchone()
        return row["last_seen_home"] if row else None

    async def update_presence(
        self,
        mac: str,
        status: str,
        ap_bssid: Optional[str],
        power: Optional[str],
    ) -> None:
        now = time.time()
        async with self.connect() as conn:
            last_home = now if status == "home" else None
            await conn.execute(
                """
                INSERT INTO presence_state (mac, status, last_seen_home, ap_bssid, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    status=excluded.status,
                    last_seen_home=CASE WHEN excluded.status='home' THEN excluded.last_seen_home
                                        ELSE last_seen_home END,
                    ap_bssid=excluded.ap_bssid,
                    updated_at=excluded.updated_at
                """,
                (mac, status, last_home, ap_bssid, now),
            )
            await conn.execute(
                "INSERT INTO presence_events (mac, ap_bssid, status, power, ts) VALUES (?, ?, ?, ?, ?)",
                (mac, ap_bssid, status, power, now),
            )
            await conn.commit()

    async def get_all_presence_states(self) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    """
                    SELECT ps.mac, ps.status, ps.last_seen_home, ps.ap_bssid, ps.updated_at,
                           dl.label, dl.color, ap.ssid AS ap_ssid
                    FROM presence_state ps
                    LEFT JOIN device_labels dl ON ps.mac = dl.mac
                    LEFT JOIN access_points ap ON ps.ap_bssid = ap.bssid
                    ORDER BY ps.updated_at DESC
                    """
                )
            ).fetchall()
        return [dict(r) for r in rows]

    async def get_presence_history(self, mac: str, limit: int = 100) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    "SELECT * FROM presence_events WHERE mac=? ORDER BY ts DESC LIMIT ?",
                    (mac, limit),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    async def get_presence_timeline(self, mac: str, hours: int = 24) -> List[Dict]:
        cutoff = time.time() - hours * 3600
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    "SELECT status, ts FROM presence_events WHERE mac=? AND ts>? ORDER BY ts",
                    (mac, cutoff),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Probes ───────────────────────────────────────────────────────────────

    async def probe_summary(self, limit: int = 30) -> Dict[str, Any]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            top_ssids = await (
                await conn.execute(
                    """
                    SELECT ssid, COUNT(*) AS count, COUNT(DISTINCT client_mac) AS unique_clients
                    FROM probe_history
                    GROUP BY ssid ORDER BY count DESC LIMIT ?
                    """,
                    (limit,),
                )
            ).fetchall()
            top_clients = await (
                await conn.execute(
                    """
                    SELECT client_mac, COUNT(DISTINCT ssid) AS unique_ssids
                    FROM probe_history
                    GROUP BY client_mac ORDER BY unique_ssids DESC LIMIT 20
                    """
                )
            ).fetchall()
        return {
            "top_ssids": [dict(r) for r in top_ssids],
            "top_clients": [dict(r) for r in top_clients],
        }

    async def clients_probing_ssid(self, ssid: str) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    """
                    SELECT ph.client_mac, MIN(ph.ts) AS first_seen, MAX(ph.ts) AS last_seen,
                           COUNT(*) AS count, dl.label
                    FROM probe_history ph
                    LEFT JOIN device_labels dl ON ph.client_mac = dl.mac
                    WHERE ph.ssid=?
                    GROUP BY ph.client_mac ORDER BY last_seen DESC
                    """,
                    (ssid,),
                )
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Rogue alerts ─────────────────────────────────────────────────────────

    async def save_rogue_alerts(self, rogues: List[Dict]) -> None:
        if not rogues:
            return
        now = time.time()
        async with self.connect() as conn:
            for r in rogues:
                existing = await (
                    await conn.execute(
                        "SELECT id FROM rogue_alerts WHERE suspect_bssid=? AND dismissed=0",
                        (r["suspect_bssid"],),
                    )
                ).fetchone()
                if not existing:
                    await conn.execute(
                        """INSERT INTO rogue_alerts (ssid, suspect_bssid, trusted_bssid, reasons, severity, ts)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (r["ssid"], r["suspect_bssid"], r["trusted_bssid"],
                         json.dumps(r["reasons"]), r["severity"], now),
                    )
            await conn.commit()

    async def list_rogue_alerts(self) -> List[Dict]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute(
                    "SELECT * FROM rogue_alerts WHERE dismissed=0 ORDER BY ts DESC"
                )
            ).fetchall()
        return [dict(r) for r in rows]

    async def dismiss_rogue_alert(self, alert_id: int) -> None:
        async with self.connect() as conn:
            await conn.execute("UPDATE rogue_alerts SET dismissed=1 WHERE id=?", (alert_id,))
            await conn.commit()

    # ── Export ───────────────────────────────────────────────────────────────

    async def export_csv(self, what: str) -> str:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            if what == "clients":
                rows = await (await conn.execute(
                    "SELECT * FROM clients ORDER BY last_seen DESC"
                )).fetchall()
            elif what == "events":
                rows = await (await conn.execute(
                    "SELECT * FROM deauth_events ORDER BY ts DESC"
                )).fetchall()
            else:
                rows = await (await conn.execute(
                    "SELECT * FROM access_points ORDER BY last_seen DESC"
                )).fetchall()
        if not rows:
            return ""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows([dict(r) for r in rows])
        return buf.getvalue()

    # ── Selected targets ─────────────────────────────────────────────────────

    async def set_selected_targets(self, bssids: List[str]) -> None:
        now = time.time()
        async with self.connect() as conn:
            await conn.execute("DELETE FROM selected_targets")
            for bssid in bssids:
                await conn.execute(
                    "INSERT INTO selected_targets (bssid, added_at) VALUES (?, ?)",
                    (bssid, now),
                )
            await conn.commit()

    async def get_selected_targets(self) -> List[str]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (
                await conn.execute("SELECT bssid FROM selected_targets ORDER BY added_at")
            ).fetchall()
        return [r["bssid"] for r in rows]

    async def export_json(self) -> Dict[str, Any]:
        async with self.connect() as conn:
            conn.row_factory = aiosqlite.Row
            aps = await (await conn.execute("SELECT * FROM access_points ORDER BY last_seen DESC")).fetchall()
            clients = await (await conn.execute("SELECT * FROM clients ORDER BY last_seen DESC")).fetchall()
            labels = await (await conn.execute("SELECT * FROM device_labels")).fetchall()
            events = await (await conn.execute("SELECT * FROM deauth_events ORDER BY ts DESC LIMIT 500")).fetchall()
            sessions = await (await conn.execute("SELECT * FROM scan_sessions ORDER BY started_at DESC")).fetchall()
        return {
            "exported_at": time.time(),
            "access_points": [dict(r) for r in aps],
            "clients": [dict(r) for r in clients],
            "device_labels": [dict(r) for r in labels],
            "deauth_events": [dict(r) for r in events],
            "scan_sessions": [dict(r) for r in sessions],
        }
