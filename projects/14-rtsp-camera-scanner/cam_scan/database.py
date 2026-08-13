"""SQLite persistence for cam-scan hits, captions, and config."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger("camscan.db")

_DB_VERSION = 1


def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


class Database:
    """Thread-safe SQLite wrapper (asyncio-safe via threading.Lock)."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._con = sqlite3.connect(str(path), check_same_thread=False)
        self._con.row_factory = _dict_factory
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._con.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER);

            CREATE TABLE IF NOT EXISTS hits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          REAL    NOT NULL,
                run_id      TEXT    DEFAULT '',
                ip          TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                endpoint    TEXT    DEFAULT '',
                username    TEXT    DEFAULT '',
                password    TEXT    DEFAULT '',
                auth_scheme TEXT    DEFAULT '',
                rtsp_url    TEXT    DEFAULT '',
                sdp_tracks  INTEGER DEFAULT 0,
                codecs      TEXT    DEFAULT '[]',
                verified    INTEGER DEFAULT 1,
                unauth      INTEGER DEFAULT 0,
                weak_auth   INTEGER DEFAULT 0,
                vulns       TEXT    DEFAULT '[]',
                severity    TEXT    DEFAULT '',
                fingerprint TEXT    DEFAULT '',
                extracted_creds TEXT DEFAULT '[]',
                cve_notes   TEXT    DEFAULT '[]',
                snapshot_path      TEXT DEFAULT '',
                http_snapshot_path TEXT DEFAULT '',
                http_snapshot_url  TEXT DEFAULT '',
                caption     TEXT    DEFAULT NULL,
                created_at  TEXT    DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_hits_ts   ON hits(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_hits_ip   ON hits(ip);
            CREATE INDEX IF NOT EXISTS idx_hits_sev  ON hits(severity);
            CREATE INDEX IF NOT EXISTS idx_hits_fp   ON hits(fingerprint);

            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recordings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                port        INTEGER NOT NULL,
                rtsp_url    TEXT DEFAULT '',
                path        TEXT DEFAULT '',
                trigger     TEXT DEFAULT 'manual',
                people_count INTEGER DEFAULT 0,
                started_at  TEXT DEFAULT (datetime('now')),
                stopped_at  TEXT DEFAULT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rec_ip ON recordings(ip);
            """)
            # Safe additive migrations for existing DBs
            existing = {
                row["name"]
                for row in self._con.execute("PRAGMA table_info(hits)").fetchall()
            }
            for col, defn in (
                ("favorited",    "INTEGER DEFAULT 0"),
                ("watched",      "INTEGER DEFAULT 0"),
                ("nmap_service", "TEXT DEFAULT ''"),
                ("nmap_device",  "TEXT DEFAULT ''"),
                ("nmap_cpe",     "TEXT DEFAULT ''"),
            ):
                if col not in existing:
                    self._con.execute(
                        f"ALTER TABLE hits ADD COLUMN {col} {defn}")
            self._con.commit()

    # ── Hits ──────────────────────────────────────────────────────────────────

    def insert_hit(self, h: dict) -> int:
        """Insert a hit dict, return the new row id."""
        cols = [
            "ts", "run_id", "ip", "port", "endpoint",
            "username", "password", "auth_scheme", "rtsp_url",
            "sdp_tracks", "codecs", "verified", "unauth", "weak_auth",
            "vulns", "severity", "fingerprint", "extracted_creds", "cve_notes",
            "snapshot_path", "http_snapshot_path", "http_snapshot_url", "caption",
            "nmap_service", "nmap_device", "nmap_cpe",
        ]
        row = {
            "ts":                 h.get("ts", 0),
            "run_id":             h.get("run_id", ""),
            "ip":                 h.get("ip", ""),
            "port":               int(h.get("port", 0)),
            "endpoint":           h.get("endpoint", ""),
            "username":           h.get("username", ""),
            "password":           h.get("password", ""),
            "auth_scheme":        h.get("auth_scheme", ""),
            "rtsp_url":           h.get("rtsp_url", ""),
            "sdp_tracks":         int(h.get("sdp_tracks", 0)),
            "codecs":             json.dumps(h.get("codecs") or []),
            "verified":           1,
            "unauth":             1 if h.get("unauth") else 0,
            "weak_auth":          1 if h.get("weak_auth") else 0,
            "vulns":              json.dumps(h.get("vulns") or []),
            "severity":           h.get("severity", ""),
            "fingerprint":        h.get("fingerprint", ""),
            "extracted_creds":    json.dumps(h.get("extracted_creds") or []),
            "cve_notes":          json.dumps(h.get("cve_notes") or []),
            "snapshot_path":      h.get("snapshot", h.get("snapshot_path", "")) or "",
            "http_snapshot_path": h.get("http_snapshot_path", "") or "",
            "http_snapshot_url":  h.get("http_snapshot_url", "") or "",
            "caption":            json.dumps(h["caption"]) if h.get("caption") else None,
            "nmap_service":       h.get("nmap_service", "") or "",
            "nmap_device":        h.get("nmap_device", "") or "",
            "nmap_cpe":           h.get("nmap_cpe", "") or "",
        }
        placeholders = ", ".join(f":{c}" for c in cols)
        sql = f"INSERT INTO hits ({', '.join(cols)}) VALUES ({placeholders})"
        with self._lock:
            cur = self._con.execute(sql, row)
            self._con.commit()
            return cur.lastrowid

    def _update_latest_by_ip_port(self, ip: str, port: int, sets: dict) -> None:
        """Update only the most recent row for (ip, port) to avoid stomping history
        and without relying on non-standard UPDATE...ORDER BY LIMIT (not enabled in
        all SQLite builds)."""
        with self._lock:
            row = self._con.execute(
                "SELECT id FROM hits WHERE ip=? AND port=? ORDER BY id DESC LIMIT 1",
                (ip, port)).fetchone()
            if row:
                cols = list(sets.keys())
                vals = [sets[c] for c in cols] + [row["id"]]
                sql = f"UPDATE hits SET {', '.join(f'{c}=?' for c in cols)} WHERE id=?"
                self._con.execute(sql, vals)
                self._con.commit()

    def update_hit_rtsp_url(self, ip: str, port: int, url: str) -> None:
        self._update_latest_by_ip_port(ip, port, {"rtsp_url": url})

    def update_hit_snapshot(self, ip: str, port: int, path: str) -> None:
        self._update_latest_by_ip_port(ip, port, {"snapshot_path": path})

    def update_hit_caption(self, ip: str, port: int, caption: dict) -> None:
        self._update_latest_by_ip_port(ip, port, {"caption": json.dumps(caption)})

    def update_hit_vulns(self, ip: str, port: int, vulns: list,
                          severity: str, fingerprint: str) -> None:
        self._update_latest_by_ip_port(ip, port, {
            "vulns": json.dumps(vulns),
            "severity": severity,
            "fingerprint": fingerprint,
        })

    def update_hit_extracted_creds(self, ip: str, port: int, creds: list) -> None:
        self._update_latest_by_ip_port(ip, port, {
            "extracted_creds": json.dumps(creds or []),
        })

    def update_hit_nmap(self, ip: str, port: int,
                        nmap_service: str, nmap_device: str, nmap_cpe: str) -> None:
        self._update_latest_by_ip_port(ip, port, {
            "nmap_service": nmap_service,
            "nmap_device":  nmap_device,
            "nmap_cpe":     nmap_cpe,
        })

    def update_favorite(self, ip: str, port: int, val: int) -> None:
        self._update_latest_by_ip_port(ip, port, {"favorited": val})

    def update_watched(self, ip: str, port: int, val: int) -> None:
        self._update_latest_by_ip_port(ip, port, {"watched": val})

    def get_hits(self, limit: int = 200, offset: int = 0,
                 severity: str = "", fingerprint: str = "",
                 search: str = "", sort: str = "ts_desc",
                 favorited: int | None = None) -> list[dict]:
        where, params = ["verified=1"], []
        if severity:
            where.append("severity=?"); params.append(severity)
        if fingerprint:
            where.append("fingerprint=?"); params.append(fingerprint)
        if search:
            where.append("(ip LIKE ? OR rtsp_url LIKE ? OR fingerprint LIKE ?)")
            params += [f"%{search}%"] * 3
        if favorited is not None:
            where.append("favorited=?"); params.append(favorited)
        order = {
            "ts_desc":  "ts DESC",
            "ts_asc":   "ts ASC",
            "severity": "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END",
            "ip":       "ip ASC",
        }.get(sort, "ts DESC")
        sql = (f"SELECT * FROM hits WHERE {' AND '.join(where)} "
               f"ORDER BY {order} LIMIT ? OFFSET ?")
        params += [limit, offset]
        with self._lock:
            rows = self._con.execute(sql, params).fetchall()
        return [_deserialise_hit(r) for r in rows]

    def count_hits(self, severity: str = "", fingerprint: str = "",
                   search: str = "", favorited: int | None = None) -> int:
        where, params = ["verified=1"], []
        if severity:
            where.append("severity=?"); params.append(severity)
        if fingerprint:
            where.append("fingerprint=?"); params.append(fingerprint)
        if search:
            where.append("(ip LIKE ? OR rtsp_url LIKE ? OR fingerprint LIKE ?)")
            params += [f"%{search}%"] * 3
        if favorited is not None:
            where.append("favorited=?"); params.append(favorited)
        sql = f"SELECT COUNT(*) AS n FROM hits WHERE {' AND '.join(where)}"
        with self._lock:
            return self._con.execute(sql, params).fetchone()["n"]

    # ── Recordings ────────────────────────────────────────────────────────────

    def insert_recording(self, ip: str, port: int, rtsp_url: str,
                         path: str, trigger: str = "manual",
                         people_count: int = 0) -> int:
        with self._lock:
            cur = self._con.execute(
                "INSERT INTO recordings(ip,port,rtsp_url,path,trigger,people_count) "
                "VALUES(?,?,?,?,?,?)",
                (ip, port, rtsp_url, path, trigger, people_count))
            self._con.commit()
            return cur.lastrowid

    def stop_recording(self, rec_id: int) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE recordings SET stopped_at=datetime('now') WHERE id=?",
                (rec_id,))
            self._con.commit()

    def get_recordings(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return self._con.execute(
                "SELECT * FROM recordings ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()

    def get_all_hits(self) -> list[dict]:
        """Load all hits for in-memory state on startup."""
        with self._lock:
            rows = self._con.execute(
                "SELECT * FROM hits WHERE verified=1 ORDER BY ts DESC").fetchall()
        return [_deserialise_hit(r) for r in rows]

    # ── Config ────────────────────────────────────────────────────────────────

    def get_config(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._con.execute(
                "SELECT value FROM config WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]

    def set_config(self, key: str, value: Any) -> None:
        with self._lock:
            self._con.execute(
                "INSERT INTO config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))
            self._con.commit()

    def get_all_config(self) -> dict:
        with self._lock:
            rows = self._con.execute("SELECT key, value FROM config").fetchall()
        out = {}
        for r in rows:
            try:
                out[r["key"]] = json.loads(r["value"])
            except Exception:
                out[r["key"]] = r["value"]
        return out

    def close(self) -> None:
        with self._lock:
            self._con.close()


def _deserialise_hit(row: dict) -> dict:
    """Convert DB row back to the hit dict format the UI expects."""
    for field in ("codecs", "vulns", "extracted_creds", "cve_notes"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                row[field] = []
    if isinstance(row.get("caption"), str) and row["caption"]:
        try:
            row["caption"] = json.loads(row["caption"])
        except Exception:
            row["caption"] = None
    # Normalise snapshot key the UI uses
    row.setdefault("snapshot", row.get("snapshot_path", ""))
    row.setdefault("nmap_service", "")
    row.setdefault("nmap_device", "")
    row.setdefault("nmap_cpe", "")
    row["unauth"] = bool(row.get("unauth"))
    row["weak_auth"] = bool(row.get("weak_auth"))
    return row
