"""Async-safe JSONL + CSV result writer."""
from __future__ import annotations

import asyncio
import csv
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Result:
    ts: float = field(default_factory=time.time)
    run_id: str = ""
    ip: str = ""
    port: int = 0
    endpoint: str = ""
    username: str = ""
    password: str = ""
    rtsp_status: int | None = None
    auth_scheme: str = ""
    sdp_present: bool = False
    sdp_tracks: int = 0
    codecs: list[str] = field(default_factory=list)
    verified: bool = False
    warnings: list[str] = field(default_factory=list)
    unauth: bool = False
    weak_auth: bool = False
    vulns: list[str] = field(default_factory=list)
    severity: str = ""
    fingerprint: str = ""
    extracted_creds: list[str] = field(default_factory=list)
    cve_notes: list[str] = field(default_factory=list)
    error: str = ""
    elapsed_ms: int = 0
    rtsp_url: str = ""
    snapshot_path: str = ""


_CSV_FIELDS = list(Result.__dataclass_fields__.keys())


class ResultWriter:
    def __init__(self, out_dir: Path, run_id: str):
        out_dir.mkdir(parents=True, exist_ok=True)
        self._jsonl = (out_dir / f"{run_id}.jsonl").open("a", buffering=1)
        self._csv_path = out_dir / f"{run_id}.csv"
        new = not self._csv_path.exists() or self._csv_path.stat().st_size == 0
        self._csv_fh = self._csv_path.open("a", newline="", buffering=1)
        self._csv = csv.DictWriter(self._csv_fh, fieldnames=_CSV_FIELDS)
        if new:
            self._csv.writeheader()
        self._lock = asyncio.Lock()
        self.success_count = 0
        self.total = 0

    async def write(self, r: Result) -> None:
        async with self._lock:
            self.total += 1
            if r.verified:
                self.success_count += 1
            d = asdict(r)
            self._jsonl.write(json.dumps(d, default=str) + "\n")
            row = {k: (",".join(v) if isinstance(v, list) else v) for k, v in d.items()}
            self._csv.writerow(row)

    def close(self) -> None:
        try:
            self._jsonl.close()
        finally:
            self._csv_fh.close()
