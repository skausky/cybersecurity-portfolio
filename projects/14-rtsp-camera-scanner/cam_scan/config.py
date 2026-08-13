from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunConfig:
    count: int = 10000
    unlimited: bool = True
    mode: str = "ips"
    rate: int = 5000
    concurrency: int = 200
    per_host_concurrency: int = 4
    timeout: float = 6.0
    rtsp_ports: tuple[int, ...] = (554, 8554)
    max_attempts_per_host: int = 60
    creds_file: Path | None = None
    paths_file: Path | None = None
    out_dir: Path = Path("output")
    log_dir: Path = Path("logs")
    json_only: bool = False
    verbosity: int = 1
    authorized: bool = False
    snapshots: bool = True
    seed: int | None = None
    run_id: str = ""
    extra_targets: list[str] = field(default_factory=list)
    us_only: bool = False
    nmap_brute: bool = False
    nmap_sv: bool = False
