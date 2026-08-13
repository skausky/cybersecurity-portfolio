"""Dual-sink logging: JSONL file + Rich console, gated by verbosity."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)


def get_console() -> Console:
    return _console


class JsonLineHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", buffering=1)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = {
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
            extra = getattr(record, "extra_fields", None)
            if isinstance(extra, dict):
                payload.update(extra)
            self._fh.write(json.dumps(payload, default=str) + "\n")
        except Exception:
            # Never silently swallow structured log records (prevents "hits that dont log")
            try:
                print(f"JsonLineHandler error for {record.name}: {record.getMessage()}", file=sys.stderr)
            except Exception:
                pass

    def close(self) -> None:
        try:
            self._fh.close()
        finally:
            super().close()


def setup_logging(log_file: Path, verbosity: int, json_only: bool) -> logging.Logger:
    # verbosity: 0=warn, 1=info, 2=debug, 3=trace(=debug + raw bytes)
    level_map = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG, 3: logging.DEBUG}
    level = level_map.get(min(verbosity, 3), logging.DEBUG)

    root = logging.getLogger("camscan")
    root.handlers.clear()
    root.setLevel(logging.DEBUG)
    root.propagate = False

    root.addHandler(JsonLineHandler(log_file))

    if not json_only:
        rich = RichHandler(console=_console, show_path=False, show_time=True,
                           markup=False, rich_tracebacks=True)
        rich.setLevel(level)
        root.addHandler(rich)
    else:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(level)
        root.addHandler(sh)

    return root


def log_event(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"extra_fields": fields})
