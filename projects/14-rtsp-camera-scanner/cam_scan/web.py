"""FastAPI web UI for cam-scan — localhost dashboard."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import shlex
import shutil
import sys
import time
import traceback
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any

from .config import RunConfig
from .events import EventBus

# Web UI dependencies (fastapi + uvicorn) are OPTIONAL.
# Importing cam_scan.web succeeds even without fastapi/uvicorn installed so
# that headless runs never fail at import time. serve() raises a clear error
# if deps are missing.
_HAS_WEB_DEPS = False
try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
    from pydantic import BaseModel
    from starlette.middleware.base import BaseHTTPMiddleware
    _HAS_WEB_DEPS = True
except ImportError:
    _HAS_WEB_DEPS = False
    uvicorn = None
    FastAPI = object
    HTTPException = Exception
    Request = object
    FileResponse = lambda *a, **k: None
    HTMLResponse = lambda *a, **k: None
    JSONResponse = lambda *a, **k: None
    StreamingResponse = lambda *a, **k: None
    BaseModel = object
    BaseHTTPMiddleware = object

    class _DummyApp:
        def get(self, *a, **k):
            def _deco(f): return f
            return _deco
        def post(self, *a, **k):
            def _deco(f): return f
            return _deco
        def add_middleware(self, *a, **k):
            pass

    class _DummyFastAPI:
        def __call__(self, *a, **k):
            return _DummyApp()
    FastAPI = _DummyFastAPI()

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("camscan.web")

# ── US Mullvad city codes (from `mullvad relay list`) ───────────────────────
async def _mullvad_get_relays() -> list[tuple[str, str]]:
    """Return list of (country_code, city_code) for all active WireGuard relays.
    Falls back to a hardcoded global list if the CLI is unavailable.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "mullvad", "relay", "list",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        relays: list[tuple[str, str]] = []
        import re as _re
        for line in out.decode(errors="replace").splitlines():
            # Lines like: "		us-qas-wg-204 (1.2.3.4, ...) - hosted by ..."
            m = _re.match(r"\s+([a-z]{2,3})-([a-z]+)-wg-\d+\s", line)
            if m:
                relays.append((m.group(1), m.group(2)))
        if relays:
            return relays
    except Exception:
        pass
    # Hardcoded fallback — major cities across all continents
    return [
        ("us","nyc"),("us","lax"),("us","chi"),("us","dal"),("us","sea"),
        ("us","atl"),("us","mia"),("us","sjc"),("gb","lon"),("gb","mnc"),
        ("de","fra"),("de","ber"),("nl","ams"),("fr","par"),("se","sto"),
        ("ch","zrh"),("no","osl"),("dk","cph"),("fi","hel"),("at","vie"),
        ("be","bru"),("es","mad"),("it","mil"),("pl","waw"),("ro","buc"),
        ("cz","prg"),("jp","tyo"),("sg","sin"),("au","syd"),("au","mel"),
        ("hk","hkg"),("ca","tor"),("ca","van"),("br","sao"),("ae","dxb"),
        ("il","tlv"),("za","jnb"),("mx","mex"),("ar","bue"),
    ]

# ── Global scan state ────────────────────────────────────────────────────────
class _State:
    pipeline: Any = None
    scan_task: asyncio.Task | None = None
    mullvad_task: asyncio.Task | None = None
    bus: EventBus = EventBus()
    hits: list[dict] = []
    scanning: bool = False
    out_dir: Path = Path("output")
    log_dir: Path = Path("logs")
    caption_enabled: bool = True
    caption_model: str = "huihui_ai/gemma-4-abliterated:e4b"
    db: Any = None
    # Recording manager — key = "ip:port", value = (proc, rec_id, out_path)
    recordings: dict[str, tuple] = {}
    auto_record_humans: bool = False
    auto_record_duration: int = 60  # seconds

_state = _State()

# ── Ollama image captioning ───────────────────────────────────────────────────
_CAPTION_PROMPT = (
    "Analyze this IP security camera image and respond ONLY with valid JSON, no markdown, no explanation. "
    "Use this exact schema:\n"
    '{"desc":"one sentence description of what is visible",'
    '"location":"indoor|outdoor|unknown",'
    '"scene":"e.g. parking lot, hallway, street, warehouse, office, home, shop",'
    '"people":0,'
    '"time":"day|night|unknown",'
    '"nsfw":0,'
    '"notes":"any notable detail: vehicles, animals, activity, signage (empty string if none)"}\n'
    "nsfw is an integer 0-10 (0=clean, 10=explicit). people is the visible person count. "
    "Be accurate and concise. Return only the JSON object."
)

async def _caption_snapshot(image_path: str) -> dict | None:
    """Call Ollama vision API. Returns structured dict or None."""
    if not _state.caption_enabled:
        return None
    try:
        img_bytes = Path(image_path).read_bytes()
        if not img_bytes:
            return None
        img_b64 = base64.b64encode(img_bytes).decode()
        payload = json.dumps({
            "model": _state.caption_model,
            "prompt": _CAPTION_PROMPT,
            "images": [img_b64],
            "stream": False,
            "format": "json",
        }).encode()

        def _call() -> dict:
            req = urllib.request.Request(
                "http://localhost:11434/api/generate",
                data=payload, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as r:
                raw = json.load(r)["response"].strip()
            # Strip markdown code fences if model added them
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)

        result = await asyncio.get_running_loop().run_in_executor(None, _call)
        # Normalise fields
        result.setdefault("desc", "")
        result.setdefault("location", "unknown")
        result.setdefault("scene", "")
        result.setdefault("people", 0)
        result.setdefault("time", "unknown")
        result.setdefault("nsfw", 0)
        result.setdefault("notes", "")
        result["nsfw"] = int(result["nsfw"])
        result["people"] = int(result["people"])
        log.info("caption %s: %s", image_path, result.get("desc", "")[:80])
        return result
    except Exception as e:
        log.debug("caption failed %s: %s", image_path, e)
        return None

# ── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(title="cam-scan", docs_url=None, redoc_url=None)

class _ErrorLogger(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception:
            log.error("Unhandled error on %s %s:\n%s",
                      request.method, request.url.path, traceback.format_exc())
            raise

app.add_middleware(_ErrorLogger)

@app.get("/snapshots/{path:path}")
async def serve_snapshot(path: str):
    base = _state.out_dir.resolve()
    try:
        full = (base / path).resolve()
    except (OSError, RuntimeError):
        raise HTTPException(400, "bad path")
    # Reject traversal outside the output directory
    if base not in full.parents and full != base:
        raise HTTPException(403, "forbidden")
    if not full.is_file():
        raise HTTPException(404)
    return FileResponse(str(full))

# ── SSE ──────────────────────────────────────────────────────────────────────
@app.get("/api/events")
async def sse_endpoint():
    q = _state.bus.subscribe()
    async def _stream():
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=20.0)
                    raw = json.loads(payload)
                    yield f"event: {raw['type']}\ndata: {json.dumps(raw['data'])}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _state.bus.unsubscribe(q)
    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── API endpoints ─────────────────────────────────────────────────────────────
class StartRequest(BaseModel):
    speed: str = "medium"
    unlimited: bool = True
    count: int = 10000
    snapshots: bool = True
    mullvad: bool = False
    mullvad_interval: int = 30
    us_only: bool = False
    nmap: bool = False

@app.post("/api/scan/start")
async def start_scan(req: StartRequest):
    if _state.scanning:
        raise HTTPException(400, "scan already running")

    speed_presets = {
        # rate = masscan pps (SYN packets). Each SYN ≈ 60 bytes.
        # 3000 pps ≈ 1.4 Mbps  — safe on any home connection
        # 5000 pps ≈ 2.4 Mbps  — safe on 50+ Mbps connections
        # 10000 pps ≈ 4.8 Mbps — may stress cheap routers, fine on fast lines
        # 20000 pps ≈ 9.6 Mbps — dedicated server / VPS only
        "safe":   dict(rate=3000,  concurrency=75,   per_host_concurrency=2, timeout=6.0),
        "medium": dict(rate=5000,  concurrency=200,  per_host_concurrency=4, timeout=5.0),
        "fast":   dict(rate=10000, concurrency=500,  per_host_concurrency=4, timeout=4.0),
        "vps":    dict(rate=20000, concurrency=1000, per_host_concurrency=8, timeout=3.0),
    }
    preset = speed_presets.get(req.speed, speed_presets["medium"])

    from .config import RunConfig
    import uuid
    cfg = RunConfig(
        count=0 if req.unlimited else max(1, req.count),
        unlimited=req.unlimited,
        rate=preset["rate"],
        concurrency=preset["concurrency"],
        per_host_concurrency=preset["per_host_concurrency"],
        timeout=preset["timeout"],
        rtsp_ports=(554, 8554),
        snapshots=req.snapshots,
        us_only=req.us_only,
        nmap_brute=req.nmap,
        nmap_sv=req.nmap,
        out_dir=_state.out_dir,
        log_dir=_state.log_dir,
        run_id=uuid.uuid4().hex[:12],
        verbosity=1,
    )

    # Reset per-run UI state so old hits don't bleed into a new scan
    _state.hits.clear()
    _state.bus.emit("clear_hits", {})

    from .pipeline import Pipeline
    _state.pipeline = Pipeline(cfg, bus=_state.bus)
    _state.scan_task = asyncio.create_task(_run_pipeline())
    _state.scanning = True
    _state.bus.emit("scan_started", {"run_id": cfg.run_id})

    if req.mullvad and shutil.which("mullvad"):
        _state.mullvad_task = asyncio.create_task(
            _mullvad_rotator(min_secs=20, max_secs=40))

    return {"run_id": cfg.run_id}

async def _hit_consumer(q: asyncio.Queue) -> None:
    """Internal bus subscriber: persists hits and triggers captions on snapshots.
    Also ensures post-enrich data (vulns from HTTP probes, snapshots from pipeline)
    reaches SQLite so history + reloads see the full intel (fixes loss of CVE data
    and snapshot paths that only lived in RAM or per-IP folders before).
    """
    try:
        while True:
            payload = await q.get()
            try:
                raw = json.loads(payload)
                etype = raw.get("type")
                if etype == "hit":
                    register_hit(raw["data"])
                elif etype == "snapshot_saved":
                    d = raw["data"]
                    path = d.get("path", "")
                    ip = d.get("ip", "")
                    port = d.get("port", 0)
                    if path:
                        # Ensure DB (and mem) get the snapshot for pipeline-triggered snaps
                        try:
                            _patch_hit_snapshot(ip, port, path)
                        except Exception:
                            pass
                    if path and _state.caption_enabled:
                        asyncio.create_task(_caption_and_emit(path, ip, port))
                elif etype == "vuln_update":
                    d = raw["data"]
                    ip = d.get("ip", "")
                    port = d.get("port", 0)
                    try:
                        _patch_hit_vulns(
                            ip, port,
                            d.get("vulns", []),
                            d.get("severity", ""),
                            d.get("fingerprint", ""),
                            extracted_creds=d.get("extracted_creds"),
                        )
                    except Exception:
                        pass
                elif etype == "nmap_update":
                    d = raw["data"]
                    try:
                        _patch_hit_nmap(
                            d.get("ip", ""), d.get("port", 0),
                            d.get("nmap_service", ""),
                            d.get("nmap_device", ""),
                            d.get("nmap_cpe", ""),
                        )
                    except Exception:
                        pass
            except Exception as e:
                log.debug("hit_consumer error: %s", e)
    except asyncio.CancelledError:
        pass
    finally:
        _state.bus.unsubscribe(q)


async def _caption_and_emit(path: str, ip: str, port: int) -> None:
    caption = await _caption_snapshot(path)
    if caption:
        _patch_hit_caption(ip, port, caption)
        _state.bus.emit("caption_update", {"ip": ip, "port": port, "caption": caption})
        if caption.get("people", 0) > 0:
            for h in _state.hits:
                if h.get("ip") == ip and h.get("port") == port:
                    if (_state.auto_record_humans or bool(h.get("watched"))) and h.get("rtsp_url"):
                        asyncio.create_task(_start_recording(
                            ip, port, h["rtsp_url"],
                            trigger="human_detected",
                            people_count=int(caption["people"])))
                    break


async def _run_pipeline() -> None:
    # Subscribe before starting so no hit event is missed.
    hit_q = _state.bus.subscribe()
    consumer = asyncio.create_task(_hit_consumer(hit_q))
    try:
        await _state.pipeline.run()
    except Exception as e:
        msg = f"pipeline crashed: {type(e).__name__}: {e}"
        log.error(msg, exc_info=True)
        _state.bus.emit("log", {"level": "ERROR", "msg": msg})
        _state.bus.emit("error", {"msg": msg})
    finally:
        # Drain: wait a moment for any final events already in the queue
        await asyncio.sleep(0.1)
        consumer.cancel()
        try:
            await consumer
        except asyncio.CancelledError:
            pass
        _state.scanning = False
        _state.bus.emit("scan_stopped", {})
        if _state.mullvad_task:
            _state.mullvad_task.cancel()
            _state.mullvad_task = None

@app.post("/api/scan/stop")
async def stop_scan():
    if _state.pipeline:
        _state.pipeline.request_stop()
    return {"ok": True}

@app.get("/api/status")
async def status():
    p = _state.pipeline
    return {
        "scanning": _state.scanning,
        "hits": len(_state.hits),
        "stats": p._public_stats() if p and hasattr(p, "_public_stats") else {},
    }

@app.get("/api/hits")
async def get_hits():
    return JSONResponse(_state.hits)


@app.get("/api/history")
async def get_history(
    limit: int = 100,
    offset: int = 0,
    severity: str = "",
    fingerprint: str = "",
    search: str = "",
    sort: str = "ts_desc",
):
    if _state.db is None:
        return JSONResponse({"rows": [], "total": 0})
    rows = _state.db.get_hits(limit, offset, severity, fingerprint, search, sort)
    total = _state.db.count_hits(severity, fingerprint, search)
    return JSONResponse({"rows": rows, "total": total})


@app.get("/api/config")
async def get_config():
    defaults = {
        "caption_enabled": _state.caption_enabled,
        "caption_model": _state.caption_model,
        "speed": "medium",
        "us_only": False,
        "snapshots": True,
        "mullvad": False,
        "auto_record_humans": _state.auto_record_humans,
        "auto_record_duration": _state.auto_record_duration,
    }
    if _state.db:
        saved = _state.db.get_all_config()
        defaults.update(saved)
    defaults["caption_enabled"] = _state.caption_enabled
    defaults["caption_model"] = _state.caption_model
    defaults["auto_record_humans"] = _state.auto_record_humans
    defaults["auto_record_duration"] = _state.auto_record_duration
    return JSONResponse(defaults)


class ConfigUpdate(BaseModel):
    key: str
    value: Any

@app.post("/api/config")
async def set_config(req: ConfigUpdate):
    if _state.db:
        _state.db.set_config(req.key, req.value)
    if req.key == "caption_enabled":
        _state.caption_enabled = bool(req.value)
    elif req.key == "caption_model":
        _state.caption_model = str(req.value)
    elif req.key == "auto_record_humans":
        _state.auto_record_humans = bool(req.value)
    elif req.key == "auto_record_duration":
        _state.auto_record_duration = max(5, int(req.value))
    return {"ok": True}


# ── Favorites & Watch ─────────────────────────────────────────────────────────
class HitToggleRequest(BaseModel):
    ip: str
    port: int
    value: int = 1

@app.post("/api/hit/favorite")
async def toggle_favorite(req: HitToggleRequest):
    for h in _state.hits:
        if h.get("ip") == req.ip and h.get("port") == req.port:
            h["favorited"] = req.value
    if _state.db:
        _state.db.update_favorite(req.ip, req.port, req.value)
    return {"ok": True, "favorited": req.value}

@app.post("/api/hit/watch")
async def toggle_watch(req: HitToggleRequest):
    for h in _state.hits:
        if h.get("ip") == req.ip and h.get("port") == req.port:
            h["watched"] = req.value
    if _state.db:
        _state.db.update_watched(req.ip, req.port, req.value)
    return {"ok": True, "watched": req.value}


# ── Server-side recording manager ─────────────────────────────────────────────
async def _start_recording(ip: str, port: int, rtsp_url: str,
                            trigger: str = "manual",
                            people_count: int = 0) -> str | None:
    """Spawn a server-managed ffmpeg recording. Returns output path or None."""
    from datetime import datetime
    key = f"{ip}:{port}"
    if key in _state.recordings:
        return None  # already recording this stream
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = _state.out_dir / ip / "recordings"
    folder.mkdir(parents=True, exist_ok=True)
    suffix = "human_detected" if trigger == "human_detected" else "manual"
    out = str(folder / f"{ts}_{suffix}.mkv")
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-rtsp_transport", "tcp", "-i", rtsp_url,
            "-c", "copy", out,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
    except Exception as e:
        log.warning("recording start failed %s: %s", key, e)
        return None
    rec_id = 0
    if _state.db:
        rec_id = _state.db.insert_recording(ip, port, rtsp_url, out,
                                              trigger, people_count)
    _state.recordings[key] = (proc, rec_id, out)
    _state.bus.emit("recording_started", {"ip": ip, "port": port, "path": out,
                                          "trigger": trigger})
    log.warning("recording started %s → %s", key, out)
    asyncio.create_task(_auto_stop_recording(
        key, proc, rec_id, ip, port, _state.auto_record_duration))
    return out


async def _auto_stop_recording(key: str, proc, rec_id: int,
                                ip: str, port: int, duration: int) -> None:
    await asyncio.sleep(duration)
    if key in _state.recordings and _state.recordings[key][0] is proc:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except Exception:
            pass
        _, _, out = _state.recordings.pop(key)
        if _state.db and rec_id:
            _state.db.stop_recording(rec_id)
        _state.bus.emit("recording_stopped", {"ip": ip, "port": port, "path": out})
        log.warning("recording stopped %s → %s", key, out)


class StreamRefRequest(BaseModel):
    ip: str
    port: int

@app.post("/api/recording/start")
async def api_start_recording(req: StreamRefRequest):
    url = next((h["rtsp_url"] for h in _state.hits
                if h.get("ip") == req.ip and h.get("port") == req.port), None)
    if not url:
        raise HTTPException(404, "hit not found")
    out = await _start_recording(req.ip, req.port, url, trigger="manual")
    if not out:
        return {"ok": False, "msg": "already recording or failed to start"}
    return {"ok": True, "path": out}

@app.post("/api/recording/stop")
async def api_stop_recording(req: StreamRefRequest):
    key = f"{req.ip}:{req.port}"
    entry = _state.recordings.get(key)
    if not entry:
        return {"ok": False, "msg": "not recording"}
    proc, rec_id, out = entry
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except Exception:
        pass
    _state.recordings.pop(key, None)
    if _state.db and rec_id:
        _state.db.stop_recording(rec_id)
    _state.bus.emit("recording_stopped", {"ip": req.ip, "port": req.port, "path": out})
    return {"ok": True, "path": out}

@app.get("/api/recordings")
async def get_recordings():
    if _state.db:
        rows = _state.db.get_recordings()
    else:
        rows = []
    active = [{"ip": k.split(":")[0], "port": int(k.split(":")[1]),
               "path": v[2]} for k, v in _state.recordings.items()]
    return JSONResponse({"active": active, "history": rows})


class SnapshotRequest(BaseModel):
    rtsp_url: str
    ip: str
    port: int


_FALLBACK_PATHS = [
    "/Streaming/Channels/1",
    "/Streaming/Channels/101",
    "/cam/realmonitor?channel=1&subtype=0",
    "/h264/ch1/main/av_stream",
    "/live",
    "/live.sdp",
    "/live/main",
    "/video0",
    "/0",
    "/1",
]


async def _ffmpeg_snap(url: str, out_path: Path,
                       transport: str = "tcp", timeout: float = 20.0) -> bool:
    """Single ffmpeg attempt. Returns True on success."""
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
        err = stderr.decode(errors="replace").strip()
        log.warning("ffmpeg [%s] %s → %s", transport, url, err[:160])
    except asyncio.TimeoutError:
        log.warning("ffmpeg timeout [%s] %s", transport, url)
    except Exception as e:
        log.warning("ffmpeg error [%s] %s: %s", transport, url, e)
    return False


def _url_swap_path(rtsp_url: str, new_path: str) -> str:
    """Replace the path component of an rtsp:// URL."""
    # rtsp://user:pw@host:port/old/path → rtsp://user:pw@host:port/new/path
    import re as _re
    return _re.sub(r"(rtsp://[^/]+)/.*", r"\1" + new_path, rtsp_url)


async def _take_snapshot_now(rtsp_url: str, ip: str, port: int) -> str | None:
    """Try multiple transports and path fallbacks to get a snapshot."""
    if not shutil.which("ffmpeg"):
        return None
    folder = _state.out_dir / ip
    folder.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in rtsp_url[7:])[:60]
    out_path = folder / f"snap_{port}_{safe}.jpg"

    # Determine if the stored path is a trivial root — if so, add fallbacks
    import re as _re
    path_match = _re.search(r"rtsp://[^/]+(/.*)$", rtsp_url)
    stored_path = path_match.group(1) if path_match else "/"
    is_root = stored_path.rstrip("/") in ("", "/")

    candidates = [rtsp_url]
    if is_root:
        for p in _FALLBACK_PATHS:
            candidates.append(_url_swap_path(rtsp_url, p))

    for url in candidates:
        for transport in ("tcp", "udp"):
            if await _ffmpeg_snap(url, out_path, transport):
                log.warning("snapshot OK [%s] %s", transport, url)
                if url != rtsp_url:
                    # Fallback path worked — persist it so launch commands use the right URL
                    _patch_hit_rtsp_url(ip, port, url)
                    _state.bus.emit("rtsp_url_updated", {"ip": ip, "port": port, "url": url})
                return str(out_path)

    log.info("snapshot failed all attempts for %s:%d", ip, port)
    return None


@app.post("/api/snapshot")
async def request_snapshot(req: SnapshotRequest):
    """Trigger a fresh snapshot for a single stream. Returns immediately;
    result is pushed via snapshot_saved SSE event when done."""
    async def _run():
        path = await _take_snapshot_now(req.rtsp_url, req.ip, req.port)
        if path:
            _patch_hit_snapshot(req.ip, req.port, path)
            _state.bus.emit("snapshot_saved", {"ip": req.ip, "port": req.port, "path": path})
            caption = await _caption_snapshot(path)
            if caption:
                _patch_hit_caption(req.ip, req.port, caption)
                _state.bus.emit("caption_update", {"ip": req.ip, "port": req.port, "caption": caption})
        else:
            _state.bus.emit("log", {"level": "WARNING",
                                    "msg": f"snapshot failed for {req.ip}:{req.port}"})
    asyncio.create_task(_run())
    return {"ok": True, "msg": "snapshot started"}


@app.post("/api/snapshot/all")
async def request_all_snapshots():
    hits = [h for h in _state.hits if h.get("rtsp_url")]
    if not hits:
        return {"ok": True, "queued": 0}
    async def _run_all():
        for h in hits:
            path = await _take_snapshot_now(h["rtsp_url"], h["ip"], h["port"])
            if path:
                _patch_hit_snapshot(h["ip"], h["port"], path)
                _state.bus.emit("snapshot_saved", {"ip": h["ip"], "port": h["port"], "path": path})
                if _state.caption_enabled:
                    caption = await _caption_snapshot(path)
                    if caption:
                        _patch_hit_caption(h["ip"], h["port"], caption)
                        _state.bus.emit("caption_update",
                                        {"ip": h["ip"], "port": h["port"], "caption": caption})
            await asyncio.sleep(0.5)
    asyncio.create_task(_run_all())
    return {"ok": True, "queued": len(hits)}


class StreamLaunchRequest(BaseModel):
    rtsp_url: str
    ip: str = ""
    port: int = 0
    mode: str = "view"   # "view" | "record" | "recprev"


def _find_terminal() -> str | None:
    for t in ("x-terminal-emulator", "gnome-terminal", "xterm", "konsole", "xfce4-terminal"):
        if shutil.which(t):
            return t
    return None


async def _open_terminal(term: str, title: str, cmd: str) -> bool:
    """Spawn cmd in a named terminal window. Returns True on success."""
    _done = "echo; read -p 'Done — press Enter to close'"
    full_cmd = f"{cmd}; {_done}"
    try:
        if term == "gnome-terminal":
            # gnome-terminal: pass bash -c as real separate args (no shell quoting layer)
            args = ["gnome-terminal", f"--title={title}", "--", "bash", "-c", full_cmd]
        elif term in ("xterm", "x-terminal-emulator"):
            # xterm: -e takes its arguments directly (exec'd, not shell-expanded).
            # Pass bash, -c, and the command string as three separate argv entries.
            args = [term, "-title", title, "-e", "bash", "-c", full_cmd]
        elif term in ("xfce4-terminal", "konsole"):
            # These pass the -e value through a shell, so we need one quoting layer.
            args = [term, f"--title={title}", "-e", f"bash -c {shlex.quote(full_cmd)}"]
        else:
            args = [term, "-e", f"bash -c {shlex.quote(full_cmd)}"]
        await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _authed_url(ip: str, port: int, path: str, user: str, pw: str) -> str:
    """Build rtsp:// URL with optional embedded credentials. (duplicated from pipeline for launch reliability)"""
    import urllib.parse
    if user or pw:
        u = urllib.parse.quote(user, safe="")
        p = urllib.parse.quote(pw, safe="")
        cred = f"{u}:{p}@"
    else:
        cred = ""
    if path and not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{cred}{ip}:{port}{path}"


def _recording_path(rtsp_url: str) -> tuple[str, str]:
    """Return (safe_label, absolute_output_path) for a recording."""
    from datetime import datetime
    # Extract IP from URL for folder name
    import re as _re
    m = _re.search(r"rtsp://(?:[^@]+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", rtsp_url)
    ip = m.group(1) if m else "unknown"
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in rtsp_url[7:])[:35]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = _state.out_dir / ip / "recordings"
    folder.mkdir(parents=True, exist_ok=True)
    out = str(folder / f"{ts}_{safe}.mkv")
    return safe, out


@app.post("/api/stream/launch")
async def launch_stream(req: StreamLaunchRequest):
    """Open stream in terminal(s). recprev spawns two windows in parallel.

    We deliberately prefer the server's _state.hits entry for the (ip, port)
    when available. We *rebuild* the authenticated URL from the structured
    fields (ip, port, endpoint, username, password) that were recorded at
    verification time. This guarantees that live view always uses proper
    authentication and a path that the scanner itself proved works with
    DESCRIBE + the creds. We fall back to the stored rtsp_url only if the
    structured fields are missing.
    """
    url = None
    if req.ip and req.port:
        for h in _state.hits:
            if h.get("ip") == req.ip and h.get("port") == req.port:
                user = h.get("username", "") or ""
                pw = h.get("password", "") or ""
                # If RTSP creds are empty but CVE extraction produced credentials, use first
                if not user and not pw:
                    ext = h.get("extracted_creds") or []
                    if ext and isinstance(ext[0], str) and ":" in ext[0]:
                        user, pw = ext[0].split(":", 1)
                # Prefer the *path* from the current rtsp_url in the payload/hit
                # (this is the one that may have been updated via snapshot fallback
                # to a working stream path like /1, /Streaming/Channels/101 etc.).
                # Then rebuild the full authenticated URL so that auth is guaranteed
                # using the creds that actually verified this hit.
                endpoint = h.get("endpoint") or "/"
                rtsp = h.get("rtsp_url") or ""
                if rtsp:
                    try:
                        parsed = urllib.parse.urlparse(rtsp)
                        if parsed.path:
                            endpoint = parsed.path
                            if parsed.query:
                                endpoint += "?" + parsed.query
                    except Exception:
                        pass
                try:
                    url = _authed_url(str(h.get("ip", "")), int(h.get("port", 0)), endpoint, user, pw)
                except Exception:
                    url = rtsp or req.rtsp_url
                break
    if not url:
        url = req.rtsp_url
    if not url:
        return {"ok": False, "msg": "no rtsp url available for this camera"}

    safe, rec_out = _recording_path(url)
    view_cmd = f"ffplay -rtsp_transport tcp {shlex.quote(url)}"
    rec_cmd  = f"ffmpeg -rtsp_transport tcp -i {shlex.quote(url)} -c copy {shlex.quote(rec_out)}"

    term = _find_terminal()
    if not term:
        cmds = {"view": view_cmd, "record": rec_cmd, "recprev": f"{rec_cmd}  &&  {view_cmd}"}
        return {"ok": False, "cmd": cmds.get(req.mode, view_cmd),
                "msg": "no terminal found — copy the command"}

    if req.mode == "recprev":
        ok1 = await _open_terminal(term, f"Recording → {rec_out}", rec_cmd)
        ok2 = await _open_terminal(term, f"Live View — {safe}", view_cmd)
        return {"ok": ok1 or ok2, "mode": "recprev",
                "rec_path": rec_out, "view_cmd": view_cmd}

    cmd = view_cmd if req.mode == "view" else rec_cmd
    title = f"Live View — {safe}" if req.mode == "view" else f"Recording → {rec_out}"
    ok = await _open_terminal(term, title, cmd)
    return {"ok": ok, "cmd": cmd}


@app.post("/api/enrich/all")
async def enrich_all():
    """Fetch snapshots + AI captions for every hit that's missing either."""
    hits = list(_state.hits)
    need = [h for h in hits if h.get("rtsp_url") and (
        not h.get("snapshot") or not h.get("caption"))]
    if not need:
        return {"ok": True, "queued": 0}

    async def _run():
        total = len(need)
        for i, h in enumerate(need):
            _state.bus.emit("enrich_progress", {"done": i, "total": total, "ip": h["ip"]})
            # Snapshot
            snap = h.get("snapshot") or h.get("snapshot_path") or ""
            if not snap or not Path(snap).exists():
                snap = await _take_snapshot_now(h["rtsp_url"], h["ip"], h["port"])
                if snap:
                    _patch_hit_snapshot(h["ip"], h["port"], snap)
                    _state.bus.emit("snapshot_saved", {"ip": h["ip"], "port": h["port"], "path": snap})
            # Caption
            if snap and Path(snap).exists() and not h.get("caption"):
                cap = await _caption_snapshot(snap)
                if cap:
                    _patch_hit_caption(h["ip"], h["port"], cap)
                    _state.bus.emit("caption_update", {"ip": h["ip"], "port": h["port"], "caption": cap})
            await asyncio.sleep(0.2)
        _state.bus.emit("enrich_progress", {"done": total, "total": total, "ip": ""})
        log.info("enrich_all complete: %d processed", total)

    asyncio.create_task(_run())
    return {"ok": True, "queued": len(need)}


class CaptionToggle(BaseModel):
    enabled: bool

@app.post("/api/caption/toggle")
async def caption_toggle(req: CaptionToggle):
    _state.caption_enabled = req.enabled
    if _state.db:
        _state.db.set_config("caption_enabled", req.enabled)
    return {"ok": True, "caption_enabled": _state.caption_enabled}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(_load_dashboard_html())

# ── Mullvad rotator ──────────────────────────────────────────────────────────
async def _mullvad_rotator(min_secs: int = 20, max_secs: int = 40) -> None:
    """Rotate to a random active Mullvad relay every 20-40 seconds (worldwide)."""
    relays = await _mullvad_get_relays()
    log.info("mullvad rotator ready: %d relays available", len(relays))

    while True:
        wait = random.randint(min_secs, max_secs)
        await asyncio.sleep(wait)

        country, city = random.choice(relays)
        location_label = f"{country}/{city}"
        log.info("mullvad: rotating to %s", location_label)
        try:
            p1 = await asyncio.create_subprocess_exec(
                "mullvad", "relay", "set", "location", country, city,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await p1.wait()
            p2 = await asyncio.create_subprocess_exec(
                "mullvad", "reconnect",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await p2.wait()
            connected = False
            for _ in range(15):
                await asyncio.sleep(1.0)
                p3 = await asyncio.create_subprocess_exec(
                    "mullvad", "status",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                out, _ = await p3.communicate()
                if b"Connected" in out:
                    connected = True
                    break
            _state.bus.emit("mullvad", {
                "city": location_label, "connected": connected})
            log.info("mullvad: %s connected=%s (next in %ds)", location_label, connected, wait)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("mullvad rotation failed: %s", e)

# ── Persistence ───────────────────────────────────────────────────────────────
def _hits_file() -> Path:
    return _state.out_dir / "hits.jsonl"


def register_hit(hit: dict) -> None:
    """Persist a verified hit to SQLite + JSONL. Called by _hit_consumer.

    Small enhancement for the web UI makeover: if we have prior annotations
    (favorited/watched) for this camera in the DB from a previous scan or
    manual toggle, merge them onto the incoming hit so that live dashboard
    cards and the current-run view correctly show the user's prior arming/
    favorite state instead of always starting "un-starred".
    """
    if _state.db is not None:
        try:
            row = _state.db._con.execute(
                "SELECT favorited, watched FROM hits WHERE ip=? AND port=? "
                "ORDER BY id DESC LIMIT 1",
                (hit.get("ip", ""), int(hit.get("port", 0)))
            ).fetchone()
            if row:
                # Only set if not already present (fresh pipeline hit won't have them)
                hit.setdefault("favorited", row.get("favorited", 0) or 0)
                hit.setdefault("watched", row.get("watched", 0) or 0)
        except Exception:
            pass  # best effort; annotations are nice-to-have on the live object

    _state.hits.append(hit)
    # SQLite (primary)
    if _state.db is not None:
        try:
            _state.db.insert_hit(hit)
        except Exception as e:
            log.warning("db insert_hit failed: %s", e)
    # JSONL fallback
    try:
        with _hits_file().open("a") as fh:
            fh.write(json.dumps(hit, default=str) + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except Exception:
                pass
    except OSError as e:
        log.warning("jsonl persist failed: %s", e)


def _patch_hit_rtsp_url(ip: str, port: int, url: str) -> None:
    for h in _state.hits:
        if h.get("ip") == ip and h.get("port") == port:
            h["rtsp_url"] = url
            break
    if _state.db is not None:
        try:
            _state.db.update_hit_rtsp_url(ip, port, url)
        except Exception as e:
            log.warning("db update rtsp_url failed: %s", e)


def _patch_hit_snapshot(ip: str, port: int, path: str) -> None:
    for h in _state.hits:
        if h.get("ip") == ip and h.get("port") == port:
            h["snapshot"] = path
            h["snapshot_path"] = path
            break
    if _state.db is not None:
        try:
            _state.db.update_hit_snapshot(ip, port, path)
        except Exception as e:
            log.warning("db update snapshot failed: %s", e)


def _patch_hit_caption(ip: str, port: int, caption: dict) -> None:
    for h in _state.hits:
        if h.get("ip") == ip and h.get("port") == port:
            h["caption"] = caption
            break
    if _state.db is not None:
        try:
            _state.db.update_hit_caption(ip, port, caption)
        except Exception as e:
            log.warning("db update caption failed: %s", e)


def _patch_hit_vulns(ip: str, port: int, vulns: list,
                     severity: str, fingerprint: str,
                     extracted_creds: list | None = None) -> None:
    for h in _state.hits:
        if h.get("ip") == ip and h.get("port") == port:
            h["vulns"] = vulns
            h["severity"] = severity
            h["fingerprint"] = fingerprint
            if extracted_creds is not None:
                h["extracted_creds"] = extracted_creds
            break
    if _state.db is not None:
        try:
            _state.db.update_hit_vulns(ip, port, vulns, severity, fingerprint)
            if extracted_creds is not None:
                _state.db.update_hit_extracted_creds(ip, port, extracted_creds)
        except Exception as e:
            log.warning("db update vulns failed: %s", e)


def _patch_hit_nmap(ip: str, port: int,
                    nmap_service: str, nmap_device: str, nmap_cpe: str) -> None:
    for h in _state.hits:
        if h.get("ip") == ip and h.get("port") == port:
            h["nmap_service"] = nmap_service
            h["nmap_device"]  = nmap_device
            h["nmap_cpe"]     = nmap_cpe
            break
    if _state.db is not None:
        try:
            _state.db.update_hit_nmap(ip, port, nmap_service, nmap_device, nmap_cpe)
        except Exception as e:
            log.warning("db update_hit_nmap failed: %s", e)


def _migrate_jsonl_to_db() -> None:
    """One-time migration: import hits.jsonl into SQLite if DB is empty."""
    if _state.db is None:
        return
    if _state.db.count_hits() > 0:
        return  # already have data, skip
    jsonl = _hits_file()
    if not jsonl.exists():
        return
    imported = 0
    seen: set[tuple] = set()
    for line in jsonl.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            h = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = (h.get("ip", ""), int(h.get("port", 0)), h.get("endpoint", ""))
        if key in seen:
            continue
        seen.add(key)
        try:
            _state.db.insert_hit(h)
            imported += 1
        except Exception:
            pass
    if imported:
        log.info("migrated %d hits from hits.jsonl → SQLite", imported)


def _load_persisted_hits() -> None:
    """Migrate JSONL → SQLite (first run), then load all rows into memory."""
    if _state.db is None:
        return
    _migrate_jsonl_to_db()
    try:
        rows = _state.db.get_all_hits()
        _state.hits.extend(rows)
        if rows:
            log.info("loaded %d persisted hits from SQLite", len(rows))
    except Exception as e:
        log.warning("failed to load hits from db: %s", e)


def _load_dashboard_html() -> str:
    """Load the self-contained dashboard UI from the package asset.
    This replaces the previous giant inline string literal, making the web GUI
    maintainable as a normal HTML/JS/CSS file while still serving a single blob.
    """
    # Preferred: works for normal installs and wheels via importlib.resources
    try:
        from importlib.resources import files
        return (files("cam_scan.web_ui") / "index.html").read_text(encoding="utf-8")
    except Exception:
        pass
    # Fallback for editable / source-tree runs
    here = Path(__file__).parent / "web_ui" / "index.html"
    if here.exists():
        return here.read_text(encoding="utf-8")
    # Last resort (should never happen)
    return "<!doctype html><title>cam-scan</title><body>UI asset missing (cam_scan/web_ui/index.html). Reinstall or restore the file.</body>"


# ── Server launcher ───────────────────────────────────────────────────────────
async def serve(host: str = "127.0.0.1", port: int = 7788,
                out_dir: Path = Path("output"),
                log_dir: Path = Path("logs")) -> None:
    if not _HAS_WEB_DEPS:
        raise RuntimeError(
            "Web UI requires fastapi and uvicorn. "
            "Install with: pip install fastapi uvicorn"
        )
    from .database import Database
    _state.out_dir = out_dir
    _state.log_dir = log_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    _state.db = Database(out_dir / "camscan.db")
    log.info("database: %s", out_dir / "camscan.db")
    _load_persisted_hits()
    # Restore config from DB
    if _state.db:
        _state.caption_enabled = bool(_state.db.get_config("caption_enabled", True))
        _state.caption_model = _state.db.get_config(
            "caption_model", "huihui_ai/gemma-4-abliterated:e4b")
        raw_arh = _state.db.get_config("auto_record_humans", False)
        _state.auto_record_humans = (raw_arh is True or raw_arh == 1
                                     or str(raw_arh).lower() == "true")
        _state.auto_record_duration = int(_state.db.get_config("auto_record_duration", 60))
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    await server.serve()


# ── Dashboard route (now loads from real asset file) ─────────────────────────
# The previous _DASHBOARD_HTML giant literal has been moved to
# cam_scan/web_ui/index.html for maintainability (see plan). The loader above
# provides graceful fallbacks.

# (old _DASHBOARD_HTML literal excised; now lives in cam_scan/web_ui/index.html)

