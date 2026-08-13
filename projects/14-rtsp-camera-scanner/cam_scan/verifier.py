"""SDP parsing + honeypot heuristics. A 200 OK alone is not success."""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass, field

_KNOWN_CODECS = {"H264", "H265", "HEVC", "MP4V-ES", "JPEG", "MJPEG",
                 "PCMA", "PCMU", "MPEG4-GENERIC", "AAC", "MP4A-LATM",
                 "VP8", "VP9", "AV1", "OPUS", "G711", "G726", "G729"}


@dataclass
class VerifyResult:
    ok: bool = False
    tracks: int = 0
    codecs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sdp_hash: str = ""


_MAX_HOSTS = 4096
_seen_sdp_by_host: "OrderedDict[str, set[str]]" = OrderedDict()


def _reset_seen() -> None:
    _seen_sdp_by_host.clear()


def _touch_host(host: str) -> set[str]:
    s = _seen_sdp_by_host.get(host)
    if s is None:
        if len(_seen_sdp_by_host) >= _MAX_HOSTS:
            _seen_sdp_by_host.popitem(last=False)
        s = set()
        _seen_sdp_by_host[host] = s
    else:
        _seen_sdp_by_host.move_to_end(host)
    return s


def verify(host: str, status: int, body: bytes) -> VerifyResult:
    r = VerifyResult()
    if status != 200:
        return r
    if not body:
        r.warnings.append("empty_body")
        return r

    text = body.decode("latin-1", errors="replace")
    r.sdp_hash = hashlib.sha1(body).hexdigest()[:16]

    # Must start with SDP version line — rejects HTML error pages and
    # marketing pages that slip through as 200 OK.
    if not text.lstrip().startswith("v="):
        r.warnings.append("not_sdp")
        return r

    # Require at least one video or audio media section.
    # We intentionally do NOT require a known codec name or a=control here —
    # many real cameras return valid SDPs with vendor payload types (96–127)
    # and no a=rtpmap line, yet ffprobe opens them fine.
    media_lines = [ln for ln in text.splitlines() if ln.startswith("m=")]
    r.tracks = sum(1 for ln in media_lines
                   if ln.startswith(("m=video", "m=audio")))
    if r.tracks == 0:
        r.warnings.append("no_media_tracks")
        return r

    # Collect codec names opportunistically for logging — not used as gate.
    codecs: list[str] = []
    for m in re.finditer(r"^a=rtpmap:\d+\s+([A-Za-z0-9\-]+)/", text,
                         flags=re.MULTILINE):
        c = m.group(1).upper()
        if c not in codecs:
            codecs.append(c)
    r.codecs = codecs

    # Soft warnings (logged but don't block success)
    if not re.search(r"^a=", text, re.MULTILINE):
        r.warnings.append("no_attributes")
    if not re.search(r"^a=control:", text, re.MULTILINE):
        r.warnings.append("no_control_attr")

    seen = _touch_host(host)
    if r.sdp_hash in seen:
        r.warnings.append("duplicate_sdp_on_host")
    else:
        seen.add(r.sdp_hash)

    r.ok = True
    return r
