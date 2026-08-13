"""Default credential pairs and RTSP endpoint paths."""
from __future__ import annotations

from pathlib import Path

DEFAULT_CREDS: list[tuple[str, str]] = [
    ("", ""),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "1234"),
    ("admin", "password"),
    ("admin", "9999"),
    ("admin", "pass"),
    ("admin", "888888"),
    ("admin", "54321"),
    ("admin", "123"),
    ("admin", "admin123"),
    ("admin", "1111"),
    ("admin", "0000"),
    ("root", ""),
    ("root", "root"),
    ("root", "admin"),
    ("root", "pass"),
    ("root", "12345"),
    ("root", "toor"),
    ("user", "user"),
    ("user", ""),
    ("guest", "guest"),
    ("guest", ""),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("666666", "666666"),
    ("888888", "888888"),
    ("ubnt", "ubnt"),
]

DEFAULT_PATHS: list[str] = [
    # Generic / bare
    "/",
    "/0",
    "/1",
    "/2",
    "/live",
    "/live.sdp",
    "/live/main",
    "/live/sub",
    "/live0",
    "/live1",
    "/live2",
    "/stream",
    "/stream0",
    "/stream1",
    "/stream2",
    "/video",
    "/video0",
    "/video1",
    "/video2",
    "/videoMain",
    "/videoSub",
    "/video/mjpg.cgi",
    # H.264 paths (Hikvision / Dahua / generic)
    "/h264",
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/h264/ch1/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/h265Preview_01_main",
    # Hikvision ISAPI / Streaming
    "/Streaming/Channels/1",
    "/Streaming/Channels/2",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/201",
    "/Streaming/Channels/202",
    "/ISAPI/Streaming/Channels/101",
    "/ISAPI/Streaming/Channels/102",
    "/ISAPI/Streaming/Channels/201",
    # Dahua
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cam/realmonitor?channel=2&subtype=0",
    "/cam/realmonitor?channel=2&subtype=1",
    # ONVIF generic
    "/onvif1",
    "/onvif2",
    "/onvif/media/video1",
    # Axis
    "/axis-media/media.amp",
    "/axis-media/media.amp?videocodec=h264",
    # Sony / Panasonic / Samsung
    "/media/video1",
    "/media/video2",
    "/MediaInput/h264",
    "/MediaInput/mpeg4",
    "/nphMpeg4/nil=",
    # Channel/profile numbering (common DVR/NVR)
    "/ch0_0.h264",
    "/ch0_1.h264",
    "/ch1_0.h264",
    "/ch1_1.h264",
    "/11",
    "/12",
    "/13",
    "/21",
    "/profile1",
    "/profile2",
    "/profile3",
    # D-Link / Foscam
    "/play1.sdp",
    "/play2.sdp",
    "/video.mp4",
    "/video.mjpg",
    # TP-Link / Reolink / generic cheap cams
    "/stream=0",
    "/stream=1",
    "/Preview_01_main",
    "/Preview_01_sub",
    # Credential-embedded paths (seen on some firmware)
    "/user=admin_password=_channel=1_stream=0.sdp",
    "/user=admin_password=admin_channel=1_stream=0.sdp",
    # MPEG-4 / MJPEG fallbacks
    "/mpeg4",
    "/mpeg4/media.amp",
    "/mjpeg",
    "/mjpeg/media.amp",
    "/mjpg/video.mjpg",
    # NetCam / Mobotix
    "/control/faststream.jpg?stream=half",
    "/record/current.mjpeg",
]


def load_creds(path: Path | None) -> list[tuple[str, str]]:
    if path is None:
        return DEFAULT_CREDS
    out: list[tuple[str, str]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            out.append((line, ""))
            continue
        u, _, p = line.partition(":")
        out.append((u, p))
    return out or DEFAULT_CREDS


def load_paths(path: Path | None) -> list[str]:
    if path is None:
        return DEFAULT_PATHS
    out = [ln.strip() for ln in path.read_text().splitlines()
           if ln.strip() and not ln.startswith("#")]
    return out or DEFAULT_PATHS
