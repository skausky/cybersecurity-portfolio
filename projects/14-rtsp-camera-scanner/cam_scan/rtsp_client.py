"""Minimal asyncio RTSP/1.0 client supporting Basic + Digest auth."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
from dataclasses import dataclass

log = logging.getLogger("camscan.rtsp")

USER_AGENT = "LibVLC/3.0.20 (LIVE555 Streaming Media v2023.07.20)"


@dataclass
class RtspResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def _parse_auth_challenge(header: str) -> tuple[str, dict[str, str]]:
    # "Digest realm=\"x\", nonce=\"y\", ..." | "Basic realm=\"x\""
    scheme, _, rest = header.strip().partition(" ")
    params: dict[str, str] = {}
    for m in re.finditer(r'(\w+)\s*=\s*("([^"]*)"|([^,\s]+))', rest):
        k = m.group(1).lower()
        v = m.group(3) if m.group(3) is not None else m.group(4)
        params[k] = v
    return scheme.lower(), params


def _digest_response(user: str, pw: str, method: str, uri: str,
                     ch: dict[str, str]) -> str:
    realm = ch.get("realm", "")
    nonce = ch.get("nonce", "")
    qop = ch.get("qop")
    algorithm = (ch.get("algorithm") or "MD5").upper()
    opaque = ch.get("opaque")

    def h(s: str) -> str:
        return hashlib.md5(s.encode()).hexdigest()

    ha1 = h(f"{user}:{realm}:{pw}")
    ha2 = h(f"{method}:{uri}")

    parts = [f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"',
             f'uri="{uri}"', f'algorithm="{algorithm}"']
    if qop:
        cnonce = os.urandom(8).hex()
        nc = "00000001"
        # qop may be a list; pick auth
        qop_val = "auth"
        response = h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop_val}:{ha2}")
        parts += [f'qop="{qop_val}"', f'nc={nc}', f'cnonce="{cnonce}"',
                  f'response="{response}"']
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
        parts.append(f'response="{response}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


class AsyncRtspClient:
    def __init__(self, host: str, port: int, timeout: float = 6.0,
                 trace: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.trace = trace
        self._cseq = 0
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __aenter__(self) -> "AsyncRtspClient":
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), timeout=self.timeout)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

    def _build_url(self, path: str) -> str:
        if path.startswith("rtsp://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"rtsp://{self.host}:{self.port}{path}"

    async def _send(self, method: str, url: str,
                    extra: dict[str, str] | None = None) -> RtspResponse:
        assert self._reader and self._writer
        self._cseq += 1
        headers = {
            "CSeq": str(self._cseq),
            "User-Agent": USER_AGENT,
            "Accept": "application/sdp",
        }
        if extra:
            headers.update(extra)
        req = f"{method} {url} RTSP/1.0\r\n" + \
              "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        if self.trace:
            log.debug(">>> %s", req.replace("\r\n", "\\r\\n"))
        self._writer.write(req.encode("latin-1"))
        await self._writer.drain()
        return await self._read_response()

    async def _read_response(self) -> RtspResponse:
        assert self._reader
        header_buf = bytearray()
        while b"\r\n\r\n" not in header_buf:
            chunk = await asyncio.wait_for(self._reader.read(4096),
                                           timeout=self.timeout)
            if not chunk:
                raise ConnectionError("connection closed before headers")
            header_buf.extend(chunk)
            if len(header_buf) > 65536:
                raise ValueError("response headers too large")
        head, _, rest = header_buf.partition(b"\r\n\r\n")
        head_str = head.decode("latin-1", errors="replace")
        if self.trace:
            log.debug("<<< %s", head_str.replace("\r\n", "\\r\\n"))
        lines = head_str.split("\r\n")
        m = re.match(r"RTSP/\d\.\d\s+(\d+)\s*(.*)", lines[0])
        if not m:
            raise ValueError(f"malformed status line: {lines[0]!r}")
        status = int(m.group(1))
        reason = m.group(2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        body = bytes(rest)
        clen = int(headers.get("content-length", "0") or 0)
        while len(body) < clen:
            chunk = await asyncio.wait_for(self._reader.read(clen - len(body)),
                                           timeout=self.timeout)
            if not chunk:
                break
            body += chunk
        return RtspResponse(status, reason, headers, body)

    async def options(self) -> RtspResponse:
        return await self._send("OPTIONS", self._build_url("/"))

    async def describe(self, path: str,
                       credentials: tuple[str, str] | None = None
                       ) -> tuple[RtspResponse, str]:
        """Returns (response, auth_scheme_used)."""
        url = self._build_url(path)
        scheme_used = "none"
        resp = await self._send("DESCRIBE", url)
        if resp.status != 401 or credentials is None:
            return resp, scheme_used
        user, pw = credentials
        challenge = resp.header("www-authenticate")
        if not challenge:
            return resp, scheme_used
        scheme, params = _parse_auth_challenge(challenge)
        if scheme == "basic":
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            auth_hdr = f"Basic {token}"
            scheme_used = "basic"
        elif scheme == "digest":
            auth_hdr = _digest_response(user, pw, "DESCRIBE", url, params)
            scheme_used = "digest"
        else:
            return resp, f"unsupported:{scheme}"
        resp2 = await self._send("DESCRIBE", url, {"Authorization": auth_hdr})
        return resp2, scheme_used
