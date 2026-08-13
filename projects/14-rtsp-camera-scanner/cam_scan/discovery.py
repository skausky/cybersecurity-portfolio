"""Async masscan wrapper. Streams (ip, port) hits as they arrive."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from typing import AsyncIterator, Iterable

log = logging.getLogger("camscan.discovery")


class MasscanError(RuntimeError):
    pass


def preflight() -> None:
    if shutil.which("masscan") is None:
        raise MasscanError("masscan binary not found in $PATH")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        log.warning("not running as root; masscan likely needs CAP_NET_RAW or sudo")


async def _default_interface() -> str | None:
    """Return the interface used for the default route (e.g. 'wg0-mullvad')."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "-o", "route", "get", "1.1.1.1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        raw, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
        # Format: "1.1.1.1 via 10.x dev wg0-mullvad src 10.x ..."
        toks = raw.decode(errors="replace").split()
        if "dev" in toks:
            return toks[toks.index("dev") + 1]
    except Exception:
        pass
    return None


async def masscan_scan(targets: Iterable[str],
                       ports: Iterable[int],
                       rate: int) -> AsyncIterator[tuple[str, int]]:
    target_list = list(targets)
    if not target_list:
        return
    port_arg = ",".join(str(p) for p in ports)

    # Write to a tempfile so we never hit ARG_MAX and masscan gets clean input
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(target_list))
        tmp = tf.name

    cmd = ["masscan", "-p" + port_arg, "--rate", str(rate),
           "-iL", tmp, "-oJ", "-", "--wait", "1"]
    iface = await _default_interface()
    if iface:
        cmd += ["-e", iface]
    log.info("masscan: %d targets | ports=%s | rate=%d pps | iface=%s",
             len(target_list), port_arg, rate, iface or "auto")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout and proc.stderr

        stderr_buf: list[str] = []
        async def _drain_stderr() -> None:
            async for raw in proc.stderr:
                line = raw.decode(errors="replace").rstrip()
                if "kpps" in line or line.startswith("rate:"):
                    continue
                stderr_buf.append(line)
                log.warning("masscan: %s", line)

        drain_task = asyncio.create_task(_drain_stderr())
        seen: set[tuple[str, int]] = set()
        try:
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip = rec.get("ip")
                for port_rec in rec.get("ports", []):
                    if port_rec.get("status") != "open":
                        continue
                    port = int(port_rec.get("port", 0))
                    if ip and port and (ip, port) not in seen:
                        seen.add((ip, port))
                        log.info("hit %s:%d", ip, port)
                        yield ip, port
        finally:
            await proc.wait()
            drain_task.cancel()
            try:
                await drain_task
            except asyncio.CancelledError:
                pass
            if proc.returncode not in (0, None):
                tail = " | ".join(stderr_buf[-5:]) or "(no stderr)"
                raise MasscanError(
                    f"masscan exited code {proc.returncode}: {tail}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
