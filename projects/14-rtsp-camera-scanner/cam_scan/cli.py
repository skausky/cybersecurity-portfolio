"""cam-scan — launch the web UI or run headless."""
from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import webbrowser
from pathlib import Path

from .logging_setup import get_console, setup_logging

BANNER = """\
[bold red]cam-scan[/bold red] — authorized RTSP security research only.
Use only on networks and devices you own or have written permission to test.
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cam-scan",
        description="RTSP camera discovery and stream verification tool.")

    p.add_argument("--port", type=int, default=7788,
                   help="web UI port (default 7788)")
    p.add_argument("--headless", action="store_true",
                   help="no web UI; run from terminal with defaults")

    # Headless-only quick options
    p.add_argument("-c", "--count", type=int, default=0,
                   help="headless: target count (0 = unlimited)")
    p.add_argument("--speed", choices=("slow", "medium", "fast"), default="medium",
                   help="headless: scan speed preset")
    p.add_argument("--no-snapshots", action="store_true",
                   help="headless: skip ffmpeg snapshot capture")
    p.add_argument("--nmap", action="store_true",
                   help="run nmap rtsp-url-brute + service detection (-sV) per host")
    p.add_argument("--nmap-brute", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="count", default=1)
    p.add_argument("--i-am-authorized", action="store_true",
                   help="required: acknowledge authorized use only")

    return p


async def _run_headless(args: argparse.Namespace) -> int:
    import uuid
    from .config import RunConfig
    from .pipeline import Pipeline

    speed = {"slow": (2000, 50, 2), "medium": (5000, 200, 4), "fast": (10000, 500, 4)}
    rate, conc, phc = speed[args.speed]
    cfg = RunConfig(
        count=args.count,
        unlimited=(args.count == 0),
        rate=rate,
        concurrency=conc,
        per_host_concurrency=phc,
        snapshots=not args.no_snapshots,
        nmap_brute=args.nmap or args.nmap_brute,
        nmap_sv=args.nmap,
        verbosity=args.verbose,
        json_only=False,
        run_id=uuid.uuid4().hex[:12],
    )
    pipe = Pipeline(cfg)
    loop = asyncio.get_running_loop()

    def _stop():
        get_console().print("[yellow]stopping…[/yellow]")
        pipe.request_stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    await pipe.run()
    return 0


async def _run_web(port: int) -> int:
    from .web import serve, _state
    console = get_console()
    console.print(f"[bold green]cam-scan dashboard[/bold green] → http://127.0.0.1:{port}")
    console.print("[dim]Press Ctrl-C to stop[/dim]")
    webbrowser.open(f"http://127.0.0.1:{port}", new=2)

    loop = asyncio.get_running_loop()
    stop_evt = asyncio.Event()

    def _shutdown():
        console.print("[yellow]shutting down…[/yellow]")
        if _state.pipeline:
            _state.pipeline.request_stop()
        stop_evt.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            pass

    serve_task = asyncio.create_task(serve(port=port))
    stop_task = asyncio.create_task(stop_evt.wait())
    done, pending = await asyncio.wait(
        {serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    return 0


def _raise_fd_limit() -> None:
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(hard, 65536)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _raise_fd_limit()
    console = get_console()
    console.print(BANNER)

    if not args.i_am_authorized:
        console.print("[bold red]Provide --i-am-authorized to confirm authorized use.[/bold red]")
        return 2

    try:
        if args.headless:
            return asyncio.run(_run_headless(args))
        else:
            return asyncio.run(_run_web(args.port))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
