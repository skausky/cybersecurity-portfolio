import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="CamJam v2")
    parser.add_argument("--cli", action="store_true", help="Run interactive CLI instead of web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default localhost only)")
    args = parser.parse_args()

    if args.cli:
        from camjam.cli.interactive import run_cli

        run_cli()
        return

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("Refusing to bind outside localhost. Use --host 127.0.0.1", file=sys.stderr)
        sys.exit(1)

    import uvicorn

    from camjam.api.app import create_app
    from camjam.api.security import create_binding

    binding = create_binding(args.host)
    app = create_app(binding)
    print(f"\n  CamJam v2 ready\n  {binding.url}\n", file=sys.stderr)
    uvicorn.run(app, host=binding.host, port=binding.port, log_level="info")


if __name__ == "__main__":
    main()