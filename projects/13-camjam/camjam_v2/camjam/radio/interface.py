import os
import shutil
import subprocess
from typing import List


class RadioInterface:
    def __init__(self, log=None):
        self._log = log or (lambda _level, _msg: None)

    def list_wifi_interfaces(self) -> List[str]:
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            return []
        interfaces = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            iface = parts[1].strip().split("@")[0]
            if iface.startswith("w") and iface != "lo":
                interfaces.append(iface)
        return interfaces

    def check_state(self, interface: str) -> str:
        try:
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            return "unknown"
        if "type monitor" in result.stdout:
            return "monitor"
        if "type managed" in result.stdout:
            return "managed"
        return "unknown"

    def stop_network_manager(self) -> None:
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=False, capture_output=True)
        subprocess.run(["systemctl", "stop", "wpa_supplicant"], check=False, capture_output=True)
        subprocess.run(["rfkill", "unblock", "wifi"], check=False, capture_output=True)

    def restart_network_manager(self) -> None:
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=False, capture_output=True)
        subprocess.run(["systemctl", "start", "wpa_supplicant"], check=False, capture_output=True)

    def kill_interfering(self) -> None:
        if shutil.which("airmon-ng"):
            subprocess.run(["airmon-ng", "check", "kill"], check=False, capture_output=True)

    def set_monitor_mode(self, interface: str) -> str:
        self.kill_interfering()
        self.stop_network_manager()
        if self.check_state(interface) == "monitor":
            return interface
        if shutil.which("airmon-ng"):
            try:
                subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True)
                mon = f"{interface}_mon"
                if os.path.exists(f"/sys/class/net/{mon}"):
                    return mon
            except subprocess.CalledProcessError:
                pass
        return self._set_monitor_direct(interface)

    def _set_monitor_direct(self, interface: str) -> str:
        mon = f"{interface}_mon"
        try:
            subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
            subprocess.run(
                ["iw", "dev", interface, "interface", "add", mon, "type", "monitor"],
                check=True,
                capture_output=True,
            )
            subprocess.run(["ip", "link", "set", mon, "up"], check=True, capture_output=True)
            return mon
        except subprocess.CalledProcessError:
            return ""

    def set_channel(self, interface: str, channel: int) -> None:
        """Tune radio; 5 GHz channels (>14) use HT20 for Realtek/Alfa adapters."""
        if channel > 14:
            for args in (
                ["iw", "dev", interface, "set", "channel", str(channel), "HT20"],
                ["iw", "dev", interface, "set", "channel", str(channel)],
            ):
                r = subprocess.run(args, capture_output=True, text=True)
                if r.returncode == 0:
                    return
        else:
            subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                check=False,
                capture_output=True,
            )

    def reset_interface(self, interface: str) -> None:
        try:
            subprocess.run(["ip", "link", "set", interface, "down"], check=True, capture_output=True)
            subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            pass