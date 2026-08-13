import json
from typing import Dict, List

from camjam.intel.classifier import classify_device, device_icon, device_label
from camjam.intel.oui import is_randomized_mac, vendor_from_mac


def ap_record(net: Dict[str, str]) -> Dict:
    bssid = net.get("bssid", "")
    vendor = vendor_from_mac(bssid)
    return {
        "bssid": bssid,
        "ssid": net.get("ssid", ""),
        "channel": net.get("channel", ""),
        "encryption": net.get("encryption", ""),
        "cipher": net.get("cipher", ""),
        "auth": net.get("auth", ""),
        "vendor_oui": vendor,
        "power": net.get("power", ""),
        "beacons": net.get("beacons", ""),
    }


def client_record(client: Dict[str, str]) -> Dict:
    mac = client.get("station_mac", "")
    probes_raw = client.get("probes", "")
    probe_list: List[str] = sorted(p.strip() for p in probes_raw.split(",") if p.strip())
    vendor = vendor_from_mac(mac)
    randomized = is_randomized_mac(mac)
    # Pull RF hints from the client record; channel comes from associated AP
    dtype = classify_device(
        vendor,
        probe_list,
        randomized,
        channel=client.get("channel", client.get("ap_channel", "")),
        speed=client.get("rate", client.get("speed", "")),
        packets=client.get("packets", ""),
    )
    traits = {
        "probes": probe_list,
        "associated_bssid": client.get("bssid", ""),
        "power_bucket": _power_bucket(client.get("power", "")),
        "device_type": dtype,
        "device_icon": device_icon(dtype),
        "device_label": device_label(dtype),
        "vendor_name": vendor,
    }
    return {
        "mac": mac,
        "vendor_oui": vendor,
        "vendor_name": vendor,
        "is_randomized": randomized,
        "device_type": dtype,
        "device_icon": device_icon(dtype),
        "power": client.get("power", ""),
        "packets": client.get("packets", ""),
        "bssid": client.get("bssid", ""),
        "probes": probes_raw,
        "traits_json": json.dumps(traits),
    }


def _power_bucket(power: str) -> str:
    try:
        p = int(power)
    except ValueError:
        return "unknown"
    if p >= -50:
        return "strong"
    if p >= -70:
        return "medium"
    return "weak"
