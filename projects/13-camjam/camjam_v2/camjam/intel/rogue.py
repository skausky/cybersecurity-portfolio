from typing import Dict, List


def detect_rogues(networks: List[Dict]) -> List[Dict]:
    """Flag APs sharing an SSID but with mismatched encryption, channel, or unusually weak signal."""
    ssid_groups: Dict[str, List[Dict]] = {}
    for net in networks:
        ssid = net.get("ssid", "")
        if not ssid or ssid in ("<hidden>", "(not associated)"):
            continue
        ssid_groups.setdefault(ssid, []).append(net)

    rogues = []
    for ssid, group in ssid_groups.items():
        if len(group) < 2:
            continue
        try:
            by_power = sorted(
                group,
                key=lambda x: int(x.get("power", "-100") or "-100"),
                reverse=True,
            )
        except (TypeError, ValueError):
            continue

        strongest = by_power[0]
        for ap in by_power[1:]:
            reasons = []
            s_enc = (strongest.get("encryption") or "").strip().upper()
            a_enc = (ap.get("encryption") or "").strip().upper()
            if s_enc and a_enc and s_enc != a_enc:
                reasons.append(f"encryption mismatch: {a_enc} vs {s_enc} on trusted AP")
            if strongest.get("channel") != ap.get("channel"):
                reasons.append(f"different channel {ap.get('channel')} vs {strongest.get('channel')}")
            try:
                p_diff = int(strongest.get("power", "-100")) - int(ap.get("power", "-100"))
                if p_diff > 35:
                    reasons.append(f"signal {p_diff} dBm weaker (possible portable rogue)")
            except (TypeError, ValueError):
                pass
            if reasons:
                severity = "high" if any("encryption" in r for r in reasons) else "medium"
                rogues.append({
                    "ssid": ssid,
                    "suspect_bssid": ap["bssid"],
                    "trusted_bssid": strongest["bssid"],
                    "reasons": reasons,
                    "severity": severity,
                })

    return rogues
