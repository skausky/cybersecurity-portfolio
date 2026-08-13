"""
Device type classifier.
Uses: OUI vendor name, probe SSIDs, MAC randomization, and optional AP hints
(channel, speed) to produce a device_type + confidence score.
"""
import re
from typing import List, Optional

# ── Vendor → device type (regex on lowercase vendor name) ────────────
VENDOR_PATTERNS: list[tuple[str, str]] = [
    # Apple — covers iPhones, iPads, Macs, Apple Watch, AirPods, HomePod, AppleTV
    (r"\bapple\b", "apple_device"),

    # Android phones / tablets
    (r"\bsamsung\b", "android_phone"),
    (r"\bgoogle\b", "android_phone"),
    (r"\bxiaomi\b|\bhongmi\b|\bmiui\b", "android_phone"),
    (r"\bhuawei\b|\bhonor\b", "android_phone"),
    (r"\boneplus\b", "android_phone"),
    (r"\boppo\b|\bbbo mobile\b", "android_phone"),
    (r"\bvivo\b", "android_phone"),
    (r"\brealme\b", "android_phone"),
    (r"\bmotorola\b|\bmoto\b", "android_phone"),
    (r"\blg electron\b|\blg innotek\b", "android_phone"),
    (r"\bsony mobile\b|\bsony ericsson\b", "android_phone"),
    (r"\bnokia\b", "android_phone"),
    (r"\bhtc corp\b|\bhtc\b", "android_phone"),
    (r"\basus\b.*mobile|\bmobile.*\basus\b", "android_phone"),
    (r"\bzte corp\b", "android_phone"),
    (r"\btcl\b", "android_phone"),
    (r"\bwiko\b", "android_phone"),
    (r"\bfairphone\b", "android_phone"),

    # Laptops / PCs / USB Wi-Fi adapters (chipset vendors = laptop)
    (r"\bintel corp\b|\bintel corporate\b", "laptop"),
    (r"\brealtek\b", "laptop"),
    (r"\bbroadcom\b", "laptop"),
    (r"\bqualcomm atheros\b|\bqualcomm\b", "laptop"),
    (r"\bazurewave\b", "laptop"),
    (r"\bmediatek\b|\bralink\b", "laptop"),
    (r"\blenovo\b", "laptop"),
    (r"\bdell\b", "laptop"),
    (r"\bhewlett.packard\b|\bhp inc\b|\bhp \b", "laptop"),
    (r"\bacer\b", "laptop"),
    (r"\bmicrosoft corp\b|\bmicrosoft\b", "laptop"),
    (r"\btoshiba\b", "laptop"),
    (r"\bfujitsu\b", "laptop"),
    (r"\bpanasonic\b", "laptop"),
    (r"\bwistron\b|\bwistron infocomm\b", "laptop"),
    (r"\bpegatron\b", "laptop"),
    (r"\bcompal\b", "laptop"),
    (r"\bquanta\b", "laptop"),
    (r"\badvanced micro\b", "laptop"),

    # IoT microcontrollers / embedded
    (r"\bespressif\b", "iot_esp"),
    (r"\bparticle\b", "iot_esp"),
    (r"\bnordic semi\b", "iot_esp"),
    (r"\bsilicon lab\b|\bsilicon laboratories\b", "iot_esp"),
    (r"\bwiznet\b", "iot_esp"),
    (r"\bmurata\b", "iot_esp"),
    (r"\bu-blox\b", "iot_esp"),
    (r"\btexas inst\b", "iot_esp"),

    # Raspberry Pi / SBC
    (r"\braspberry pi\b", "iot_raspberry"),

    # Amazon ecosystem
    (r"\bamazon\b|\bamzn\b", "amazon_device"),
    (r"\bring llc\b|\bring video\b", "amazon_device"),
    (r"\bblink\b", "amazon_device"),

    # Smart home / lighting / plugs
    (r"\bphilips\b|\bsignify\b", "smart_home"),
    (r"\blifx\b", "smart_home"),
    (r"\bgovee\b", "smart_home"),
    (r"\btuya\b|\blocaltuya\b", "smart_home"),
    (r"\btp-link\b|\btp link\b|\bkasa\b", "smart_home"),
    (r"\bbelkin\b|\bwemo\b", "smart_home"),
    (r"\bsengled\b|\byeelight\b|\bszechuan\b", "smart_home"),
    (r"\bnest\b|\bgoogle nest\b", "smart_home"),
    (r"\becobee\b", "smart_home"),
    (r"\bhue\b", "smart_home"),
    (r"\binsteon\b|\blutron\b", "smart_home"),
    (r"\bshelly\b", "smart_home"),

    # Audio devices / speakers / headphones
    (r"\bsonos\b", "audio_device"),
    (r"\bbose\b", "audio_device"),
    (r"\bjbl\b|\bharman\b|\bharman kardon\b", "audio_device"),
    (r"\bsennheiser\b", "audio_device"),
    (r"\bjabra\b|\bgn audio\b", "audio_device"),
    (r"\bplantronics\b|\bpoly\b", "audio_device"),
    (r"\baudio-technica\b", "audio_device"),
    (r"\bdenon\b|\bmarantz\b", "audio_device"),

    # Gaming consoles / controllers
    (r"\bnintendo\b", "gaming"),
    (r"\bsony inter\b|\bsony network\b|\bplaystation\b", "gaming"),
    (r"\bvalve corp\b|\bsteam deck\b", "gaming"),
    (r"\bxbox\b|\bmicrosoft xbox\b", "gaming"),
    (r"\bsteelseries\b|\brazer\b|\bcorsair\b", "gaming"),

    # Network gear / routers / APs / switches
    (r"\bcisco\b|\bcisco-linksys\b", "network_gear"),
    (r"\bubiquiti\b|\bui\b.*ubiquiti", "network_gear"),
    (r"\bmikrotik\b", "network_gear"),
    (r"\bnetgear\b", "network_gear"),
    (r"\blinksys\b", "network_gear"),
    (r"\bzyxel\b", "network_gear"),
    (r"\bruckus\b|\baruba\b|\bmeraki\b", "network_gear"),
    (r"\bbuffalo\b", "network_gear"),
    (r"\bd-link\b|\bdlink\b", "network_gear"),
    (r"\bfortinet\b|\bfortiwifi\b", "network_gear"),
    (r"\bpalo alto\b", "network_gear"),
    (r"\bjuniper\b|\bjunos\b", "network_gear"),
    (r"\bengenius\b", "network_gear"),
    (r"\bwatchguard\b", "network_gear"),
    (r"\bsophos\b", "network_gear"),

    # IP cameras / NVRs / doorbells
    (r"\bhikvision\b", "camera"),
    (r"\bdahua\b", "camera"),
    (r"\bamcrest\b", "camera"),
    (r"\breolink\b", "camera"),
    (r"\bwyze labs\b|\bwyze\b", "camera"),
    (r"\baxis comm\b|\baxis\b", "camera"),
    (r"\bhanwha\b|\bsamsung techwin\b", "camera"),
    (r"\bbosch security\b", "camera"),
    (r"\bvivint\b|\badt\b", "camera"),
    (r"\bfoscam\b|\bzmodo\b|\banker eufycam\b|\beufy\b", "camera"),
    (r"\barlo tech\b|\bnetgear arlo\b", "camera"),
    (r"\bgoogle nest cam\b", "camera"),

    # Printers / MFPs
    (r"\bhp inc\b|\bhewlett-packard\b", "printer"),
    (r"\bbrother\b", "printer"),
    (r"\bepson\b", "printer"),
    (r"\blexmark\b", "printer"),
    (r"\bcanon\b", "printer"),
    (r"\bxerox\b", "printer"),
    (r"\bricoh\b|\bricoh co\b", "printer"),
    (r"\bkonica\b|\bminolta\b|\bkonicaminolta\b", "printer"),
    (r"\bsharp\b", "printer"),
    (r"\bkyocera\b", "printer"),
    (r"\boki\b|\boki data\b", "printer"),

    # Streaming / media players
    (r"\broku\b", "streaming"),
    (r"\bnvidia corp\b", "streaming"),     # Shield TV
    (r"\bgoogle chrome\b|\bchromecast\b", "streaming"),

    # Vehicles / automotive
    (r"\btesla\b", "vehicle"),
    (r"\bford motor\b|\bford\b.*\bmotor", "vehicle"),
    (r"\bbmw\b|\bbayerische\b", "vehicle"),
    (r"\bmercedes\b|\bdaimler\b", "vehicle"),
    (r"\baudi\b", "vehicle"),
    (r"\bvolvo\b", "vehicle"),
    (r"\bgeneral motor\b|\bgm\b", "vehicle"),
    (r"\bhyundai\b|\bkia\b", "vehicle"),
    (r"\btoyota\b|\blexus\b", "vehicle"),
    (r"\bvolkswagen\b|\bvw\b", "vehicle"),
    (r"\bsubaru\b|\brivian\b|\blucid\b", "vehicle"),
    (r"\bcontinent\b.*\bauton", "vehicle"),      # Continental Automotive

    # Smart TVs
    (r"\bsamsung.*tv\b|\btizen\b", "smart_tv"),
    (r"\blg electron.*tv\b|\bwebos\b", "smart_tv"),
    (r"\bvizio\b", "smart_tv"),
    (r"\btcl.*tv\b", "smart_tv"),
    (r"\bhisense\b", "smart_tv"),

    # Medical / industrial (rare but good to flag)
    (r"\bphilips medical\b|\bge health\b|\bsiemens health\b", "medical"),
]

PROBE_PATTERNS: list[tuple[str, str]] = [
    (r"\bgalaxy\b|\bandroid\b|\bpixel\b", "android_phone"),
    (r"\biphone\b|\bipad\b|\bmacbook\b|\bairport\b", "apple_device"),
    (r"\bprinter\b|\bprint.srv\b|\bhp.laserjet\b", "printer"),
    (r"\broku\b|\bfiretv\b|\bappletv\b|\bchromecast\b|\bshield\b", "streaming"),
    (r"\bandroidap\b|\bandroid.ap\b|\bhotspot\b", "android_phone"),
    (r"\biphone\s+hotspot\b|\bpersonal hotspot\b", "apple_device"),
    (r"\bxbox\b|\bplaystation\b|\bnintendo\b", "gaming"),
    (r"\becho\b|\bamazon\b", "amazon_device"),
    (r"\bcamera\b|\bcam\b", "camera"),
    (r"\bring\b|\bdoorbell\b", "amazon_device"),
    (r"\bnest\b|\becobee\b", "smart_home"),
    (r"\bsonos\b", "audio_device"),
    (r"\btesla\b|\bvehicle\b|\bcar\b", "vehicle"),
]

DEVICE_ICONS: dict[str, str] = {
    "apple_device":  "🍎",
    "android_phone": "📱",
    "laptop":        "💻",
    "iot_esp":       "🔌",
    "iot_raspberry": "🍓",
    "amazon_device": "📦",
    "smart_home":    "🏠",
    "audio_device":  "🔊",
    "gaming":        "🎮",
    "network_gear":  "🌐",
    "camera":        "📷",
    "printer":       "🖨️",
    "streaming":     "📺",
    "vehicle":       "🚗",
    "smart_tv":      "📺",
    "medical":       "🏥",
    "mobile_device": "📱",
    "unknown":       "❓",
}

DEVICE_LABELS: dict[str, str] = {
    "apple_device":  "Apple Device",
    "android_phone": "Android Phone",
    "laptop":        "Laptop / PC",
    "iot_esp":       "IoT (ESP/MCU)",
    "iot_raspberry": "Raspberry Pi",
    "amazon_device": "Amazon Device",
    "smart_home":    "Smart Home",
    "audio_device":  "Audio Device",
    "gaming":        "Gaming Console",
    "network_gear":  "Network Gear",
    "camera":        "IP Camera",
    "printer":       "Printer",
    "streaming":     "Streaming Device",
    "vehicle":       "Vehicle",
    "smart_tv":      "Smart TV",
    "medical":       "Medical Device",
    "mobile_device": "Mobile Device",
    "unknown":       "Unknown",
}


def classify_device(
    vendor: str,
    probes: List[str],
    is_randomized: bool,
    channel: Optional[str] = None,
    speed: Optional[str] = None,
    packets: Optional[str] = None,
) -> str:
    """
    Returns a device_type string.

    Extra hints:
      channel — AP channel the client is associated with (5 GHz → newer device)
      speed   — negotiated data rate from airodump (high rates → 802.11ac/ax → modern)
      packets — packet count (very low = IoT; high + 5GHz = laptop/phone)
    """
    v = vendor.lower()

    # Vendor-name matching first (most reliable when OUI is not randomized)
    for pattern, dtype in VENDOR_PATTERNS:
        if re.search(pattern, v):
            return dtype

    # Probe SSID matching
    for probe in probes:
        p = probe.lower()
        for pattern, dtype in PROBE_PATTERNS:
            if re.search(pattern, p):
                return dtype

    # Heuristic fallbacks using RF hints
    if is_randomized:
        # Randomized MACs are always phones/tablets (iOS/Android enforce this)
        ch = _parse_int(channel)
        spd = _parse_int(speed)
        if ch and ch > 14:
            # 5 GHz + randomized = modern phone
            return "android_phone" if spd and spd > 200 else "mobile_device"
        return "mobile_device"

    # Very low speed → likely IoT (e.g. 1–11 Mbps = 802.11b/g only)
    spd = _parse_int(speed)
    if spd and spd <= 11:
        return "iot_esp"

    # High-rate 5 GHz client with no OUI match → probably a laptop
    ch = _parse_int(channel)
    if ch and ch > 14 and spd and spd >= 300:
        return "laptop"

    return "unknown"


def _parse_int(val: Optional[str]) -> Optional[int]:
    try:
        return int(str(val or "").strip())
    except (ValueError, TypeError):
        return None


def device_icon(device_type: str) -> str:
    return DEVICE_ICONS.get(device_type, "❓")


def device_label(device_type: str) -> str:
    return DEVICE_LABELS.get(device_type, "Unknown")
