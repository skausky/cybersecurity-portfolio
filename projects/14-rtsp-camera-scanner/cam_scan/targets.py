"""Random public IPv4 target generation with IANA-reserved filtering."""
from __future__ import annotations

import ipaddress
import random
from typing import Iterator, Literal

Mode = Literal["ips", "cidr24", "cidr16"]

# Major US residential/ISP allocations (ARIN-registered, predominantly domestic).
# Covers Comcast, Charter/Spectrum, AT&T, Verizon, Cox, CenturyLink, T-Mobile, etc.
# ~85-90% of IPs drawn from these blocks will geolocate to the US.
_US_BLOCKS = [
    ipaddress.IPv4Network(n) for n in (
        # Comcast
        "24.0.0.0/12", "50.128.0.0/9", "73.0.0.0/8",
        "96.0.0.0/11", "174.48.0.0/12", "184.56.0.0/13",
        # Charter / Spectrum
        "24.58.0.0/15", "71.0.0.0/10", "72.128.0.0/9",
        "75.64.0.0/11", "98.192.0.0/10",
        # AT&T (residential)
        "12.0.0.0/8", "68.64.0.0/11", "107.192.0.0/10",
        # Verizon / Frontier
        "69.128.0.0/9", "97.0.0.0/10", "174.192.0.0/10",
        # Cox Communications
        "68.0.0.0/11", "75.0.0.0/11",
        # CenturyLink / Lumen
        "63.224.0.0/11", "65.0.0.0/11", "66.192.0.0/11",
        # T-Mobile home internet
        "172.32.0.0/11",
        # Bright House / Windstream / misc US cable
        "76.0.0.0/10", "99.0.0.0/10",
    )
]
# Flatten overlaps and build as IPv4Network list for membership test
_US_BLOCKS = sorted(set(_US_BLOCKS), key=lambda n: int(n.network_address))

_EXCLUDED = [
    ipaddress.IPv4Network(n) for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
]


def _is_public(ip: ipaddress.IPv4Address) -> bool:
    if (ip.is_private or ip.is_reserved or ip.is_multicast
            or ip.is_loopback or ip.is_link_local or ip.is_unspecified):
        return False
    return not any(ip in net for net in _EXCLUDED)


def random_us_ip(rng: random.Random | None = None) -> ipaddress.IPv4Address:
    """Pick a random IP from the US-block table."""
    r = rng or random
    # Weight blocks by size so larger blocks get proportionally more draws
    block = r.choices(_US_BLOCKS, weights=[n.num_addresses for n in _US_BLOCKS], k=1)[0]
    while True:
        offset = r.randint(1, block.num_addresses - 2)
        ip = block.network_address + offset
        addr = ipaddress.IPv4Address(ip)
        if _is_public(addr):
            return addr


def random_public_ip(rng: random.Random | None = None) -> ipaddress.IPv4Address:
    r = rng or random
    while True:
        candidate = ipaddress.IPv4Address(r.randint(1, (1 << 32) - 2))
        if _is_public(candidate):
            return candidate


def random_public_cidr(prefix_len: int,
                       rng: random.Random | None = None) -> ipaddress.IPv4Network:
    if not 8 <= prefix_len <= 32:
        raise ValueError("prefix_len must be in [8, 32]")
    r = rng or random
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    while True:
        base = r.randint(1, (1 << 32) - 2) & mask
        net = ipaddress.IPv4Network((base, prefix_len), strict=True)
        if any(net.overlaps(ex) for ex in _EXCLUDED):
            continue
        if not _is_public(net.network_address) and prefix_len >= 31:
            continue
        return net


def generate(count: int, mode: Mode = "ips",
             seed: int | None = None,
             us_only: bool = False) -> Iterator[str]:
    """Yield `count` target strings (single IPs or CIDR blocks)."""
    if count <= 0:
        return
    rng = random.Random(seed)
    if mode == "ips":
        ip_fn = random_us_ip if us_only else random_public_ip
        for _ in range(count):
            yield str(ip_fn(rng))
    elif mode == "cidr24":
        for _ in range(count):
            yield str(random_public_cidr(24, rng))
    elif mode == "cidr16":
        for _ in range(count):
            yield str(random_public_cidr(16, rng))
    else:
        raise ValueError(f"unknown mode: {mode}")


def batched(it: Iterator[str], size: int) -> Iterator[list[str]]:
    buf: list[str] = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf
