"""ARP-based host discovery — reads the system ARP cache (no raw sockets needed)."""
from __future__ import annotations
import re
import subprocess
from gravwell.models.dataclasses import Host

# Regex covers both Windows and Linux/macOS ARP output:
#   Windows:  "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
#   Linux:    "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
#   macOS:    "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
_ARP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})"          # IPv4 address
    r"[^\n]*?"                              # anything between
    r"([0-9a-f]{2}[:\-][0-9a-f]{2}[:\-]"  # MAC address (colon or dash)
    r"[0-9a-f]{2}[:\-][0-9a-f]{2}[:\-]"
    r"[0-9a-f]{2}[:\-][0-9a-f]{2})",
    re.IGNORECASE,
)

_IGNORE_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def get_arp_hosts() -> list[Host]:
    """Parse the system ARP table and return discovered hosts."""
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
    except Exception:
        return []

    hosts: list[Host] = []
    seen: set[str] = set()

    for m in _ARP_RE.finditer(output):
        ip  = m.group(1)
        mac = m.group(2).replace("-", ":").lower()

        if ip in seen or mac in _IGNORE_MACS:
            continue
        seen.add(ip)

        hosts.append(Host(
            ip=ip,
            mac=mac.upper(),
            status="up",
            source_files=["discovery:arp"],
        ))

    return hosts
