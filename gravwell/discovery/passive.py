"""Passive host discovery via network traffic capture on a VPN interface.

Sniffs packets on the specified interface and extracts every unique unicast
IPv4 address observed as a source or destination.  This reveals hosts that
firewalls won't answer for in active scans — the host simply has to *send*
traffic through the tunnel.

Requirements
------------
  pip install scapy
  Windows: also install Npcap from https://npcap.com/  (replaces WinPcap)
  Linux:   run as root, or set the raw-socket capability:
           sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

DNS resolver tagging
--------------------
When a packet is directed *to* port 53 UDP from an observed internal IP,
that IP is tagged as "dns-resolver" — a useful pivot for internal DNS enum.

All discovered hosts are assigned:
  source_files = ["discovery:passive"]
"""
from __future__ import annotations

import ipaddress

from gravwell.models.dataclasses import Host


def passive_listen(
    interface: str,
    duration: float = 30.0,
    target_net: str | None = None,
) -> list[Host]:
    """Capture traffic on *interface* for *duration* seconds.

    Parameters
    ----------
    interface:
        Network interface name (e.g. "tun0", "Ethernet 2", "\\Device\\NPF_{...}").
        Use :func:`list_interfaces` to enumerate available interfaces.
    duration:
        How long to listen in seconds (default 30).
    target_net:
        Optional CIDR to restrict results (e.g. "10.10.0.0/16").
        If given, only IPs inside this network are returned.

    Returns
    -------
    list[Host]
        One Host per unique interesting IP observed in traffic.

    Raises
    ------
    RuntimeError
        If scapy is not installed or the interface cannot be opened.
    """
    try:
        from scapy.all import sniff, IP, UDP  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required for passive discovery.\n"
            "Install with:  pip install scapy\n"
            "Windows also needs Npcap from https://npcap.com/"
        ) from exc

    # Restrict to target subnet if provided
    target_network: ipaddress.IPv4Network | None = None
    if target_net:
        try:
            target_network = ipaddress.ip_network(target_net, strict=False)
        except ValueError:
            pass

    # ip_str → set of tags
    seen: dict[str, set[str]] = {}

    def _process(pkt) -> None:
        if not pkt.haslayer(IP):
            return
        ip_layer = pkt[IP]
        for ip_str in (ip_layer.src, ip_layer.dst):
            if not _is_interesting(ip_str, target_network):
                continue
            tags = seen.setdefault(ip_str, set())
            # Tag the *source* of a DNS query as a likely internal resolver
            if (pkt.haslayer(UDP) and pkt[UDP].dport == 53
                    and ip_str == ip_layer.src):
                tags.add("dns-resolver")

    try:
        sniff(
            iface=interface,
            filter="ip",
            prn=_process,
            timeout=duration,
            store=False,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to capture on interface '{interface}': {exc}\n"
            "Check that the interface name is correct and you have "
            "sufficient privileges (root / Npcap)."
        ) from exc

    hosts: list[Host] = []
    for ip_str, tags in seen.items():
        hosts.append(Host(
            ip=ip_str,
            status="up",
            tags=sorted(tags),
            source_files=["discovery:passive"],
        ))
    return hosts


def list_interfaces() -> list[str]:
    """Return available network interface names (requires scapy)."""
    try:
        from scapy.all import get_if_list  # type: ignore[import]
        return get_if_list()
    except ImportError:
        return []


def _is_interesting(
    ip_str: str,
    target_net: ipaddress.IPv4Network | None = None,
) -> bool:
    """Return True for unicast, non-loopback, non-link-local IPv4 addresses."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    if (addr.is_multicast or addr.is_loopback or addr.is_unspecified
            or addr.is_link_local or str(addr) == "255.255.255.255"):
        return False
    if target_net is not None and addr not in target_net:
        return False
    return True
