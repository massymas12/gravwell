#!/usr/bin/env python3
"""
GravWell Collection Agent v1.2

Collects network reconnaissance data from the local machine and optionally
uploads it to a GravWell server for import into the network graph.

Discovery methods (all stdlib-only, no third-party packages required):
  - ARP / IPv6 neighbor table
  - Active TCP connection harvest (netstat)
  - Windows DNS cache (ipconfig /displaydns) and SMB browse list (net view)
  - mDNS multicast (224.0.0.251:5353) — Apple, Linux/Avahi, IoT devices
  - SSDP multicast (239.255.255.250:1900) — UPnP / smart appliances
  - TCP-first host discovery (50+ common ports) with ICMP supplement
  - NetBIOS Node Status (UDP 137) hostname resolution
  - Reverse DNS sweep (PTR records)
  - TLS certificate extraction (CN + SANs reveal internal FQDNs)
  - HTTP/HTTPS enrichment (Server header + page title fingerprinting)
  - nmap -sn / nmap port scan (used automatically when available)

Usage:
    python collect.py [options]

    --output PATH     Write JSON to PATH  (default: gravwell_collect_<host>_<ts>.json)
    --server URL      GravWell server URL (e.g. https://gravwell.corp.local)
    --key TOKEN       API key for server upload
    --no-sweep        Skip active host discovery (TCP probe + ping)
    --no-scan         Skip port scan
    --routes          Also sweep routed (non-directly-attached) subnets
    --timeout SECS    Scan/ping timeout in seconds (default: 1.0)
    --workers N       Concurrent threads for socket scan (default: 150)
    --rate N          Raw SYN scan rate packets/sec — Linux/macOS + root only (default: 10000)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

VERSION = "1.4"

# ── Port lists ────────────────────────────────────────────────────────────────

_TOP_PORTS: List[Tuple[int, str]] = [
    # ── Remote access ──────────────────────────────────────────
    (21,    "ftp"),
    (22,    "ssh"),
    (23,    "telnet"),
    (3389,  "rdp"),
    (5900,  "vnc"),
    (5901,  "vnc-1"),
    (5985,  "winrm"),
    (5986,  "winrm-https"),
    # ── Windows / AD ───────────────────────────────────────────
    (88,    "kerberos"),
    (135,   "msrpc"),
    (139,   "netbios-ssn"),
    (389,   "ldap"),
    (445,   "smb"),
    (636,   "ldaps"),
    (3268,  "ldap-gc"),
    (3269,  "ldaps-gc"),
    # ── Web ────────────────────────────────────────────────────
    (80,    "http"),
    (443,   "https"),
    (8080,  "http-alt"),
    (8443,  "https-alt"),
    (8888,  "jupyter"),
    (8000,  "http-dev"),
    (8008,  "http-alt2"),
    # ── Mail ───────────────────────────────────────────────────
    (25,    "smtp"),
    (110,   "pop3"),
    (143,   "imap"),
    (465,   "smtps"),
    (587,   "smtp-submission"),
    (993,   "imaps"),
    (995,   "pop3s"),
    # ── DNS / NTP / infrastructure ─────────────────────────────
    (53,    "dns"),
    (111,   "rpcbind"),
    # ── Databases ──────────────────────────────────────────────
    (1433,  "mssql"),
    (1521,  "oracle-db"),
    (3306,  "mysql"),
    (5432,  "postgresql"),
    (6379,  "redis"),
    (9200,  "elasticsearch"),
    (27017, "mongodb"),
    (5984,  "couchdb"),
    (7474,  "neo4j"),
    # ── Linux / Unix ───────────────────────────────────────────
    (2049,  "nfs"),
    (512,   "rexec"),
    (513,   "rlogin"),
    (514,   "rsh"),
    # ── macOS ──────────────────────────────────────────────────
    (548,   "afp"),
    (3283,  "apple-remote-desktop"),
    # ── Containers / orchestration ─────────────────────────────
    (2375,  "docker"),
    (2376,  "docker-tls"),
    (2379,  "etcd"),
    (6443,  "kubernetes-api"),
    (10250, "kubelet"),
    # ── VoIP ───────────────────────────────────────────────────
    (5060,  "sip"),
    (5061,  "sip-tls"),
    # ── Printers ───────────────────────────────────────────────
    (515,   "lpd"),
    (631,   "ipp"),
    (9100,  "jetdirect"),
    # ── Network / management ───────────────────────────────────
    (179,   "bgp"),
    (830,   "netconf"),
    (8291,  "mikrotik-winbox"),
    # ── Media / cameras ────────────────────────────────────────
    (554,   "rtsp"),
    (8554,  "rtsp-alt"),
    # ── Hypervisors ────────────────────────────────────────────
    (902,   "vmware-esxi"),
    (5480,  "vmware-appliance"),
]

_TOP_PORT_NUMS = [p for p, _ in _TOP_PORTS]

# Ports where we attempt to read a plain-text banner
_BANNER_PORTS = {21, 22, 25, 80, 110, 143, 514, 8080}

# Ports where we attempt TLS certificate extraction
_TLS_PORTS = {443, 636, 993, 995, 465, 3269, 5061, 8443}

# Ports where we attempt HTTP enrichment (title + Server header)
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
_HTTPS_PORTS = {443, 8443}

# Raw SYN scanner constants
_RAW_SYN_SECRET: bytes = os.urandom(8)   # per-run HMAC secret — prevents cookie forgery
_RAW_SYN_SRC_PORT: int = 61000           # source port for outgoing SYN packets

# ── OS / role inference ───────────────────────────────────────────────────────
# Maps open port sets → (os_family_hint, role_tags).
# Evaluated in order; first match wins for os_family, all matches accumulate tags.

_ROLE_SIGNATURES: List[Tuple[set, Optional[str], List[str]]] = [
    # Windows / AD
    ({445, 135},            "Windows",  ["smb"]),
    ({445, 88},             "Windows",  ["dc"]),          # Domain Controller
    ({445, 88, 389},        "Windows",  ["dc"]),
    ({3389},                "Windows",  ["rdp"]),
    ({5985},                "Windows",  ["winrm"]),
    ({139},                 "Windows",  []),
    # Linux
    ({22, 111},             "Linux",    []),
    ({22, 2049},            "Linux",    ["nfs"]),
    ({22, 514},             "Linux",    []),
    # macOS
    ({548},                 "macOS",    []),
    ({3283},                "macOS",    []),
    ({548, 5900},           "macOS",    []),
    # Web servers
    ({80, 443},             None,       ["web"]),
    ({80},                  None,       ["web"]),
    ({443},                 None,       ["web"]),
    # Databases
    ({3306},                None,       ["db"]),           # MySQL
    ({5432},                None,       ["db"]),           # PostgreSQL
    ({1433},                None,       ["db"]),           # MSSQL
    ({27017},               None,       ["db"]),           # MongoDB
    ({6379},                None,       ["db"]),           # Redis
    ({1521},                None,       ["db"]),           # Oracle
    # Mail
    ({25, 143},             None,       ["mail"]),
    ({25, 993},             None,       ["mail"]),
    # Printers
    ({9100},                None,       ["printer"]),
    ({515},                 None,       ["printer"]),
    ({631},                 None,       ["printer"]),
    # VoIP
    ({5060},                None,       ["voip"]),
    ({5061},                None,       ["voip"]),
    # Cameras / media
    ({554},                 None,       ["camera"]),
    ({8554},                None,       ["camera"]),
    # Containers / orchestration
    ({2375},                None,       ["docker"]),
    ({2376},                None,       ["docker"]),
    ({6443},                None,       ["kubernetes"]),
    ({10250},               None,       ["kubernetes"]),
    # Hypervisors
    ({902},                 None,       ["hypervisor"]),
    ({5480},                None,       ["hypervisor"]),
    # Network devices (SSH + no SMB/RDP — router/switch heuristic)
    ({22},                  None,       []),               # too generic alone
    ({23},                  "Network",  ["legacy-mgmt"]),
    ({179},                 "Network",  ["router"]),
    ({830},                 "Network",  ["router"]),
    ({8291},                "Network",  ["router"]),       # MikroTik
    # Remote access
    ({5900},                None,       ["vnc"]),
    ({3389},                None,       ["rdp"]),
]


def infer_os_and_roles(open_ports: List[int]) -> Tuple[Optional[str], List[str]]:
    """Return (os_family_hint, role_tags) inferred from a set of open ports."""
    port_set = set(open_ports)
    os_hint: Optional[str] = None
    roles: List[str] = []
    seen_tags: set = set()

    for sig_ports, sig_os, sig_tags in _ROLE_SIGNATURES:
        if sig_ports.issubset(port_set):
            if os_hint is None and sig_os:
                os_hint = sig_os
            for tag in sig_tags:
                if tag not in seen_tags:
                    roles.append(tag)
                    seen_tags.add(tag)

    # Network device heuristic: SSH only, no Windows/Linux-specific ports
    windows_ports = {135, 139, 445, 3389, 5985, 5986, 88, 389}
    linux_ports   = {111, 2049, 514}
    web_ports     = {80, 443, 8080, 8443}
    if (22 in port_set
            and not port_set & windows_ports
            and not port_set & linux_ports
            and not port_set & web_ports
            and len(port_set) <= 3):
        if os_hint is None:
            os_hint = "Network"

    return os_hint, roles


# ── Own system information ────────────────────────────────────────────────────

def collect_self() -> dict:
    """Return a dict describing this machine."""
    hostname = socket.gethostname()
    system = platform.system()

    interfaces: List[dict] = []
    try:
        if system == "Windows":
            interfaces = _interfaces_windows()
        elif system == "Linux":
            interfaces = _interfaces_linux()
        elif system == "Darwin":
            interfaces = _interfaces_macos()
    except Exception as exc:
        _warn(f"Interface enumeration error: {exc}")

    # Fallback: probe a remote addr so the OS picks a source IP
    if not interfaces:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            interfaces = [{"name": "primary", "ip": ip, "netmask": "", "mac": ""}]
        except Exception:
            pass

    all_ips = [i["ip"] for i in interfaces if i.get("ip")]
    all_macs = list({i["mac"] for i in interfaces if i.get("mac")})

    result: dict = {
        "hostname": hostname,
        "platform": system,
        "platform_version": platform.platform(),
        "ips": all_ips,
        "macs": all_macs,
        "interfaces": interfaces,
        "gateway": _collect_default_gateway(system),
        "dns_servers": _collect_dns_servers(system),
    }

    if system == "Windows":
        domain_info = _collect_domain_info_windows()
        result.update(domain_info)

    return result


def _interfaces_windows() -> List[dict]:
    out = _run("ipconfig /all")
    interfaces: List[dict] = []
    current: dict = {}
    dns_servers: List[str] = []
    for line in out.splitlines():
        m = re.match(r"^(\S.*) adapter (.+):", line)
        if m:
            if current.get("ip"):
                interfaces.append(current)
            current = {"name": m.group(2), "ip": "", "netmask": "", "mac": ""}
            continue
        if not current:
            continue
        if not current.get("ip"):
            m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
            if m:
                current["ip"] = m.group(1)
        if not current.get("netmask"):
            m = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
            if m:
                current["netmask"] = m.group(1)
        if not current.get("mac"):
            m = re.search(r"Physical Address[^:]*:\s*([\dA-F-]{17})", line, re.I)
            if m:
                current["mac"] = m.group(1).replace("-", ":").upper()
    if current.get("ip"):
        interfaces.append(current)
    return interfaces


def _interfaces_linux() -> List[dict]:
    out = _run("ip addr show")
    interfaces: List[dict] = []
    current: dict = {}
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            if current.get("ip"):
                interfaces.append(current)
            current = {"name": m.group(1), "ip": "", "netmask": "", "mac": ""}
            continue
        if not current:
            continue
        if not current.get("mac"):
            m = re.search(r"link/ether\s+([\da-f:]{17})", line, re.I)
            if m:
                current["mac"] = m.group(1).upper()
        if not current.get("ip"):
            m = re.search(r"inet\s+([\d.]+)/(\d+)", line)
            if m:
                ip, prefix = m.groups()
                try:
                    nm = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                except ValueError:
                    nm = ""
                current["ip"] = ip
                current["netmask"] = nm
    if current.get("ip"):
        interfaces.append(current)
    return interfaces


def _interfaces_macos() -> List[dict]:
    out = _run("ifconfig")
    interfaces: List[dict] = []
    current: dict = {}
    for line in out.splitlines():
        m = re.match(r"^(\S+):", line)
        if m:
            if current.get("ip"):
                interfaces.append(current)
            current = {"name": m.group(1), "ip": "", "netmask": "", "mac": ""}
            continue
        if not current:
            continue
        if not current.get("mac"):
            m = re.search(r"ether\s+([\da-f:]{17})", line, re.I)
            if m:
                current["mac"] = m.group(1).upper()
        if not current.get("ip"):
            m = re.search(r"inet\s+([\d.]+)\s+netmask\s+0x([0-9a-fA-F]+)", line)
            if m:
                ip, nm_hex = m.groups()
                try:
                    nm_int = int(nm_hex, 16)
                    nm = ".".join(str((nm_int >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
                except ValueError:
                    nm = ""
                current["ip"] = ip
                current["netmask"] = nm
    if current.get("ip"):
        interfaces.append(current)
    return interfaces


def _collect_default_gateway(system: str) -> str:
    """Return the default gateway IP, empty string if not found."""
    try:
        if system == "Windows":
            out = _run("ipconfig")
            m = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", out)
            return m.group(1) if m else ""
        elif system == "Linux":
            out = _run("ip route show default")
            m = re.search(r"default via ([\d.]+)", out)
            return m.group(1) if m else ""
        elif system == "Darwin":
            out = _run("netstat -rn")
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0] == "default":
                    # Gateway is second column; skip link# entries
                    gw = parts[1] if len(parts) > 1 else ""
                    if re.match(r"[\d.]+", gw):
                        return gw
    except Exception:
        pass
    return ""


def _collect_dns_servers(system: str) -> List[str]:
    """Return a list of DNS server IPs."""
    servers: List[str] = []
    try:
        if system == "Windows":
            out = _run("ipconfig /all")
            for line in out.splitlines():
                m = re.search(r"DNS Servers[^:]*:\s*([\d.]+)", line)
                if m:
                    servers.append(m.group(1))
                elif servers:
                    # continuation lines for multiple DNS servers
                    m = re.match(r"\s+([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\s*$", line)
                    if m:
                        servers.append(m.group(1))
        elif system in ("Linux", "Darwin"):
            try:
                with open("/etc/resolv.conf") as fh:
                    for line in fh:
                        m = re.match(r"nameserver\s+([\d.]+)", line.strip())
                        if m:
                            servers.append(m.group(1))
            except OSError:
                pass
            if system == "Darwin" and not servers:
                out = _run("scutil --dns")
                for line in out.splitlines():
                    m = re.search(r"nameserver\[\d+\]\s*:\s*([\d.]+)", line)
                    if m:
                        ip = m.group(1)
                        if ip not in servers:
                            servers.append(ip)
    except Exception:
        pass
    return servers


def _collect_domain_info_windows() -> dict:
    """Return domain/workgroup info from the Windows workstation config."""
    result: dict = {}
    out = _run("net config workstation")
    m = re.search(r"Workstation Domain\s+(\S+)", out)
    if m:
        result["domain"] = m.group(1)
    m = re.search(r"Full Computer Name\s+(\S+)", out)
    if m:
        result["fqdn"] = m.group(1)
    return result


# ── Routing table / extra networks ───────────────────────────────────────────

def discover_networks(system: str) -> Tuple[List[str], List[str]]:
    """Return (directly_attached, routed) network CIDR strings.

    Directly-attached networks are connected to an interface (no next-hop).
    Routed networks go through a gateway and are only swept with --routes.
    Loopback, link-local, and 0.0.0.0/0 are excluded.
    """
    direct: List[str] = []
    routed: List[str] = []
    try:
        if system == "Linux":
            _parse_routes_linux(direct, routed)
        elif system == "Windows":
            _parse_routes_windows(direct, routed)
        elif system == "Darwin":
            _parse_routes_macos(direct, routed)
    except Exception as exc:
        _warn(f"Routing table error: {exc}")
    return direct, routed


def _is_useful_network(net_str: str) -> bool:
    """Return True for private, non-loopback, non-link-local networks."""
    try:
        net = ipaddress.IPv4Network(net_str, strict=False)
        return (net.is_private and not net.is_loopback
                and not net.is_link_local and net.prefixlen < 32)
    except ValueError:
        return False


def _parse_routes_linux(direct: List[str], routed: List[str]) -> None:
    out = _run("ip route show")
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("default"):
            continue
        m = re.match(r"([\d./]+)\s+", line)
        if not m:
            continue
        net_str = m.group(1)
        if not _is_useful_network(net_str):
            continue
        if "via" in line:
            if net_str not in routed:
                routed.append(net_str)
        else:
            if net_str not in direct:
                direct.append(net_str)


def _parse_routes_windows(direct: List[str], routed: List[str]) -> None:
    out = _run("route print")
    in_table = False
    for line in out.splitlines():
        if "Network Destination" in line:
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        dest, mask, gw = parts[0], parts[1], parts[2]
        try:
            net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)
            net_str = str(net)
        except ValueError:
            continue
        if not _is_useful_network(net_str):
            continue
        if gw.lower() in ("on-link", "0.0.0.0"):
            if net_str not in direct:
                direct.append(net_str)
        else:
            if net_str not in routed:
                routed.append(net_str)


def _parse_routes_macos(direct: List[str], routed: List[str]) -> None:
    out = _run("netstat -rn")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] in ("Routing", "Internet:", "Destination"):
            continue
        dest, gw = parts[0], parts[1]
        # Convert short notation e.g. "192.168.1" → "192.168.1.0/24"
        try:
            net = ipaddress.IPv4Network(dest, strict=False)
        except ValueError:
            # macOS may show "192.168.1" without prefix
            try:
                parts_ip = dest.split(".")
                while len(parts_ip) < 4:
                    parts_ip.append("0")
                net = ipaddress.IPv4Network(".".join(parts_ip), strict=False)
            except ValueError:
                continue
        net_str = str(net)
        if not _is_useful_network(net_str):
            continue
        if gw.startswith("link#") or gw == "lo0":
            if net_str not in direct:
                direct.append(net_str)
        elif re.match(r"[\d.]+", gw):
            if net_str not in routed:
                routed.append(net_str)


# ── ARP table ─────────────────────────────────────────────────────────────────

def collect_arp() -> List[dict]:
    system = platform.system()
    neighbors: List[dict] = []
    try:
        if system == "Windows":
            neighbors = _arp_windows()
        elif system == "Linux":
            neighbors = _arp_linux()
            neighbors += _ipv6_neighbors_linux()
        elif system == "Darwin":
            neighbors = _arp_macos()
            neighbors += _ipv6_neighbors_macos()
    except Exception as exc:
        _warn(f"ARP collection error: {exc}")
    return neighbors


def _arp_windows() -> List[dict]:
    out = _run("arp -a")
    neighbors = []
    for line in out.splitlines():
        m = re.match(r"\s+([\d.]+)\s+([\da-fA-F-]{17})\s+(\w+)", line)
        if m:
            ip, mac, kind = m.groups()
            if kind.lower() in ("dynamic", "static"):
                neighbors.append({
                    "ip": ip,
                    "mac": mac.replace("-", ":").upper(),
                    "source": "arp",
                })
    return neighbors


def _arp_linux() -> List[dict]:
    out = _run("ip neigh show")
    neighbors = []
    if out:
        for line in out.splitlines():
            # Only include entries that have a resolved MAC
            m = re.match(r"([\d.]+)\s+dev\s+\S+\s+lladdr\s+([\da-fA-F:]{17})", line)
            if m:
                neighbors.append({
                    "ip": m.group(1),
                    "mac": m.group(2).upper(),
                    "source": "arp",
                })
        if neighbors:
            return neighbors
    # Fallback: arp -a
    out = _run("arp -a")
    for line in out.splitlines():
        m = re.match(r"\S+\s+\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})", line)
        if m:
            neighbors.append({
                "ip": m.group(1),
                "mac": m.group(2).upper(),
                "source": "arp",
            })
    return neighbors


def _arp_macos() -> List[dict]:
    out = _run("arp -a")
    neighbors = []
    for line in out.splitlines():
        m = re.match(r"(\S+)\s+\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})", line)
        if m:
            hn, ip, mac = m.groups()
            entry: dict = {"ip": ip, "mac": mac.upper(), "source": "arp"}
            if hn != "?":
                entry["hostname"] = hn
            neighbors.append(entry)
    return neighbors


def _ipv6_neighbors_linux() -> List[dict]:
    out = _run("ip -6 neigh show")
    neighbors = []
    for line in out.splitlines():
        m = re.match(r"([0-9a-fA-F:]+)\s+dev\s+\S+\s+lladdr\s+([\da-fA-F:]{17})", line)
        if m:
            ipv6, mac = m.groups()
            # Skip link-local (fe80::) — not routable and rarely useful
            if not ipv6.lower().startswith("fe80"):
                neighbors.append({
                    "ip": ipv6,
                    "mac": mac.upper(),
                    "source": "ipv6_neigh",
                })
    return neighbors


def _ipv6_neighbors_macos() -> List[dict]:
    out = _run("ndp -an")
    neighbors = []
    for line in out.splitlines():
        # Neighbor (ipv6addr) at mac on ifname ...
        parts = line.split()
        if len(parts) < 3:
            continue
        ipv6 = parts[0].split("%")[0]  # strip %ifname suffix
        mac = parts[2]
        if not re.match(r"[0-9a-fA-F:]{17}", mac):
            continue
        if ipv6.lower().startswith("fe80"):
            continue
        try:
            ipaddress.IPv6Address(ipv6)
            neighbors.append({"ip": ipv6, "mac": mac.upper(), "source": "ipv6_neigh"})
        except ValueError:
            pass
    return neighbors


# ── Active connection harvesting ──────────────────────────────────────────────

def collect_active_connections() -> List[dict]:
    """Harvest remote IPs from established TCP connections via netstat.

    Discovers servers that block all inbound probes (ICMP + TCP scan) but are
    reachable from this machine — e.g. cloud endpoints, internal APIs, etc.
    """
    neighbors: List[dict] = []
    seen: set = set()
    try:
        out = _run("netstat -an")
        for line in out.splitlines():
            upper = line.upper()
            if "ESTABLISHED" not in upper and "CLOSE_WAIT" not in upper:
                continue
            parts = line.split()
            # Find IP:port pairs; local addr is first, remote is second
            addrs = [p for p in parts
                     if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:.]\d+$", p)]
            if len(addrs) < 2:
                continue
            m = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:.]\d+$", addrs[1])
            if not m:
                continue
            ip = m.group(1)
            try:
                addr = ipaddress.IPv4Address(ip)
                if not addr.is_private or addr.is_loopback or addr.is_unspecified:
                    continue
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                neighbors.append({"ip": ip, "source": "netstat"})
    except Exception as exc:
        _warn(f"netstat harvest error: {exc}")
    return neighbors


# ── Windows-specific passive discovery ───────────────────────────────────────

def collect_windows_dns_cache() -> List[dict]:
    """Parse ipconfig /displaydns for cached A records (Windows only)."""
    neighbors: List[dict] = []
    seen: set = set()
    try:
        out = _run("ipconfig /displaydns")
        current_name = ""
        for line in out.splitlines():
            m = re.search(r"Record Name[^:]*:\s+(\S+)", line)
            if m:
                current_name = m.group(1).rstrip(".")
                continue
            m = re.search(r"A \(Host\) Record[^:]*:\s+([\d.]+)", line)
            if m:
                ip = m.group(1)
                try:
                    addr = ipaddress.IPv4Address(ip)
                    if addr.is_loopback or addr.is_unspecified or not addr.is_private:
                        continue
                except ValueError:
                    continue
                if ip not in seen:
                    seen.add(ip)
                    entry: dict = {"ip": ip, "source": "dns_cache"}
                    if current_name:
                        entry["hostname"] = current_name
                    neighbors.append(entry)
    except Exception as exc:
        _warn(f"DNS cache harvest error: {exc}")
    return neighbors


def collect_smb_neighbors_windows() -> List[dict]:
    """Enumerate Windows machines via SMB browse list (net view)."""
    neighbors: List[dict] = []
    seen: set = set()
    try:
        out = _run("net view")
        for line in out.splitlines():
            m = re.match(r"\\\\(\S+)", line.strip())
            if not m:
                continue
            name = m.group(1)
            try:
                ip = socket.gethostbyname(name)
                try:
                    if not ipaddress.IPv4Address(ip).is_private:
                        continue
                except ValueError:
                    continue
                if ip not in seen:
                    seen.add(ip)
                    neighbors.append({"ip": ip, "hostname": name, "source": "smb"})
            except Exception:
                pass
    except Exception as exc:
        _warn(f"SMB browse error: {exc}")
    return neighbors


# ── NetBIOS name resolution ───────────────────────────────────────────────────

def _netbios_node_status(ip: str, timeout_secs: float) -> Optional[str]:
    """Send NBNS Node Status Request to IP:137. Returns machine name or None."""
    # Header + wildcard name "*\x00×15" L2-encoded + QTYPE=NBSTAT, QCLASS=IN
    pkt = (
        b"\xa4\x56\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_secs)
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) < 13:
            return None
        # QD count tells us how many question entries are echoed back (38 bytes each)
        qd_count = int.from_bytes(data[4:6], "big")
        # answer name = 34 bytes, RR meta (type+class+ttl+rdlen) = 10 bytes
        num_names_offset = 12 + qd_count * 38 + 34 + 10
        if num_names_offset >= len(data):
            return None
        num_names = data[num_names_offset]
        if num_names == 0 or num_names > 32:
            return None
        name_start = num_names_offset + 1
        for i in range(num_names):
            off = name_start + i * 18
            if off + 17 > len(data):
                break
            name_type = data[off + 15]
            flags = int.from_bytes(data[off + 16:off + 18], "big")
            if (flags & 0x8000) or name_type != 0x00:
                continue  # Skip group names and non-workstation entries
            name = data[off:off + 15].decode("ascii", errors="replace").rstrip()
            if name:
                return name
        return None
    except Exception:
        return None


def enrich_netbios(neighbors: List[dict], timeout_secs: float = 1.5) -> None:
    """Query UDP 137 for each neighbor without a hostname to get its NetBIOS name."""
    targets = [n for n in neighbors if not n.get("hostname") and n.get("ip")]
    if not targets:
        return
    lock = threading.Lock()

    def _query(neighbor: dict) -> None:
        ip = neighbor.get("ip", "")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return
        name = _netbios_node_status(ip, timeout_secs)
        if name:
            with lock:
                neighbor["hostname"] = name

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_query, targets))


# ── mDNS / SSDP passive discovery ────────────────────────────────────────────

def _mdns_query(sock: socket.socket, addr: str, port: int) -> None:
    """Send mDNS PTR query for _services._dns-sd._udp.local to solicit responses."""
    pkt = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c\x00\x01"
    )
    try:
        sock.sendto(pkt, (addr, port))
    except Exception:
        pass


def _parse_mdns_name(data: bytes) -> str:
    """Extract a meaningful host label from an mDNS packet (best effort)."""
    try:
        if len(data) < 13:
            return ""
        offset = 12  # Skip DNS header
        parts: List[str] = []
        while offset < len(data):
            length = data[offset]
            if length == 0 or length & 0xC0 == 0xC0:
                break
            offset += 1
            if offset + length > len(data):
                break
            label = data[offset:offset + length].decode("ascii", errors="replace")
            if not label.startswith("_") and label.lower() != "local":
                parts.append(label)
            offset += length
        return parts[0] if parts else ""
    except Exception:
        return ""


def _mdns_listen(timeout_secs: float) -> List[dict]:
    """Join the mDNS multicast group, send a query, and collect responding IPs."""
    import struct
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    neighbors: List[dict] = []
    seen: set = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass  # Windows / older Linux
        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            sock.close()
            return neighbors  # Port owned by avahi-daemon or similar
        mcast = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mcast)
        _mdns_query(sock, MDNS_ADDR, MDNS_PORT)
        deadline = time.monotonic() + timeout_secs
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 0.5))
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if src_ip in seen:
                continue
            seen.add(src_ip)
            hostname = _parse_mdns_name(data)
            entry: dict = {"ip": src_ip, "source": "mdns"}
            if hostname:
                entry["hostname"] = hostname
            neighbors.append(entry)
        sock.close()
    except Exception as exc:
        _warn(f"mDNS listen error: {exc}")
    return neighbors


def _ssdp_listen(timeout_secs: float) -> List[dict]:
    """Send SSDP M-SEARCH and collect responding UPnP device IPs."""
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    neighbors: List[dict] = []
    seen: set = set()
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))
        sock.sendto(msearch.encode(), (SSDP_ADDR, SSDP_PORT))
        deadline = time.monotonic() + timeout_secs
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 0.5))
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if src_ip in seen:
                continue
            seen.add(src_ip)
            entry: dict = {"ip": src_ip, "source": "ssdp"}
            response = data.decode("utf-8", errors="replace")
            m = re.search(r"^Server:\s*(.+)", response, re.I | re.M)
            if m:
                entry["ssdp_server"] = m.group(1).strip()[:100]
            neighbors.append(entry)
        sock.close()
    except Exception as exc:
        _warn(f"SSDP listen error: {exc}")
    return neighbors


def mdns_ssdp_listen(timeout_secs: float = 5.0) -> List[dict]:
    """Discover LAN devices via mDNS (224.0.0.251:5353) and SSDP (239.255.255.250:1900).

    Covers Apple/Linux/IoT devices (mDNS/Bonjour) and UPnP appliances such as
    smart TVs, NAS boxes, printers, and routers (SSDP). No third-party packages.
    """
    results: List[dict] = []
    lock = threading.Lock()

    def _run_listener(fn):
        items = fn(timeout_secs)
        with lock:
            results.extend(items)

    threads = [
        threading.Thread(target=_run_listener, args=(_mdns_listen,), daemon=True),
        threading.Thread(target=_run_listener, args=(_ssdp_listen,), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


# ── Reverse DNS sweep ─────────────────────────────────────────────────────────

def reverse_dns_sweep(ips: List[str]) -> Dict[str, str]:
    """PTR-resolve a list of IPs concurrently. Returns {ip: hostname}."""
    result: Dict[str, str] = {}
    lock = threading.Lock()

    def _resolve(ip: str) -> None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                with lock:
                    result[ip] = hostname
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_resolve, ips))
    return result


# ── TLS certificate extraction ────────────────────────────────────────────────

def enrich_tls(scan_results: List[dict], timeout: float = 2.0, workers: int = 30) -> None:
    """Extract TLS certificate CN and SANs from HTTPS/LDAPS/etc ports.

    Stores tls_cn and tls_sans on matching port entries (in-place). SANs
    often reveal internal FQDNs not visible via reverse DNS or NetBIOS.
    """
    import ssl

    tasks = [
        (host["ip"], pe["port"], pe)
        for host in scan_results
        for pe in host.get("open_ports", [])
        if pe.get("port") in _TLS_PORTS
    ]
    if not tasks:
        return

    def _grab_cert(task: Tuple) -> None:
        ip, port, port_entry = task
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
            if not cert:
                return
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "")
            if cn:
                port_entry["tls_cn"] = cn
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            if sans:
                port_entry["tls_sans"] = sans
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_grab_cert, tasks))


# ── HTTP enrichment ───────────────────────────────────────────────────────────

def enrich_http(scan_results: List[dict], timeout: float = 3.0, workers: int = 20) -> None:
    """Extract <title> and Server header from HTTP/HTTPS ports.

    Stores http_title and http_server on matching port entries (in-place).
    Page titles fingerprint appliances, routers, and management UIs that
    don't expose hostnames any other way.
    """
    import ssl
    import urllib.request

    tasks = [
        (host["ip"], pe["port"], pe)
        for host in scan_results
        for pe in host.get("open_ports", [])
        if pe.get("port") in _HTTP_PORTS or pe.get("port") in _HTTPS_PORTS
    ]
    if not tasks:
        return

    def _fetch(task: Tuple) -> None:
        ip, port, port_entry = task
        is_https = port in _HTTPS_PORTS
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GravWell/1.1"})
            if is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            with resp:
                server = resp.headers.get("Server", "")
                if server:
                    port_entry["http_server"] = server[:100]
                ctype = resp.headers.get("Content-Type", "")
                if "html" in ctype.lower():
                    body = resp.read(8192).decode("utf-8", errors="replace")
                    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
                    if m:
                        port_entry["http_title"] = m.group(1).strip()
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_fetch, tasks))


# ── Raw SYN scanner ──────────────────────────────────────────────────────────
#
# Linux/macOS + root only.  Crafts IP+TCP SYN packets via SOCK_RAW, fires them
# at a configurable rate, and listens for SYN-ACKs on a parallel RX thread.
# Responses are validated with an HMAC SYN cookie stored in the TCP seq field —
# no per-target state table is needed.
#
# The OS automatically sends RST to any SYN-ACK that arrives on our source
# port (nothing is listening there), which cleanly tears down half-open
# connections on the target.  The raw RX socket sees the SYN-ACK before the
# kernel's RST goes out, so no responses are missed.


def _raw_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack_from('!' + 'H' * (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _syn_cookie(dst_ip: str, dst_port: int) -> int:
    """HMAC-MD5 cookie packed into a uint32, embedded in the TCP sequence number."""
    msg = f"{dst_ip}:{dst_port}".encode()
    digest = hmac.new(_RAW_SYN_SECRET, msg, hashlib.md5).digest()
    return struct.unpack('!I', digest[:4])[0]


def _build_syn(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Return a 40-byte raw IP + TCP SYN packet."""
    seq = _syn_cookie(dst_ip, dst_port)
    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)

    # TCP header (checksum = 0 placeholder)
    tcp = struct.pack('!HHIIBBHHH',
        _RAW_SYN_SRC_PORT, dst_port,
        seq, 0,        # seq, ack=0
        0x50, 0x02,    # data offset=5 (20 bytes), flags=SYN
        1024, 0, 0,    # window, checksum placeholder, urgent
    )
    pseudo = struct.pack('!4s4sBBH', src_b, dst_b, 0, 6, len(tcp))
    tcp_cs = _raw_checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack('!H', tcp_cs) + tcp[18:]

    # IP header (checksum = 0 placeholder)
    ip = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40,    # ver+IHL, TOS, total len (20+20)
        0, 0x4000,      # id=0, DF flag
        64, 6, 0,       # TTL, proto=TCP, checksum placeholder
        src_b, dst_b,
    )
    ip_cs = _raw_checksum(ip)
    ip = ip[:10] + struct.pack('!H', ip_cs) + ip[12:]
    return ip + tcp


def _parse_syn_ack(pkt: bytes) -> Optional[Tuple[str, int]]:
    """Return (src_ip, src_port) if *pkt* is a SYN-ACK matching our cookie, else None."""
    try:
        ihl = (pkt[0] & 0x0F) * 4
        if pkt[9] != 6:                      # not TCP
            return None
        src_ip  = socket.inet_ntoa(pkt[12:16])
        tcp     = pkt[ihl:]
        src_port = struct.unpack('!H', tcp[0:2])[0]
        dst_port = struct.unpack('!H', tcp[2:4])[0]
        ack_num  = struct.unpack('!I', tcp[8:12])[0]
        flags    = tcp[13]
        if dst_port != _RAW_SYN_SRC_PORT:    # not addressed to us
            return None
        if flags & 0x12 != 0x12:             # not SYN+ACK
            return None
        expected = (_syn_cookie(src_ip, src_port) + 1) & 0xFFFFFFFF
        if ack_num != expected:              # cookie mismatch — not our packet
            return None
        return src_ip, src_port
    except Exception:
        return None


def _raw_syn_scan(
    targets: List[str],
    ports: List[int],
    timeout_secs: float = 1.0,
    rate_pps: int = 10_000,
) -> Optional[Tuple[List[str], Dict[str, List[int]]]]:
    """Raw SYN scanner — Linux/macOS with root privileges only.

    Sends IP+TCP SYN packets at *rate_pps* packets/second via a raw socket.
    A parallel RX thread captures SYN-ACKs and validates them via HMAC cookie.
    No per-target state table; dead hosts cost zero wait time.

    Scans *ports* against every IP in *targets* in a single pass, so discovery
    and port scan are combined into one sweep.

    Returns (live_ips, {ip: [open_ports]}) or None if unavailable.
    """
    if platform.system() == "Windows" or not _is_elevated():
        return None

    try:
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        rx_sock.settimeout(0.05)
    except OSError:
        return None

    # Determine our outbound source IP
    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        src_ip = _s.getsockname()[0]
        _s.close()
    except Exception:
        tx_sock.close()
        rx_sock.close()
        return None

    open_ports: Dict[str, List[int]] = {}
    lock = threading.Lock()
    tx_done = threading.Event()

    tasks = [(ip, port) for ip in targets for port in ports]
    total_pkts = len(tasks)

    def _tx() -> None:
        interval = 1.0 / rate_pps
        next_send = time.monotonic()
        for ip, port in tasks:
            pkt = _build_syn(src_ip, ip, port)
            try:
                tx_sock.sendto(pkt, (ip, 0))
            except Exception:
                pass
            next_send += interval
            delta = next_send - time.monotonic()
            if delta > 0:
                time.sleep(delta)
        tx_done.set()

    def _rx() -> None:
        deadline: Optional[float] = None
        while True:
            if tx_done.is_set():
                if deadline is None:
                    deadline = time.monotonic() + timeout_secs
                if time.monotonic() >= deadline:
                    break
            try:
                pkt, _ = rx_sock.recvfrom(65535)
                result = _parse_syn_ack(pkt)
                if result:
                    ip, port = result
                    with lock:
                        if ip not in open_ports:
                            open_ports[ip] = []
                        if port not in open_ports[ip]:
                            open_ports[ip].append(port)
            except socket.timeout:
                continue
            except OSError:
                break

    rx_thread = threading.Thread(target=_rx, daemon=True)
    tx_thread = threading.Thread(target=_tx, daemon=True)
    rx_thread.start()
    tx_thread.start()
    tx_thread.join()
    rx_thread.join()

    tx_sock.close()
    rx_sock.close()

    live = list(open_ports.keys())
    send_secs = total_pkts / rate_pps
    _info(f"  Raw SYN: {total_pkts:,} pkts @ {rate_pps:,} pps "
          f"({send_secs:.1f}s TX + {timeout_secs:.1f}s wait) → "
          f"{len(live)} hosts")
    return live, open_ports


# ── Host discovery ────────────────────────────────────────────────────────────

# Ports probed to determine liveness when ICMP is blocked.
# One hit on any port = host is alive. Covers all major OS/device types:
#   Windows:  135, 445, 3389
#   Linux:    22
#   macOS:    22, 548
#   Web:      80, 443, 8080, 8443
#   Printers: 9100, 631
#   Network:  23
#   Cameras:  554
#   VoIP:     5060
_PROBE_PORTS = [22, 80, 135, 443, 445, 548, 554, 631, 3389, 5060, 8080, 8443, 9100, 23]


def host_discovery(
    networks: List[str],
    timeout_secs: float = 1.0,
    workers: int = 200,
    rate_pps: int = 10_000,
) -> Tuple[List[str], Dict[str, List[int]]]:
    """Discover live hosts across the given CIDR networks.

    Priority:
      1. nmap -sn         — ARP + TCP SYN + ICMP simultaneously. Best if available.
      2. Raw SYN scan     — masscan-style; Linux/macOS + root only. Combines host
                            discovery and port scan into one pass at up to rate_pps
                            packets/second. Dead hosts cost zero wait time.
      3. TCP connect()    — parallel socket connects; works everywhere without root.
         + ICMP ping      — run concurrently with TCP to catch ICMP-only devices.

    Returns (live_ips, known_open) where known_open is {ip: [open_ports]}
    — passed to port_scan to skip re-scanning already-confirmed ports.
    """
    targets = _expand_networks(networks)
    if not targets:
        return [], {}

    _info(f"Host discovery: {len(targets)} targets across {len(networks)} network(s)…")

    # 1. nmap -sn
    nmap_live = _nmap_host_discovery(targets, timeout_secs)
    if nmap_live is not None:
        _info(f"Host discovery done (nmap -sn): {len(nmap_live)} hosts")
        return nmap_live, {}

    # 2. Raw SYN scan — scans all _TOP_PORTS in one pass (discovery + port scan)
    raw = _raw_syn_scan(targets, _TOP_PORT_NUMS, timeout_secs, rate_pps)
    if raw is not None:
        live, known_open = raw
        _info(f"Host discovery done (raw SYN): {len(live)} hosts")
        return live, known_open

    # 3. TCP connect + ICMP — run concurrently
    tcp_result: List[Tuple[List[str], Dict[str, List[int]]]] = []
    icmp_live: List[str] = []

    def _run_tcp() -> None:
        tcp_result.append(_tcp_probe_sweep(targets, timeout_secs, workers))

    def _run_icmp() -> None:
        icmp_live.extend(_icmp_sweep(targets, timeout_secs, workers))

    t_tcp  = threading.Thread(target=_run_tcp,  daemon=True)
    t_icmp = threading.Thread(target=_run_icmp, daemon=True)
    t_tcp.start()
    t_icmp.start()
    t_tcp.join()
    t_icmp.join()

    tcp_live, known_open = tcp_result[0] if tcp_result else ([], {})
    live_set: set = set(tcp_live)
    new_icmp = [ip for ip in icmp_live if ip not in live_set]
    live_set.update(icmp_live)
    _info(f"  TCP probe: {len(tcp_live)} hosts  |  ICMP: {len(new_icmp)} additional")

    _info(f"Host discovery done: {len(live_set)} hosts")
    return list(live_set), known_open


def _expand_networks(networks: List[str]) -> List[str]:
    """Expand CIDR networks into individual host IPs, chunking large nets at /24."""
    targets: List[str] = []
    for net_str in networks:
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            if net.prefixlen < 24:
                for subnet in net.subnets(new_prefix=24):
                    targets.extend(str(h) for h in subnet.hosts())
            else:
                targets.extend(str(h) for h in net.hosts())
        except ValueError:
            continue
    return targets


def _nmap_write_targets(ips: List[str]) -> str:
    """Write IPs to a temp file and return its path. Caller must delete it."""
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="nmap_targets_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(ips))
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _nmap_host_discovery(targets: List[str], timeout_secs: float) -> Optional[List[str]]:
    """Use nmap -sn for multi-probe host discovery. Returns None if nmap unavailable."""
    import shutil
    if not shutil.which("nmap"):
        return None
    tmp = _nmap_write_targets(targets)
    try:
        timing = "-T4" if timeout_secs <= 1.0 else "-T3"
        _info("  Using nmap -sn for host discovery…")
        import xml.etree.ElementTree as ET
        cmd_xml = ["nmap", "-sn", "-oX", "-", timing, "-iL", tmp]
        r = subprocess.run(cmd_xml, capture_output=True, text=True, timeout=600)
        xml_out = r.stdout.strip()
        if not xml_out.startswith("<?xml"):
            return None

        root = ET.fromstring(xml_out)
        live = []
        for host_el in root.findall("host"):
            state = host_el.find("status")
            if state is None or state.get("state") != "up":
                continue
            addr_el = host_el.find('address[@addrtype="ipv4"]')
            if addr_el is not None:
                live.append(addr_el.get("addr", ""))
        return [ip for ip in live if ip]
    except Exception as exc:
        _warn(f"nmap -sn failed ({exc}), falling back to TCP+ICMP discovery")
        return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _tcp_probe_sweep(targets: List[str], timeout_secs: float,
                     workers: int) -> Tuple[List[str], Dict[str, List[int]]]:
    """TCP connect probe: a host is alive if any probe port accepts a connection.

    All probe ports are tried in parallel per host (scatter). A dead host
    costs exactly one timeout (0.5 s) regardless of how many ports are probed,
    rather than N × timeout for a sequential approach.

    Returns (live_ips, {ip: [open_probe_ports]}) — the open probe ports are
    passed to port_scan so they don't need to be re-scanned.
    """
    live: List[str] = []
    open_probe_ports: Dict[str, List[int]] = {}
    lock = threading.Lock()
    probe_timeout = min(timeout_secs, 0.5)

    def _probe(ip: str) -> Optional[Tuple[str, List[int]]]:
        open_ports: List[int] = []
        found = threading.Event()

        def _try_port(port: int) -> None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(probe_timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    with lock:
                        open_ports.append(port)
                    found.set()
                    return
                s.close()
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(_PROBE_PORTS)) as port_ex:
            futs = [port_ex.submit(_try_port, p) for p in _PROBE_PORTS]
            concurrent.futures.wait(futs, timeout=probe_timeout + 0.1)
            for f in futs:
                f.cancel()

        return (ip, open_ports) if open_ports else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_probe, targets):
            if result:
                ip, ports = result
                live.append(ip)
                open_probe_ports[ip] = ports
    return live, open_probe_ports


def _icmp_sweep(targets: List[str], timeout_secs: float,
                workers: int) -> List[str]:
    """ICMP ping sweep. Uses fping when available, else threaded system ping."""
    # Try fping first
    fping_result = _fping_sweep(targets, timeout_secs)
    if fping_result is not None:
        return fping_result

    system = platform.system()
    live: List[str] = []
    lock = threading.Lock()

    def _ping(ip: str) -> Optional[str]:
        if system == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_secs * 1000)), ip]
        elif system == "Darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_secs * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_secs))), ip]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout_secs + 2)
            return ip if r.returncode == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_ping, targets):
            if result:
                with lock:
                    live.append(result)
    return live


def _fping_sweep(targets: List[str], timeout_secs: float) -> Optional[List[str]]:
    """Run fping against a list of IPs. Returns None if fping is unavailable."""
    import shutil
    if not shutil.which("fping"):
        return None
    try:
        ms = max(100, int(timeout_secs * 1000))
        inp = "\n".join(targets).encode()
        r = subprocess.run(
            ["fping", "-a", "-t", str(ms), "-f", "-"],
            input=inp,
            capture_output=True,
            timeout=len(targets) * timeout_secs / 10 + 60,
        )
        return [line.strip() for line in r.stdout.decode().splitlines() if line.strip()]
    except Exception as exc:
        _warn(f"fping failed ({exc}), falling back to system ping")
        return None


# ── Port scan ─────────────────────────────────────────────────────────────────

def port_scan(
    ips: List[str],
    timeout: float = 1.0,
    workers: int = 150,
    known_open: Optional[Dict[str, List[int]]] = None,
) -> List[dict]:
    """TCP scan of top ports. Uses nmap when available, otherwise socket scan.

    known_open: optional {ip: [port, ...]} of ports already confirmed open
    during host discovery — those are seeded directly and skipped during scan.
    """
    nmap = _nmap_scan(ips, timeout)
    if nmap:
        return nmap

    # Seed results with already-known open ports from the probe sweep
    results: Dict[str, dict] = {}
    pre_known: Dict[str, set] = {}
    if known_open:
        for ip, ports in known_open.items():
            if ip not in ips:
                continue
            port_map = {p: svc for p, svc in _TOP_PORTS}
            if ip not in results:
                results[ip] = {"ip": ip, "open_ports": []}
            pre_known[ip] = set(ports)
            for p in ports:
                results[ip]["open_ports"].append({
                    "port": p, "proto": "tcp",
                    "service": port_map.get(p, ""),
                })

    # Build tasks — skip ports already confirmed open
    tasks = [
        (ip, port, svc)
        for ip in ips
        for port, svc in _TOP_PORTS
        if port not in pre_known.get(ip, set())
    ]
    _info(f"Port scan (socket): {len(ips)} host(s), "
          f"{len(tasks)} tasks ({len(_TOP_PORTS)} ports - pre-known)…")
    lock = threading.Lock()

    def _try(task: Tuple[str, int, str]) -> Optional[Tuple[str, int, str, Optional[str]]]:
        ip, port, svc = task
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = _grab_banner(s, ip, port, timeout)
                s.close()
                return (ip, port, svc, banner)
            s.close()
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_try, tasks):
            if result:
                ip, port, svc, banner = result
                with lock:
                    if ip not in results:
                        results[ip] = {"ip": ip, "open_ports": []}
                    port_entry: dict = {"port": port, "proto": "tcp", "service": svc}
                    if banner:
                        port_entry["banner"] = banner
                    results[ip]["open_ports"].append(port_entry)

    # OS/role inference for each discovered host
    for ip, data in results.items():
        open_port_nums = [p["port"] for p in data["open_ports"]]
        os_hint, roles = infer_os_and_roles(open_port_nums)
        if os_hint:
            data["os_hint"] = os_hint
        if roles:
            data["role_hints"] = roles

    _info(f"Port scan done: {len(results)} host(s) with open ports")
    return list(results.values())


def _grab_banner(sock: socket.socket, ip: str, port: int,
                 timeout: float) -> Optional[str]:
    """Grab a plain-text banner from an already-connected socket."""
    if port not in _BANNER_PORTS:
        return None
    try:
        sock.settimeout(min(timeout, 2.0))
        if port in (80, 8080):
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        # SSH, FTP, SMTP, POP3, IMAP send banners immediately — just read
        data = sock.recv(256)
        banner = data.decode("utf-8", errors="replace").split("\n")[0].strip()
        return banner[:200] if banner else None
    except Exception:
        return None


def _nmap_scan(ips: List[str], timeout: float) -> Optional[List[dict]]:
    """Run nmap and return structured results. Returns None if nmap unavailable."""
    import shutil

    if not shutil.which("nmap"):
        return None

    try:
        import xml.etree.ElementTree as ET

        ports = ",".join(str(p) for p, _ in _TOP_PORTS)
        timing = "-T4" if timeout <= 1.0 else "-T3"

        cmd = [
            "nmap", "-oX", "-", "--open", timing,
            "-p", ports,
            "-sV", "--version-intensity", "2",  # fast service version detection
        ]

        # OS detection requires raw socket privileges
        if _is_elevated():
            cmd.append("-O")

        tmp = _nmap_write_targets(ips)
        try:
            cmd += ["-iL", tmp]
            _info(f"nmap scan: {len(ips)} host(s)…")
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        xml_out = r.stdout.strip()
        if not xml_out.startswith("<?xml"):
            return None

        root = ET.fromstring(xml_out)
        results = []
        for host_el in root.findall("host"):
            state = host_el.find("status")
            if state is None or state.get("state") != "up":
                continue
            addr_el = host_el.find('address[@addrtype="ipv4"]')
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            entry: dict = {"ip": ip, "open_ports": []}

            # MAC address (only present when nmap is on the same L2 segment)
            mac_el = host_el.find('address[@addrtype="mac"]')
            if mac_el is not None:
                entry["mac"] = mac_el.get("addr", "").upper()
                vendor = mac_el.get("vendor", "")
                if vendor:
                    entry["mac_vendor"] = vendor

            # Hostname
            hn_el = host_el.find("hostnames/hostname")
            if hn_el is not None:
                entry["hostname"] = hn_el.get("name", "")

            # OS detection
            os_match = host_el.find("os/osmatch")
            if os_match is not None:
                entry["os_hint"] = os_match.get("name", "")

            # Open ports + service versions
            for port_el in (host_el.find("ports") or []):
                st = port_el.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc_el = port_el.find("service")
                port_entry: dict = {
                    "port": int(port_el.get("portid", 0)),
                    "proto": port_el.get("protocol", "tcp"),
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                }
                if svc_el is not None:
                    parts = [svc_el.get("product", ""),
                             svc_el.get("version", ""),
                             svc_el.get("extrainfo", "")]
                    banner = " ".join(p for p in parts if p).strip()
                    if banner:
                        port_entry["banner"] = banner
                entry["open_ports"].append(port_entry)

            if entry["open_ports"]:
                open_port_nums = [p["port"] for p in entry["open_ports"]]
                os_inferred, roles = infer_os_and_roles(open_port_nums)
                # Only set os_hint from inference if nmap -O didn't already provide one
                if not entry.get("os_hint") and os_inferred:
                    entry["os_hint"] = os_inferred
                if roles:
                    entry["role_hints"] = roles
                results.append(entry)

        _info(f"nmap done: {len(results)} host(s) with open ports")
        return results

    except Exception as exc:
        _warn(f"nmap failed ({exc}), falling back to socket scan")
        return None


def _is_elevated() -> bool:
    """Return True if running as root (Unix) or Administrator (Windows)."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ── Output ────────────────────────────────────────────────────────────────────

def build_payload(
    self_info: dict,
    neighbors: List[dict],
    scan_results: List[dict],
    meta: Optional[dict] = None,
) -> dict:
    return {
        "gravwell_agent": True,
        "agent_version": VERSION,
        "collected_at": datetime.datetime.utcnow().isoformat() + "Z",
        "self": self_info,
        "neighbors": neighbors,
        "port_scan": scan_results,
        **(meta or {}),
    }


def write_json(data: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def upload(data: dict, server: str, key: str) -> bool:
    """POST the payload to the GravWell server, gzip-compressed."""
    import gzip
    import ssl
    import urllib.error
    import urllib.request

    url = server.rstrip("/") + "/api/agent/submit"
    body = gzip.compress(json.dumps(data).encode(), compresslevel=6)
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type":     "application/json",
            "Content-Encoding": "gzip",
            "X-Gravwell-Key":   key,
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            _info(f"Server: {resp.read().decode()}")
            return True
    except urllib.error.HTTPError as exc:
        _warn(f"Server rejected upload (HTTP {exc.code}): {exc.read().decode()}")
    except Exception as exc:
        _warn(f"Upload error: {exc}")
    return False


# ── Utilities ─────────────────────────────────────────────────────────────────

def _run(cmd: str) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except Exception:
        return ""


def _info(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr, flush=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GravWell Collection Agent — network recon and asset discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python collect.py
  python collect.py --no-scan
  python collect.py --routes
  python collect.py --server https://gravwell.corp.local --key abc123
  python collect.py --output /tmp/recon.json --server https://gravwell.corp.local --key abc123
""",
    )
    parser.add_argument("--output", "-o", default="", help="Output file path (default: auto-named)")
    parser.add_argument("--server", "-s", default="", help="GravWell server URL")
    parser.add_argument("--key", "-k", default="", help="API key for server upload")
    parser.add_argument("--no-sweep", action="store_true", help="Skip active host discovery (TCP probe + ping)")
    parser.add_argument("--no-scan", action="store_true", help="Skip port scan")
    parser.add_argument("--routes", action="store_true",
                        help="Also sweep routed (non-directly-attached) subnets")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Scan/ping timeout in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=150,
                        help="Concurrent threads for socket scan (default: 150)")
    parser.add_argument("--rate", type=int, default=10_000,
                        help="Raw SYN scan rate in packets/sec — Linux/macOS + root only (default: 10000)")
    args = parser.parse_args()

    _info(f"GravWell Collection Agent v{VERSION}")
    if _is_elevated():
        _info("Running elevated — OS detection enabled")

    system = platform.system()

    # 1. Own system info
    _info("Collecting system information…")
    self_info = collect_self()
    _info(f"  Host: {self_info['hostname']}  IPs: {self_info['ips']}")
    if self_info.get("gateway"):
        _info(f"  Gateway: {self_info['gateway']}")
    if self_info.get("dns_servers"):
        _info(f"  DNS: {', '.join(self_info['dns_servers'])}")
    if self_info.get("domain"):
        _info(f"  Domain: {self_info['domain']}")

    # 2. Routing table
    direct_nets, routed_nets = discover_networks(system)
    _info(f"  Networks — directly attached: {len(direct_nets)}, routed: {len(routed_nets)}")

    # 3. Passive discovery (ARP + netstat + Windows-specific sources)
    _info("Passive discovery…")
    neighbors = collect_arp()
    existing_ips: set = {n["ip"] for n in neighbors}

    for n in collect_active_connections():
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])

    if system == "Windows":
        for n in collect_windows_dns_cache():
            if n["ip"] not in existing_ips:
                neighbors.append(n)
                existing_ips.add(n["ip"])
        for n in collect_smb_neighbors_windows():
            if n["ip"] not in existing_ips:
                neighbors.append(n)
                existing_ips.add(n["ip"])

    _info(f"  {len(neighbors)} neighbour(s) from passive sources")

    # 4. mDNS / SSDP multicast discovery (runs concurrently with ping sweep)
    _info("mDNS/SSDP multicast discovery (5 s, background)…")
    _mdns_ssdp_bag: List[dict] = []
    _mdns_thread = threading.Thread(
        target=lambda: _mdns_ssdp_bag.extend(mdns_ssdp_listen(5.0)),
        daemon=True,
    )
    _mdns_thread.start()

    # 5. Ping sweep
    known_open: Dict[str, List[int]] = {}
    if not args.no_sweep:
        # Always sweep directly-attached networks; add routed ones with --routes
        sweep_nets = list(direct_nets)

        # Fall back to deriving /24 from interface config if routing table gave nothing
        if not sweep_nets:
            for iface in self_info.get("interfaces", []):
                ip = iface.get("ip")
                nm = iface.get("netmask")
                if not ip or not nm:
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{nm}", strict=False)
                    n24 = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                    if n24 not in sweep_nets:
                        sweep_nets.append(n24)
                except ValueError:
                    pass

        if args.routes and routed_nets:
            _info(f"  Adding {len(routed_nets)} routed subnet(s) to sweep (--routes)")
            sweep_nets += [n for n in routed_nets if n not in sweep_nets]

        if sweep_nets:
            live, known_open = host_discovery(sweep_nets, timeout_secs=args.timeout, workers=args.workers, rate_pps=args.rate)
            for ip in live:
                if ip not in existing_ips:
                    neighbors.append({"ip": ip, "source": "ping_sweep"})
                    existing_ips.add(ip)
            # Re-read ARP to fill in MACs of newly discovered hosts
            arp_map = {n["ip"]: n for n in collect_arp()}
            for n in neighbors:
                if not n.get("mac") and n["ip"] in arp_map:
                    n["mac"] = arp_map[n["ip"]].get("mac", "")
            for entry in arp_map.values():
                if entry["ip"] not in existing_ips:
                    neighbors.append(entry)
                    existing_ips.add(entry["ip"])

    # Merge mDNS/SSDP results (thread should be done by now; join to be safe)
    _mdns_thread.join()
    for n in _mdns_ssdp_bag:
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])
    if _mdns_ssdp_bag:
        _info(f"  mDNS/SSDP: {len(_mdns_ssdp_bag)} device(s) found")

    _info(f"Total neighbours discovered: {len(neighbors)}")

    # 6. Port scan
    scan_results: List[dict] = []
    if not args.no_scan and neighbors:
        scan_targets = list({n["ip"] for n in neighbors} | set(self_info.get("ips", [])))
        scan_results = port_scan(
            scan_targets,
            timeout=args.timeout,
            workers=args.workers,
            known_open=known_open,
        )

    # 7. Post-scan enrichment — all four methods are pure I/O; run concurrently
    _info("Post-scan enrichment (TLS / HTTP / NetBIOS / rDNS — concurrent)…")
    rdns: Dict[str, str] = {}

    def _do_tls() -> None:
        if scan_results:
            enrich_tls(scan_results, timeout=min(args.timeout + 1, 3.0))

    def _do_http() -> None:
        if scan_results:
            enrich_http(scan_results, timeout=min(args.timeout + 2, 4.0))

    def _do_netbios() -> None:
        enrich_netbios(neighbors, timeout_secs=min(args.timeout, 1.5))

    def _do_rdns() -> None:
        rdns.update(reverse_dns_sweep(list(existing_ips)))

    enrich_threads = [
        threading.Thread(target=_do_tls,     daemon=True),
        threading.Thread(target=_do_http,    daemon=True),
        threading.Thread(target=_do_netbios, daemon=True),
        threading.Thread(target=_do_rdns,    daemon=True),
    ]
    for t in enrich_threads:
        t.start()
    for t in enrich_threads:
        t.join()

    for n in neighbors:
        if not n.get("hostname") and n["ip"] in rdns:
            n["hostname"] = rdns[n["ip"]]

    # 8. Build payload
    meta = {
        "direct_networks": direct_nets,
        "routed_networks": routed_nets,
        "elevated": _is_elevated(),
    }
    payload = build_payload(self_info, neighbors, scan_results, meta=meta)

    # 9. Write local file
    out_path = args.output
    if not out_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"gravwell_collect_{self_info['hostname']}_{ts}.json"
    write_json(payload, out_path)
    _info(f"Saved: {out_path}")

    # 10. Upload if requested
    if args.server:
        if not args.key:
            _warn("--server requires --key")
        else:
            _info(f"Uploading to {args.server}…")
            ok = upload(payload, args.server, args.key)
            if not ok:
                _warn("Upload failed — results saved locally")

    # Summary
    total_ports = sum(len(h.get("open_ports", [])) for h in scan_results)
    print("\n── Collection summary ─────────────────────────────────")
    print(f"  Own IPs:    {', '.join(self_info.get('ips', []))}")
    print(f"  Gateway:    {self_info.get('gateway') or '(unknown)'}")
    print(f"  Neighbours: {len(neighbors)}")
    print(f"  Scanned:    {len(scan_results)} hosts with open ports ({total_ports} total)")
    print(f"  Output:     {out_path}")
    print("──────────────────────────────────────────────────────")


if __name__ == "__main__":
    main()
