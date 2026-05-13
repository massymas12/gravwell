#!/usr/bin/env python3
"""
GravWell Collection Agent v2.0

Collects network reconnaissance data from the local machine and optionally
uploads it to a GravWell server for import into the network graph.

Discovery methods (all stdlib-only, no third-party packages required):
  - ARP / IPv6 neighbor table
  - Active TCP connection harvest (netstat)
  - SSH known_hosts file and system hosts file (passive, zero traffic)
  - Windows DNS cache (ipconfig /displaydns), SMB browse list, Active Directory
  - mDNS multicast (224.0.0.251:5353) — Apple, Linux/Avahi, IoT devices
  - SSDP multicast (239.255.255.250:1900) — UPnP / smart appliances
  - WS-Discovery multicast (239.255.255.250:3702) — printers, cameras, Windows
  - LLMNR passive listen (224.0.0.252:5355) — Windows name-resolution snooping
  - TCP-first host discovery (50+ common ports) with ICMP supplement
  - NetBIOS Node Status (UDP 137) hostname resolution
  - SNMP v2c sysDescr + sysName query (community "public")
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
    --no-verify-tls   Skip TLS certificate verification (for self-signed server certs)
    --ot-mode         OT/ICS-safe discovery: BACnet/EtherNet-IP broadcasts only, no sweep,
                      no banner grabbing, no TCP scan (safe for PLCs, RTUs, safety systems)
    --ot-scan         With --ot-mode: also run a low-concurrency TCP port scan on discovered
                      OT hosts (only if you know your devices tolerate unexpected connections)
    --include CIDR    Only actively probe hosts in this subnet (repeat or comma-separate)
    --exclude CIDR    Never actively probe hosts in this subnet — OT-safe (repeat or comma-separate)
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

VERSION = "2.1"

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


# ── Banner / HTTP header → OS fingerprinting ─────────────────────────────────

# SSH banner substrings → (os_family, os_name).  Evaluated top-to-bottom;
# first match wins.  openssh_for_windows must come before generic openssh.
_SSH_OS_PATTERNS: List[Tuple[str, str, str]] = [
    ("openssh_for_windows",  "Windows",  "Windows"),
    ("ubuntu",               "Linux",    "Ubuntu"),
    ("debian",               "Linux",    "Debian"),
    ("raspbian",             "Linux",    "Raspberry Pi OS"),
    ("centos",               "Linux",    "CentOS"),
    ("rhel",                 "Linux",    "RHEL"),
    ("fedora",               "Linux",    "Fedora"),
    ("amzn",                 "Linux",    "Amazon Linux"),
    ("amazon",               "Linux",    "Amazon Linux"),
    ("alpine",               "Linux",    "Alpine Linux"),
    ("kali",                 "Linux",    "Kali Linux"),
    ("freebsd",              "FreeBSD",  "FreeBSD"),
    ("netbsd",               "NetBSD",   "NetBSD"),
    ("openbsd",              "OpenBSD",  "OpenBSD"),
    ("dropbear",             "Linux",    "Linux (embedded)"),
    ("openssh",              "Linux",    ""),                   # generic fallback
]

_IIS_VERSIONS: Dict[str, str] = {
    "10.0": "Windows Server 2016+",
    "8.5":  "Windows Server 2012 R2",
    "8.0":  "Windows Server 2012",
    "7.5":  "Windows Server 2008 R2",
    "7.0":  "Windows Server 2008",
    "6.0":  "Windows Server 2003",
}

# Substrings found in Apache/nginx Server headers → (os_family, os_name)
_HTTP_DISTRO_PATTERNS: List[Tuple[str, str, str]] = [
    ("ubuntu",    "Linux",    "Ubuntu"),
    ("debian",    "Linux",    "Debian"),
    ("centos",    "Linux",    "CentOS"),
    ("red hat",   "Linux",    "RHEL"),
    ("fedora",    "Linux",    "Fedora"),
    ("amzn",      "Linux",    "Amazon Linux"),
    ("amazon",    "Linux",    "Amazon Linux"),
    ("alpine",    "Linux",    "Alpine Linux"),
    ("raspbian",  "Linux",    "Raspberry Pi OS"),
    ("freebsd",   "FreeBSD",  "FreeBSD"),
    ("darwin",    "macOS",    "macOS"),
    ("win",       "Windows",  "Windows"),
]


def _os_from_banner(banner: str, port: int) -> Tuple[Optional[str], Optional[str]]:
    """Parse a service banner → (os_family, os_name). Both may be None."""
    if not banner:
        return None, None
    b = banner.lower()

    if port == 22:
        for substr, family, name in _SSH_OS_PATTERNS:
            if substr in b:
                return family, (name or None)

    if port == 21:
        if "microsoft" in b or "iis" in b:
            return "Windows", "Windows"
        if any(x in b for x in ("vsftpd", "proftpd", "wu-ftpd", "pure-ftpd")):
            return "Linux", None

    if port == 25:
        if "microsoft" in b or "exchange" in b:
            return "Windows", "Windows"
        if any(x in b for x in ("postfix", "exim", "sendmail", "dovecot", "qmail")):
            return "Linux", None

    if port in (110, 143):
        if "microsoft" in b or "exchange" in b:
            return "Windows", "Windows"
        if any(x in b for x in ("dovecot", "courier", "cyrus", "uw-imap")):
            return "Linux", None

    return None, None


def _os_from_http_headers(server: str, powered_by: str = "") -> Tuple[Optional[str], Optional[str]]:
    """Parse HTTP Server / X-Powered-By headers → (os_family, os_name)."""
    s = server.lower()
    p = powered_by.lower()

    # IIS → Windows with version-specific name
    m = re.search(r"microsoft-iis/(\d+\.\d+)", s)
    if m:
        return "Windows", _IIS_VERSIONS.get(m.group(1), "Windows Server")
    if "microsoft httpapi" in s or "asp.net" in p:
        return "Windows", None

    # Distro tags embedded in Apache/nginx Server strings
    for substr, family, name in _HTTP_DISTRO_PATTERNS:
        if substr in s:
            return family, (name or None)

    # Generic server software → usually Linux
    if any(x in s for x in ("apache", "nginx", "lighttpd", "caddy",
                              "gunicorn", "uvicorn", "aiohttp", "tornado")):
        return "Linux", None

    return None, None


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

    # Filter loopback, link-local, multicast, etc. right after the OS parsers run
    # and BEFORE the fallback checks.  All three platform parsers include the loopback
    # adapter.  If we filter after the fallbacks, a machine that reports only 127.0.0.1
    # (e.g. a container during startup) would skip both fallbacks, then end up with
    # all_ips = [] after filtering.
    interfaces = [i for i in interfaces if i.get("ip") and _is_routable_host_ip(i["ip"])]

    # Fallback tier 1: hostname resolution — pure local, zero network traffic.
    # Works on air-gapped systems as long as the hostname is in /etc/hosts or DNS.
    if not interfaces:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    interfaces = [{"name": "primary", "ip": ip, "netmask": "", "mac": ""}]
                    break
        except Exception:
            pass

    # Fallback tier 2: routing-table probe — UDP connect() sends NO packets;
    # the OS simply consults its routing table to pick a source address.
    # Try private addresses first so this works on isolated networks that
    # have a local router but no internet access.
    if not interfaces:
        for _dst in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect((_dst, 80))
                    ip = s.getsockname()[0]
                finally:
                    s.close()
                if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                    interfaces = [{"name": "primary", "ip": ip, "netmask": "", "mac": ""}]
                    break
            except Exception:
                continue

    all_ips = [i["ip"] for i in interfaces]
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
                    if re.fullmatch(r"[\d.]+", gw) and gw != "0.0.0.0":
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
            # macOS netstat -rn uses truncated notation: "192.168.1/24" or "192.168.1"
            try:
                if "/" in dest:
                    addr_part, pfx = dest.rsplit("/", 1)
                    octets = addr_part.split(".")
                    while len(octets) < 4:
                        octets.append("0")
                    net = ipaddress.IPv4Network(f"{'.'.join(octets)}/{pfx}", strict=False)
                else:
                    octets = dest.split(".")
                    pfx = {1: 8, 2: 16, 3: 24}.get(len(octets), 32)
                    while len(octets) < 4:
                        octets.append("0")
                    net = ipaddress.IPv4Network(f"{'.'.join(octets)}/{pfx}", strict=False)
            except ValueError:
                continue
        net_str = str(net)
        if not _is_useful_network(net_str):
            continue
        if gw.startswith("link#") or gw == "lo0":
            if net_str not in direct:
                direct.append(net_str)
        elif re.fullmatch(r"[\d.]+", gw):
            if net_str not in routed:
                routed.append(net_str)


# ── ARP table ─────────────────────────────────────────────────────────────────

def _is_routable_host_ip(ip: str) -> bool:
    """Return True only for unicast IPs that represent real hosts.

    Rejects multicast (224.x–239.x), broadcast, loopback, link-local,
    and unspecified addresses — all of which appear in ARP/neighbour
    tables but are not actual network devices.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
        or (isinstance(addr, ipaddress.IPv4Address) and str(addr).endswith(".255"))
    )


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
            if kind.lower() in ("dynamic", "static") and _is_routable_host_ip(ip):
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
            if m and _is_routable_host_ip(m.group(1)):
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
        if m and _is_routable_host_ip(m.group(1)):
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
            if not _is_routable_host_ip(ip):
                continue
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
        if not re.fullmatch(r"[0-9a-fA-F:]{17}", mac):
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


# ── Passive file-based sources ───────────────────────────────────────────────

def collect_ssh_known_hosts() -> List[dict]:
    """Read ~/.ssh/known_hosts for previously contacted hosts.

    Hashed entries (|1|…) are skipped — the host cannot be recovered from them.
    Hostnames are resolved to IPs; unresolvable entries are dropped.
    """
    import pathlib as _pl
    path = _pl.Path.home() / ".ssh" / "known_hosts"
    results: List[dict] = []
    seen: set = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("|"):
                continue
            host_field = line.split()[0]
            for host in host_field.split(","):
                host = host.strip()
                if host.startswith("["):
                    host = host[1:host.find("]")] if "]" in host else host[1:]
                try:
                    ipaddress.IPv4Address(host)
                    ip = host
                    hostname = None
                except ValueError:
                    try:
                        ip = socket.gethostbyname(host)
                        hostname = host
                    except Exception:
                        continue
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue
                if ip not in seen:
                    seen.add(ip)
                    entry: dict = {"ip": ip, "source": "ssh_known_hosts"}
                    if hostname:
                        entry["hostname"] = hostname
                    results.append(entry)
    except Exception:
        pass
    return results


def collect_hosts_file() -> List[dict]:
    """Read the system hosts file for static IP→hostname mappings."""
    import pathlib as _pl
    if platform.system() == "Windows":
        path = _pl.Path(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        path = _pl.Path("/etc/hosts")
    results: List[dict] = []
    seen: set = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if ip.startswith("127.") or ip == "0.0.0.0":
                continue
            if ip not in seen:
                seen.add(ip)
                entry: dict = {"ip": ip, "source": "hosts_file"}
                entry["hostname"] = parts[1]
                results.append(entry)
    except Exception:
        pass
    return results


def collect_ad_computers() -> List[dict]:
    """Enumerate domain-joined computers via 'net group' (Windows only).

    Queries Active Directory for all computer accounts.  Each account name
    ends with '$' (e.g. DESKTOP-ABC123$); that suffix is stripped before
    DNS resolution.  Silently returns [] if not domain-joined or if the
    command fails.
    """
    if platform.system() != "Windows":
        return []
    results: List[dict] = []
    seen: set = set()
    try:
        r = subprocess.run(
            ["net", "group", "Domain Computers", "/domain"],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode != 0:
            return []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line or "---" in line or "Group name" in line \
                    or "Comment" in line or "Members" in line \
                    or line.startswith("The command"):
                continue
            for token in line.split():
                if not token.endswith("$"):
                    continue
                hostname = token.rstrip("$")
                try:
                    ip = socket.gethostbyname(hostname)
                    if ip.startswith("127.") or ip == "0.0.0.0":
                        continue
                    if ip not in seen:
                        seen.add(ip)
                        results.append({"ip": ip, "hostname": hostname,
                                        "source": "active_directory"})
                except Exception:
                    pass
    except Exception as exc:
        _warn(f"AD computer enumeration error: {exc}")
    return results


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
        try:
            s.sendto(pkt, (ip, 137))
            data, _ = s.recvfrom(1024)
        finally:
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
    sock = None
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
            if src_ip in seen or not _is_routable_host_ip(src_ip):
                continue
            seen.add(src_ip)
            hostname = _parse_mdns_name(data)
            entry: dict = {"ip": src_ip, "source": "mdns"}
            if hostname:
                entry["hostname"] = hostname
            neighbors.append(entry)
    except Exception as exc:
        _warn(f"mDNS listen error: {exc}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
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
    sock = None
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
            if src_ip in seen or not _is_routable_host_ip(src_ip):
                continue
            seen.add(src_ip)
            entry: dict = {"ip": src_ip, "source": "ssdp"}
            response = data.decode("utf-8", errors="replace")
            m = re.search(r"^Server:\s*(.+)", response, re.I | re.M)
            if m:
                entry["ssdp_server"] = m.group(1).strip()[:100]
            neighbors.append(entry)
    except Exception as exc:
        _warn(f"SSDP listen error: {exc}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return neighbors


def _wsdiscovery_listen(timeout_secs: float) -> List[dict]:
    """Send WS-Discovery Probe and collect ProbeMatch responses.

    WS-Discovery (UDP 3702 multicast) is used by printers, IP cameras (ONVIF),
    scanners, and modern Windows/Linux hosts.  The Probe sends to the WSD
    multicast group; responding devices describe their type in the Types element.
    """
    import uuid as _uuid
    WSD_ADDR = "239.255.255.250"
    WSD_PORT = 3702
    probe = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
        ' xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">'
        "<soap:Header>"
        "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
        "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
        f"<wsa:MessageID>uuid:{_uuid.uuid4()}</wsa:MessageID>"
        "</soap:Header>"
        "<soap:Body><wsd:Probe>"
        "<wsd:Types>wsdp:Device</wsd:Types>"
        "</wsd:Probe></soap:Body></soap:Envelope>"
    ).encode("utf-8")
    neighbors: List[dict] = []
    seen: set = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))
        sock.sendto(probe, (WSD_ADDR, WSD_PORT))
        deadline = time.monotonic() + timeout_secs
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 0.5))
            try:
                data, (src_ip, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if src_ip in seen or not _is_routable_host_ip(src_ip):
                continue
            seen.add(src_ip)
            entry: dict = {"ip": src_ip, "source": "wsd"}
            try:
                text = data.decode("utf-8", errors="replace")
                m = re.search(r"<[^:>]*:?Types[^>]*>([^<]+)<", text)
                if m:
                    entry["wsd_types"] = m.group(1).strip()[:120]
                m = re.search(r"<[^:>]*:?XAddrs[^>]*>([^<]+)<", text)
                if m:
                    entry["wsd_xaddrs"] = m.group(1).strip()[:200]
            except Exception:
                pass
            neighbors.append(entry)
    except Exception as exc:
        _warn(f"WS-Discovery error: {exc}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return neighbors


def _llmnr_listen(timeout_secs: float) -> List[dict]:
    """Passively listen for LLMNR queries on 224.0.0.252:5355.

    Windows falls back to LLMNR when DNS resolution fails — devices actively
    querying the network reveal their presence and often their hostname.
    This is a pure passive listen; no queries are sent.
    """
    import struct as _struct
    LLMNR_ADDR = "224.0.0.252"
    LLMNR_PORT = 5355
    neighbors: List[dict] = []
    seen: set = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
        try:
            sock.bind(("", LLMNR_PORT))
        except OSError:
            return neighbors
        mcast = _struct.pack("4sL", socket.inet_aton(LLMNR_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mcast)
        deadline = time.monotonic() + timeout_secs
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, 0.5))
            try:
                data, (src_ip, _) = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            if src_ip in seen or not _is_routable_host_ip(src_ip):
                continue
            seen.add(src_ip)
            entry: dict = {"ip": src_ip, "source": "llmnr"}
            try:
                # DNS-like header: 12 bytes; QR bit 15 of flags word = 0 for query
                if len(data) > 12 and not (data[2] & 0x80):
                    offset, parts = 12, []
                    while offset < len(data):
                        n = data[offset]
                        if n == 0:
                            break
                        offset += 1
                        parts.append(data[offset:offset + n].decode("ascii", errors="replace"))
                        offset += n
                    if parts:
                        entry["llmnr_query"] = ".".join(parts)
            except Exception:
                pass
            neighbors.append(entry)
    except Exception as exc:
        _warn(f"LLMNR listen error: {exc}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return neighbors


def mdns_ssdp_listen(timeout_secs: float = 5.0) -> List[dict]:
    """Discover LAN devices via mDNS, SSDP, WS-Discovery, and LLMNR.

    Runs all four multicast/passive listeners concurrently:
      - mDNS  224.0.0.251:5353 — Apple, Linux/Avahi, IoT (Bonjour)
      - SSDP  239.255.255.250:1900 — UPnP (smart TVs, NAS, routers)
      - WSD   239.255.255.250:3702 — printers, cameras (ONVIF), Windows
      - LLMNR 224.0.0.252:5355     — passive Windows name-resolution snooping
    """
    results: List[dict] = []
    lock = threading.Lock()

    def _run_listener(fn):
        items = fn(timeout_secs)
        with lock:
            results.extend(items)

    threads = [
        threading.Thread(target=_run_listener, args=(_mdns_listen,),      daemon=True),
        threading.Thread(target=_run_listener, args=(_ssdp_listen,),      daemon=True),
        threading.Thread(target=_run_listener, args=(_wsdiscovery_listen,), daemon=True),
        threading.Thread(target=_run_listener, args=(_llmnr_listen,),     daemon=True),
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
        (host, pe["port"], pe)
        for host in scan_results
        for pe in host.get("open_ports", [])
        if pe.get("port") in _HTTP_PORTS or pe.get("port") in _HTTPS_PORTS
    ]
    if not tasks:
        return

    def _fetch(task: Tuple) -> None:
        host_data, port, port_entry = task
        ip = host_data["ip"]
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
                server     = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                if server:
                    port_entry["http_server"] = server[:100]
                h_family, h_name = _os_from_http_headers(server, powered_by)
                if h_family and "os_hint" not in host_data:
                    host_data["os_hint"] = h_family
                if h_name and "os_name_hint" not in host_data:
                    host_data["os_name_hint"] = h_name
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


# ── SNMP enrichment ──────────────────────────────────────────────────────────

def _snmp_get(ip: str, community: str = "public", timeout: float = 1.5) -> dict:
    """Send a single SNMP v2c Get-Request for sysDescr + sysName.

    Pure stdlib — no net-snmp, no pysnmp.  Encodes the request manually in
    BER and parses the response with a naive OCTET STRING scan.
    Returns {"snmp_descr": ..., "snmp_name": ...} or {} on any failure.
    """
    SYSDESCR = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # 1.3.6.1.2.1.1.1.0
    SYSNAME  = b"\x2b\x06\x01\x02\x01\x01\x05\x00"  # 1.3.6.1.2.1.1.5.0

    def _tlv(tag: int, val: bytes) -> bytes:
        n = len(val)
        if n < 128:
            return bytes([tag, n]) + val
        elif n < 256:
            return bytes([tag, 0x81, n]) + val
        else:
            return bytes([tag, 0x82, n >> 8, n & 0xFF]) + val

    comm = community.encode()
    varbinds = (
        _tlv(0x30, _tlv(0x06, SYSDESCR) + b"\x05\x00") +
        _tlv(0x30, _tlv(0x06, SYSNAME)  + b"\x05\x00")
    )
    pdu = _tlv(0xA0,
        _tlv(0x02, b"\x01") +   # request-id
        _tlv(0x02, b"\x00") +   # error-status
        _tlv(0x02, b"\x00") +   # error-index
        _tlv(0x30, varbinds)
    )
    packet = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, comm) + pdu)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, 161))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
    except Exception:
        return {}

    # Extract all OCTET STRING values from the response via a linear BER scan.
    # Order in a GetResponse: community (skip), sysDescr value, sysName value.
    strings: List[str] = []
    i = 0
    while i < len(data) - 1:
        if data[i] == 0x04:
            i += 1
            n = data[i]; i += 1
            if n & 0x80:
                nb = n & 0x7F
                n = int.from_bytes(data[i:i + nb], "big")
                i += nb
            val = data[i:i + n]
            i += n
            try:
                s = val.decode("utf-8", errors="replace").strip()
                if s:
                    strings.append(s)
            except Exception:
                pass
        else:
            i += 1

    # Drop community string and any empty/binary-looking values
    values = [s for s in strings if s != community and s.isprintable()]
    result: dict = {}
    if values:
        result["snmp_descr"] = values[0][:300]
    if len(values) > 1:
        result["snmp_name"] = values[1][:100]
    return result


def enrich_snmp(neighbors: List[dict], community: str = "public",
                timeout: float = 1.5, workers: int = 50) -> None:
    """Query UDP 161 (SNMP) on every neighbor for sysDescr and sysName.

    sysDescr identifies the OS / firmware version of routers, switches, APs,
    printers, and management cards.  sysName fills in the hostname if unknown.
    Uses community string "public" (read-only, no write risk).
    """
    def _do(neighbor: dict) -> None:
        ip = neighbor.get("ip", "")
        if not ip:
            return
        result = _snmp_get(ip, community=community, timeout=timeout)
        if not result:
            return
        if result.get("snmp_descr"):
            neighbor["snmp_descr"] = result["snmp_descr"]
        if result.get("snmp_name"):
            neighbor["snmp_name"] = result["snmp_name"]
            if not neighbor.get("hostname"):
                neighbor["hostname"] = result["snmp_name"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_do, neighbors))


# ── SNMP VLAN MIB walk (Q-BRIDGE-MIB, RFC 4363) ──────────────────────────────

# dot1qVlanStaticName: 1.3.6.1.2.1.17.7.1.4.3.1.1  (vlan_id → name)
_OID_Q_VLAN_NAME = [1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1]
# dot1qTpFdbPort:     1.3.6.1.2.1.17.7.1.2.2.1.2   (vlan_id.mac[6] → port)
_OID_Q_FDB_PORT  = [1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2]


def _oid_encode(components: List[int]) -> bytes:
    """BER-encode an OID from its integer components."""
    first = components[0] * 40 + components[1]
    out = bytearray([first])
    for c in components[2:]:
        if c == 0:
            out.append(0)
        else:
            buf: List[int] = []
            while c:
                buf.append(c & 0x7f)
                c >>= 7
            for i, b in enumerate(reversed(buf)):
                out.append(b | (0x80 if i < len(buf) - 1 else 0))
    return bytes(out)


def _oid_decode(raw: bytes) -> List[int]:
    """Decode raw OID value bytes (after TLV header) into integer components."""
    if not raw:
        return []
    components = [raw[0] // 40, raw[0] % 40]
    i = 1
    while i < len(raw):
        val = 0
        while i < len(raw):
            b = raw[i]; i += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                break
        components.append(val)
    return components


def _ber_read_len(data: bytes, off: int) -> Tuple[int, int]:
    """Read a BER length field at *off*. Returns (length, new_offset)."""
    b = data[off]; off += 1
    if not (b & 0x80):
        return b, off
    nb = b & 0x7f
    return int.from_bytes(data[off:off + nb], "big"), off + nb


def _parse_snmp_varbinds(data: bytes) -> List[Tuple[List[int], bytes]]:
    """Parse a raw SNMP GetResponse and return (oid_components, raw_value_bytes) pairs."""
    try:
        off = 0
        if data[off] != 0x30:
            return []
        off += 1
        _, off = _ber_read_len(data, off)
        # version INTEGER
        off += 1; vlen, off = _ber_read_len(data, off); off += vlen
        # community OCTET STRING
        off += 1; clen, off = _ber_read_len(data, off); off += clen
        # GetResponse-PDU 0xA2
        if data[off] != 0xA2:
            return []
        off += 1; _, off = _ber_read_len(data, off)
        # request-id, error-status, error-index
        for _ in range(3):
            off += 1; fl, off = _ber_read_len(data, off); off += fl
        # VarBindList SEQUENCE
        if data[off] != 0x30:
            return []
        off += 1; vbl_len, off = _ber_read_len(data, off)
        vbl_end = off + vbl_len
        results: List[Tuple[List[int], bytes]] = []
        while off < vbl_end:
            if data[off] != 0x30:
                break
            off += 1; vb_len, off = _ber_read_len(data, off)
            vb_end = off + vb_len
            if off >= vb_end or data[off] != 0x06:
                off = vb_end; continue
            off += 1; oid_len, off = _ber_read_len(data, off)
            oid_comps = _oid_decode(data[off:off + oid_len]); off += oid_len
            if off < vb_end:
                off += 1; val_len, off = _ber_read_len(data, off)
                val_bytes = data[off:off + val_len]; off += val_len
                results.append((oid_comps, val_bytes))
            off = vb_end
        return results
    except Exception:
        return []


def _snmp_walk_bulk(
    ip: str,
    community: str,
    base_oid: List[int],
    max_results: int = 500,
    timeout: float = 2.0,
) -> List[Tuple[List[int], bytes]]:
    """Walk an SNMP subtree with GetBulkRequest (v2c, stdlib BER only).

    Returns [(oid_components, raw_value_bytes)] for all entries in the subtree.
    """
    def _tlv(tag: int, val: bytes) -> bytes:
        n = len(val)
        if n < 128:
            return bytes([tag, n]) + val
        if n < 256:
            return bytes([tag, 0x81, n]) + val
        return bytes([tag, 0x82, n >> 8, n & 0xFF]) + val

    comm_bytes = community.encode()
    base_len = len(base_oid)
    results: List[Tuple[List[int], bytes]] = []
    current_oid = base_oid[:]
    req_id = 1

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, 161))
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return []

    try:
        for _ in range(30):
            oid_raw = _oid_encode(current_oid)
            varbind = _tlv(0x30, _tlv(0x06, oid_raw) + b"\x05\x00")
            pdu = _tlv(0xA5,                             # GetBulkRequest
                _tlv(0x02, req_id.to_bytes(2, "big")) +  # request-id
                _tlv(0x02, b"\x00") +                    # non-repeaters
                _tlv(0x02, b"\x32") +                    # max-repetitions=50
                _tlv(0x30, varbind)
            )
            packet = _tlv(0x30,
                _tlv(0x02, b"\x01") +   # version=1 (v2c)
                _tlv(0x04, comm_bytes) +
                pdu
            )
            req_id = (req_id + 1) & 0xFFFF

            try:
                sock.send(packet)
                raw = sock.recv(65535)
            except Exception:
                break

            varbinds = _parse_snmp_varbinds(raw)
            if not varbinds:
                break

            last_oid: Optional[List[int]] = None
            found_in_subtree = False
            for oid_comps, val_bytes in varbinds:
                if oid_comps[:base_len] != base_oid:
                    continue
                found_in_subtree = True
                results.append((oid_comps, val_bytes))
                last_oid = oid_comps
                if len(results) >= max_results:
                    break

            if not found_in_subtree or last_oid is None or len(results) >= max_results:
                break
            current_oid = last_oid
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return results


def collect_vlan_snmp(
    switch_ips: List[str],
    community: str = "public",
    timeout: float = 2.0,
) -> Tuple[List[dict], List[dict]]:
    """Query SNMP Q-BRIDGE-MIB from known switches for VLAN names and the
    forwarding database (which MACs/hosts are in which VLAN).

    Returns:
      vlans    = [{"switch_ip": str, "vlan_id": int, "vlan_name": str}]
      vlan_fdb = [{"switch_ip": str, "vlan_id": int, "mac": str}]
    """
    vlans: List[dict] = []
    vlan_fdb: List[dict] = []
    base_name_len = len(_OID_Q_VLAN_NAME)
    base_fdb_len  = len(_OID_Q_FDB_PORT)

    for switch_ip in switch_ips:
        # VLAN name table: index is a single vlan_id component
        for oid_comps, val_bytes in _snmp_walk_bulk(
            switch_ip, community, _OID_Q_VLAN_NAME, timeout=timeout
        ):
            if len(oid_comps) != base_name_len + 1:
                continue
            vlan_id = oid_comps[-1]
            if not (1 <= vlan_id <= 4094):  # VLAN 0 reserved; > 4094 invalid per 802.1Q
                continue
            try:
                vlan_name = val_bytes.decode("utf-8", errors="replace").strip()
            except Exception:
                vlan_name = ""
            vlans.append({
                "switch_ip": switch_ip,
                "vlan_id": vlan_id,
                "vlan_name": vlan_name or f"VLAN {vlan_id}",
            })

        # FDB: index is vlan_id followed by 6 MAC octets
        for oid_comps, val_bytes in _snmp_walk_bulk(
            switch_ip, community, _OID_Q_FDB_PORT, timeout=timeout
        ):
            if len(oid_comps) != base_fdb_len + 7:
                continue
            vlan_id = oid_comps[base_fdb_len]
            if not (1 <= vlan_id <= 4094):
                continue
            mac_octets = oid_comps[base_fdb_len + 1:]
            if len(mac_octets) != 6 or any(b > 255 for b in mac_octets):
                continue
            mac = ":".join(f"{b:02x}" for b in mac_octets)
            vlan_fdb.append({
                "switch_ip": switch_ip,
                "vlan_id": vlan_id,
                "mac": mac,
            })

    return vlans, vlan_fdb


# ── LLDP / CDP passive sniff ─────────────────────────────────────────────────

def _lldp_listen(timeout_secs: float = 15.0) -> List[dict]:
    """Sniff LLDP frames to discover directly-connected switches (Linux + root only).

    LLDP (IEEE 802.1AB) frames are sent by switches every 30 seconds to
    multicast 01:80:C2:00:00:0E.  Each frame describes the sending switch:
    system name, management IP, and — crucially — the port number the frame
    arrived on, which is the switch port *our* machine is plugged into.

    Returns one neighbor dict per switch:
      source          "lldp"
      ip              switch management IP (from Management Address TLV)
      mac             switch source MAC (Ethernet header)
      hostname        switch system name
      lldp_port_id    switch port our host is on (e.g. GigabitEthernet0/1)
      lldp_system_desc system description (OS / firmware string)
      lldp_capabilities list of enabled capability strings

    Silently returns [] on non-Linux, non-elevated, or socket failure.
    """
    if platform.system() != "Linux" or not _is_elevated():
        return []

    ETH_P_LLDP = 0x88CC

    def _fmt_mac(b: bytes) -> str:
        return ":".join(f"{x:02X}" for x in b)

    def _parse_pdu(pdu: bytes) -> dict:
        info: dict = {}
        i = 0
        while i + 2 <= len(pdu):
            hdr = int.from_bytes(pdu[i:i + 2], "big")
            tlv_type = (hdr >> 9) & 0x7F
            tlv_len  = hdr & 0x1FF
            i += 2
            if tlv_type == 0:
                break
            if i + tlv_len > len(pdu):
                break
            val = pdu[i:i + tlv_len]
            i += tlv_len

            if tlv_type == 1 and tlv_len > 1:          # Chassis ID
                subtype = val[0]
                if subtype == 4 and tlv_len >= 7:       # MAC address
                    info["chassis_mac"] = _fmt_mac(val[1:7])
                elif subtype in (5, 7):                 # network addr / locally assigned
                    info["chassis_id"] = val[1:].decode("ascii", errors="replace").strip()

            elif tlv_type == 2 and tlv_len > 1:         # Port ID
                subtype = val[0]
                pid = val[1:]
                if subtype in (1, 5, 7):                # interface alias/name/local
                    info["port_id"] = pid.decode("ascii", errors="replace").strip()
                elif subtype == 3 and len(pid) >= 6:    # MAC address
                    info["port_id"] = _fmt_mac(pid[:6])

            elif tlv_type == 5:                         # System Name
                info["system_name"] = val.decode("utf-8", errors="replace").strip()

            elif tlv_type == 6:                         # System Description
                info["system_desc"] = val.decode("utf-8", errors="replace").strip()[:300]

            elif tlv_type == 7 and tlv_len >= 4:        # System Capabilities
                enabled = int.from_bytes(val[2:4], "big")
                cap_names = ["Other", "Repeater", "Bridge", "WAP",
                             "Router", "Phone", "DOCSIS", "Station"]
                info["capabilities"] = [n for bit, n in enumerate(cap_names)
                                        if enabled & (1 << bit)]

            elif tlv_type == 8 and tlv_len > 2:         # Management Address
                addr_len = val[0]
                if addr_len >= 2 and len(val) > addr_len:
                    addr_subtype = val[1]
                    addr_bytes = val[2:1 + addr_len]
                    if addr_subtype == 1 and len(addr_bytes) == 4:  # IPv4
                        try:
                            mgmt = str(ipaddress.IPv4Address(addr_bytes))
                            if not mgmt.startswith("127."):
                                info["mgmt_ip"] = mgmt
                        except Exception:
                            pass
        return info

    neighbors: List[dict] = []
    seen: set = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,  # type: ignore[attr-defined]
                             socket.htons(ETH_P_LLDP))
        sock.settimeout(0.5)
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            try:
                frame, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(frame) < 14 or frame[12:14] != b"\x88\xcc":
                continue
            src_mac = _fmt_mac(frame[6:12])
            info = _parse_pdu(frame[14:])
            ip = info.get("mgmt_ip", "")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            entry: dict = {"ip": ip, "source": "lldp", "mac": src_mac}
            if info.get("system_name"):
                entry["hostname"] = info["system_name"]
            if info.get("port_id"):
                entry["lldp_port_id"] = info["port_id"]
            if info.get("system_desc"):
                entry["lldp_system_desc"] = info["system_desc"]
            if info.get("capabilities"):
                entry["lldp_capabilities"] = info["capabilities"]
            neighbors.append(entry)
    except Exception as exc:
        _warn(f"LLDP sniff error: {exc}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    if neighbors:
        _info(f"  LLDP: {len(neighbors)} switch(es) found")
    return neighbors


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

    tx_sock = None
    rx_sock = None
    try:
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        rx_sock.settimeout(0.05)
    except OSError:
        if tx_sock is not None:
            try:
                tx_sock.close()
            except Exception:
                pass
        return None

    # Determine our outbound source IP — same two-tier fallback as collect_self().
    # Private destinations are tried first so this works on isolated networks.
    src_ip = None
    for _dst in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"):
        try:
            _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                _s.connect((_dst, 80))
                candidate = _s.getsockname()[0]
            finally:
                _s.close()
            if candidate and not candidate.startswith("127.") and candidate != "0.0.0.0":
                src_ip = candidate
                break
        except Exception:
            continue
    if not src_ip:
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
        try:
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
        finally:
            tx_done.set()  # always signal RX — even if TX crashes mid-run

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
            if found.is_set():  # host already confirmed alive — skip pending probes
                return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(probe_timeout)
                try:
                    if s.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
                        found.set()
                finally:
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
            try:
                if s.connect_ex((ip, port)) == 0:
                    banner = _grab_banner(s, ip, port, timeout)
                    return (ip, port, svc, banner)
            finally:
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
                        b_family, b_name = _os_from_banner(banner, port)
                        if b_family and "os_hint" not in results[ip]:
                            results[ip]["os_hint"] = b_family
                        if b_name and "os_name_hint" not in results[ip]:
                            results[ip]["os_name_hint"] = b_name
                    results[ip]["open_ports"].append(port_entry)

    # OS/role inference from port signatures — only fills gaps left by banner parsing
    for ip, data in results.items():
        open_port_nums = [p["port"] for p in data["open_ports"]]
        os_hint, roles = infer_os_and_roles(open_port_nums)
        if os_hint and "os_hint" not in data:
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


# ── OT-safe active discovery ──────────────────────────────────────────────────
#
# All techniques here use a single broadcast/multicast packet and collect
# responses.  No unicast probing of unknown hosts, no banner grabbing,
# no data sent after connection.  Safe for PLCs, RTUs, HMIs, safety systems.

# OT protocol + common IT management ports — the only ports probed in OT mode
_OT_PORTS: List[Tuple[int, str]] = [
    (80,    "http"),           # HMI / SCADA web interfaces
    (443,   "https"),          # HMI / SCADA HTTPS
    (22,    "ssh"),            # managed switches, Linux-based RTUs
    (23,    "telnet"),         # legacy PLCs
    (21,    "ftp"),            # some PLCs / RTUs
    (161,   "snmp"),           # SNMP (UDP — tested separately)
    (502,   "modbus"),         # Modbus TCP
    (102,   "s7comm"),         # Siemens S7 (ISO-TSAP)
    (44818, "ethernet-ip"),    # EtherNet/IP / CIP (Rockwell, Allen-Bradley)
    (47808, "bacnet"),         # BACnet/IP
    (20000, "dnp3"),           # DNP3 over TCP
    (4840,  "opc-ua"),         # OPC-UA
    (2404,  "iec104"),         # IEC 60870-5-104
    (1911,  "niagara-fox"),    # Niagara / Tridium Fox
    (4911,  "niagara-foxs"),   # Niagara Fox TLS
    (9600,  "omron-fins"),     # Omron FINS
    (18245, "ge-srtp"),        # GE SRTP (Series 90)
    (1962,  "pcworx"),         # Phoenix Contact PCWorx
    (2455,  "wago"),           # WAGO Fieldbus
    (34962, "profinet-rt"),    # PROFINET RT (UDP)
    (2222,  "ethernet-ip-ud"), # EtherNet/IP implicit messaging
]

# Ports that are UDP-only — skip in TCP connect scan (handled by broadcast or SNMP)
_OT_UDP_ONLY: set = {161, 47808, 34962, 2222}

# OT port → role tag mapping
_OT_PORT_ROLES: Dict[int, str] = {
    502:   "modbus",
    102:   "s7-plc",
    44818: "ethernet-ip",
    47808: "bacnet",
    20000: "dnp3",
    4840:  "opc-ua",
    2404:  "iec104",
    1911:  "niagara",
    4911:  "niagara",
    9600:  "omron-fins",
    18245: "ge-srtp",
    1962:  "pcworx",
}


_OT_FW_RULES = [
    ("GravWell-OT-BACnet",     "UDP", 47808),
    ("GravWell-OT-EtherNetIP", "UDP", 44818),
]


def _add_ot_firewall_rules() -> bool:
    """Create temporary inbound UDP firewall rules for OT discovery ports.

    Windows only.  Requires admin — silently skips if netsh fails.
    Returns True if any rules were successfully added (caller must clean up).
    """
    if platform.system() != "Windows":
        return False
    added = False
    for name, proto, port in _OT_FW_RULES:
        try:
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}", f"protocol={proto}", "dir=in",
                 f"localport={port}", "action=allow"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                added = True
                _info(f"  Firewall rule added: {name} ({proto}/{port})")
            else:
                _warn(f"  Could not add firewall rule {name}: {r.stderr.strip() or r.stdout.strip()}")
        except Exception as exc:
            _warn(f"  Firewall rule creation failed: {exc}")
    return added


def _remove_ot_firewall_rules() -> None:
    """Delete the temporary OT firewall rules created by _add_ot_firewall_rules."""
    if platform.system() != "Windows":
        return
    for name, _proto, _port in _OT_FW_RULES:
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            pass
    _info("  OT firewall rules removed.")


def _local_iface_pairs() -> List[Tuple[str, str]]:
    """Return (local_ip, broadcast_addr) for every non-loopback interface.

    Binding a send socket to local_ip before sending forces the OS to route
    the packet out the correct NIC.  On Windows an unbound socket may pick
    a VPN adapter, loopback, or virtual interface and the packet never
    reaches the physical LAN.

    Uses the same platform-specific parsers as collect_self() so every
    adapter in ipconfig/ip-addr appears — not just the ones gethostname()
    happens to resolve to.
    """
    pairs: List[Tuple[str, str]] = []
    seen: set = set()

    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            ifaces = _interfaces_windows()
        elif sys_name == "Linux":
            ifaces = _interfaces_linux()
        elif sys_name == "Darwin":
            ifaces = _interfaces_macos()
        else:
            ifaces = []

        for iface in ifaces:
            ip = iface.get("ip", "")
            nm = iface.get("netmask", "")
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{nm}", strict=False)
                bcast = str(net.broadcast_address)
            except ValueError:
                bcast = ip.rsplit(".", 1)[0] + ".255"
            if ip not in seen:
                seen.add(ip)
                pairs.append((ip, bcast))
    except Exception:
        pass

    # Socket-based fallback if platform parsers return nothing
    if not pairs:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue
                bcast = ip.rsplit(".", 1)[0] + ".255"
                if ip not in seen:
                    seen.add(ip)
                    pairs.append((ip, bcast))
        except Exception:
            pass

    if not pairs:
        pairs.append(("", "255.255.255.255"))
    return pairs


def _udp_broadcast(packet: bytes, port: int, recv_port: int,
                   timeout: float, max_resp: int = 512) -> List[Tuple[str, bytes]]:
    """Send *packet* as a UDP broadcast on every local interface and collect responses.

    Uses a dedicated send socket per interface (bound to that interface's IP)
    so Windows routes each packet out the correct NIC.  Responses are collected
    on a shared receive socket bound to *recv_port* (SO_REUSEADDR).

    Returns a list of (src_ip, data) tuples, one per responding host.
    """
    responses: List[Tuple[str, bytes]] = []
    seen: set = set()

    recv_sock: Optional[socket.socket] = None
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            recv_sock.bind(("", recv_port))
        except OSError:
            recv_sock.bind(("", 0))   # port already in use — fall back to ephemeral

        for local_ip, bcast in _local_iface_pairs():
            s: Optional[socket.socket] = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                if local_ip:
                    s.bind((local_ip, 0))
                s.sendto(packet, (bcast, port))
                _info(f"  → {bcast}:{port} (via {local_ip or 'any'})")
            except Exception as exc:
                _warn(f"  broadcast to {bcast}:{port} failed: {exc}")
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

        recv_sock.settimeout(0.25)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, (src_ip, _) = recv_sock.recvfrom(max_resp)
            except socket.timeout:
                continue
            if src_ip not in seen:
                seen.add(src_ip)
                responses.append((src_ip, data))
    except Exception as exc:
        _warn(f"UDP broadcast on port {port} failed: {exc}")
    finally:
        if recv_sock:
            try:
                recv_sock.close()
            except Exception:
                pass

    return responses


def _bacnet_whois(timeout: float = 3.0) -> List[dict]:
    """Send a BACnet Who-Is broadcast; collect I-Am responses.

    BACnet/IP uses UDP port 47808.  Sends from every local interface so the
    packet is visible on the physical LAN regardless of Windows routing.
    Safe for all BACnet/IP devices (Honeywell, Siemens, Johnson Controls, etc.).
    """
    BACNET_PORT = 47808
    # BVLC(4) + NPDU(2) + APDU Who-Is(2) = 8 bytes
    WHO_IS = bytes([
        0x81, 0x0b, 0x00, 0x08,   # BVLC: type, Original-Broadcast-NPDU, len=8
        0x01, 0x00,               # NPDU: version=1, control=0x00
        0x10, 0x08,               # APDU: Unconfirmed-REQ + Who-Is service
    ])
    found: List[dict] = []
    for src_ip, data in _udp_broadcast(WHO_IS, BACNET_PORT, BACNET_PORT, timeout, 512):
        entry: dict = {"ip": src_ip, "source": "bacnet-whois"}
        try:
            apdu_start = 6   # skip BVLC + minimal NPDU
            if len(data) > apdu_start + 4 and data[apdu_start] == 0x10 and data[apdu_start + 1] == 0x00:
                obj_bytes = data[apdu_start + 2: apdu_start + 6]
                instance = int.from_bytes(obj_bytes, "big") & 0x3FFFFF
                entry["bacnet_device_id"] = instance
        except Exception:
            pass
        found.append(entry)
    return found


def _enip_list_identity(timeout: float = 3.0) -> List[dict]:
    """Send EtherNet/IP List Identity broadcast; collect responses.

    List Identity (command 0x0063) is a read-only discovery request defined
    in the CIP spec.  Safe for Rockwell, Allen-Bradley, and any CIP device.
    Returns device type, product name, and vendor information.
    """
    ENIP_PORT = 44818
    LIST_IDENTITY = bytes([
        0x63, 0x00,                          # Command: List Identity
        0x00, 0x00,                          # Length: 0
        0x00, 0x00, 0x00, 0x00,              # Session handle
        0x00, 0x00, 0x00, 0x00,              # Status
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,              # Sender context (8 bytes)
        0x00, 0x00, 0x00, 0x00,              # Options
    ])
    found: List[dict] = []
    for src_ip, data in _udp_broadcast(LIST_IDENTITY, ENIP_PORT, ENIP_PORT, timeout, 1024):
        entry: dict = {"ip": src_ip, "source": "enip-list-identity"}
        try:
            if len(data) >= 26 and data[0] == 0x63 and data[1] == 0x00:
                # EIP encapsulation header = 24 bytes, CPF header = 6 bytes.
                # Identity item data starts at offset 30:
                #   [30:32] encap version, [32:48] sockaddr_in (sin_family+port+addr+zero),
                #   [48:50] vendor ID, [50:52] device type, [52:54] product code,
                #   [54] major rev, [55] minor rev, [56:58] status, [58:62] serial,
                #   [62] name length, [63:] product name (ASCII)
                if len(data) > 62:
                    vendor_id   = int.from_bytes(data[48:50], "little")
                    device_type = int.from_bytes(data[50:52], "little")
                    name_len = data[62]
                    if name_len and len(data) >= 63 + name_len:
                        product = data[63: 63 + name_len].decode("ascii", errors="replace").strip()
                        entry["enip_product"] = product
                    entry["enip_vendor_id"]   = vendor_id
                    entry["enip_device_type"] = device_type
        except Exception:
            pass
        found.append(entry)
    return found


def ot_safe_scan(ips: List[str], timeout: float = 3.0,
                 workers: int = 20) -> List[dict]:
    """Gentle port scan for OT networks.

    Rules:
      - Only known OT + management ports (_OT_PORTS)
      - No banner grabbing — connect test only, then immediately close
      - Low concurrency (default 20), moderate timeout (default 3 s)
      - Assigns OT role tags based on open ports
    """
    results: Dict[str, dict] = {}
    lock = threading.Lock()
    tasks = [(ip, port, svc) for ip in ips for port, svc in _OT_PORTS
             if port not in _OT_UDP_ONLY]   # skip UDP-only protocols

    def _try_ot(task: Tuple) -> Optional[Tuple]:
        ip, port, svc = task
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                connected = s.connect_ex((ip, port)) == 0
            finally:
                s.close()   # close immediately — no banner grab
            if connected:
                return (ip, port, svc)
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_try_ot, tasks):
            if result:
                ip, port, svc = result
                with lock:
                    if ip not in results:
                        results[ip] = {"ip": ip, "open_ports": []}
                    results[ip]["open_ports"].append(
                        {"port": port, "proto": "tcp", "service": svc}
                    )

    # Assign OT role tags and OS hints from open ports
    for data in results.values():
        open_port_nums = [p["port"] for p in data["open_ports"]]
        roles = [_OT_PORT_ROLES[p] for p in open_port_nums if p in _OT_PORT_ROLES]
        if roles:
            data["role_hints"] = list(dict.fromkeys(roles))  # deduplicate
        # OS hint from port evidence
        os_hint, _ = infer_os_and_roles(open_port_nums)
        if os_hint:
            data["os_hint"] = os_hint

    _info(f"OT scan done: {len(results)} host(s) with open ports")
    return list(results.values())


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
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "self": self_info,
        "neighbors": neighbors,
        "port_scan": scan_results,
        **(meta or {}),
    }


def write_json(data: dict, path: str) -> str:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)
    return path


def upload(data: dict, server: str, key: str, verify_tls: bool = True) -> bool:
    """POST the payload to the GravWell server, gzip-compressed."""
    import gzip
    import ssl
    import urllib.error
    import urllib.request

    if not server.startswith(("http://", "https://")):
        server = "https://" + server
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
    if not verify_tls:
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


# ── Include / exclude filters ────────────────────────────────────────────────

def _parse_cidr_list(specs: List[str]) -> List[ipaddress.IPv4Network]:
    """Expand a list of CIDR/IP strings (comma-separated entries supported)."""
    nets: List[ipaddress.IPv4Network] = []
    for spec in specs:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.IPv4Network(part, strict=False))
            except ValueError:
                _warn(f"Invalid CIDR/IP ignored: {part!r}")
    return nets


def _ip_allowed(ip: str,
                includes: List[ipaddress.IPv4Network],
                excludes: List[ipaddress.IPv4Network]) -> bool:
    """Return True if *ip* should be actively probed.

    Excludes take priority: an IP matching any exclude net is always blocked.
    If includes are specified the IP must also match at least one of them.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return True
    if excludes and any(addr in net for net in excludes):
        return False
    if includes and not any(addr in net for net in includes):
        return False
    return True


# ── Interactive setup wizard ──────────────────────────────────────────────────

def _wizard(args) -> object:
    """Walk the user through configuration interactively.

    Called automatically when no CLI flags are given and stdin is a TTY.
    Returns the same *args* namespace with answers filled in.
    """
    def _ask(prompt: str, default: str = "") -> str:
        disp = f" [{default}]" if default else " [blank]"
        try:
            val = input(f"  {prompt}{disp}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        return val if val else default

    def _ask_bool(prompt: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        try:
            val = input(f"  {prompt} [{hint}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not val:
            return default
        return val.startswith("y")

    print("\n" + "─" * 56)
    print("  GravWell Collection Agent — interactive setup")
    print("  Press Enter to accept the default shown in [ ].")
    print("─" * 56 + "\n")

    # Show detected networks so the user can make informed exclude/include choices
    try:
        _sys = platform.system()
        direct, routed = discover_networks(_sys)
        if direct:
            print(f"  Detected local networks : {', '.join(direct)}")
        if routed:
            print(f"  Detected routed networks: {', '.join(routed)}")
        print()
    except Exception:
        pass

    print("── Upload ──────────────────────────────────────────")
    server = _ask("GravWell server URL (blank = save locally only)",
                  getattr(args, "server", "") or "")
    key = ""
    if server:
        key = _ask("API token", getattr(args, "key", "") or "")

    print("\n── Output ──────────────────────────────────────────")
    output = _ask("Output file path (blank = auto-named)",
                  getattr(args, "output", "") or "")

    print("\n── Scope  ──────────────────────────────────────────")
    ot_mode = _ask_bool("OT/ICS network? (enables safe broadcast-only discovery, no banner grabbing)", False)
    exclude_str = _ask("Subnets to EXCLUDE from active probing, comma-separated (blank = none)", "")
    include_str = _ask("Subnets to LIMIT active probing to, comma-separated (blank = all)", "")

    print("\n── Discovery ───────────────────────────────────────")
    if ot_mode:
        print("  (OT mode: ping/TCP sweep replaced with BACnet Who-Is + EtherNet/IP broadcast)")
        print("  TCP port scan is OFF by default — safe for PLCs, RTUs, and safety systems.")
        ot_scan = _ask_bool("Enable TCP port scan on discovered OT hosts? (only if devices tolerate it)", False)
    no_sweep = False if ot_mode else _ask_bool("Skip active host discovery (ping/TCP sweep)?", False)
    no_scan  = False if ot_mode else _ask_bool("Skip port scan?", False)
    routes   = _ask_bool("Also sweep routed (non-directly-attached) subnets?", False)

    print("\n── Tuning ──────────────────────────────────────────")
    timeout_str = _ask("Scan timeout in seconds", str(getattr(args, "timeout", 1.0)))
    workers_str = _ask("Worker threads", str(getattr(args, "workers", 150)))

    try:
        timeout_val = float(timeout_str)
    except ValueError:
        timeout_val = 1.0
    try:
        workers_val = int(workers_str)
    except ValueError:
        workers_val = 150

    # Summary
    print("\n── Summary ─────────────────────────────────────────")
    print(f"  Server  : {server or '(local file only)'}")
    if output:
        print(f"  Output  : {output}")
    if exclude_str:
        print(f"  Exclude : {exclude_str}")
    if include_str:
        print(f"  Include : {include_str}")
    if ot_mode:
        ot_scan_label = "yes (TCP scan enabled via --ot-scan)" if ot_scan else "yes — broadcast-only, no TCP scan"
        print(f"  OT mode : {ot_scan_label}")
    else:
        print(f"  OT mode : no")
    print(f"  Sweep   : {'skip' if no_sweep else 'yes'}")
    print(f"  Scan    : {'skip' if no_scan else 'yes'}")
    print(f"  Routes  : {'yes' if routes else 'no'}")
    print(f"  Timeout : {timeout_val}s   Workers: {workers_val}")
    print()

    if not _ask_bool("Proceed with these settings?", True):
        sys.exit(0)
    print()

    args.server        = server
    args.key           = key
    args.output        = output
    args.exclude       = [exclude_str] if exclude_str else []
    args.include       = [include_str] if include_str else []
    args.ot_mode       = ot_mode
    args.ot_scan       = ot_scan if ot_mode else False
    args.no_sweep      = no_sweep
    args.no_scan       = no_scan
    args.routes        = routes
    args.timeout       = timeout_val
    args.workers       = workers_val
    if server:
        args.no_verify_tls = _ask_bool(
            "Skip TLS certificate verification? (required for self-signed certs)", False
        )
    else:
        args.no_verify_tls = False
    return args


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:  # noqa: C901
    try:
        _main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        import traceback
        print("\n[ERROR] Unexpected crash — please report the following traceback:\n",
              file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


def _main() -> None:
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
    parser.add_argument("--no-verify-tls", action="store_true", default=False,
                        help="Skip TLS certificate verification (needed for self-signed server certs)")
    parser.add_argument("--ot-mode", action="store_true", default=False,
                        help="OT-safe discovery: broadcast-only host detection, "
                             "no banner grabbing, no TCP port scan by default")
    parser.add_argument("--ot-scan", action="store_true", default=False,
                        help="With --ot-mode: also run a low-concurrency TCP port scan on "
                             "discovered OT hosts (use only if you know your devices tolerate it)")
    parser.add_argument("--include", action="append", default=[], metavar="CIDR",
                        help="Only actively probe hosts inside this CIDR "
                             "(can repeat or comma-separate; passive data still collected for all hosts)")
    parser.add_argument("--exclude", action="append", default=[], metavar="CIDR",
                        help="Never actively probe hosts inside this CIDR "
                             "(OT-safe: excluded hosts still appear in output from passive sources)")
    args = parser.parse_args()

    # No flags given and running in an interactive terminal → guided setup
    if len(sys.argv) == 1 and sys.stdin.isatty():
        args = _wizard(args)

    include_nets = _parse_cidr_list(args.include)
    exclude_nets = _parse_cidr_list(args.exclude)
    _has_filter  = bool(include_nets or exclude_nets)
    if include_nets:
        _info(f"Include filter: only probe {', '.join(str(n) for n in include_nets)}")
    if exclude_nets:
        _info(f"Exclude filter: never probe {', '.join(str(n) for n in exclude_nets)}")

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

    # 3. Passive discovery (ARP + netstat + file sources + Windows-specific)
    _info("Passive discovery…")
    neighbors = collect_arp()
    existing_ips: set = {n["ip"] for n in neighbors}

    for n in collect_active_connections():
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])

    # LLDP passive sniff — Linux + root only; reveals directly-connected switches
    # and the specific switch port our machine is plugged into.
    # Run early in passive discovery so the switch IP is known before the sweep.
    _lldp_neighbors = _lldp_listen(timeout_secs=15.0) if not args.ot_mode else []
    _vlans: List[dict] = []
    _vlan_fdb: List[dict] = []
    for n in _lldp_neighbors:
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])

    for n in collect_ssh_known_hosts():
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])

    for n in collect_hosts_file():
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
        for n in collect_ad_computers():
            if n["ip"] not in existing_ips:
                neighbors.append(n)
                existing_ips.add(n["ip"])

    _info(f"  {len(neighbors)} neighbour(s) from passive sources")

    # 4. mDNS / SSDP multicast discovery (runs concurrently with sweep)
    # Skipped in OT mode — multicast queries are still active traffic on the OT LAN.
    _mdns_ssdp_bag: List[dict] = []
    if not args.ot_mode:
        _info("mDNS/SSDP multicast discovery (5 s, background)…")
        _mdns_thread = threading.Thread(
            target=lambda: _mdns_ssdp_bag.extend(mdns_ssdp_listen(5.0)),
            daemon=True,
        )
        _mdns_thread.start()
    else:
        _mdns_thread = None

    # 4b. OT protocol broadcasts (BACnet Who-Is + EtherNet/IP List Identity)
    if args.ot_mode:
        _ot_ifaces = _local_iface_pairs()
        _info(f"OT broadcast interfaces: {[f'{ip}→{bcast}' for ip, bcast in _ot_ifaces]}")
        _ot_fw_added = _add_ot_firewall_rules()
        try:
            _info("OT mode: sending BACnet Who-Is broadcast…")
            for entry in _bacnet_whois(timeout=args.timeout + 2):
                if entry["ip"] not in existing_ips:
                    neighbors.append(entry)
                    existing_ips.add(entry["ip"])

            _info("OT mode: sending EtherNet/IP List Identity broadcast…")
            for entry in _enip_list_identity(timeout=args.timeout + 2):
                if entry["ip"] not in existing_ips:
                    neighbors.append(entry)
                    existing_ips.add(entry["ip"])
        finally:
            if _ot_fw_added:
                _remove_ot_firewall_rules()

    # 5. Active sweep — skipped in OT mode (broadcasts above replace it)
    known_open: Dict[str, List[int]] = {}
    if not args.no_sweep and not args.ot_mode:
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

        if _has_filter:
            filtered_nets = []
            for cidr in sweep_nets:
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                except ValueError:
                    filtered_nets.append(cidr)
                    continue
                if exclude_nets and any(net.overlaps(ex) for ex in exclude_nets):
                    _info(f"  Skipping sweep of {cidr} (excluded)")
                    continue
                if include_nets and not any(net.overlaps(inc) for inc in include_nets):
                    _info(f"  Skipping sweep of {cidr} (not in --include list)")
                    continue
                filtered_nets.append(cidr)
            sweep_nets = filtered_nets

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
    if _mdns_thread is not None:
        _mdns_thread.join()
    for n in _mdns_ssdp_bag:
        if n["ip"] not in existing_ips:
            neighbors.append(n)
            existing_ips.add(n["ip"])
    if _mdns_ssdp_bag:
        _info(f"  mDNS/SSDP: {len(_mdns_ssdp_bag)} device(s) found")

    _info(f"Total neighbours discovered: {len(neighbors)}")

    # 6. Port scan
    # In OT mode the TCP scan is off by default — only enabled by --ot-scan.
    # Bare TCP connects to legacy PLCs / RTUs can fill connection state tables
    # or trigger unexpected behaviour even without sending any data.
    _scan_suppressed = args.ot_mode and not getattr(args, "ot_scan", False)
    if _scan_suppressed:
        _info("OT mode: TCP port scan suppressed (use --ot-scan to enable)")
    scan_results: List[dict] = []
    if not args.no_scan and not _scan_suppressed and neighbors:
        scan_targets = list({n["ip"] for n in neighbors} | set(self_info.get("ips", [])))
        if _has_filter:
            before = len(scan_targets)
            scan_targets = [ip for ip in scan_targets
                            if _ip_allowed(ip, include_nets, exclude_nets)]
            skipped = before - len(scan_targets)
            if skipped:
                _info(f"  {skipped} host(s) skipped by --include/--exclude filter (passive data retained)")
        if args.ot_mode:
            _info("OT mode: running TCP port scan (--ot-scan enabled)…")
            scan_results = ot_safe_scan(
                scan_targets,
                timeout=max(args.timeout, 3.0),
                workers=min(args.workers, 20),
            )
        else:
            scan_results = port_scan(
                scan_targets,
                timeout=args.timeout,
                workers=args.workers,
                known_open=known_open,
            )

    # 7. Post-scan enrichment — all methods run concurrently
    # NetBIOS + SNMP are suppressed in OT mode (UDP unicast to every host).
    _info("Post-scan enrichment (TLS / HTTP / SNMP / NetBIOS / rDNS — concurrent)…")
    rdns: Dict[str, str] = {}

    def _do_tls() -> None:
        if scan_results:
            enrich_tls(scan_results, timeout=min(args.timeout + 1, 3.0))

    def _do_http() -> None:
        if scan_results:
            enrich_http(scan_results, timeout=min(args.timeout + 2, 4.0))

    def _active_neighbors() -> List[dict]:
        if not _has_filter:
            return neighbors
        return [n for n in neighbors if _ip_allowed(n["ip"], include_nets, exclude_nets)]

    def _active_ips() -> List[str]:
        if not _has_filter:
            return list(existing_ips)
        return [ip for ip in existing_ips if _ip_allowed(ip, include_nets, exclude_nets)]

    def _do_snmp() -> None:
        if not args.ot_mode:
            enrich_snmp(_active_neighbors(), timeout=min(args.timeout + 0.5, 2.0))

    def _do_netbios() -> None:
        if not args.ot_mode:
            enrich_netbios(_active_neighbors(), timeout_secs=min(args.timeout, 1.5))

    def _do_rdns() -> None:
        rdns.update(reverse_dns_sweep(_active_ips()))

    enrich_threads = [
        threading.Thread(target=_do_tls,     daemon=True),
        threading.Thread(target=_do_http,    daemon=True),
        threading.Thread(target=_do_snmp,    daemon=True),
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

    # 7b. VLAN MIB — IT mode only, query switches discovered via LLDP
    if not args.ot_mode and _lldp_neighbors:
        _switch_ips = list({n["ip"] for n in _lldp_neighbors if n.get("ip")})
        if _switch_ips:
            _info(f"SNMP VLAN MIB query on {len(_switch_ips)} switch(es)…")
            _vlans, _vlan_fdb = collect_vlan_snmp(_switch_ips)
            if _vlans:
                _info(f"  {len(_vlans)} VLAN(s), {len(_vlan_fdb)} FDB entries")
            else:
                _info("  No VLAN data returned (switch may not support Q-BRIDGE-MIB)")

    # 8. Build payload
    # Build physical link records from LLDP neighbors — one record per
    # (agent_ip, switch_ip) pair, labelled with the switch port we're on.
    physical_links: List[dict] = []
    for n in _lldp_neighbors:
        if not n.get("lldp_port_id"):
            continue
        for agent_ip in (self_info.get("ips") or []):
            physical_links.append({
                "host_ip": agent_ip,
                "peer_ip": n["ip"],
                "port_id": n["lldp_port_id"],
                "link_type": "lldp",
            })

    meta = {
        "direct_networks": direct_nets,
        "routed_networks": routed_nets,
        "elevated": _is_elevated(),
        "physical_links": physical_links,
        "vlans": _vlans,
        "vlan_fdb": _vlan_fdb,
    }
    payload = build_payload(self_info, neighbors, scan_results, meta=meta)

    # 9. Write local file
    out_path = args.output
    if not out_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"gravwell_collect_{self_info['hostname']}_{ts}.json"
    _info(f"Writing output to: {os.path.abspath(out_path)}")
    try:
        write_json(payload, out_path)
    except Exception as exc:
        _warn(f"Failed to write output file: {exc}")
        raise
    _info(f"Saved: {out_path}")

    # 10. Upload if requested
    if args.server:
        if not args.key:
            _warn("--server requires --key")
        else:
            _info(f"Uploading to {args.server}…")
            ok = upload(payload, args.server, args.key,
                        verify_tls=not args.no_verify_tls)
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
