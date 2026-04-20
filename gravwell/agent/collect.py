#!/usr/bin/env python3
"""
GravWell Collection Agent v1.1

Collects network reconnaissance data from the local machine and optionally
uploads it to a GravWell server for import into the network graph.

Usage:
    python collect.py [options]

    --output PATH     Write JSON to PATH  (default: gravwell_collect_<host>_<ts>.json)
    --server URL      GravWell server URL (e.g. https://gravwell.corp.local)
    --key TOKEN       API key for server upload
    --no-sweep        Skip subnet ping sweep (passive ARP table only)
    --no-scan         Skip port scan
    --routes          Also sweep routed (non-directly-attached) subnets
    --timeout SECS    Port-scan / ping timeout in seconds (default: 1.0)
    --workers N       Concurrent threads for scanning (default: 150)

Requires no third-party packages.  nmap and fping are used automatically
when available.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
from typing import Dict, List, Optional, Tuple

VERSION = "1.1"

# ── Top-port list ─────────────────────────────────────────────────────────────
_TOP_PORTS: List[Tuple[int, str]] = [
    (21,    "ftp"),
    (22,    "ssh"),
    (23,    "telnet"),
    (25,    "smtp"),
    (53,    "dns"),
    (80,    "http"),
    (88,    "kerberos"),
    (110,   "pop3"),
    (111,   "rpcbind"),
    (135,   "msrpc"),
    (139,   "netbios-ssn"),
    (143,   "imap"),
    (389,   "ldap"),
    (443,   "https"),
    (445,   "smb"),
    (636,   "ldaps"),
    (993,   "imaps"),
    (995,   "pop3s"),
    (1433,  "mssql"),
    (1521,  "oracle-db"),
    (2049,  "nfs"),
    (2375,  "docker"),
    (2376,  "docker-tls"),
    (3306,  "mysql"),
    (3389,  "rdp"),
    (5432,  "postgresql"),
    (5900,  "vnc"),
    (5985,  "winrm"),
    (5986,  "winrm-https"),
    (6379,  "redis"),
    (6443,  "kubernetes-api"),
    (8080,  "http-alt"),
    (8443,  "https-alt"),
    (8888,  "jupyter"),
    (9200,  "elasticsearch"),
    (10250, "kubelet"),
    (27017, "mongodb"),
]

# Ports where we attempt to read a plain-text banner
_BANNER_PORTS = {21, 22, 25, 80, 110, 143, 8080}


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


# ── Ping sweep ────────────────────────────────────────────────────────────────

def ping_sweep(
    networks: List[str],
    timeout_secs: float = 1.0,
    workers: int = 200,
) -> List[str]:
    """Ping all hosts in the given CIDR networks. Returns list of live IPs.

    Tries fping first (much faster); falls back to parallel ping.
    Networks larger than /24 are chunked into /24 slices.
    """
    targets: List[str] = []
    for net_str in networks:
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            if net.prefixlen < 24:
                # Chunk into /24 slices to avoid massive target lists
                slices = list(net.subnets(new_prefix=24))
                for s in slices:
                    targets.extend(str(h) for h in s.hosts())
            else:
                targets.extend(str(h) for h in net.hosts())
        except ValueError:
            continue

    if not targets:
        return []

    _info(f"Ping sweep: {len(targets)} targets across {len(networks)} network(s)…")

    # Try fping first — orders of magnitude faster
    responding = _fping_sweep(targets, timeout_secs)
    if responding is not None:
        _info(f"Ping sweep done (fping): {len(responding)} hosts responded")
        return responding

    # Fallback: threaded per-host ping
    system = platform.system()
    responding = []
    lock = threading.Lock()

    def _ping(ip: str) -> Optional[str]:
        if system == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_secs * 1000)), ip]
        elif system == "Darwin":
            # macOS -W is in milliseconds
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_secs * 1000)), ip]
        else:
            # Linux -W is in seconds (integer)
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
                    responding.append(result)

    _info(f"Ping sweep done: {len(responding)} hosts responded")
    return responding


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
        _warn(f"fping failed ({exc}), falling back to ping")
        return None


# ── Port scan ─────────────────────────────────────────────────────────────────

def port_scan(
    ips: List[str],
    timeout: float = 1.0,
    workers: int = 150,
) -> List[dict]:
    """TCP scan of top ports. Uses nmap when available, otherwise socket scan."""
    nmap = _nmap_scan(ips, timeout)
    if nmap is not None:
        return nmap

    _info(f"Port scan (socket): {len(ips)} host(s), {len(_TOP_PORTS)} ports each…")
    results: Dict[str, dict] = {}
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

    tasks = [(ip, port, svc) for ip in ips for port, svc in _TOP_PORTS]
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

    # Reverse DNS for each discovered host
    for ip, data in results.items():
        try:
            data["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

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

        cmd += ips
        _info(f"nmap scan: {len(ips)} host(s)…")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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
    """POST the payload to the GravWell server."""
    import ssl
    import urllib.error
    import urllib.request

    url = server.rstrip("/") + "/api/agent/submit"
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "X-Gravwell-Key": key},
        method="POST",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
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
    parser.add_argument("--no-sweep", action="store_true", help="Skip ping sweep")
    parser.add_argument("--no-scan", action="store_true", help="Skip port scan")
    parser.add_argument("--routes", action="store_true",
                        help="Also sweep routed (non-directly-attached) subnets")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Scan/ping timeout in seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=150,
                        help="Concurrent threads (default: 150)")
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

    # 3. ARP table (passive)
    _info("Reading ARP/neighbor table…")
    neighbors = collect_arp()
    _info(f"  {len(neighbors)} neighbour(s)")

    # 4. Ping sweep
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
            live = ping_sweep(sweep_nets, timeout_secs=args.timeout, workers=args.workers)
            existing = {n["ip"] for n in neighbors}
            for ip in live:
                if ip not in existing:
                    neighbors.append({"ip": ip, "source": "ping_sweep"})
                    existing.add(ip)
            # Re-read ARP to fill in MACs of newly discovered hosts
            arp_map = {n["ip"]: n for n in collect_arp()}
            for n in neighbors:
                if not n.get("mac") and n["ip"] in arp_map:
                    n["mac"] = arp_map[n["ip"]].get("mac", "")
            for entry in arp_map.values():
                if entry["ip"] not in existing:
                    neighbors.append(entry)

    _info(f"Total neighbours discovered: {len(neighbors)}")

    # 5. Port scan
    scan_results: List[dict] = []
    if not args.no_scan and neighbors:
        scan_targets = list({n["ip"] for n in neighbors} | set(self_info.get("ips", [])))
        scan_results = port_scan(scan_targets, timeout=args.timeout, workers=args.workers)

    # 6. Build payload
    meta = {
        "direct_networks": direct_nets,
        "routed_networks": routed_nets,
        "elevated": _is_elevated(),
    }
    payload = build_payload(self_info, neighbors, scan_results, meta=meta)

    # 7. Write local file
    out_path = args.output
    if not out_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"gravwell_collect_{self_info['hostname']}_{ts}.json"
    write_json(payload, out_path)
    _info(f"Saved: {out_path}")

    # 8. Upload if requested
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
