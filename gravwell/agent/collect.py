#!/usr/bin/env python3
"""
GravWell Collection Agent v1.0

Collects network reconnaissance data from the local machine and optionally
uploads it to a GravWell server for import into the network graph.

Usage:
    python collect.py [options]

    --output PATH     Write JSON to PATH  (default: gravwell_collect_<host>_<ts>.json)
    --server URL      GravWell server URL (e.g. https://gravwell.corp.local)
    --key TOKEN       API key for server authentication
    --no-sweep        Skip subnet ping sweep (passive ARP table only)
    --no-scan         Skip port scan
    --timeout SECS    Port-scan / ping timeout in seconds (default: 1.0)
    --workers N       Concurrent threads for scanning (default: 150)

Requires no third-party packages.  nmap is used automatically when available.
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
import uuid
from typing import Dict, List, Optional, Tuple

VERSION = "1.0"

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
    (3306,  "mysql"),
    (3389,  "rdp"),
    (5432,  "postgresql"),
    (5900,  "vnc"),
    (5985,  "winrm"),
    (5986,  "winrm-https"),
    (6379,  "redis"),
    (8080,  "http-alt"),
    (8443,  "https-alt"),
    (9200,  "elasticsearch"),
    (27017, "mongodb"),
]


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

    # Fallback: basic primary IP only
    if not interfaces:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            interfaces = [{"name": "eth0", "ip": ip, "netmask": "", "mac": ""}]
        except Exception:
            pass

    all_ips = [i["ip"] for i in interfaces if i.get("ip")]
    all_macs = list({i["mac"] for i in interfaces if i.get("mac")})

    return {
        "hostname": hostname,
        "platform": system,
        "platform_version": platform.platform(),
        "ips": all_ips,
        "macs": all_macs,
        "interfaces": interfaces,
    }


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
        m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
        if m and not current.get("ip"):
            current["ip"] = m.group(1).rstrip("(Preferred)").strip()
        m = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
        if m:
            current["netmask"] = m.group(1)
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
        m = re.search(r"link/ether\s+([\da-f:]{17})", line, re.I)
        if m:
            current["mac"] = m.group(1).upper()
        m = re.search(r"inet\s+([\d.]+)/(\d+)", line)
        if m and not current.get("ip"):
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
        m = re.match(r"^(\w+\d*):", line)
        if m:
            if current.get("ip"):
                interfaces.append(current)
            current = {"name": m.group(1), "ip": "", "netmask": "", "mac": ""}
            continue
        if not current:
            continue
        m = re.search(r"ether\s+([\da-f:]{17})", line, re.I)
        if m:
            current["mac"] = m.group(1).upper()
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


# ── ARP table ─────────────────────────────────────────────────────────────────

def collect_arp() -> List[dict]:
    system = platform.system()
    try:
        if system == "Windows":
            return _arp_windows()
        elif system == "Linux":
            return _arp_linux()
        elif system == "Darwin":
            return _arp_macos()
    except Exception as exc:
        _warn(f"ARP collection error: {exc}")
    return []


def _arp_windows() -> List[dict]:
    out = _run("arp -a")
    neighbors = []
    for line in out.splitlines():
        # "  10.3.10.1          aa-bb-cc-dd-ee-ff     dynamic"
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
    # Try `ip neigh show` first (modern)
    out = _run("ip neigh show")
    neighbors = []
    if out:
        for line in out.splitlines():
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
        # "router.local (10.3.10.1) at aa:bb:cc:dd:ee:ff on en0 ..."
        m = re.match(r"(\S+)\s+\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})", line)
        if m:
            hn, ip, mac = m.groups()
            entry: dict = {"ip": ip, "mac": mac.upper(), "source": "arp"}
            if hn != "?":
                entry["hostname"] = hn
            neighbors.append(entry)
    return neighbors


# ── Ping sweep ────────────────────────────────────────────────────────────────

def ping_sweep(
    networks: List[str],
    timeout_secs: float = 1.0,
    workers: int = 200,
) -> List[str]:
    """ICMP ping all hosts in the given CIDR networks. Returns list of live IPs."""
    targets: List[str] = []
    for net_str in networks:
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 1022:
                hosts = hosts[:254]
            targets.extend(str(h) for h in hosts)
        except ValueError:
            continue

    if not targets:
        return []

    _info(f"Ping sweep: {len(targets)} targets on {len(networks)} network(s)…")
    system = platform.system()
    responding: List[str] = []
    lock = threading.Lock()

    def _ping(ip: str) -> Optional[str]:
        if system == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_secs * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_secs))), ip]
        try:
            r = subprocess.run(
                cmd, capture_output=True, timeout=timeout_secs + 2
            )
            if r.returncode == 0:
                return ip
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_ping, targets):
            if result:
                with lock:
                    responding.append(result)

    _info(f"Ping sweep done: {len(responding)} hosts responded")
    return responding


# ── Port scan ─────────────────────────────────────────────────────────────────

def port_scan(
    ips: List[str],
    timeout: float = 1.0,
    workers: int = 150,
) -> List[dict]:
    """TCP connect scan of top ports. Uses nmap when available."""
    nmap = _nmap_scan(ips, timeout)
    if nmap is not None:
        return nmap

    _info(f"Port scan (socket): {len(ips)} host(s), {len(_TOP_PORTS)} ports each…")
    results: Dict[str, dict] = {}
    lock = threading.Lock()

    def _try(task: Tuple[str, int, str]) -> Optional[Tuple[str, int, str]]:
        ip, port, svc = task
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return (ip, port, svc)
            s.close()
        except Exception:
            pass
        return None

    tasks = [(ip, port, svc) for ip in ips for port, svc in _TOP_PORTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(_try, tasks):
            if result:
                ip, port, svc = result
                with lock:
                    if ip not in results:
                        results[ip] = {"ip": ip, "open_ports": []}
                    results[ip]["open_ports"].append(
                        {"port": port, "proto": "tcp", "service": svc}
                    )

    # Attempt reverse DNS for each discovered host
    for ip, data in results.items():
        try:
            data["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    _info(f"Port scan done: {len(results)} host(s) with open ports")
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
        cmd = ["nmap", "-oX", "-", "--open", timing, "-p", ports] + ips
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
            hn_el = host_el.find("hostnames/hostname")
            if hn_el is not None:
                entry["hostname"] = hn_el.get("name", "")
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
                if svc_el is not None and svc_el.get("product"):
                    port_entry["banner"] = svc_el.get("product", "")
                entry["open_ports"].append(port_entry)
            if entry["open_ports"]:
                results.append(entry)

        _info(f"nmap done: {len(results)} host(s) with open ports")
        return results

    except Exception as exc:
        _warn(f"nmap failed ({exc}), falling back to socket scan")
        return None


# ── Output ────────────────────────────────────────────────────────────────────

def build_payload(
    self_info: dict,
    neighbors: List[dict],
    scan_results: List[dict],
) -> dict:
    return {
        "gravwell_agent": True,
        "agent_version": VERSION,
        "collected_at": datetime.datetime.utcnow().isoformat() + "Z",
        "agent_id": str(uuid.uuid4()),
        "self": self_info,
        "neighbors": neighbors,
        "port_scan": scan_results,
    }


def write_json(data: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def upload(data: dict, server: str, key: str) -> bool:
    """POST the payload to the GravWell server. Returns True on success."""
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
    # Allow self-signed certs common on internal servers
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
  python collect.py --server https://gravwell.corp.local --key abc123
  python collect.py --output /tmp/recon.json --server https://gravwell.corp.local --key abc123
""",
    )
    parser.add_argument("--output", "-o", default="", help="Output file path (default: auto-named)")
    parser.add_argument("--server", "-s", default="", help="GravWell server URL")
    parser.add_argument("--key", "-k", default="", help="API key for server upload")
    parser.add_argument("--no-sweep", action="store_true", help="Skip ping sweep")
    parser.add_argument("--no-scan", action="store_true", help="Skip port scan")
    parser.add_argument("--timeout", type=float, default=1.0, help="Scan timeout seconds (default: 1.0)")
    parser.add_argument("--workers", type=int, default=150, help="Concurrent threads (default: 150)")
    args = parser.parse_args()

    _info(f"GravWell Collection Agent v{VERSION}")

    # 1. Own system info
    _info("Collecting system information…")
    self_info = collect_self()
    _info(f"  Host: {self_info['hostname']}  IPs: {self_info['ips']}")

    # 2. ARP table (passive)
    _info("Reading ARP table…")
    neighbors = collect_arp()
    _info(f"  {len(neighbors)} ARP neighbour(s)")

    # 3. Ping sweep
    if not args.no_sweep:
        networks: List[str] = []
        for iface in self_info.get("interfaces", []):
            ip = iface.get("ip")
            nm = iface.get("netmask")
            if not ip or not nm:
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{nm}", strict=False)
                if net.prefixlen >= 16:
                    n24 = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                    if n24 not in networks:
                        networks.append(n24)
            except ValueError:
                pass
        if networks:
            live = ping_sweep(networks, timeout_secs=args.timeout, workers=args.workers)
            existing = {n["ip"] for n in neighbors}
            for ip in live:
                if ip not in existing:
                    neighbors.append({"ip": ip, "source": "ping_sweep"})
                    existing.add(ip)
            # Re-read ARP to capture MACs of newly discovered hosts
            arp_map = {n["ip"]: n for n in collect_arp()}
            for n in neighbors:
                if not n.get("mac") and n["ip"] in arp_map:
                    n["mac"] = arp_map[n["ip"]].get("mac", "")
            for entry in arp_map.values():
                if entry["ip"] not in existing:
                    neighbors.append(entry)

    _info(f"Total neighbours discovered: {len(neighbors)}")

    # 4. Port scan
    scan_results: List[dict] = []
    if not args.no_scan and neighbors:
        scan_targets = list({n["ip"] for n in neighbors} | set(self_info.get("ips", [])))
        scan_results = port_scan(scan_targets, timeout=args.timeout, workers=args.workers)

    # 5. Build payload
    payload = build_payload(self_info, neighbors, scan_results)

    # 6. Write local file
    out_path = args.output
    if not out_path:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"gravwell_collect_{self_info['hostname']}_{ts}.json"
    write_json(payload, out_path)
    _info(f"Saved: {out_path}")

    # 7. Upload if requested
    if args.server:
        if not args.key:
            _warn("--server requires --key")
        else:
            _info(f"Uploading to {args.server}…")
            ok = upload(payload, args.server, args.key)
            if ok:
                _info("Upload successful")
            else:
                _warn("Upload failed — results saved locally")

    # Summary
    total_ports = sum(len(h.get("open_ports", [])) for h in scan_results)
    print("\n── Collection summary ─────────────────")
    print(f"  Own IPs:    {', '.join(self_info.get('ips', []))}")
    print(f"  Neighbours: {len(neighbors)}")
    print(f"  Scanned:    {len(scan_results)} hosts with open ports ({total_ports} total)")
    print(f"  Output:     {out_path}")
    print("────────────────────────────────────────")


if __name__ == "__main__":
    main()
