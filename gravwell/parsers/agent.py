"""Parser for GravWell collection agent output (JSON)."""
from __future__ import annotations

import json
from pathlib import Path

from gravwell.models.dataclasses import Host, ParseResult, Service
from gravwell.parsers.base import BaseParser


def _tls_hostnames(port_info: dict) -> list:
    """Extract unique, non-wildcard DNS names from a port entry's TLS cert fields."""
    names = []
    cn = port_info.get("tls_cn", "")
    if cn and not cn.startswith("*"):
        names.append(cn)
    for san in (port_info.get("tls_sans") or []):
        if san and not san.startswith("*") and san not in names:
            names.append(san)
    return names


_OS_FAMILY_MAP = {
    "Windows": "Windows",
    "Linux":   "Linux",
    "macOS":   "macOS",
    "Network": "Network",
}


class AgentParser(BaseParser):
    name = "agent"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 512)
        return '"gravwell_agent"' in head and '"agent_version"' in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        try:
            with open(filepath, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            result.errors.append(f"JSON parse error: {exc}")
            return result
        return cls._parse_data(result, data)

    @classmethod
    def parse_dict(cls, data: dict, source_name: str = "agent-api") -> ParseResult:
        """Parse an agent payload dict directly — no temp file needed."""
        result = ParseResult(source_file=source_name, parser_name=cls.name)
        return cls._parse_data(result, data)

    @classmethod
    def _parse_data(cls, result: ParseResult, data: dict) -> ParseResult:
        if not data.get("gravwell_agent"):
            result.errors.append("Not a GravWell agent output file")
            return result

        # Build an IP → Host map so we can merge port-scan results later
        host_map: dict[str, Host] = {}

        # ── 1. The agent's own machine ────────────────────────────────────────
        self_info = data.get("self") or {}
        self_ips: list[str] = self_info.get("ips") or []
        self_macs: list[str] = self_info.get("macs") or []
        hostname: str = self_info.get("hostname") or ""
        platform: str = self_info.get("platform") or ""
        pver: str = self_info.get("platform_version") or ""

        if self_ips:
            primary_ip = self_ips[0]
            os_name = pver or platform or None
            os_family = platform if platform in ("Windows", "Linux", "Darwin") else None
            if os_family == "Darwin":
                os_family = "macOS"
            h = Host(
                ip=primary_ip,
                hostnames=[hostname] if hostname else [],
                mac=self_macs[0] if self_macs else None,
                os_name=os_name,
                os_family=os_family,
                additional_ips=self_ips[1:],
                tags=["gravwell-agent-source"],
            )
            host_map[primary_ip] = h
            for extra in self_ips[1:]:
                host_map[extra] = h
            result.hosts.append(h)

        # ── Single pass: build hostname + MAC lookup tables for neighbour merge.
        # OS hints and open ports are consumed directly in section 3.
        scan_hostnames: dict[str, str] = {}
        scan_macs: dict[str, str] = {}
        for scan in (data.get("port_scan") or []):
            ip = scan.get("ip")
            if not ip:
                continue
            if scan.get("hostname"):
                scan_hostnames[ip] = scan["hostname"]
            if scan.get("mac"):
                scan_macs[ip] = scan["mac"]

        # ── 2. Neighbours (ARP / ping sweep / LLDP / …) ──────────────────────
        for neighbor in (data.get("neighbors") or []):
            ip = neighbor.get("ip")
            if not ip or ip in host_map:
                continue
            mac = neighbor.get("mac") or scan_macs.get(ip) or None
            hn = neighbor.get("hostname") or scan_hostnames.get(ip) or ""
            source = neighbor.get("source", "")
            tags = ["arp-discovered"]
            if source == "lldp":
                tags = ["lldp-switch"]
            elif source == "cdp":
                tags = ["cdp-switch"]
            h = Host(
                ip=ip,
                hostnames=[hn] if hn else [],
                mac=mac,
                tags=tags,
            )
            if neighbor.get("lldp_system_desc") and not h.os_name:
                h.os_name = neighbor["lldp_system_desc"][:120]
            if neighbor.get("snmp_descr") and not h.os_name:
                h.os_name = neighbor["snmp_descr"][:120]
            host_map[ip] = h
            result.hosts.append(h)

        # ── 2b. Physical links from LLDP ──────────────────────────────────────
        for link in (data.get("physical_links") or []):
            host_ip = link.get("host_ip", "")
            peer_ip = link.get("peer_ip", "")
            if host_ip and peer_ip:
                result.physical_links.append({
                    "host_ip": host_ip,
                    "peer_ip": peer_ip,
                    "port_id": link.get("port_id", ""),
                    "link_type": link.get("link_type", "lldp"),
                })

        # ── 3. Merge port-scan → services (create host if scan-only) ─────────
        for scan in (data.get("port_scan") or []):
            ip = scan.get("ip")
            if not ip:
                continue
            if ip not in host_map:
                hn = scan.get("hostname") or ""
                h = Host(
                    ip=ip,
                    hostnames=[hn] if hn else [],
                    mac=scan.get("mac") or None,
                    tags=["scan-only"],
                )
                host_map[ip] = h
                result.hosts.append(h)
            host = host_map[ip]
            if not host.hostnames and scan.get("hostname"):
                host.hostnames = [scan["hostname"]]
            if not host.mac and scan.get("mac"):
                host.mac = scan["mac"]
            if scan.get("os_hint"):
                hint = scan["os_hint"]
                if not host.os_name:
                    host.os_name = hint
                if not host.os_family:
                    host.os_family = _OS_FAMILY_MAP.get(hint)
            for role in (scan.get("role_hints") or []):
                if role not in host.tags:
                    host.tags.append(role)
            for port_info in (scan.get("open_ports") or []):
                port = port_info.get("port")
                if not port:
                    continue

                banner = port_info.get("banner") or None
                if not banner:
                    parts = []
                    if port_info.get("http_server"):
                        parts.append(port_info["http_server"])
                    if port_info.get("http_title"):
                        parts.append(f'[{port_info["http_title"]}]')
                    if parts:
                        banner = " ".join(parts)

                host.services.append(Service(
                    port=int(port),
                    protocol=port_info.get("proto", "tcp"),
                    state="open",
                    service_name=port_info.get("service") or None,
                    banner=banner,
                ))

                for hn in _tls_hostnames(port_info):
                    if hn not in host.hostnames:
                        host.hostnames.append(hn)

        # ── 4. VLAN data (from SNMP Q-BRIDGE-MIB walk) ───────────────────────
        for v in (data.get("vlans") or []):
            if isinstance(v.get("vlan_id"), int) and v.get("switch_ip"):
                result.vlans.append(v)
        for entry in (data.get("vlan_fdb") or []):
            if entry.get("mac") and isinstance(entry.get("vlan_id"), int):
                result.vlan_fdb.append(entry)

        if not result.hosts:
            result.warnings.append("No hosts found in agent output")
        else:
            n_svc = sum(len(h.services) for h in result.hosts)
            result.warnings.append(
                f"Agent import: {len(result.hosts)} host(s), {n_svc} service(s)"
            )

        return result
