"""Parser for GravWell collection agent output (JSON)."""
from __future__ import annotations

import json
from pathlib import Path

from gravwell.models.dataclasses import Host, ParseResult, Service
from gravwell.parsers.base import BaseParser


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

        # Pre-index port-scan results and hostnames by IP for O(1) merge
        scan_ports: dict[str, list[dict]] = {}
        scan_hostnames: dict[str, str] = {}
        for scan in (data.get("port_scan") or []):
            ip = scan.get("ip")
            if not ip:
                continue
            scan_ports[ip] = scan.get("open_ports") or []
            if scan.get("hostname"):
                scan_hostnames[ip] = scan["hostname"]

        # ── 2. Neighbours (ARP / ping sweep) ─────────────────────────────────
        for neighbor in (data.get("neighbors") or []):
            ip = neighbor.get("ip")
            if not ip or ip in host_map:
                continue
            mac = neighbor.get("mac") or None
            hn = neighbor.get("hostname") or scan_hostnames.get(ip) or ""
            h = Host(
                ip=ip,
                hostnames=[hn] if hn else [],
                mac=mac,
                tags=["arp-discovered"],
            )
            host_map[ip] = h
            result.hosts.append(h)

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
                    tags=["scan-only"],
                )
                host_map[ip] = h
                result.hosts.append(h)
            host = host_map[ip]
            # Update hostname from scan if missing
            if not host.hostnames and scan.get("hostname"):
                host.hostnames = [scan["hostname"]]
            for port_info in (scan.get("open_ports") or []):
                port = port_info.get("port")
                if not port:
                    continue
                host.services.append(Service(
                    port=int(port),
                    protocol=port_info.get("proto", "tcp"),
                    state="open",
                    service_name=port_info.get("service") or None,
                    banner=port_info.get("banner") or None,
                ))

        if not result.hosts:
            result.warnings.append("No hosts found in agent output")
        else:
            n_svc = sum(len(h.services) for h in result.hosts)
            result.warnings.append(
                f"Agent import: {len(result.hosts)} host(s), {n_svc} service(s)"
            )

        return result
