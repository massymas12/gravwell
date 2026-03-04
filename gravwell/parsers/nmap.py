from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import (
    infer_os, normalize_os_family,
    CONF_EXPLICIT_EXACT, CONF_EXPLICIT_HIGH, CONF_EXPLICIT_MEDIUM,
    CONF_INFERRED_STRONG,
)


class NmapParser(BaseParser):
    name = "nmap"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath)
        return "<nmaprun" in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        try:
            tree = ET.parse(filepath)
        except ET.ParseError as e:
            result.errors.append(f"XML parse error: {e}")
            return result

        root = tree.getroot()
        for host_el in root.findall("host"):
            hosts = cls._parse_host(host_el, filepath, result)
            if hosts:
                result.hosts.extend(hosts)
        return result

    @classmethod
    def _parse_host(
        cls, el: ET.Element, filepath: Path, result: ParseResult
    ) -> list[Host]:
        status = el.find("status")
        if status is not None and status.get("state") == "down":
            return []

        ipv4_addrs: list[str] = []
        mac = None
        mac_vendor = None
        for addr in el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype == "ipv4":
                ipv4_addrs.append(addr.get("addr", ""))
            elif atype == "mac":
                mac = addr.get("addr")
                mac_vendor = addr.get("vendor")

        # Fall back to IPv6 if no IPv4 found
        if not ipv4_addrs:
            for addr in el.findall("address"):
                if addr.get("addrtype") == "ipv6":
                    ipv4_addrs.append(addr.get("addr", ""))
                    break

        ipv4_addrs = [a for a in ipv4_addrs if a]
        if not ipv4_addrs:
            result.warnings.append("Host with no IP address skipped")
            return []

        ip = ipv4_addrs[0]
        extra_ips = ipv4_addrs[1:]  # rare: multiple IPv4 in one <host> element

        hostnames: list[str] = []
        hostnames_el = el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)

        os_name = None
        os_family = "Unknown"
        os_confidence = 0
        os_el = el.find("os")
        if os_el is not None:
            best = None
            best_acc = -1
            for match in os_el.findall("osmatch"):
                acc = int(match.get("accuracy", "0"))
                if acc > best_acc:
                    best_acc = acc
                    best = match
            if best is not None:
                os_name = best.get("name")
                osclass = best.find("osclass")
                if osclass is not None:
                    os_family = normalize_os_family(osclass.get("osfamily", ""))
                else:
                    os_family = normalize_os_family(os_name or "")
                # Map osmatch accuracy → confidence bucket
                if best_acc >= 90:
                    os_confidence = CONF_EXPLICIT_EXACT
                elif best_acc >= 70:
                    os_confidence = CONF_EXPLICIT_HIGH
                elif best_acc >= 50:
                    os_confidence = CONF_EXPLICIT_MEDIUM
                else:
                    os_confidence = CONF_INFERRED_STRONG

        services: list[Service] = []
        ports_el = el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                svc = cls._parse_port(port_el)
                if svc:
                    services.append(svc)

        # Fill in OS from port/service signals if nmap didn't fingerprint one
        if os_confidence == 0:
            os_name, os_family, os_confidence = infer_os(
                services, [],
                mac_vendor,
                explicit_os_name=os_name,
                explicit_os_family=os_family if os_family != "Unknown" else None,
                explicit_confidence=os_confidence,
            )

        source = str(filepath.name) if hasattr(filepath, "name") else str(filepath)
        primary = Host(
            ip=ip,
            hostnames=hostnames,
            os_name=os_name,
            os_family=os_family or "Unknown",
            os_confidence=os_confidence,
            mac=mac,
            mac_vendor=mac_vendor,
            status="up",
            services=services,
            source_files=[source],
        )
        hosts = [primary]
        # Rare case: multiple IPv4 on a single nmap <host> element — emit each
        # as a sibling Host with the same MAC so ingestion MAC-merge links them.
        for extra_ip in extra_ips:
            hosts.append(Host(
                ip=extra_ip,
                hostnames=hostnames,
                os_name=os_name,
                os_family=os_family or "Unknown",
                os_confidence=os_confidence,
                mac=mac,
                mac_vendor=mac_vendor,
                status="up",
                services=[],        # services belong to the primary IP
                source_files=[source],
            ))
        return hosts

    @classmethod
    def _parse_port(cls, port_el: ET.Element) -> Service | None:
        state_el = port_el.find("state")
        if state_el is None:
            return None
        state = state_el.get("state", "unknown")

        protocol = port_el.get("protocol", "tcp")
        port_num = int(port_el.get("portid", "0"))

        service_name = None
        product = None
        version = None
        svc_el = port_el.find("service")
        if svc_el is not None:
            service_name = svc_el.get("name")
            product = svc_el.get("product")
            version = svc_el.get("version")

        banner = None
        for script in port_el.findall("script"):
            if script.get("id") in ("banner", "http-server-header"):
                banner = script.get("output")
                break

        return Service(
            port=port_num,
            protocol=protocol,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
            banner=banner,
        )
