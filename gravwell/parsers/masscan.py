from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import infer_os


class MasscanParser(BaseParser):
    name = "masscan"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 512).strip()
        if "<masscan" in head or "masscan version" in head.lower():
            return True
        if head.startswith("["):
            # Masscan JSON records contain "ports" (the scan results array) and
            # either "timestamp" or "proto"/"ttl" (per-port fields).
            # Require at least one of these to avoid grabbing any JSON array
            # (e.g. CrowdStrike Spotlight exports also start with '[').
            return '"ports"' in head and (
                '"timestamp"' in head or '"proto"' in head or '"ttl"' in head
            )
        return False

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        head = cls._read_head(filepath, 64).strip()
        if head.startswith("["):
            cls._parse_json(filepath, result)
        else:
            cls._parse_xml(filepath, result)
        return result

    @classmethod
    def _parse_json(cls, filepath: Path, result: ParseResult) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            result.errors.append(f"JSON parse error: {e}")
            return

        hosts: dict[str, Host] = {}
        for entry in data:
            ip = entry.get("ip")
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = Host(ip=ip, source_files=[filepath.name])
            host = hosts[ip]
            for port_info in entry.get("ports", []):
                port = port_info.get("port")
                proto = port_info.get("proto", "tcp")
                status = port_info.get("status", "open")
                svc_name = None
                svc_data = port_info.get("service")
                if isinstance(svc_data, dict):
                    svc_name = svc_data.get("name")
                if port:
                    host.services.append(Service(
                        port=int(port),
                        protocol=proto,
                        state=status,
                        service_name=svc_name,
                    ))
        for host in hosts.values():
            os_name, os_family, conf = infer_os(host.services, [], host.mac_vendor)
            host.os_name = os_name
            host.os_family = os_family or "Unknown"
            host.os_confidence = conf
        result.hosts = list(hosts.values())

    @classmethod
    def _parse_xml(cls, filepath: Path, result: ParseResult) -> None:
        try:
            tree = ET.parse(filepath)
        except ET.ParseError as e:
            result.errors.append(f"XML parse error: {e}")
            return
        hosts: dict[str, Host] = {}
        root = tree.getroot()
        for host_el in root.findall(".//host"):
            ip = None
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = Host(ip=ip, source_files=[filepath.name])
            host = hosts[ip]
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    state = state_el.get("state", "open") if state_el is not None else "open"
                    proto = port_el.get("protocol", "tcp")
                    port_num = int(port_el.get("portid", "0"))
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name") if svc_el is not None else None
                    host.services.append(Service(
                        port=port_num,
                        protocol=proto,
                        state=state,
                        service_name=svc_name,
                    ))
        for host in hosts.values():
            os_name, os_family, conf = infer_os(host.services, [], host.mac_vendor)
            host.os_name = os_name
            host.os_family = os_family or "Unknown"
            host.os_confidence = conf
        result.hosts = list(hosts.values())
