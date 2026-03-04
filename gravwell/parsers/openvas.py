from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import infer_os

_SEVERITY_THRESHOLDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _cvss_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def _parse_port_str(port_str: str) -> tuple[int | None, str]:
    """Parse '80/tcp' or 'general/tcp' → (port_or_None, protocol)."""
    if not port_str or port_str.startswith("general"):
        return None, "tcp"
    parts = port_str.split("/")
    try:
        return int(parts[0]), parts[1] if len(parts) > 1 else "tcp"
    except (ValueError, IndexError):
        return None, "tcp"


class OpenVASParser(BaseParser):
    name = "openvas"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath)
        return ("<report" in head and "openvas" in head.lower()) or \
               "gsa" in head.lower() or \
               "<omp>" in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        try:
            tree = ET.parse(filepath)
        except ET.ParseError as e:
            result.errors.append(f"XML parse error: {e}")
            return result

        root = tree.getroot()
        # Support both <report> root and <omp><get_reports_response><report>
        report_el = root if root.tag == "report" else root.find(".//report")
        if report_el is None:
            result.errors.append("No <report> element found")
            return result

        hosts: dict[str, Host] = {}

        for result_el in report_el.findall(".//result"):
            host_el = result_el.find("host")
            if host_el is None:
                continue
            ip = (host_el.text or "").strip()
            if not ip:
                continue

            if ip not in hosts:
                hosts[ip] = Host(ip=ip, source_files=[filepath.name])
            host = hosts[ip]

            port_str = ""
            port_el = result_el.find("port")
            if port_el is not None:
                port_str = (port_el.text or "").strip()

            port, protocol = _parse_port_str(port_str)

            # Service
            if port is not None:
                existing_ports = {s.port for s in host.services}
                if port not in existing_ports:
                    host.services.append(Service(
                        port=port, protocol=protocol, state="open"
                    ))

            # Vulnerability
            nvt_el = result_el.find("nvt")
            name = ""
            cve_ids: list[str] = []
            if nvt_el is not None:
                name_el = nvt_el.find("name")
                name = (name_el.text or "").strip() if name_el is not None else ""
                cve_el = nvt_el.find("cve")
                if cve_el is not None and cve_el.text:
                    # May be comma-separated
                    raw = cve_el.text.strip()
                    if raw.upper() != "NOCVE":
                        cve_ids = [c.strip() for c in raw.split(",") if c.strip()]

            severity_score = 0.0
            severity_el = result_el.find("severity")
            if severity_el is not None and severity_el.text:
                try:
                    severity_score = float(severity_el.text)
                except ValueError:
                    pass

            desc_el = result_el.find("description")
            description = (desc_el.text or "").strip() if desc_el is not None else ""

            if name:
                host.vulnerabilities.append(Vulnerability(
                    name=name,
                    severity=_cvss_to_severity(severity_score),
                    cvss_score=severity_score,
                    cve_ids=cve_ids,
                    port=port,
                    description=description,
                ))

        for host in hosts.values():
            os_name, os_family, conf = infer_os(
                host.services, host.vulnerabilities, None
            )
            host.os_name = os_name
            host.os_family = os_family or "Unknown"
            host.os_confidence = conf
        result.hosts = list(hosts.values())
        return result
