from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import (
    infer_os, normalize_os_family,
    CONF_EXPLICIT_HIGH, CONF_EXPLICIT_MEDIUM,
)

_SEVERITY_MAP = {
    "4": "critical",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}


class NessusParser(BaseParser):
    name = "nessus"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath)
        return "NessusClientData_v2" in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        # iterparse keeps only ONE <ReportHost> element in memory at a time.
        # ET.parse() would load the full XML tree (can be 300–500 MB for large
        # .nessus files), so this is the critical memory fix for large imports.
        try:
            for _event, elem in ET.iterparse(str(filepath), events=("end",)):
                if elem.tag == "ReportHost":
                    host = cls._parse_report_host(elem, filepath, result)
                    if host:
                        result.hosts.append(host)
                    # Free all children (<HostProperties>, <ReportItem>s) immediately
                    # so memory stays proportional to a single host, not the full file.
                    elem.clear()
        except ET.ParseError as e:
            result.errors.append(f"XML parse error: {e}")
        return result

    @classmethod
    def _parse_report_host(
        cls, el: ET.Element, filepath: Path, result: ParseResult
    ) -> Host | None:
        ip = el.get("name", "")
        if not ip:
            result.warnings.append("ReportHost with no name skipped")
            return None

        # Host properties
        props: dict[str, str] = {}
        host_props = el.find("HostProperties")
        if host_props is not None:
            for tag in host_props.findall("tag"):
                props[tag.get("name", "")] = (tag.text or "").strip()

        # Resolve IP if name is a hostname
        actual_ip = props.get("host-ip", ip)
        hostname = props.get("host-fqdn") or (ip if ip != actual_ip else None)
        hostnames = [hostname] if hostname else []

        os_str = props.get("operating-system")
        os_confidence = CONF_EXPLICIT_HIGH if os_str else 0
        if not os_str:
            os_str = props.get("os")
            os_confidence = CONF_EXPLICIT_MEDIUM if os_str else 0
        os_family = normalize_os_family(os_str or "")

        mac_raw = props.get("mac-address", "")
        mac = mac_raw.split("\n")[0].strip() if mac_raw else None

        services: dict[tuple[int, str], Service] = {}
        vulns: list[Vulnerability] = []

        for item in el.findall("ReportItem"):
            port_str = item.get("port", "0")
            protocol = item.get("protocol", "tcp")
            svc_name = item.get("svc_name")
            severity_str = item.get("severity", "0")
            port = int(port_str) if port_str.isdigit() else 0

            # Build service entry
            if port > 0:
                key = (port, protocol)
                if key not in services:
                    services[key] = Service(
                        port=port,
                        protocol=protocol,
                        state="open",
                        service_name=svc_name,
                    )

            # Build vulnerability (skip plugin 0 = open port info unless interesting)
            plugin_id = item.get("pluginID", "0")
            plugin_name = item.get("pluginName", "")
            severity = _SEVERITY_MAP.get(severity_str, "info")

            # Skip pure port-open informational items (plugin family "Port scanners")
            plugin_family = item.get("pluginFamily", "")
            if plugin_family in ("Port scanners", "Settings") and severity == "info":
                continue

            cvss_score = 0.0
            cvss3_el = item.find("cvss3_base_score")
            cvss2_el = item.find("cvss_base_score")
            if cvss3_el is not None and cvss3_el.text:
                try:
                    cvss_score = float(cvss3_el.text)
                except ValueError:
                    pass
            elif cvss2_el is not None and cvss2_el.text:
                try:
                    cvss_score = float(cvss2_el.text)
                except ValueError:
                    pass

            cve_ids: list[str] = []
            for cve_el in item.findall("cve"):
                if cve_el.text:
                    cve_ids.append(cve_el.text.strip())

            desc_el = item.find("description")
            sol_el = item.find("solution")
            description = (desc_el.text or "").strip() if desc_el is not None else ""
            solution = (sol_el.text or "").strip() if sol_el is not None else ""

            vuln = Vulnerability(
                name=plugin_name,
                severity=severity,
                cvss_score=cvss_score,
                plugin_id=plugin_id,
                cve_ids=cve_ids,
                port=port if port > 0 else None,
                description=description,
                solution=solution,
            )
            vulns.append(vuln)

        svc_list = list(services.values())
        # Improve OS with port/service/vuln signals when scanner data is weak
        final_os_name, final_os_family, final_conf = infer_os(
            svc_list, vulns, mac,
            explicit_os_name=os_str,
            explicit_os_family=os_family if os_family != "Unknown" else None,
            explicit_confidence=os_confidence,
        )
        source = filepath.name
        return Host(
            ip=actual_ip,
            hostnames=hostnames,
            os_name=final_os_name,
            os_family=final_os_family or "Unknown",
            os_confidence=final_conf,
            mac=mac,
            status="up",
            services=svc_list,
            vulnerabilities=vulns,
            source_files=[source],
        )
