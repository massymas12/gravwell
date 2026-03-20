from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import (
    infer_os, normalize_os_family,
    CONF_EXPLICIT_EXACT, CONF_EXPLICIT_HIGH, CONF_EXPLICIT_MEDIUM,
    CONF_INFERRED_STRONG,
)

_CVE_RE   = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CVSS_RE  = re.compile(r"\b(\d+\.\d)\b")


def _cvss_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score  > 0.0: return "low"
    return "info"


class NmapParser(BaseParser):
    name = "nmap"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath)
        return "nmaprun" in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            # File may be incomplete (e.g. scan interrupted before </nmaprun>)
            try:
                content = filepath.read_bytes().decode("utf-8", errors="replace")
                last = content.rfind("</host>")
                if last == -1:
                    result.errors.append(f"XML parse error: {e}")
                    return result
                truncated = content[: last + len("</host>")] + "\n</nmaprun>"
                root = ET.fromstring(truncated)
                result.warnings.append(
                    "File appears incomplete (scan was interrupted) — partial results imported"
                )
            except Exception:
                result.errors.append(f"XML parse error: {e}")
                return result

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
        vulns: list[Vulnerability] = []
        ports_el = el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                svc = cls._parse_port(port_el)
                if svc:
                    services.append(svc)
                port_num = int(port_el.get("portid", "0"))
                vulns.extend(cls._parse_vuln_scripts(port_el, port_num))

        # Host-level scripts — e.g. smb-vuln-ms17-010 runs against the host
        hostscript_el = el.find("hostscript")
        if hostscript_el is not None:
            vulns.extend(cls._parse_vuln_scripts(hostscript_el, None))

        # Deduplicate by (cve_id, port) so multi-script runs don't double-count
        vulns = _dedup_vulns(vulns)

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
            vulnerabilities=vulns,
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

    # ── Vulnerability script parsing ─────────────────────────────────────────

    @classmethod
    def _parse_vuln_scripts(
        cls, element: ET.Element, port_num: int | None
    ) -> list[Vulnerability]:
        """Parse all <script> children of a <port> or <hostscript> element."""
        vulns = []
        for script in element.findall("script"):
            vulns.extend(cls._parse_script(script, port_num))
        return vulns

    @classmethod
    def _parse_script(
        cls, script: ET.Element, port_num: int | None
    ) -> list[Vulnerability]:
        script_id = script.get("id", "")
        output    = script.get("output", "")

        if script_id == "vulners":
            return cls._parse_vulners(script, port_num)
        if script_id == "vulscan":
            return cls._parse_vulscan(output, script_id, port_num)
        # Any NSE script in the vuln or exploit category
        if "vuln" in script_id or "exploit" in script_id:
            return cls._parse_nse_vuln(script, script_id, output, port_num)
        return []

    @classmethod
    def _parse_vulners(
        cls, script: ET.Element, port_num: int | None
    ) -> list[Vulnerability]:
        """Parse the vulners NSE script — structured nested CVE tables.

        The script nests CVE entries either flat or under a version-string key:
          <table key="OpenSSH 7.4">
            <table>
              <elem key="type">CVE</elem>
              <elem key="id">CVE-2018-15473</elem>
              <elem key="cvss">5.0</elem>
            </table>
          </table>
        We walk all <table> elements and collect those that have both an
        "id" elem matching CVE-XXXX-XXXX and a "cvss" elem.
        """
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        for table in script.iter("table"):
            elems = {e.get("key"): (e.text or "").strip()
                     for e in table.findall("elem")}
            cve_id   = elems.get("id", "")
            cvss_txt = elems.get("cvss", "")
            if not cve_id or not _CVE_RE.match(cve_id):
                continue
            cve_id = cve_id.upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            try:
                score = float(cvss_txt)
            except (ValueError, TypeError):
                score = 0.0
            vulns.append(Vulnerability(
                name=cve_id,
                severity=_cvss_severity(score),
                cvss_score=score,
                cve_ids=[cve_id],
                port=port_num,
                description="Identified by vulners NSE script",
                plugin_id="vulners",
            ))
        return vulns

    @classmethod
    def _parse_nse_vuln(
        cls, script: ET.Element, script_id: str,
        output: str, port_num: int | None
    ) -> list[Vulnerability]:
        """Parse NSE vuln-category scripts (smb-vuln-*, rdp-vuln-*, etc.).

        These scripts emit a structured table when the target is VULNERABLE:
          <table key="VULNERABLE">
            <elem key="title">MS17-010 EternalBlue</elem>
            <elem key="state">VULNERABLE</elem>
            <table key="ids">
              <elem>CVE:CVE-2017-0144</elem>
            </table>
            <elem key="cvss">9.3</elem>
          </table>
        We also scan plain text output as a fallback for simpler scripts.
        """
        # Only emit a finding when the script explicitly reports VULNERABLE
        state_els = [e for e in script.iter("elem")
                     if (e.get("key") or "").lower() == "state"]
        state_texts = [e.text or "" for e in state_els]
        if not any("VULNERABLE" in t.upper() for t in state_texts):
            if "VULNERABLE" not in output.upper():
                return []

        # Collect CVE IDs from every <elem> text and from output
        cve_ids: list[str] = []
        seen_cves: set[str] = set()
        for el in script.iter("elem"):
            for m in _CVE_RE.finditer(el.text or ""):
                cve = m.group(0).upper()
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    cve_ids.append(cve)
        for m in _CVE_RE.finditer(output):
            cve = m.group(0).upper()
            if cve not in seen_cves:
                seen_cves.add(cve)
                cve_ids.append(cve)

        # CVSS score — try structured elem first, then risk_factor text
        score = 0.0
        cvss_els = [e for e in script.iter("elem")
                    if (e.get("key") or "").lower() == "cvss"]
        if cvss_els and cvss_els[0].text:
            try:
                score = float(cvss_els[0].text)
            except ValueError:
                pass
        if score == 0.0:
            risk_els = [e for e in script.iter("elem")
                        if (e.get("key") or "").lower() in ("risk_factor", "risk factor")]
            if risk_els:
                risk = (risk_els[0].text or "").strip().lower()
                score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}.get(risk, 0.0)

        # Title / description
        title_els = [e for e in script.iter("elem")
                     if (e.get("key") or "").lower() == "title"]
        title = title_els[0].text if title_els else ""
        desc_els = [e for e in script.iter("elem")
                    if (e.get("key") or "").lower() == "description"]
        desc = desc_els[0].text if desc_els else (output[:500] if output else "")

        name = cve_ids[0] if cve_ids else (title or script_id)
        return [Vulnerability(
            name=name,
            severity=_cvss_severity(score),
            cvss_score=score,
            cve_ids=cve_ids,
            port=port_num,
            description=(desc or title or "").strip(),
            plugin_id=script_id,
        )]

    @classmethod
    def _parse_vulscan(
        cls, output: str, script_id: str, port_num: int | None
    ) -> list[Vulnerability]:
        """Parse vulscan text output — lines typically contain CVE IDs and scores."""
        vulns: list[Vulnerability] = []
        seen: set[str] = set()
        for line in output.splitlines():
            m = _CVE_RE.search(line)
            if not m:
                continue
            cve = m.group(0).upper()
            if cve in seen:
                continue
            seen.add(cve)
            score = 0.0
            nums = _CVSS_RE.findall(line)
            if nums:
                try:
                    score = float(nums[0])
                except ValueError:
                    pass
            vulns.append(Vulnerability(
                name=cve,
                severity=_cvss_severity(score),
                cvss_score=score,
                cve_ids=[cve],
                port=port_num,
                plugin_id=script_id,
            ))
        return vulns


def _dedup_vulns(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Deduplicate by primary CVE ID + port. When same CVE appears on multiple
    ports, keep the highest-scoring entry for each (CVE, port) pair."""
    best: dict[tuple, Vulnerability] = {}
    for v in vulns:
        key_cve = v.cve_ids[0] if v.cve_ids else v.name
        key = (key_cve.upper(), v.port)
        if key not in best or v.cvss_score > best[key].cvss_score:
            best[key] = v
    return list(best.values())
