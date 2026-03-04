"""Parser for Nuclei vulnerability scanner output (JSONL / JSON array)."""
from __future__ import annotations
import json
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import infer_os

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}

# Default CVSS estimates when no score is provided by Nuclei
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

_PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    1433: "ms-sql-s", 1521: "oracle", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 8080: "http-alt", 8443: "https-alt",
}

_SCHEME_DEFAULTS: dict[str, tuple[int, str]] = {
    "http":  (80,  "tcp"),
    "https": (443, "tcp"),
    "ftp":   (21,  "tcp"),
    "ftps":  (990, "tcp"),
    "ssh":   (22,  "tcp"),
    "smtp":  (25,  "tcp"),
    "ldap":  (389, "tcp"),
    "ldaps": (636, "tcp"),
    "rdp":   (3389, "tcp"),
}


class NucleiParser(BaseParser):
    name = "nuclei"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 512)
        # Nuclei JSONL/JSON always contains these keys in each result entry
        return '"template-id"' in head and '"info"' in head and '"severity"' in head

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
        except OSError as e:
            result.errors.append(f"Read error: {e}")
            return result

        records = _load_records(content, result)
        if not records:
            return result

        hosts: dict[str, Host] = {}

        for entry in records:
            if not isinstance(entry, dict):
                continue

            # ── Resolve host IP ──────────────────────────────────────────────
            ip = (entry.get("ip") or "").strip()
            if not ip or not _is_valid_ip(ip):
                ip = _ip_from_uri(entry.get("host") or "")
            if not ip:
                result.warnings.append(
                    f"Skipping entry with no resolvable IP: "
                    f"{entry.get('template-id', '?')}"
                )
                continue

            if ip not in hosts:
                hosts[ip] = Host(ip=ip, source_files=[filepath.name], status="up")
            host = hosts[ip]

            # ── Port / protocol ──────────────────────────────────────────────
            port, transport = _port_proto_from_uri(
                entry.get("matched-at") or entry.get("host") or ""
            )

            if port and not any(
                s.port == port and s.protocol == transport for s in host.services
            ):
                host.services.append(Service(
                    port=port,
                    protocol=transport,
                    state="open",
                    service_name=_PORT_SERVICE.get(port),
                ))

            # ── Vulnerability ────────────────────────────────────────────────
            info = entry.get("info") or {}
            vuln = _build_vulnerability(entry, info, port)
            if vuln:
                host.vulnerabilities.append(vuln)

            # ── Tags → host tags ─────────────────────────────────────────────
            for tag in (info.get("tags") or []):
                if isinstance(tag, str) and tag not in host.tags:
                    host.tags.append(tag)

        # Run OS inference using all collected port/vuln signals
        for host in hosts.values():
            os_name, os_family, conf = infer_os(
                host.services, host.vulnerabilities, None
            )
            host.os_name = os_name
            host.os_family = os_family or "Unknown"
            host.os_confidence = conf

        result.hosts = list(hosts.values())
        return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_records(content: str, result: ParseResult) -> list[dict]:
    """Parse JSONL (one object per line) or a JSON array/object."""
    records: list[dict] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            pass

    if records:
        return records

    # Fallback: try parsing the whole content as a JSON array or single object
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError as e:
        result.errors.append(f"JSON parse error: {e}")
    return []


def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ip_from_uri(uri: str) -> str:
    """Extract a bare IP address from a URI like 'https://1.2.3.4:8080/'."""
    if not uri:
        return ""
    if "://" not in uri:
        uri = f"tcp://{uri}"
    try:
        hostname = urlparse(uri).hostname or ""
    except Exception:
        return ""
    return hostname if _is_valid_ip(hostname) else ""


def _port_proto_from_uri(uri: str) -> tuple[int | None, str]:
    """Return (port, transport_proto) inferred from a URI."""
    if not uri:
        return None, "tcp"
    if "://" not in uri:
        uri = f"tcp://{uri}"
    try:
        parsed = urlparse(uri)
    except Exception:
        return None, "tcp"

    port = parsed.port
    scheme = (parsed.scheme or "tcp").lower()
    default_port, transport = _SCHEME_DEFAULTS.get(scheme, (None, "tcp"))
    return (port if port is not None else default_port), transport


def _build_vulnerability(
    entry: dict, info: dict, port: int | None
) -> Vulnerability | None:
    name = info.get("name") or entry.get("template-id") or ""
    if not name:
        return None

    severity_raw = (info.get("severity") or "info").lower()
    severity = _SEVERITY_MAP.get(severity_raw, "info")

    classification = info.get("classification") or {}
    try:
        cvss_score = float(classification.get("cvss-score") or 0.0)
    except (TypeError, ValueError):
        cvss_score = 0.0
    if cvss_score == 0.0:
        cvss_score = _SEVERITY_CVSS.get(severity, 0.0)

    # CVE IDs
    cve_ids: list[str] = []
    raw_cves = classification.get("cve-id") or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    for cve in raw_cves:
        cve = str(cve).strip().upper()
        if cve and cve not in cve_ids:
            cve_ids.append(cve)

    # Description: combine info.description, matcher, matched-at, extracted data
    parts: list[str] = []
    if info.get("description"):
        parts.append(info["description"].strip())
    if entry.get("matcher-name"):
        parts.append(f"Matcher: {entry['matcher-name']}")
    matched_at = entry.get("matched-at")
    if matched_at:
        parts.append(f"Matched at: {matched_at}")
    extracted = entry.get("extracted-results") or entry.get("extracted_results")
    if extracted:
        if isinstance(extracted, list):
            extracted = ", ".join(str(x) for x in extracted[:5])
        parts.append(f"Extracted: {extracted}")

    solution = (info.get("remediation") or "").strip()
    plugin_id = entry.get("template-id") or entry.get("template") or None

    return Vulnerability(
        name=name,
        severity=severity,
        cvss_score=cvss_score,
        plugin_id=plugin_id,
        cve_ids=cve_ids,
        port=port,
        description="\n".join(parts),
        solution=solution,
    )
