"""Parser for CrowdStrike Falcon exported assets.

Supports four common export forms:
  1. **Device inventory CSV**  — exported from Falcon Console > Hosts > Manage > Export
  2. **Device inventory JSON** — CrowdStrike API ``/devices/entities/devices/v2`` response
     or a plain JSON array of device objects
  3. **Spotlight vulnerability CSV** — Falcon Spotlight > Vulnerabilities > Export
  4. **Spotlight vulnerability JSON** — API ``/spotlight/entities/vulnerabilities/v2``

Detection heuristics (most-to-least specific):
  - JSON with ``resources[].device_id``  → device inventory JSON
  - JSON with ``resources[].cve.id``     → Spotlight JSON
  - Plain JSON array with ``device_id``  → device inventory JSON array
  - CSV header with ``device_id`` or ``agent_version`` → device inventory CSV
  - CSV header with ``cve_id`` or ``CVE ID``           → Spotlight CSV
"""
from __future__ import annotations
import csv
import io
import ipaddress
import json
import re
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser


# ── Severity mapping (CrowdStrike uses CRITICAL/HIGH/MEDIUM/LOW/NONE) ─────────
_SEV_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "info",
    "unknown":  "info",
}

# ── Service ports commonly seen in CrowdStrike product metadata ────────────────
_PRODUCT_PORTS: dict[str, tuple[int, str, str]] = {
    # product_name_substring → (port, proto, service_name)
    "http":    (80,   "tcp", "http"),
    "https":   (443,  "tcp", "https"),
    "smb":     (445,  "tcp", "smb"),
    "rdp":     (3389, "tcp", "rdp"),
    "ssh":     (22,   "tcp", "ssh"),
    "ftp":     (21,   "tcp", "ftp"),
    "telnet":  (23,   "tcp", "telnet"),
}


# ── Detection helpers ─────────────────────────────────────────────────────────

# Strong CS-only keys — any one of these is sufficient to confirm CrowdStrike.
_CS_STRONG = (
    '"local_ips"',              # CrowdStrike Discover / Asset Management export (array of IPs)
    '"device_id"',              # Falcon device inventory — very CS-specific
    '"falcon_host_link"',       # Falcon device inventory
    '"agent_version"',          # Falcon device inventory
    '"product_type_desc"',      # Falcon device inventory ("Workstation", "Server", "DC")
    '"crowdstrike_id"',         # some export formats
    '"mac_addresses"',          # Discover asset export (array of MACs)
    '"ip_address_history"',     # Discover export: historical IPs array
    '"asset_criticality"',      # Spotlight console export (hostname-only vuln list)
    '"vulnerability_confidence"',  # Spotlight console export
)

# Weak CS keys that appear in many tools; need TWO of these to confirm.
_CS_WEAK = (
    '"cid"',                 # CrowdStrike CID (customer ID)
    '"aid"',                 # CrowdStrike agent ID
    '"host_info"',           # Spotlight vuln format (API)
    '"exprt_rating"',        # Spotlight ExPRT risk rating
    '"system_manufacturer"', # hardware vendor field in Discover exports
    '"host_id"',             # flat vulnerability export format
    '"vuln_type"',           # Spotlight API vuln type field
    '"local_ip"',            # flat vuln export (singular, not array)
    '"machine_domain"',      # Discover asset export — AD domain name
    '"last_seen_timestamp"', # Discover asset export timestamp field
    '"device_type"',         # Discover asset export — device category (Laptop/Server/etc.)
    '"ip_address_history"',  # also listed as weak fallback (already strong above)
    '"vulnerability_id"',    # Spotlight console export CVE field
)

# Filename hints — file was exported from a CrowdStrike product
_CS_FILENAME_HINTS = (
    "crowdstrike", "falcon", "spotlight", "cs_device", "cs_host",
    "cs_vuln", "falconhost", "crowdstrike_device",
    "vulnerabilities",  # e.g. "39719_vulnerabilities_2026-03-03T16_10_27Z.json"
)


def _is_cs_json(head: str, filename: str = "") -> bool:
    stripped = head.strip()
    if not stripped.startswith(("{", "[")):
        return False
    # One strong key is enough
    if any(k in head for k in _CS_STRONG):
        return True
    # Two weak keys confirm it
    if sum(1 for k in _CS_WEAK if k in head) >= 2:
        return True
    # Filename hint + any weak key
    name_lower = filename.lower()
    if any(h in name_lower for h in _CS_FILENAME_HINTS):
        if any(k in head for k in _CS_WEAK):
            return True
    return False


def _is_cs_csv(head: str, filename: str = "") -> bool:
    # Filename hint alone is strong enough for CSV (structure check below)
    name_lower = filename.lower()
    if any(h in name_lower for h in _CS_FILENAME_HINTS):
        first_line = head.splitlines()[0].lower() if head.strip() else ""
        if "," in first_line and any(
            w in first_line for w in ("ip", "hostname", "host", "device", "cve")
        ):
            return True
    # Column-header based detection
    first_line = head.splitlines()[0].lower() if head.strip() else ""
    cs_fields = {
        "device_id", "agent_version", "product_type_desc",
        "platform_name", "cve_id", "cve id", "exprt_rating",
        "local_ip_addresses", "falcon_host_link",
    }
    fields_in_header = {f.strip().strip('"') for f in first_line.split(",")}
    return bool(fields_in_header & cs_fields)


class CrowdStrikeParser(BaseParser):
    name = "crowdstrike"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        # 16 KB — enough to find keys even past a large API metadata preamble
        head = cls._read_head(filepath, 16384)
        stripped = head.strip()
        fname = filepath.name
        if stripped.startswith(("{", "[")):
            return _is_cs_json(head, fname)
        return _is_cs_csv(head, fname)

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        head = cls._read_head(filepath, 512)
        if head.strip().startswith(("{", "[")):
            result = cls._parse_json_stream(filepath, result)
        else:
            try:
                with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as fh:
                    text = fh.read()
                result = cls._parse_csv(text, result)
            except OSError as e:
                result.errors.append(f"File read error: {e}")

        # hn: = spotlight merges; nip: = device-inventory assets with no local IP
        real_hosts = [
            h for h in result.hosts
            if not h.ip.startswith("hn:")
        ]
        if not result.hosts:
            result.warnings.append("No hosts found in CrowdStrike export")
        elif not real_hosts:
            # Console-spotlight export: only hostname-keyed records (no IPs)
            # Warning already added by the stream parser; nothing more to add here.
            pass
        return result

    # ── Streaming JSON (ijson) — O(1) memory regardless of file size ──────────

    @classmethod
    def _parse_json_stream(cls, filepath: Path, result: ParseResult) -> ParseResult:
        """Parse JSON by streaming one record at a time via ijson.

        A 100 MB Spotlight export (39 k vuln records) previously required
        ~300 MB of Python objects from ``json.loads``.  With streaming the
        peak memory is bounded by a single decoded record (~2–5 KB).
        """
        try:
            import ijson
        except ImportError:
            # ijson not installed — fall back to full-load (may OOM on large files)
            try:
                with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as fh:
                    text = fh.read()
                return cls._parse_json_full(text, result)
            except OSError as e:
                result.errors.append(f"File read error: {e}")
                return result

        head = cls._read_head(filepath, 16384)

        # ijson prefix determines which part of the JSON tree we iterate:
        #   {"resources": [...]}  →  "resources.item"
        #   [{...}, ...]          →  "item"
        has_envelope = head.lstrip().startswith("{") and '"resources"' in head
        prefix = "resources.item" if has_envelope else "item"

        # Detect sub-format from the first 16 KB so we don't need to peek
        # at the first record (which would consume the ijson generator).
        #
        # Formats:
        #   spotlight_api      — {"resources":[{"cve":{...},"host_info":{...}}]}
        #   flat_vuln          — [{"host_id":"...","local_ip":"...","cve_id":"..."}]
        #   console_spotlight  — [{hostname, vulnerability_id, exprt_rating, asset_criticality...}]
        #                        (Spotlight console UI export — hostname-only, no IP field)
        #   device             — [{...device fields...}]  (Discover / Asset Mgmt)
        is_spotlight = ('"cve"' in head) and (
            '"host_info"' in head or '"aid"' in head
        )
        is_flat_vuln = ('"host_id"' in head or '"local_ip"' in head) and (
            '"cve_id"' in head or '"vulnerability"' in head or
            '"cve"' in head or "vulnerabilities" in filepath.name.lower()
        )
        is_console_spotlight = (
            '"asset_criticality"' in head
            or '"vulnerability_confidence"' in head
            or ('"exprt_rating"' in head and '"hostname"' in head)
        ) and '"vulnerability_id"' in head

        host_map: dict[str, Host] = {}
        skipped_no_ip = 0
        skipped_dupe  = 0
        total_recs    = 0
        try:
            with open(filepath, "rb") as fh:
                for rec in ijson.items(fh, prefix):
                    if not isinstance(rec, dict):
                        continue
                    total_recs += 1
                    if is_spotlight:
                        _spotlight_rec_to_host_map(rec, host_map, result.source_file)
                    elif is_flat_vuln:
                        _flat_vuln_rec_to_host_map(rec, host_map, result.source_file)
                    elif is_console_spotlight:
                        _console_spotlight_rec_to_host_map(rec, host_map, result.source_file)
                    else:
                        host = _device_to_host(rec, result.source_file)
                        if not host:
                            skipped_no_ip += 1
                        elif host.ip in host_map:
                            skipped_dupe += 1
                        else:
                            host_map[host.ip] = host
        except Exception as e:
            result.errors.append(f"JSON stream error: {e}")

        if skipped_no_ip:
            msg = (
                f"{skipped_no_ip} of {total_recs} records skipped — no routable IP, "
                f"hostname, or device ID found "
                f"(checked: local_ip, local_ips, network_interfaces, ip_address_history). "
                "These records could not be identified. "
                "Note: devices with a hostname but no local IP are imported with a "
                "'no-local-ip' tag and can be assigned an IP via the Edit modal."
            )
            result.warnings.append(msg)
        if skipped_dupe:
            result.warnings.append(
                f"{skipped_dupe} of {total_recs} records had a duplicate IP — merged into existing host."
            )

        result.hosts = list(host_map.values())
        if is_console_spotlight:
            hn_count = sum(1 for h in result.hosts if h.ip.startswith("hn:"))
            if hn_count:
                result.warnings.append(
                    f"Spotlight console export: {hn_count} hostnames with vulnerabilities. "
                    "These will be merged into existing hosts from your device inventory import."
                )
            elif total_recs:
                result.warnings.append(
                    "No vulnerabilities could be parsed from this Spotlight console export."
                )
        return result

    @classmethod
    def _parse_json_full(cls, text: str, result: ParseResult) -> ParseResult:
        """Full-load fallback used only when ijson is unavailable."""
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            result.errors.append(f"JSON parse error: {e}")
            return result

        if isinstance(obj, dict) and "resources" in obj:
            resources = obj["resources"]
        elif isinstance(obj, list):
            resources = obj
        else:
            result.warnings.append("Unrecognised CrowdStrike JSON structure")
            return result

        if not isinstance(resources, list):
            result.warnings.append("CrowdStrike JSON 'resources' is not a list")
            return result

        host_map: dict[str, Host] = {}
        first = resources[0] if resources and isinstance(resources[0], dict) else {}
        is_spotlight = "cve" in first or ("aid" in first and "host_info" in first)
        is_console_spotlight = (
            "asset_criticality" in first
            or "vulnerability_confidence" in first
            or ("exprt_rating" in first and "hostname" in first)
        ) and "vulnerability_id" in first
        skipped_no_ip = 0
        skipped_dupe  = 0

        for rec in resources:
            if not isinstance(rec, dict):
                continue
            if is_spotlight:
                _spotlight_rec_to_host_map(rec, host_map, result.source_file)
            elif is_console_spotlight:
                _console_spotlight_rec_to_host_map(rec, host_map, result.source_file)
            else:
                host = _device_to_host(rec, result.source_file)
                if not host:
                    skipped_no_ip += 1
                elif host.ip in host_map:
                    skipped_dupe += 1
                else:
                    host_map[host.ip] = host

        if skipped_no_ip:
            result.warnings.append(
                f"{skipped_no_ip} of {len(resources)} records skipped — no routable IP found. "
                "These are likely offline or sensor-less assets."
            )
        if skipped_dupe:
            result.warnings.append(
                f"{skipped_dupe} of {len(resources)} records had a duplicate IP — merged into existing host."
            )

        result.hosts = list(host_map.values())
        return result

    # ── CSV ───────────────────────────────────────────────────────────────────

    @classmethod
    def _parse_csv(cls, text: str, result: ParseResult) -> ParseResult:
        reader = csv.DictReader(io.StringIO(text))
        headers = {h.strip().lower().replace(" ", "_") for h in (reader.fieldnames or [])}

        # Is this a Spotlight CSV?
        if "cve_id" in headers or "cve_base_score" in headers:
            return cls._parse_spotlight_csv(reader, result)
        return cls._parse_device_csv(reader, result)

    @classmethod
    def _parse_device_csv(cls, reader: csv.DictReader, result: ParseResult) -> ParseResult:
        host_map: dict[str, Host] = {}
        for row in reader:
            norm = {k.strip().lower().replace(" ", "_"): (v or "").strip()
                    for k, v in row.items()}
            host = _device_row_to_host(norm, result.source_file)
            if host and host.ip != "0.0.0.0":
                if host.ip not in host_map:
                    host_map[host.ip] = host
        result.hosts = list(host_map.values())
        return result

    @classmethod
    def _parse_spotlight_csv(cls, reader: csv.DictReader, result: ParseResult) -> ParseResult:
        host_map: dict[str, Host] = {}
        for row in reader:
            norm = {k.strip().lower().replace(" ", "_"): (v or "").strip()
                    for k, v in row.items()}
            ip = (norm.get("local_ip") or norm.get("ip_address")
                  or norm.get("local_ip_addresses") or "").split(",")[0].strip()
            if not ip or not _valid_ip(ip):
                continue

            hostname = norm.get("hostname") or norm.get("device_hostname") or ""
            os_ver   = norm.get("os_version") or norm.get("platform") or ""
            platform = norm.get("platform_name") or norm.get("platform") or ""

            if ip not in host_map:
                host_map[ip] = Host(
                    ip=ip,
                    hostnames=[hostname] if hostname else [],
                    os_name=os_ver or None,
                    os_family=_map_platform(platform),
                    status="up",
                    source_files=[result.source_file],
                    tags=["crowdstrike-spotlight"],
                )

            host = host_map[ip]

            cve_id = norm.get("cve_id") or norm.get("cve_id_") or ""
            if cve_id:
                sev_raw = (norm.get("severity") or "unknown").lower()
                severity = _SEV_MAP.get(sev_raw, "info")
                try:
                    cvss = float(norm.get("cve_base_score") or norm.get("cvss_base_score") or 0.0)
                except (ValueError, TypeError):
                    cvss = 0.0
                product = (norm.get("product_name_version") or norm.get("product")
                           or norm.get("app_name") or "")
                remediation = norm.get("remediation_action") or norm.get("solution") or ""
                vuln = Vulnerability(
                    name=f"{cve_id}: {product}" if product else cve_id,
                    severity=severity,
                    cvss_score=cvss,
                    plugin_id=cve_id,
                    cve_ids=[cve_id] if cve_id else [],
                    solution=remediation,
                )
                host.vulnerabilities.append(vuln)

        result.hosts = list(host_map.values())
        return result


# ── Private helpers ───────────────────────────────────────────────────────────

def _spotlight_rec_to_host_map(
    rec: dict, host_map: dict[str, "Host"], source: str
) -> None:
    """Accumulate one Spotlight record into *host_map* (modifies in-place).

    One call per JSON record — compatible with both streaming (ijson) and
    full-load paths, keeping the logic in a single place.
    """
    host_info = rec.get("host_info") or {}
    ip = (
        host_info.get("local_ip") or host_info.get("ip_address")
        or rec.get("local_ip") or ""
    ).strip()
    if not ip or not _valid_ip(ip):
        return

    if ip not in host_map:
        hostname = (host_info.get("hostname") or rec.get("hostname") or "").strip()
        os_ver = (host_info.get("os_version") or rec.get("os_version") or "").strip()
        platform = (
            host_info.get("platform") or host_info.get("platform_name")
            or rec.get("platform_name") or ""
        ).strip()
        from gravwell.models.dataclasses import Host as _Host
        host_map[ip] = _Host(
            ip=ip,
            hostnames=[hostname] if hostname else [],
            os_name=os_ver or None,
            os_family=_map_platform(platform or os_ver),
            status="up",
            source_files=[source],
            tags=["crowdstrike-spotlight"],
        )

    host = host_map[ip]
    cve_block = rec.get("cve") or {}
    cve_id = (cve_block.get("id") or "").strip()
    if not cve_id:
        return

    sev_raw = (cve_block.get("severity") or "unknown").lower()
    severity = _SEV_MAP.get(sev_raw, "info")
    try:
        cvss = float(cve_block.get("base_score") or 0.0)
    except (ValueError, TypeError):
        cvss = 0.0

    app_block = rec.get("app") or {}
    product = (
        app_block.get("product_name_version") or app_block.get("product_name") or ""
    )
    from gravwell.models.dataclasses import Vulnerability as _Vuln
    host.vulnerabilities.append(
        _Vuln(
            name=f"{cve_id}: {product}" if product else cve_id,
            severity=severity,
            cvss_score=cvss,
            plugin_id=cve_id,
            cve_ids=[cve_id],
            description=cve_block.get("description") or "",
            solution=cve_block.get("remediation_level") or "",
        )
    )


def _flat_vuln_rec_to_host_map(
    rec: dict, host_map: dict[str, "Host"], source: str
) -> None:
    """Parse one record from a flat CrowdStrike vulnerability export.

    This format stores one host+CVE pair per JSON object, e.g.:
      {"host_id":"...","hostname":"...","local_ip":"10.x.x.x","cve_id":"CVE-...","severity":"HIGH",...}

    Groups records by IP, merging multiple CVEs onto the same Host.
    """
    ip = (
        rec.get("local_ip") or rec.get("ip") or rec.get("ip_address") or ""
    ).strip()
    if not ip or not _valid_ip(ip):
        return

    if ip not in host_map:
        hostname = (rec.get("hostname") or rec.get("host_name") or "").strip()
        os_ver   = (rec.get("os_version") or rec.get("platform") or "").strip()
        from gravwell.models.dataclasses import Host as _Host
        host_map[ip] = _Host(
            ip=ip,
            hostnames=[hostname] if hostname else [],
            os_name=os_ver or None,
            os_family=_map_platform(os_ver),
            status="up",
            source_files=[source],
            tags=["crowdstrike"],
        )

    host = host_map[ip]

    # Vulnerability — try several common field-name patterns
    cve_id = (
        rec.get("cve_id") or rec.get("cve") or rec.get("vulnerability_id")
        or rec.get("vuln_id") or rec.get("finding_id") or ""
    ).strip()
    if not cve_id:
        return

    sev_raw  = (rec.get("severity") or rec.get("risk_level") or "unknown").lower()
    severity = _SEV_MAP.get(sev_raw, "info")
    try:
        cvss = float(
            rec.get("cvss_score") or rec.get("cvss_base_score")
            or rec.get("base_score") or rec.get("cvss") or 0.0
        )
    except (ValueError, TypeError):
        cvss = 0.0

    product = (
        rec.get("product_name") or rec.get("product_name_version")
        or rec.get("affected_software") or rec.get("application") or ""
    )
    solution = (
        rec.get("remediation") or rec.get("solution")
        or rec.get("remediation_action") or ""
    )
    description = rec.get("description") or rec.get("vuln_description") or ""

    from gravwell.models.dataclasses import Vulnerability as _Vuln
    host.vulnerabilities.append(
        _Vuln(
            name=f"{cve_id}: {product}" if product else cve_id,
            severity=severity,
            cvss_score=cvss,
            plugin_id=cve_id,
            cve_ids=[cve_id],
            description=description,
            solution=solution,
        )
    )


def _console_spotlight_rec_to_host_map(
    rec: dict, host_map: dict[str, "Host"], source: str
) -> None:
    """Parse one record from the Spotlight console UI export.

    This format is exported from the Falcon Spotlight UI and contains one
    vulnerability per record, keyed by *hostname* only — no IP address is
    included.  Records are grouped by a synthetic ``"hn:<hostname>"`` key so
    they can be matched to existing hosts during ingestion via hostname lookup.

    Example record fields:
      hostname, vulnerability_id (CVE), severity, exprt_rating,
      asset_criticality, products, recommended_remediations,
      vulnerability_confidence, status, days_open, cisa_info
    """
    hostname = (rec.get("hostname") or "").strip()
    if not hostname:
        return

    # Synthetic key for hostname-keyed host (no IP available)
    key = f"hn:{hostname.lower()}"

    if key not in host_map:
        from gravwell.models.dataclasses import Host as _Host
        host_map[key] = _Host(
            ip=key,
            hostnames=[hostname],
            status="up",
            source_files=[source],
            tags=["crowdstrike-spotlight"],
        )

    host = host_map[key]

    cve_id = (rec.get("vulnerability_id") or "").strip()
    if not cve_id:
        return

    # Use the more severe of severity / exprt_rating
    sev_raw  = (rec.get("severity") or "unknown").lower()
    expr_raw = (rec.get("exprt_rating") or "").lower()
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sev1 = _SEV_MAP.get(sev_raw, "info")
    sev2 = _SEV_MAP.get(expr_raw, "info")
    severity = sev1 if _sev_rank.get(sev1, 0) >= _sev_rank.get(sev2, 0) else sev2

    # This export has no CVSS score; approximate from severity so the CVSS columns
    # in the UI reflect relative risk rather than showing 0.0 for everything.
    _sev_to_cvss = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.0, "info": 0.0}
    cvss_score = _sev_to_cvss.get(severity, 0.0)

    # Product name from products array
    products = rec.get("products") or []
    product = ""
    if isinstance(products, list) and products:
        p0 = products[0] if isinstance(products[0], dict) else {}
        product = p0.get("product_name_version") or p0.get("product_name") or ""

    # Remediation detail
    remeds = rec.get("recommended_remediations") or []
    solution = ""
    if isinstance(remeds, list) and remeds:
        r0 = remeds[0] if isinstance(remeds[0], dict) else {}
        solution = r0.get("detail") or r0.get("remediation") or ""

    # CISA KEV flag
    cisa = rec.get("cisa_info") or {}
    is_kev = isinstance(cisa, dict) and cisa.get("is_cisa_kev", False)
    description = "CISA Known Exploited Vulnerability" if is_kev else ""

    from gravwell.models.dataclasses import Vulnerability as _Vuln
    host.vulnerabilities.append(
        _Vuln(
            name=f"{cve_id}: {product}" if product else cve_id,
            severity=severity,
            cvss_score=cvss_score,
            plugin_id=cve_id,
            cve_ids=[cve_id],
            description=description,
            solution=solution,
        )
    )


_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')


def _looks_like_mac(s: str) -> bool:
    """Return True if *s* matches a MAC address pattern (XX:XX:XX:XX:XX:XX or XX-XX-...)."""
    return bool(_MAC_RE.match(s))


def _pick_primary_ip(ips: list) -> str:
    """Pick the best IP from a list: prefer non-link-local, non-loopback (IPv4 or IPv6)."""
    valid = [i.strip() for i in ips if isinstance(i, str) and _valid_ip(i.strip())]
    preferred = [ip for ip in valid if not _is_link_local_or_loopback(ip)]
    return preferred[0] if preferred else (valid[0] if valid else "")


def _device_to_host(rec: dict, source: str) -> Host | None:
    """Convert a CrowdStrike device JSON record to a Host.

    Handles the Falcon API format, CrowdStrike Discover/Asset Management
    export, and all selectable export fields:
      hostname, os_version, system_manufacturer, mac_addresses,
      ip_address_history, device_type, local_ip, local_ips, connection_ip.
    """
    # ── IP resolution ─────────────────────────────────────────────────────────
    extra_ips: list[str] = []

    def _is_usable(addr: str) -> bool:
        """True if addr is a valid, routable (non-link-local, non-loopback) IP."""
        return _valid_ip(addr) and not _is_link_local_or_loopback(addr)

    # 1. local_ips: current known IPs array (Discover export)
    local_ips_raw = rec.get("local_ips")
    if isinstance(local_ips_raw, list) and local_ips_raw:
        ip = _pick_primary_ip(local_ips_raw)
        extra_ips = [
            i.strip() for i in local_ips_raw
            if isinstance(i, str) and _is_usable(i.strip()) and i.strip() != ip
        ]
    else:
        # 2. Scalar local_ip / connection_ip — only use if routable
        _scalar = (rec.get("local_ip") or rec.get("connection_ip") or "").strip()
        ip = _scalar if _is_usable(_scalar) else ""

    # 3. network_interfaces array — each element may carry a local_ip
    if not ip:
        net_ifaces = rec.get("network_interfaces") or []
        if isinstance(net_ifaces, list):
            iface_ips = [
                iface.get("local_ip", "").strip()
                for iface in net_ifaces
                if isinstance(iface, dict) and _is_usable(iface.get("local_ip", "").strip())
            ]
            ip = iface_ips[0] if iface_ips else ""
            extra_ips = list(dict.fromkeys(
                [a for a in iface_ips[1:] if a != ip] + extra_ips
            ))

    # 4. ip_address_history — most recent routable historical IP
    ip_hist_raw = rec.get("ip_address_history")
    if isinstance(ip_hist_raw, list) and ip_hist_raw:
        hist_ips = [
            i.strip() for i in ip_hist_raw
            if isinstance(i, str) and _is_usable(i.strip())
        ]
        if not ip:
            ip = hist_ips[0] if hist_ips else ""
        for h in hist_ips:
            if h != ip and h not in extra_ips:
                extra_ips.append(h)

    # 5. external_ip — intentionally NOT used as primary key.
    # CrowdStrike often stores a shared NAT/VPN/sensor IP in external_ip; using
    # it as the host key would collapse hundreds of distinct machines into one
    # entry (skipped_dupe).  Instead, fall back to a hostname-based synthetic key.
    ext_ip_val = (rec.get("external_ip") or "").strip()

    if not ip:
        _hostname_for_key = (rec.get("hostname") or "").strip()
        _device_id_for_key = (rec.get("device_id") or rec.get("aid") or "").strip()
        if _hostname_for_key and not _looks_like_mac(_hostname_for_key):
            ip = f"nip:{_hostname_for_key.lower()}"
        elif _device_id_for_key:
            ip = f"nip:{_device_id_for_key.lower()}"
        # If we used external_ip as ip before and it's the same as ext_ip_val,
        # skip adding it to extra_ips (it will be tagged separately below).
        # Store external_ip as the first additional_ip so ingestion can promote
        # it to the stored DB ip when it's unique (no other host has claimed it).
        if ip and ext_ip_val and _is_usable(ext_ip_val) and ext_ip_val not in extra_ips:
            extra_ips.insert(0, ext_ip_val)

    if not ip:
        return None

    # ── Hostname / MAC ────────────────────────────────────────────────────────
    hostname_raw = (rec.get("hostname") or "").strip()
    if _looks_like_mac(hostname_raw):
        # Network devices exported by Discover often use MAC as "hostname"
        mac = hostname_raw.replace("-", ":").upper()
        hostname = ""
    else:
        hostname = hostname_raw
        # mac_addresses is an array in Discover exports; mac_address is a string
        mac_addresses_raw = rec.get("mac_addresses")
        if isinstance(mac_addresses_raw, list) and mac_addresses_raw:
            mac_raw = mac_addresses_raw[0]
        else:
            mac_raw = (rec.get("mac_address") or "").strip()
        mac = mac_raw.replace("-", ":").upper() if mac_raw else None

    os_ver         = (rec.get("os_version") or rec.get("os_build") or "").strip()
    platform       = (rec.get("platform_name") or "").strip()
    manufacturer   = (rec.get("system_manufacturer") or "").strip() or None
    product_desc   = (rec.get("product_type_desc") or "").strip()
    device_type    = (rec.get("device_type") or "").strip()          # Laptop/Desktop/Server/Mobile
    agent_ver      = (rec.get("agent_version") or "").strip()
    machine_domain = (rec.get("machine_domain") or "").strip()
    status_raw     = (rec.get("status") or "normal").lower()
    status = "up" if "normal" in status_raw or "detected" in status_raw else "up"

    tags: list[str] = ["crowdstrike"]
    if product_desc:
        tags.append(f"product-type:{product_desc.lower().replace(' ', '-')}")
    if device_type:
        tags.append(f"device-type:{device_type.lower()}")
    if agent_ver:
        tags.append(f"cs-agent:{agent_ver}")
    if machine_domain:
        tags.append(f"domain:{machine_domain.upper()}")

    # CrowdStrike group tags: "SensorGroupingTags/Production" → strip prefix
    raw_tags = rec.get("tags") or rec.get("groups") or []
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.replace(";", ",").split(",")]
    for rt in raw_tags:
        rt = rt.strip()
        if rt:
            rt = re.sub(r'^[A-Za-z]+GroupingTags/', '', rt)
            if rt:
                tags.append(f"cs-tag:{rt}")

    # External IP as extra tag if different from local
    if ext_ip_val and ext_ip_val != ip and _valid_ip(ext_ip_val):
        tags.append(f"external-ip:{ext_ip_val}")

    # Mark hosts that have no real local IP (only found via hostname/device_id key)
    if ip.startswith("nip:"):
        tags.append("no-local-ip")

    # Data providers — indicates how CrowdStrike discovered this asset.
    # Common values: "CrowdStrike", "Active Directory", "Okta", "ServiceNow", etc.
    # AD-discovered assets have no sensor; they're known to exist but may have
    # no current network presence (no IP, no agent_version).
    data_providers_raw = rec.get("data_providers") or []
    if isinstance(data_providers_raw, str):
        data_providers_raw = [p.strip() for p in data_providers_raw.split(",")]
    data_providers_norm = [dp.strip().lower() for dp in data_providers_raw if dp.strip()]
    for dp in data_providers_norm:
        tags.append(f"source:{dp.replace(' ', '-')}")
    # No agent_version + discovered only via AD = sensorless AD computer account
    if not agent_ver and any("active" in dp and "directory" in dp for dp in data_providers_norm):
        tags.append("no-sensor")

    if "domain controller" in product_desc.lower():
        tags.append("role:dc")

    # Use os_version as fallback when platform_name is absent (Discover format)
    os_family = _map_platform(platform or os_ver)

    return Host(
        ip=ip,
        hostnames=[hostname] if hostname else [],
        os_name=os_ver or None,
        os_family=os_family,
        mac=mac,
        mac_vendor=manufacturer,
        status=status,
        source_files=[source],
        tags=tags,
        additional_ips=extra_ips,
    )


def _device_row_to_host(norm: dict[str, str], source: str) -> Host | None:
    """Convert a normalised CrowdStrike device CSV row to a Host."""
    # CSV can have local_ip_addresses as comma-separated
    ip_raw = (norm.get("local_ip") or norm.get("local_ip_addresses")
              or norm.get("ip") or "").strip()
    ip_parts = [i.strip() for i in ip_raw.split(",")
                if i.strip() and _valid_ip(i.strip())
                and not _is_link_local_or_loopback(i.strip())]
    ip = ip_parts[0] if ip_parts else ip_raw.split(",")[0].strip()
    extra_ips = ip_parts[1:]
    if not ip or not _valid_ip(ip):
        ip = (norm.get("external_ip") or "").strip()
    if not ip or not _valid_ip(ip):
        return None

    hostname    = norm.get("hostname") or norm.get("device_hostname") or ""
    os_ver      = norm.get("os_version") or norm.get("platform") or ""
    platform    = norm.get("platform_name") or norm.get("platform") or ""
    mac_raw     = norm.get("mac_address") or norm.get("mac") or ""
    mac         = mac_raw.replace("-", ":").upper() if mac_raw else None
    manufacturer = norm.get("system_manufacturer") or None
    product_desc = norm.get("product_type_desc") or ""
    agent_ver   = norm.get("agent_version") or ""

    tags: list[str] = ["crowdstrike"]
    if product_desc:
        tags.append(f"product-type:{product_desc.lower().replace(' ', '-')}")
    if agent_ver:
        tags.append(f"cs-agent:{agent_ver}")

    raw_tags_str = norm.get("tags") or norm.get("sensor_grouping_tags") or ""
    for rt in raw_tags_str.replace(";", ",").split(","):
        rt = rt.strip()
        if rt:
            rt = re.sub(r'^[A-Za-z]+GroupingTags/', '', rt)
            if rt:
                tags.append(f"cs-tag:{rt}")

    ext_ip = (norm.get("external_ip") or "").strip()
    if ext_ip and ext_ip != ip and _valid_ip(ext_ip):
        tags.append(f"external-ip:{ext_ip}")

    if "domain controller" in product_desc.lower():
        tags.append("role:dc")

    return Host(
        ip=ip,
        hostnames=[hostname] if hostname else [],
        os_name=os_ver or None,
        os_family=_map_platform(platform),
        mac=mac,
        mac_vendor=manufacturer,
        status="up",
        source_files=[source],
        tags=tags,
        additional_ips=extra_ips,
    )


def _map_platform(platform: str) -> str:
    p = platform.lower()
    if "windows" in p:
        return "Windows"
    if "linux" in p or "rhel" in p or "centos" in p or "ubuntu" in p or "debian" in p:
        return "Linux"
    if "mac" in p or "darwin" in p or "osx" in p:
        return "macOS"
    return "Unknown"


def _valid_ip(s: str) -> bool:
    """Validate an IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_link_local_or_loopback(s: str) -> bool:
    """Return True if the IP is a link-local or loopback address (IPv4 or IPv6)."""
    try:
        a = ipaddress.ip_address(s)
        return a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return False
