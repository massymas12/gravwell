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
    '"local_ips"',          # CrowdStrike Discover / Asset Management export (array of IPs)
    '"device_id"',          # Falcon device inventory — very CS-specific
    '"falcon_host_link"',   # Falcon device inventory
    '"agent_version"',      # Falcon device inventory
    '"product_type_desc"',  # Falcon device inventory ("Workstation", "Server", "DC")
    '"crowdstrike_id"',     # some export formats
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

        if not result.hosts:
            result.warnings.append("No hosts with IP addresses found in CrowdStrike export")
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
        #   spotlight_api  — {"resources":[{"cve":{...},"host_info":{...}}]}
        #   flat_vuln      — [{"host_id":"...","local_ip":"...","cve_id":"..."}]
        #   device         — [{...device fields...}]  (Discover / Asset Mgmt)
        is_spotlight = ('"cve"' in head) and (
            '"host_info"' in head or '"aid"' in head
        )
        is_flat_vuln = ('"host_id"' in head or '"local_ip"' in head) and (
            '"cve_id"' in head or '"vulnerability"' in head or
            '"cve"' in head or "vulnerabilities" in filepath.name.lower()
        )

        host_map: dict[str, Host] = {}
        try:
            with open(filepath, "rb") as fh:
                for rec in ijson.items(fh, prefix):
                    if not isinstance(rec, dict):
                        continue
                    if is_spotlight:
                        _spotlight_rec_to_host_map(rec, host_map, result.source_file)
                    elif is_flat_vuln:
                        _flat_vuln_rec_to_host_map(rec, host_map, result.source_file)
                    else:
                        host = _device_to_host(rec, result.source_file)
                        if host and host.ip and host.ip != "0.0.0.0":
                            if host.ip not in host_map:
                                host_map[host.ip] = host
        except Exception as e:
            result.errors.append(f"JSON stream error: {e}")

        result.hosts = list(host_map.values())
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

        for rec in resources:
            if not isinstance(rec, dict):
                continue
            if is_spotlight:
                _spotlight_rec_to_host_map(rec, host_map, result.source_file)
            else:
                host = _device_to_host(rec, result.source_file)
                if host and host.ip and host.ip != "0.0.0.0":
                    if host.ip not in host_map:
                        host_map[host.ip] = host

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


_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')


def _looks_like_mac(s: str) -> bool:
    """Return True if *s* matches a MAC address pattern (XX:XX:XX:XX:XX:XX or XX-XX-...)."""
    return bool(_MAC_RE.match(s))


def _pick_primary_ip(ips: list) -> str:
    """Pick the best IP from a list: prefer non-APIPA (169.254.x.x), non-loopback."""
    valid = [i.strip() for i in ips if isinstance(i, str) and _valid_ip(i.strip())]
    non_apipa = [ip for ip in valid if not ip.startswith("169.254.") and not ip.startswith("127.")]
    return non_apipa[0] if non_apipa else (valid[0] if valid else "")


def _device_to_host(rec: dict, source: str) -> Host | None:
    """Convert a CrowdStrike device JSON record to a Host.

    Handles both the Falcon API format (``local_ip`` string) and the
    CrowdStrike Discover/Asset Management export format (``local_ips`` array).
    """
    # ── IP resolution ─────────────────────────────────────────────────────────
    # Discover format: "local_ips": ["10.0.0.1", "169.254.x.x", ...]
    local_ips_raw = rec.get("local_ips")
    extra_ips: list[str] = []
    if isinstance(local_ips_raw, list) and local_ips_raw:
        ip = _pick_primary_ip(local_ips_raw)
        extra_ips = [
            i.strip() for i in local_ips_raw
            if isinstance(i, str) and _valid_ip(i.strip())
            and i.strip() != ip and not i.strip().startswith("169.254.")
        ]
    else:
        # Falcon API format: single string
        ip = (rec.get("local_ip") or rec.get("connection_ip") or "").strip()

    if not ip or not _valid_ip(ip):
        ip = (rec.get("external_ip") or "").strip()
    if not ip or not _valid_ip(ip):
        return None

    # ── Hostname / MAC ────────────────────────────────────────────────────────
    hostname_raw = (rec.get("hostname") or "").strip()
    if _looks_like_mac(hostname_raw):
        # Network devices exported by Discover often use MAC as "hostname"
        mac = hostname_raw.replace("-", ":").upper()
        hostname = ""
    else:
        hostname = hostname_raw
        mac_raw = (rec.get("mac_address") or "").strip()
        mac = mac_raw.replace("-", ":").upper() if mac_raw else None

    os_ver       = (rec.get("os_version") or rec.get("os_build") or "").strip()
    platform     = (rec.get("platform_name") or "").strip()
    manufacturer = (rec.get("system_manufacturer") or "").strip() or None
    product_desc = (rec.get("product_type_desc") or "").strip()
    agent_ver    = (rec.get("agent_version") or "").strip()
    status_raw   = (rec.get("status") or "normal").lower()
    status = "up" if "normal" in status_raw or "detected" in status_raw else "up"

    tags: list[str] = ["crowdstrike"]
    if product_desc:
        tags.append(f"product-type:{product_desc.lower().replace(' ', '-')}")
    if agent_ver:
        tags.append(f"cs-agent:{agent_ver}")

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
    ext_ip = (rec.get("external_ip") or "").strip()
    if ext_ip and ext_ip != ip and _valid_ip(ext_ip):
        tags.append(f"external-ip:{ext_ip}")

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
                and not i.strip().startswith("169.254.")]
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
    """Quick IPv4 sanity check — avoids importing ipaddress for every row."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
