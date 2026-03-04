from __future__ import annotations
import hashlib
import os
from pathlib import Path
from sqlalchemy import func, case
from sqlalchemy.orm import Session
from gravwell.models.dataclasses import ParseResult, Host, Service, Vulnerability
from gravwell.models.orm import (
    HostORM, ServiceORM, VulnerabilityORM, CVERefORM, ScanFileORM
)


def ingest_parse_result(
    session: Session, result: ParseResult
) -> tuple[int, int, bool]:
    """Upsert all hosts/services/vulns from a ParseResult.

    Returns (host_count, vuln_count, already_ingested).
    already_ingested is True when the file's SHA-256 was already recorded —
    the file is identical to a previous import so no DB writes are done.
    """
    checksum = _compute_checksum(result.source_file)
    if checksum and session.query(ScanFileORM).filter_by(checksum=checksum).first():
        return 0, 0, True

    # Process hosts in batches, expunging ORM objects from the identity map
    # after each batch.  Without this, SQLAlchemy accumulates every
    # VulnerabilityORM/ServiceORM/HostORM for the whole session, which can
    # reach hundreds of MB for files with tens of thousands of findings.
    # expunge_all() removes Python-side objects while keeping uncommitted DB
    # rows visible to subsequent queries in the same transaction.
    _BATCH = 100
    total_vulns = 0
    for i, host in enumerate(result.hosts):
        _upsert_host(session, host)
        total_vulns += len(host.vulnerabilities)
        if (i + 1) % _BATCH == 0:
            session.expunge_all()
    session.flush()
    _record_scan_file(session, result, checksum)
    return len(result.hosts), total_vulns, False


def _upsert_host(session: Session, host: Host) -> HostORM:
    existing = session.query(HostORM).filter_by(ip=host.ip).first()
    if not existing and host.mac:
        # MAC-based fallback: same physical device seen on a different interface
        existing = session.query(HostORM).filter_by(mac=host.mac).first()
        if existing:
            all_known = [existing.ip] + existing.additional_ips
            if host.ip not in all_known:
                existing.additional_ips = existing.additional_ips + [host.ip]
            # fall through to the normal merge block below
    if existing:
        orm = existing
        # Merge hostnames (union, preserve order)
        merged_hostnames = list(dict.fromkeys(orm.hostnames + host.hostnames))
        orm.hostnames = merged_hostnames
        # Prefer the higher-confidence OS; fall back to "more specific name wins"
        incoming_conf = host.os_confidence
        existing_conf = getattr(orm, "_os_confidence_cache", 0)
        if host.os_name and (
            not orm.os_name
            or incoming_conf > existing_conf
            or (incoming_conf == existing_conf and len(host.os_name) > len(orm.os_name or ""))
        ):
            orm.os_name = host.os_name
            orm.os_family = host.os_family or "Unknown"
            orm._os_confidence_cache = incoming_conf  # transient, not persisted
        if host.mac and not orm.mac:
            orm.mac = host.mac
            orm.mac_vendor = host.mac_vendor
        # Union source files and tags
        orm.source_files = list(dict.fromkeys(orm.source_files + host.source_files))
        orm.tags = list(dict.fromkeys(orm.tags + host.tags))
        # Union additional_ips from the incoming host (e.g. CrowdStrike multi-IP devices)
        if host.additional_ips:
            already = set([orm.ip] + orm.additional_ips)
            extras = [ip for ip in host.additional_ips if ip not in already]
            if extras:
                orm.additional_ips = orm.additional_ips + extras
    else:
        orm = HostORM(
            ip=host.ip,
            os_name=host.os_name,
            os_family=host.os_family,
            mac=host.mac,
            mac_vendor=host.mac_vendor,
            status=host.status,
        )
        orm.hostnames = host.hostnames
        orm.source_files = host.source_files
        orm.tags = host.tags
        orm.additional_ips = host.additional_ips
        session.add(orm)
        session.flush()

    for svc in host.services:
        _upsert_service(session, orm.id, svc)

    # Pre-load all existing vulns for this host in one query instead of one
    # SELECT per vulnerability (avoids N+1 pattern on large Spotlight imports).
    existing_vuln_map: dict[tuple, VulnerabilityORM] = {
        (v.plugin_id, v.port): v
        for v in session.query(VulnerabilityORM).filter_by(host_id=orm.id).all()
    }
    for vuln in host.vulnerabilities:
        svc_id = _find_service_id(session, orm.id, vuln.port)
        _upsert_vulnerability(session, orm.id, svc_id, vuln, existing_vuln_map)

    _update_host_aggregates(session, orm)
    return orm


def _upsert_service(session: Session, host_id: int, svc: Service) -> ServiceORM:
    existing = session.query(ServiceORM).filter_by(
        host_id=host_id, port=svc.port, protocol=svc.protocol
    ).first()
    if existing:
        if svc.product and not existing.product:
            existing.product = svc.product
        if svc.version and not existing.version:
            existing.version = svc.version
        if svc.banner and not existing.banner:
            existing.banner = svc.banner
        if svc.service_name and not existing.service_name:
            existing.service_name = svc.service_name
        return existing
    orm = ServiceORM(
        host_id=host_id,
        port=svc.port,
        protocol=svc.protocol,
        state=svc.state,
        service_name=svc.service_name,
        product=svc.product,
        version=svc.version,
        banner=svc.banner,
    )
    session.add(orm)
    session.flush()
    return orm


def _upsert_vulnerability(
    session: Session,
    host_id: int,
    service_id: int | None,
    vuln: Vulnerability,
    existing_map: dict[tuple, "VulnerabilityORM"] | None = None,
) -> VulnerabilityORM:
    # Key: host + plugin_id + port (or name as fallback)
    plugin_key = vuln.plugin_id or f"name:{vuln.name[:64]}"
    key = (plugin_key, vuln.port)

    # Use pre-loaded map when available (avoids per-vuln SELECT query).
    if existing_map is not None:
        existing = existing_map.get(key)
    else:
        existing = session.query(VulnerabilityORM).filter_by(
            host_id=host_id, plugin_id=plugin_key, port=vuln.port
        ).first()

    if existing:
        if vuln.cvss_score > existing.cvss_score:
            existing.cvss_score = vuln.cvss_score
        # Refresh description so re-ingesting updated output (e.g. new users
        # found by enum4linux) keeps the finding accurate
        if vuln.description and vuln.description != existing.description:
            existing.description = vuln.description
        return existing

    orm = VulnerabilityORM(
        host_id=host_id,
        service_id=service_id,
        plugin_id=plugin_key,
        name=vuln.name,
        severity=vuln.severity,
        cvss_score=vuln.cvss_score,
        port=vuln.port,
        description=vuln.description,
        solution=vuln.solution,
    )
    session.add(orm)
    session.flush()
    for cve_id in vuln.cve_ids:
        if cve_id:
            session.add(CVERefORM(vuln_id=orm.id, cve_id=cve_id))

    # Track the new ORM in the map so duplicate CVEs within the same import
    # (same host × same CVE) hit the update path on subsequent records.
    if existing_map is not None:
        existing_map[key] = orm

    return orm


def _find_service_id(session: Session, host_id: int, port: int | None) -> int | None:
    if port is None:
        return None
    svc = session.query(ServiceORM).filter_by(host_id=host_id, port=port).first()
    return svc.id if svc else None


def _update_host_aggregates(session: Session, host: HostORM) -> None:
    row = session.query(
        func.max(VulnerabilityORM.cvss_score),
        func.sum(case((VulnerabilityORM.severity == "critical", 1), else_=0)),
        func.sum(case((VulnerabilityORM.severity == "high",     1), else_=0)),
        func.sum(case((VulnerabilityORM.severity == "medium",   1), else_=0)),
        func.sum(case((VulnerabilityORM.severity == "low",      1), else_=0)),
    ).filter(VulnerabilityORM.host_id == host.id).one()
    host.max_cvss             = float(row[0] or 0.0)
    host.vuln_count_critical  = int(row[1] or 0)
    host.vuln_count_high      = int(row[2] or 0)
    host.vuln_count_medium    = int(row[3] or 0)
    host.vuln_count_low       = int(row[4] or 0)


def _compute_checksum(source_file: str) -> str | None:
    if not source_file or not os.path.exists(source_file):
        return None
    try:
        with open(source_file, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _record_scan_file(
    session: Session, result: ParseResult, checksum: str | None
) -> None:
    filepath = result.source_file
    filename = os.path.basename(filepath) if filepath else "unknown"
    session.add(ScanFileORM(
        filepath=filepath,
        filename=filename,
        parser_name=result.parser_name,
        host_count=len(result.hosts),
        warning_count=len(result.warnings),
        error_count=len(result.errors),
        checksum=checksum,
    ))
