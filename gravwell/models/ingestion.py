from __future__ import annotations
import hashlib
import os
from datetime import datetime
from pathlib import Path
from sqlalchemy import func, case
from sqlalchemy.orm import Session
from gravwell.models.dataclasses import ParseResult, Host, Service, Vulnerability
from gravwell.models.orm import (
    HostORM, ServiceORM, VulnerabilityORM, CVERefORM, ScanFileORM, SubnetLabelORM,
    PhysicalLinkORM, VlanORM, HostVlanORM,
)
from gravwell.models.os_inference import infer_os


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
        _upsert_host(session, host, result.parser_name)
        total_vulns += len(host.vulnerabilities)
        if (i + 1) % _BATCH == 0:
            session.expunge_all()
    session.flush()
    if result.subnet_labels:
        _upsert_subnet_labels(session, result.subnet_labels)
    if result.physical_links:
        _upsert_physical_links(session, result.physical_links)
    if result.vlans or result.vlan_fdb:
        _upsert_vlans(session, result.vlans, result.vlan_fdb)
    _record_scan_file(session, result, checksum)
    # hn: → spotlight merges (not new hosts), nip: → device-inventory assets
    # that were imported without a local IP (these ARE real hosts, count them).
    real_hosts = sum(
        1 for h in result.hosts
        if not h.ip.startswith("hn:")
    )
    return real_hosts, total_vulns, False


def _infer_domain_tags(hostnames: list[str]) -> list[str]:
    """Return domain: tags inferred from FQDNs (host.domain.tld → domain:DOMAIN.TLD).

    Only considers hostnames with 3+ labels (host + domain + tld) to avoid
    false positives from simple single-label or .local mDNS names.
    """
    domains: set[str] = set()
    for hn in (hostnames or []):
        parts = hn.rstrip(".").split(".")
        if len(parts) >= 3:
            domains.add("domain:" + ".".join(parts[1:]).upper())
    return sorted(domains)


def _upsert_host(session: Session, host: Host, parser_name: str = "") -> HostORM | None:
    # ── Hostname-only synthetic-key records ───────────────────────────────────
    # "hn:<hostname>" — CrowdStrike Spotlight console exports (no IP).
    #   Merge vulns into existing host by hostname; skip if no match (device
    #   inventory must be imported first).
    # "nip:<hostname|device_id>" — CrowdStrike device records with no local IP
    #   (link-local only, or sensor-behind-NAT).  Try hostname match; if no
    #   match, CREATE the host so the asset is not silently dropped.
    if host.ip.startswith(("hn:", "nip:")):
        hn = host.hostnames[0] if host.hostnames else host.ip.split(":", 1)[1]
        # JSON-stored list: search for the hostname as a quoted JSON string
        existing = session.query(HostORM).filter(
            HostORM._hostnames.like(f'%"{hn}"%')
        ).first()
        if existing:
            # Merge vulns into the matched host
            existing_vuln_map: dict[tuple, VulnerabilityORM] = {
                (v.plugin_id, v.port): v
                for v in session.query(VulnerabilityORM).filter_by(host_id=existing.id).all()
            }
            for vuln in host.vulnerabilities:
                svc_id = _find_service_id(session, existing.id, vuln.port)
                _upsert_vulnerability(session, existing.id, svc_id, vuln,
                                      existing_vuln_map, source=parser_name)
            _delete_stale_source_vulns(session, parser_name, host.vulnerabilities,
                                       existing_vuln_map)
            _update_host_aggregates(session, existing)
            return existing

        # Spotlight: skip until device inventory is imported first
        if host.ip.startswith("hn:"):
            return None

        # nip: device-inventory host with no local IP — create it so the asset
        # is visible.  Use the first additional_ip (external_ip stored there)
        # as the stored ip if it's a real address; otherwise keep the nip: key.
        stored_ip = host.ip
        if host.additional_ips:
            candidate = host.additional_ips[0]
            # Only use external_ip as stored_ip if it's not already claimed by
            # a different host (avoids silently merging distinct devices).
            if not session.query(HostORM).filter_by(ip=candidate).first():
                stored_ip = candidate
        # Check if this nip: host was already created by a prior import
        existing_nip = session.query(HostORM).filter_by(ip=stored_ip).first()
        if existing_nip:
            _update_host_aggregates(session, existing_nip)
            return existing_nip
        orm = HostORM(
            ip=stored_ip,
            os_name=host.os_name,
            os_family=host.os_family,
            mac=host.mac,
            mac_vendor=host.mac_vendor,
            status=host.status,
        )
        orm.hostnames = host.hostnames
        orm.source_files = host.source_files
        orm.tags = list(dict.fromkeys(host.tags + _infer_domain_tags(host.hostnames)))
        # Store remaining additional_ips (skip the one promoted to stored_ip)
        orm.additional_ips = [
            a for a in host.additional_ips if a != stored_ip
        ]
        session.add(orm)
        session.flush()
        _update_host_aggregates(session, orm)
        return orm

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
        # Seed OS with the incoming data if it's better than what we have —
        # the definitive re-inference happens below after services are upserted.
        incoming_conf = host.os_confidence
        existing_conf = orm.os_confidence or 0
        if host.os_name and (
            not orm.os_name
            or incoming_conf > existing_conf
            or (incoming_conf == existing_conf and len(host.os_name) > len(orm.os_name or ""))
        ):
            orm.os_name = host.os_name
            orm.os_family = host.os_family or "Unknown"
            orm.os_confidence = incoming_conf
        if host.mac and not orm.mac:
            orm.mac = host.mac
            orm.mac_vendor = host.mac_vendor
        # Union source files and tags (also infer domain from FQDNs)
        orm.source_files = list(dict.fromkeys(orm.source_files + host.source_files))
        merged_tags = list(dict.fromkeys(
            orm.tags + host.tags + _infer_domain_tags(orm.hostnames)
        ))
        orm.tags = merged_tags
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
            os_confidence=host.os_confidence,
            mac=host.mac,
            mac_vendor=host.mac_vendor,
            status=host.status,
        )
        orm.hostnames = host.hostnames
        orm.source_files = host.source_files
        orm.tags = list(dict.fromkeys(host.tags + _infer_domain_tags(host.hostnames)))
        orm.additional_ips = host.additional_ips
        session.add(orm)
        session.flush()

    # ── nip: promotion ────────────────────────────────────────────────────────
    # If a previous import created a hostname-keyed "nip:<hostname>" placeholder
    # for this same device (because local_ip was missing at the time), absorb its
    # vulns/services into this real-IP host and delete the stale nip: row.
    _absorb_nip_stubs(session, orm, host.hostnames)

    # Pre-load existing services in one query to avoid N+1 in _upsert_service.
    existing_svc_map: dict[tuple, ServiceORM] = {
        (s.port, s.protocol): s
        for s in session.query(ServiceORM).filter_by(host_id=orm.id).all()
    }
    for svc in host.services:
        _upsert_service(session, orm.id, svc, existing_svc_map)

    # Re-infer OS from ALL services now in the DB (combines every scan file
    # imported so far).  Pass the current stored values as the explicit baseline
    # so high-confidence scanner fingerprints (nmap osmatch ≥ 75) are preserved
    # while low-confidence inferred guesses get corrected when better signals arrive.
    _recompute_os(session, orm)

    # Pre-load all existing vulns for this host in one query instead of one
    # SELECT per vulnerability (avoids N+1 pattern on large Spotlight imports).
    existing_vuln_map: dict[tuple, VulnerabilityORM] = {
        (v.plugin_id, v.port): v
        for v in session.query(VulnerabilityORM).filter_by(host_id=orm.id).all()
    }
    # Build service port→id map from what is now in the DB (avoids N+1
    # _find_service_id calls — one query covers all vulnerabilities for this host).
    svc_id_map: dict[int | None, int | None] = {
        s.port: s.id
        for s in session.query(ServiceORM.port, ServiceORM.id).filter_by(host_id=orm.id).all()
    }
    for vuln in host.vulnerabilities:
        svc_id = svc_id_map.get(vuln.port)
        _upsert_vulnerability(session, orm.id, svc_id, vuln, existing_vuln_map,
                              source=parser_name)
    _delete_stale_source_vulns(session, parser_name, host.vulnerabilities,
                               existing_vuln_map)

    _update_host_aggregates(session, orm)
    return orm


def _absorb_nip_stubs(
    session: Session, real_orm: HostORM, hostnames: list[str]
) -> None:
    """Migrate data from any stale nip: placeholder rows into *real_orm*.

    When a CrowdStrike device is imported a second time with ip_address_history
    populated (giving a real IP), a "nip:<hostname>" row may already exist from
    the first import.  Move its vulns/services to the real-IP host, then delete
    the stub so it no longer shows a nip: address in the UI.
    """
    for hn in hostnames:
        nip_key = f"nip:{hn.lower()}"
        stub = session.query(HostORM).filter_by(ip=nip_key).first()
        if stub and stub.id != real_orm.id:
            # Re-home vulns
            session.query(VulnerabilityORM).filter_by(host_id=stub.id).update(
                {"host_id": real_orm.id}, synchronize_session=False
            )
            # Re-home services
            session.query(ServiceORM).filter_by(host_id=stub.id).update(
                {"host_id": real_orm.id}, synchronize_session=False
            )
            session.delete(stub)
            session.flush()


def _recompute_os(session: Session, orm: HostORM) -> None:
    """Re-run OS inference over all services currently in the DB for this host.

    Uses the stored os_name/family/confidence as the explicit baseline so that
    high-confidence scanner fingerprints (nmap osmatch, etc.) are not overridden
    by inference.  Low-confidence inferred guesses *can* be overridden when a
    different scan file contributes a stronger signal (e.g. port 9100 = printer).
    """
    all_svc_orm = session.query(ServiceORM).filter_by(host_id=orm.id).all()
    all_svcs = [
        Service(
            port=s.port,
            protocol=s.protocol or "tcp",
            state=s.state or "open",
            service_name=s.service_name,
            product=s.product,
            version=s.version,
            banner=s.banner,
        )
        for s in all_svc_orm
    ]
    new_name, new_family, new_conf = infer_os(
        all_svcs,
        [],
        orm.mac_vendor,
        explicit_os_name=orm.os_name,
        explicit_os_family=orm.os_family,
        explicit_confidence=orm.os_confidence or 0,
    )
    if new_conf > (orm.os_confidence or 0) or (
        new_conf == (orm.os_confidence or 0)
        and new_name
        and len(new_name) > len(orm.os_name or "")
    ):
        orm.os_name = new_name
        orm.os_family = new_family or "Unknown"
        orm.os_confidence = new_conf


def _upsert_service(
    session: Session,
    host_id: int,
    svc: Service,
    existing_map: dict[tuple, "ServiceORM"] | None = None,
) -> ServiceORM:
    key = (svc.port, svc.protocol)
    if existing_map is not None:
        existing = existing_map.get(key)
    else:
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
    if existing_map is not None:
        existing_map[key] = orm  # keep map current for within-host dedup
    return orm


def _delete_stale_source_vulns(
    session: Session,
    source: str,
    incoming_vulns: list[Vulnerability],
    existing_map: dict[tuple, "VulnerabilityORM"],
) -> None:
    """Delete vulns attributed to *source* that are absent from the new import.

    When a scanner re-scans a host and a previously reported vulnerability is
    no longer present (patched, service removed, etc.) that finding should be
    removed rather than left stale.  Only vulns whose ``source`` matches the
    current parser are touched — findings from other scanners are untouched.
    Vulns with source=NULL (imported before this feature existed) are ignored.
    """
    if not source:
        return
    incoming_keys = {
        (v.plugin_id or f"name:{v.name[:64]}", v.port)
        for v in incoming_vulns
    }
    for (plugin_id, port), orm_v in list(existing_map.items()):
        if orm_v.source == source and (plugin_id, port) not in incoming_keys:
            session.delete(orm_v)
            del existing_map[(plugin_id, port)]


def _upsert_vulnerability(
    session: Session,
    host_id: int,
    service_id: int | None,
    vuln: Vulnerability,
    existing_map: dict[tuple, "VulnerabilityORM"] | None = None,
    source: str = "",
) -> VulnerabilityORM:
    # Key: host + plugin_id + port (or name as fallback)
    plugin_key = vuln.plugin_id or f"name:{vuln.name[:64]}"
    key = (plugin_key, vuln.port)
    now = datetime.utcnow()

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
        existing.last_seen = now
        if source and not existing.source:
            existing.source = source
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
        source=source or None,
        first_seen=now,
        last_seen=now,
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


def _upsert_subnet_labels(session: Session, labels: dict[str, str]) -> None:
    """Insert or update SubnetLabelORM rows from an IPAM import.

    Existing user-edited labels are preserved; only blank labels are overwritten
    by the IPAM name.  IPAM names are always written when no label exists yet.
    """
    for cidr, label in labels.items():
        existing = session.query(SubnetLabelORM).filter_by(subnet_cidr=cidr).first()
        if existing:
            if label and not existing.label:
                existing.label = label
        else:
            session.add(SubnetLabelORM(subnet_cidr=cidr, label=label))
    session.flush()


def _upsert_physical_links(session: Session, links: list[dict]) -> None:
    """Upsert LLDP/CDP-confirmed physical connections."""
    for link in links:
        host_ip = link.get("host_ip", "")
        peer_ip = link.get("peer_ip", "")
        port_id = link.get("port_id", "")
        link_type = link.get("link_type", "lldp")
        if not host_ip or not peer_ip:
            continue
        existing = session.query(PhysicalLinkORM).filter_by(
            host_ip=host_ip, peer_ip=peer_ip, port_id=port_id,
        ).first()
        if not existing:
            session.add(PhysicalLinkORM(
                host_ip=host_ip, peer_ip=peer_ip,
                port_id=port_id, link_type=link_type,
            ))
    session.flush()


def _upsert_vlans(session: Session, vlans: list[dict], vlan_fdb: list[dict]) -> None:
    """Persist VLAN name table and FDB entries; resolve host IPs via MAC."""
    # Upsert VLAN name table
    for v in vlans:
        switch_ip = v.get("switch_ip", "")
        vlan_id = v.get("vlan_id")
        vlan_name = v.get("vlan_name", "")
        if not switch_ip or vlan_id is None:
            continue
        existing = session.query(VlanORM).filter_by(
            switch_ip=switch_ip, vlan_id=vlan_id
        ).first()
        if existing:
            existing.vlan_name = vlan_name
        else:
            session.add(VlanORM(switch_ip=switch_ip, vlan_id=vlan_id, vlan_name=vlan_name))

    # Build VLAN ID → name lookup
    vlan_name_map: dict[int, str] = {
        v["vlan_id"]: v.get("vlan_name", f"VLAN {v['vlan_id']}")
        for v in vlans if v.get("vlan_id") is not None
    }

    # Build normalised MAC → IP map from hosts table
    mac_to_ip: dict[str, str] = {
        h.mac.lower(): h.ip
        for h in session.query(HostORM.mac, HostORM.ip).filter(HostORM.mac.isnot(None)).all()
        if h.mac
    }

    # Upsert FDB entries, resolving MAC → IP where possible
    for entry in vlan_fdb:
        switch_ip = entry.get("switch_ip", "")
        vlan_id = entry.get("vlan_id")
        mac = (entry.get("mac") or "").lower()
        if not switch_ip or vlan_id is None or not mac:
            continue
        host_ip = mac_to_ip.get(mac)
        vlan_name = vlan_name_map.get(vlan_id, f"VLAN {vlan_id}")
        existing = session.query(HostVlanORM).filter_by(
            host_mac=mac, vlan_id=vlan_id
        ).first()
        if existing:
            if host_ip:
                existing.host_ip = host_ip
            existing.vlan_name = vlan_name
            existing.switch_ip = switch_ip
        else:
            session.add(HostVlanORM(
                host_mac=mac, host_ip=host_ip,
                vlan_id=vlan_id, vlan_name=vlan_name,
                switch_ip=switch_ip,
            ))
    session.flush()


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
