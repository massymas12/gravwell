"""Encrypted project export/import — .gwexport bundles.

Wire:
  export_project(db_path) -> raw JSON bytes
  encrypt_bundle(payload, passphrase) -> .gwexport binary
  decrypt_bundle(data, passphrase) -> raw JSON bytes
  import_project(json_bytes, db_path) -> (host_count, vuln_count)

File format: magic(8) | version(1) | salt(16) | nonce(12) | AES-256-GCM ciphertext
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_MAGIC          = b"GWEXPORT"
_VERSION        = 1
_KDF_ITERATIONS = 480_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bundle(payload: bytes, passphrase: str) -> bytes:
    """Encrypt *payload* with AES-256-GCM and return the .gwexport binary blob."""
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    ct    = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, payload, None)
    return _MAGIC + bytes([_VERSION]) + salt + nonce + ct


def decrypt_bundle(data: bytes, passphrase: str) -> bytes:
    """Decrypt a .gwexport blob. Raises ValueError on bad passphrase or magic."""
    if not data.startswith(_MAGIC):
        raise ValueError("Not a valid GravWell export file")
    pos     = len(_MAGIC)
    version = data[pos]; pos += 1
    if version != _VERSION:
        raise ValueError(f"Unsupported export version {version}")
    salt  = data[pos:pos + 16]; pos += 16
    nonce = data[pos:pos + 12]; pos += 12
    try:
        return AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, data[pos:], None)
    except Exception:
        raise ValueError("Incorrect passphrase or corrupted export file")


def export_project(db_path: str) -> bytes:
    """Serialize the entire project to JSON bytes (unencrypted)."""
    from gravwell.database import get_session
    from gravwell.models.orm import (
        HostORM, ServiceORM, VulnerabilityORM, CVERefORM,
        ScanFileORM, PhysicalLinkORM, VlanORM, HostVlanORM,
        SubnetLabelORM, CustomEdgeORM, NodePositionORM, HostRoleOverrideORM,
    )

    with get_session(db_path) as session:
        hosts_data = []
        for h in session.query(HostORM).order_by(HostORM.ip).all():
            svcs = [
                {
                    "port":         s.port,
                    "protocol":     s.protocol,
                    "state":        s.state,
                    "service_name": s.service_name,
                    "product":      s.product,
                    "version":      s.version,
                    "banner":       s.banner,
                }
                for s in session.query(ServiceORM).filter_by(host_id=h.id).all()
            ]
            vulns = []
            for v in session.query(VulnerabilityORM).filter_by(host_id=h.id).all():
                cve_ids = [
                    r.cve_id
                    for r in session.query(CVERefORM).filter_by(vuln_id=v.id).all()
                ]
                vulns.append({
                    "name":        v.name,
                    "severity":    v.severity,
                    "cvss_score":  v.cvss_score or 0.0,
                    "plugin_id":   v.plugin_id,
                    "cve_ids":     cve_ids,
                    "port":        v.port,
                    "description": v.description or "",
                    "solution":    v.solution or "",
                })
            hosts_data.append({
                "ip":              h.ip,
                "hostnames":       h.hostnames,
                "os_name":         h.os_name,
                "os_family":       h.os_family,
                "os_confidence":   h.os_confidence or 0,
                "mac":             h.mac,
                "mac_vendor":      h.mac_vendor,
                "status":          h.status or "up",
                "tags":            h.tags,
                "additional_ips":  h.additional_ips,
                "notes":           h.notes or "",
                "subnet_override": h.subnet_override,
                "services":        svcs,
                "vulnerabilities": vulns,
            })

        scan_files = [
            {
                "filename":    sf.filename,
                "parser_name": sf.parser_name,
                "host_count":  sf.host_count,
                "ingested_at": sf.ingested_at.isoformat() if sf.ingested_at else None,
            }
            for sf in session.query(ScanFileORM).order_by(ScanFileORM.ingested_at).all()
        ]

        physical_links = [
            {
                "host_ip":   lnk.host_ip,
                "peer_ip":   lnk.peer_ip,
                "port_id":   lnk.port_id or "",
                "link_type": lnk.link_type or "lldp",
            }
            for lnk in session.query(PhysicalLinkORM).all()
        ]

        vlans = [
            {
                "switch_ip": v.switch_ip,
                "vlan_id":   v.vlan_id,
                "vlan_name": v.vlan_name or "",
            }
            for v in session.query(VlanORM).all()
        ]

        vlan_fdb = [
            {
                "host_mac":  fdb.host_mac,
                "host_ip":   fdb.host_ip,
                "vlan_id":   fdb.vlan_id,
                "vlan_name": fdb.vlan_name or "",
                "switch_ip": fdb.switch_ip,
            }
            for fdb in session.query(HostVlanORM).all()
        ]

        subnet_labels = {
            sl.subnet_cidr: sl.label or ""
            for sl in session.query(SubnetLabelORM).all()
        }

        custom_edges = [
            {
                "source_ip": ce.source_ip,
                "target_ip": ce.target_ip,
                "label":     ce.label or "",
            }
            for ce in session.query(CustomEdgeORM).all()
        ]

        node_positions = [
            {"node_ip": np.node_ip, "x": np.x, "y": np.y}
            for np in session.query(NodePositionORM).all()
        ]

        role_overrides = [
            {"host_ip": ro.host_ip, "roles_json": ro.roles_json}
            for ro in session.query(HostRoleOverrideORM).all()
        ]

    payload = {
        "version":         1,
        "gravwell_export": True,
        "exported_at":     datetime.utcnow().isoformat(),
        "hosts":           hosts_data,
        "scan_files":      scan_files,
        "physical_links":  physical_links,
        "vlans":           vlans,
        "vlan_fdb":        vlan_fdb,
        "subnet_labels":   subnet_labels,
        "custom_edges":    custom_edges,
        "node_positions":  node_positions,
        "role_overrides":  role_overrides,
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def import_project(json_bytes: bytes, db_path: str) -> tuple[int, int]:
    """Ingest a decrypted export bundle into the project at *db_path*.

    Returns (host_count, vuln_count). Merges into existing data — no deletions.
    """
    from gravwell.database import get_session
    from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
    from gravwell.models.ingestion import ingest_parse_result
    from gravwell.models.orm import (
        CustomEdgeORM, NodePositionORM, HostRoleOverrideORM, HostORM,
    )

    data = json.loads(json_bytes.decode("utf-8"))
    if not data.get("gravwell_export"):
        raise ValueError("Not a valid GravWell export bundle")

    hosts = []
    for h in data.get("hosts", []):
        services = [
            Service(
                port=s["port"],
                protocol=s.get("protocol", "tcp"),
                state=s.get("state", "open"),
                service_name=s.get("service_name"),
                product=s.get("product"),
                version=s.get("version"),
                banner=s.get("banner"),
            )
            for s in h.get("services", [])
        ]
        vulns = [
            Vulnerability(
                name=v["name"],
                severity=v["severity"],
                cvss_score=float(v.get("cvss_score", 0.0)),
                plugin_id=v.get("plugin_id"),
                cve_ids=v.get("cve_ids", []),
                port=v.get("port"),
                description=v.get("description", ""),
                solution=v.get("solution", ""),
            )
            for v in h.get("vulnerabilities", [])
        ]
        hosts.append(Host(
            ip=h["ip"],
            hostnames=h.get("hostnames", []),
            os_name=h.get("os_name"),
            os_family=h.get("os_family"),
            os_confidence=h.get("os_confidence", 0),
            mac=h.get("mac"),
            mac_vendor=h.get("mac_vendor"),
            status=h.get("status", "up"),
            tags=h.get("tags", []),
            additional_ips=h.get("additional_ips", []),
            services=services,
            vulnerabilities=vulns,
        ))

    exported_at = data.get("exported_at", datetime.utcnow().isoformat())
    result = ParseResult(
        hosts=hosts,
        source_file=f"gwexport:{exported_at}",
        parser_name="gwexport",
        physical_links=data.get("physical_links", []),
        vlans=data.get("vlans", []),
        vlan_fdb=data.get("vlan_fdb", []),
        subnet_labels=data.get("subnet_labels", {}),
    )

    with get_session(db_path) as session:
        h_count, v_count, _ = ingest_parse_result(session, result)

        # Notes and subnet overrides: write only when the local host has none
        notes_map  = {hd["ip"]: hd.get("notes", "")           for hd in data.get("hosts", [])}
        subnet_map = {hd["ip"]: hd.get("subnet_override")      for hd in data.get("hosts", [])}
        for host_orm in session.query(HostORM).all():
            if not host_orm.notes and notes_map.get(host_orm.ip):
                host_orm.notes = notes_map[host_orm.ip]
            if not host_orm.subnet_override and subnet_map.get(host_orm.ip):
                host_orm.subnet_override = subnet_map[host_orm.ip]

        # Custom edges: insert only if not already present
        for ce in data.get("custom_edges", []):
            if not session.query(CustomEdgeORM).filter_by(
                source_ip=ce["source_ip"], target_ip=ce["target_ip"]
            ).first():
                session.add(CustomEdgeORM(
                    source_ip=ce["source_ip"],
                    target_ip=ce["target_ip"],
                    label=ce.get("label", ""),
                ))

        # Node positions: always overwrite so the sender's graph layout is preserved
        for np in data.get("node_positions", []):
            existing = session.query(NodePositionORM).filter_by(node_ip=np["node_ip"]).first()
            if existing:
                existing.x = np["x"]
                existing.y = np["y"]
            else:
                session.add(NodePositionORM(node_ip=np["node_ip"], x=np["x"], y=np["y"]))

        # Role overrides: insert only if no local override exists
        for ro in data.get("role_overrides", []):
            if not session.query(HostRoleOverrideORM).filter_by(host_ip=ro["host_ip"]).first():
                session.add(HostRoleOverrideORM(
                    host_ip=ro["host_ip"],
                    roles_json=ro["roles_json"],
                ))

    return h_count, v_count
