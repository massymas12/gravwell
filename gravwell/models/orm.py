from __future__ import annotations
import json
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, Boolean,
    ForeignKey, UniqueConstraint, event
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class HostORM(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    _hostnames = Column("hostnames", Text, default="[]")
    os_name = Column(String(256))
    os_family = Column(String(64))
    mac = Column(String(17))
    mac_vendor = Column(String(128))
    status = Column(String(16), default="up")
    _tags = Column("tags", Text, default="[]")
    _source_files = Column("source_files", Text, default="[]")
    # Denormalized aggregates — refreshed after every ingest
    max_cvss = Column(Float, default=0.0)
    vuln_count_critical = Column(Integer, default=0)
    vuln_count_high = Column(Integer, default=0)
    vuln_count_medium = Column(Integer, default=0)
    vuln_count_low = Column(Integer, default=0)
    # Analyst notes — free-form text added via the UI
    notes = Column(Text, default="")
    # Secondary IPs for multi-homed hosts (routers, firewalls, multi-NIC servers).
    # Primary IP stays in `ip`; additional interfaces stored here as JSON list.
    _additional_ips = Column("additional_ips", Text, default="[]")
    # User-defined subnet override: forces this host into a specific subnet compound
    # group regardless of its IP address (e.g. "10.0.2.0/24"). NULL = auto-detect.
    subnet_override = Column(String(50), default=None)

    services = relationship("ServiceORM", back_populates="host",
                            cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityORM", back_populates="host",
                                   cascade="all, delete-orphan")

    @property
    def hostnames(self) -> list[str]:
        try:
            return json.loads(self._hostnames or "[]")
        except (json.JSONDecodeError, ValueError):
            return []

    @hostnames.setter
    def hostnames(self, val: list[str]) -> None:
        self._hostnames = json.dumps(val)

    @property
    def tags(self) -> list[str]:
        try:
            return json.loads(self._tags or "[]")
        except (json.JSONDecodeError, ValueError):
            return []

    @tags.setter
    def tags(self, val: list[str]) -> None:
        self._tags = json.dumps(val)

    @property
    def source_files(self) -> list[str]:
        try:
            return json.loads(self._source_files or "[]")
        except (json.JSONDecodeError, ValueError):
            return []

    @source_files.setter
    def source_files(self, val: list[str]) -> None:
        self._source_files = json.dumps(val)

    @property
    def additional_ips(self) -> list[str]:
        try:
            return json.loads(self._additional_ips or "[]")
        except (json.JSONDecodeError, ValueError):
            return []

    @additional_ips.setter
    def additional_ips(self, val: list[str]) -> None:
        self._additional_ips = json.dumps(val)


class ServiceORM(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False)
    state = Column(String(16), default="open")
    service_name = Column(String(128))
    product = Column(String(256))
    version = Column(String(128))
    banner = Column(Text)

    host = relationship("HostORM", back_populates="services")
    vulnerabilities = relationship("VulnerabilityORM", back_populates="service")


class VulnerabilityORM(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("host_id", "plugin_id", "port"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    plugin_id = Column(String(64))
    name = Column(String(512), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    cvss_score = Column(Float, default=0.0, index=True)
    port = Column(Integer)
    description = Column(Text, default="")
    solution = Column(Text, default="")

    host = relationship("HostORM", back_populates="vulnerabilities")
    service = relationship("ServiceORM", back_populates="vulnerabilities")
    cve_refs = relationship("CVERefORM", back_populates="vulnerability",
                            cascade="all, delete-orphan")


class CVERefORM(Base):
    __tablename__ = "cve_refs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    cve_id = Column(String(32), nullable=False)

    vulnerability = relationship("VulnerabilityORM", back_populates="cve_refs")


class ScanFileORM(Base):
    __tablename__ = "scan_files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filepath = Column(Text)
    filename = Column(String(256))
    parser_name = Column(String(64))
    host_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    checksum = Column(String(64))
    ingested_at = Column(DateTime, default=datetime.utcnow)


class CustomEdgeORM(Base):
    """Manually added connections between two host IPs."""
    __tablename__ = "custom_edges"
    __table_args__ = (UniqueConstraint("source_ip", "target_ip"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False)
    target_ip = Column(String(45), nullable=False)
    label = Column(String(128))
    created_at = Column(DateTime, default=datetime.utcnow)


class HiddenEdgeORM(Base):
    """Auto-generated edges that the user has hidden/deleted."""
    __tablename__ = "hidden_edges"
    __table_args__ = (UniqueConstraint("edge_id"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    edge_id = Column(String(256), nullable=False)   # Cytoscape edge id
    source_id = Column(String(64), nullable=False)  # source node id (for display)
    target_id = Column(String(64), nullable=False)  # target node id (for display)
    created_at = Column(DateTime, default=datetime.utcnow)


class SubnetLabelORM(Base):
    """Custom display label and visual size for a subnet compound node."""
    __tablename__ = "subnet_labels"
    __table_args__ = (UniqueConstraint("subnet_cidr"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    subnet_cidr = Column(String(50), nullable=False)   # e.g. "192.168.1.0/24"
    label = Column(String(128), nullable=True, default="")  # e.g. "DMZ"
    box_padding = Column(Integer, default=30)          # Cytoscape compound padding px
    created_at = Column(DateTime, default=datetime.utcnow)


class HostRoleOverrideORM(Base):
    """User-managed key-terrain / role assignments for a host.

    Stores a JSON array of role strings that *replaces* auto-detection for
    any role the user has explicitly reviewed (e.g. removing a false-positive DC).
    Roles: "dc", "router", "web", "db", "rdp", "smb", "legacy".
    """
    __tablename__ = "host_role_overrides"
    __table_args__ = (UniqueConstraint("host_ip"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), nullable=False)
    roles_json = Column(Text, nullable=False, default="[]")
    updated_at = Column(DateTime, default=datetime.utcnow)


class CVEEnrichmentORM(Base):
    """KEV / EPSS enrichment cache keyed by CVE ID.

    Populated by the 'Enrich CVEs' action which calls:
      - CISA KEV (Known Exploited Vulnerabilities catalog)
      - FIRST.org EPSS (Exploit Prediction Scoring System)
    """
    __tablename__ = "cve_enrichment"

    cve_id = Column(String(32), primary_key=True)
    in_kev = Column(Boolean, default=False)      # confirmed exploited in the wild
    kev_date_added = Column(String(16))          # "2021-12-10"
    kev_name = Column(String(256))               # short name from KEV catalog
    epss_score = Column(Float)                   # 0.0–1.0 probability of exploitation
    epss_percentile = Column(Float)              # 0.0–1.0 relative rank
    fetched_at = Column(DateTime)


class HostConfigORM(Base):
    """Raw config file (Cisco IOS / NX-OS) attached to a specific host."""
    __tablename__ = "host_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), nullable=False, index=True)
    filename = Column(String(256))
    config_text = Column(Text)
    ingested_at = Column(DateTime, default=datetime.utcnow)


class NodePositionORM(Base):
    """User-defined node positions on the graph canvas.

    Persisted so that manually arranged layouts survive page reloads and
    re-ingestions.  The preset layout uses these as authoritative positions
    (overriding computed positions) and cose-bilkent uses them as a warm start.
    """
    __tablename__ = "node_positions"
    __table_args__ = (UniqueConstraint("node_ip"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_ip = Column(String(45), nullable=False)
    x = Column(Float, nullable=False)
    y = Column(Float, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
