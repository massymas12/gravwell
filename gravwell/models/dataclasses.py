from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str           # "tcp" | "udp"
    state: str              # "open" | "closed" | "filtered"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class Vulnerability:
    name: str
    severity: str           # "critical" | "high" | "medium" | "low" | "info"
    cvss_score: float = 0.0
    plugin_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    port: int | None = None
    description: str = ""
    solution: str = ""


@dataclass
class Host:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    os_name: str | None = None
    os_family: str | None = None    # "Windows" | "Linux" | "Network" | "Unknown"
    os_confidence: int = 0          # 0-100; higher wins during ingestion merge
    mac: str | None = None
    mac_vendor: str | None = None
    status: str = "up"
    services: list[Service] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    additional_ips: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    hosts: list[Host] = field(default_factory=list)
    source_file: str = ""
    parser_name: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
