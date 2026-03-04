from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
import networkx as nx


@dataclass
class PathStep:
    ip: str
    hostnames: list[str]
    os_family: str
    max_cvss: float
    open_ports: list[int]
    kev_count: int = 0
    max_epss: float = 0.0
    edge_to_next: str | None = None


@dataclass
class AttackPath:
    steps: list[PathStep]
    total_risk_score: float
    hop_count: int


@dataclass
class PivotCandidate:
    ip: str
    os_family: str
    os_name: str
    hostnames: list[str]
    betweenness: float
    subnet_count: int
    max_cvss: float
    risk_score: float
    open_ports: list[int]
    kev_count: int = 0
    max_epss: float = 0.0
    pivot_reasons: list[str] = field(default_factory=list)


@dataclass
class ExposedHost:
    ip: str
    os_family: str
    os_name: str
    hostnames: list[str]
    max_cvss: float
    critical_vuln_count: int
    high_vuln_count: int
    open_ports: list[int]
    reachable_from_external: bool
    kev_count: int = 0
    max_epss: float = 0.0


@dataclass
class HighValueTarget:
    ip: str
    os_family: str
    os_name: str
    hostnames: list[str]
    roles: list[str]        # e.g. ["domain_controller", "database", "web_server"]
    max_cvss: float
    open_ports: list[int]
    risk_score: float       # role weight + CVSS + KEV contribution
    kev_count: int = 0
    max_epss: float = 0.0


@dataclass
class LegacySystem:
    ip: str
    os_family: str
    os_name: str
    hostnames: list[str]
    eol_label: str          # human-readable EOL notice
    max_cvss: float
    open_ports: list[int]
    kev_count: int = 0
    max_epss: float = 0.0


@dataclass
class KerberoastIndicator:
    ip: str
    os_name: str
    hostnames: list[str]
    spn_services: list[str]  # service names likely registered as SPNs
    is_dc: bool
    max_cvss: float
    confidence: str = "confirmed"  # "confirmed" | "likely"


@dataclass
class CleartextHost:
    ip: str
    os_name: str
    hostnames: list[str]
    cleartext_ports: list[str]   # e.g. ["FTP:21", "Telnet:23"]
    max_cvss: float


@dataclass
class AdminInterface:
    ip: str
    os_name: str
    hostnames: list[str]
    admin_ports: list[str]       # e.g. ["RDP:3389", "WinRM:5985"]
    max_cvss: float
    is_external: bool


@dataclass
class SmbSpreadHost:
    ip: str
    os_name: str
    hostnames: list[str]
    smb_neighbor_count: int      # reachable neighbours with SMB open
    max_cvss: float
    risk_score: float


@dataclass
class DomainEnumHost:
    ip: str
    os_name: str
    hostnames: list[str]
    domain: str
    max_cvss: float


# ── Role detection port sets ──────────────────────────────────────────────────

_DC_PORTS        = {88, 3268, 3269}
_DB_PORTS        = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
_WEB_PORTS       = {80, 443, 8080, 8443, 8888}
_MAIL_PORTS      = {25, 110, 143, 465, 587, 636, 993, 995}
_FILE_PORTS      = {445, 2049}
_REMOTE_PORTS    = {3389, 5900, 5985, 5986}
_CRED_PORTS      = {88, 389, 636, 3268, 3269}   # Kerberos, LDAP, GC

# Role weight (used in risk_score)
_ROLE_WEIGHT: dict[str, int] = {
    "domain_controller": 10,
    "credential_store":   8,
    "database":           8,
    "network_device":     7,
    "remote_access":      6,
    "file_server":        5,
    "web_server":         5,
    "mail_server":        4,
}

# EOL OS patterns: (substring_to_match, label)
_EOL_PATTERNS: list[tuple[str, str]] = [
    ("windows xp",           "Windows XP (EOL Apr 2014)"),
    ("server 2003",          "Windows Server 2003 (EOL Jul 2015)"),
    ("windows vista",        "Windows Vista (EOL Apr 2017)"),
    ("windows 7",            "Windows 7 (EOL Jan 2020)"),
    ("server 2008",          "Windows Server 2008 (EOL Jan 2020)"),
    ("server 2012 r2",       "Windows Server 2012 R2 (EOL Oct 2023)"),
    ("server 2012",          "Windows Server 2012 (EOL Oct 2023)"),
    ("windows 8.1",          "Windows 8.1 (EOL Jan 2023)"),
    ("windows 8.0",          "Windows 8 (EOL Jan 2016)"),
    ("windows 8 ",           "Windows 8 (EOL Jan 2016)"),
    ("centos linux 6",       "CentOS 6 (EOL Nov 2020)"),
    ("centos 6",             "CentOS 6 (EOL Nov 2020)"),
    ("centos linux 7",       "CentOS 7 (EOL Jun 2024)"),
    ("centos 7",             "CentOS 7 (EOL Jun 2024)"),
    ("centos linux 8",       "CentOS 8 (EOL Dec 2021)"),
    ("centos 8",             "CentOS 8 (EOL Dec 2021)"),
    ("ubuntu 14.04",         "Ubuntu 14.04 LTS (EOL Apr 2019)"),
    ("ubuntu 16.04",         "Ubuntu 16.04 LTS (EOL Apr 2021)"),
    ("ubuntu 18.04",         "Ubuntu 18.04 LTS (EOL Apr 2023)"),
    ("ubuntu 20.04",         "Ubuntu 20.04 LTS (EOL Apr 2025)"),
    ("debian 7",             "Debian 7 Wheezy (EOL May 2016)"),
    ("debian 8",             "Debian 8 Jessie (EOL Jun 2020)"),
    ("debian 9",             "Debian 9 Stretch (EOL Jun 2022)"),
    ("debian 10",            "Debian 10 Buster (EOL Jun 2024)"),
    ("red hat enterprise linux 5", "RHEL 5 (EOL Mar 2017)"),
    ("red hat enterprise linux 6", "RHEL 6 (EOL Nov 2020)"),
    ("red hat enterprise linux 7", "RHEL 7 (EOL Jun 2024)"),
    ("5.1.",                 "Windows XP / Server 2003 (build 5.1)"),
    ("5.2.",                 "Windows XP x64 / Server 2003 (build 5.2)"),
    ("6.0.",                 "Windows Vista / Server 2008 (build 6.0)"),
    ("6.1.",                 "Windows 7 / Server 2008 R2 (build 6.1)"),
    ("6.2.",                 "Windows 8 / Server 2012 (build 6.2)"),
    ("6.3.",                 "Windows 8.1 / Server 2012 R2 (build 6.3)"),
]


# ── Public API ────────────────────────────────────────────────────────────────

def find_attack_paths(
    G: nx.Graph, src_ip: str, dst_ip: str, cutoff: int = 8
) -> list[AttackPath]:
    """Find all simple attack paths from src to dst, sorted by risk score."""
    if src_ip not in G or dst_ip not in G:
        return []

    try:
        raw_paths = list(nx.all_simple_paths(G, src_ip, dst_ip, cutoff=cutoff))
    except nx.NetworkXNoPath:
        return []

    paths: list[AttackPath] = []
    for path in raw_paths[:20]:
        steps: list[PathStep] = []
        total_risk = 0.0
        for i, ip in enumerate(path):
            attrs = G.nodes[ip]
            kev_count = attrs.get("kev_count", 0) or 0
            max_epss  = attrs.get("max_epss", 0.0) or 0.0
            edge_to_next = None
            if i < len(path) - 1:
                edge_data = G.get_edge_data(ip, path[i + 1]) or {}
                edge_to_next = edge_data.get("edge_type", "")
            steps.append(PathStep(
                ip=ip,
                hostnames=attrs.get("hostnames", []),
                os_family=attrs.get("os_family", "Unknown"),
                max_cvss=attrs.get("max_cvss", 0.0),
                open_ports=attrs.get("open_ports", []),
                kev_count=kev_count,
                max_epss=max_epss,
                edge_to_next=edge_to_next,
            ))
            if 0 < i < len(path) - 1:
                # Boost intermediate-node risk when it has KEV-confirmed vulns
                cvss = attrs.get("max_cvss", 0.0)
                kev_boost = min(kev_count * 0.5, 2.0)  # up to +2.0 risk bonus
                total_risk += cvss + kev_boost

        paths.append(AttackPath(
            steps=steps,
            total_risk_score=total_risk,
            hop_count=len(path) - 1,
        ))

    paths.sort(key=lambda p: p.total_risk_score, reverse=True)
    return paths[:10]


def find_pivot_candidates(G: nx.Graph, top_n: int = 15) -> list[PivotCandidate]:
    """Identify hosts with high betweenness centrality or multi-subnet reach."""
    if G.number_of_nodes() < 3:
        return []

    centrality = nx.betweenness_centrality(G)
    candidates: list[PivotCandidate] = []

    for ip, between in centrality.items():
        attrs = G.nodes[ip]
        if attrs.get("node_type") != "host":
            continue

        subnets: set[str] = set()
        for _, _, edge_attrs in G.edges(ip, data=True):
            if edge_attrs.get("edge_type") == "subnet":
                subnets.add(edge_attrs.get("subnet", ""))

        max_cvss   = attrs.get("max_cvss", 0.0)
        kev_count  = attrs.get("kev_count", 0) or 0
        max_epss   = attrs.get("max_epss", 0.0) or 0.0
        open_ports = set(attrs.get("open_ports", []))
        os_family  = attrs.get("os_family", "Unknown")
        reasons: list[str] = []

        if between > 0:
            reasons.append(f"betweenness={between:.3f}")
        if len(subnets) > 1:
            reasons.append(f"bridges {len(subnets)} subnets")
        if open_ports & {3389, 5985, 22}:
            reasons.append("remote-access exposed")
        if open_ports & {445, 135, 139}:
            reasons.append("SMB/RPC reachable")
        if os_family == "Network":
            reasons.append("network device")
        if kev_count > 0:
            reasons.append(f"{kev_count} KEV vuln{'s' if kev_count > 1 else ''}")
        if max_epss >= 0.5:
            reasons.append(f"EPSS {max_epss:.0%}")

        # Score: topology centrality × vuln severity × role bonus × KEV multiplier
        role_bonus = 1.5 if os_family == "Network" else 1.0
        kev_mult   = 1.5 if kev_count > 0 else 1.0
        risk_score = (between + 0.001) * (max_cvss + 1.0) * role_bonus * kev_mult

        if between > 0 or len(subnets) > 1:
            candidates.append(PivotCandidate(
                ip=ip,
                os_family=os_family,
                os_name=attrs.get("os_name") or "",
                hostnames=attrs.get("hostnames", []),
                betweenness=between,
                subnet_count=max(len(subnets), 1),
                max_cvss=max_cvss,
                risk_score=risk_score,
                open_ports=sorted(attrs.get("open_ports", [])),
                kev_count=kev_count,
                max_epss=max_epss,
                pivot_reasons=reasons,
            ))

    candidates.sort(key=lambda c: c.risk_score, reverse=True)
    return candidates[:top_n]


def get_critical_exposure(
    G: nx.Graph, min_cvss: float = 7.0
) -> list[ExposedHost]:
    """List hosts with CVSS >= min_cvss, sorted by max_cvss desc."""
    exposed: list[ExposedHost] = []
    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue
        max_cvss = attrs.get("max_cvss", 0.0)
        if max_cvss < min_cvss:
            continue

        try:
            addr = ipaddress.ip_address(ip)
            is_external = not addr.is_private
        except ValueError:
            is_external = False

        kev_count = attrs.get("kev_count", 0) or 0
        max_epss  = attrs.get("max_epss", 0.0) or 0.0
        exposed.append(ExposedHost(
            ip=ip,
            os_family=attrs.get("os_family", "Unknown"),
            os_name=attrs.get("os_name") or "",
            hostnames=attrs.get("hostnames", []),
            max_cvss=max_cvss,
            critical_vuln_count=attrs.get("vuln_count_critical", 0),
            high_vuln_count=attrs.get("vuln_count_high", 0),
            open_ports=sorted(attrs.get("open_ports", [])),
            reachable_from_external=is_external,
            kev_count=kev_count,
            max_epss=max_epss,
        ))

    # KEV-confirmed hosts first, then by CVSS descending
    exposed.sort(key=lambda e: (-(e.kev_count > 0), -e.max_cvss))
    return exposed


def find_high_value_targets(G: nx.Graph) -> list[HighValueTarget]:
    """Classify hosts by strategic role (DC, DB, web, etc.) regardless of CVSS."""
    targets: list[HighValueTarget] = []

    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        open_ports = set(attrs.get("open_ports", []))
        os_family  = attrs.get("os_family", "Unknown")
        os_name    = attrs.get("os_name") or ""
        hostnames  = attrs.get("hostnames", [])
        max_cvss   = attrs.get("max_cvss", 0.0)

        roles: list[str] = []

        # Domain Controller
        if open_ports & _DC_PORTS or _dc_hostname(hostnames):
            roles.append("domain_controller")

        # Credential / directory store
        if (open_ports & _CRED_PORTS) and "domain_controller" not in roles:
            roles.append("credential_store")

        # Database
        if open_ports & _DB_PORTS:
            roles.append("database")

        # Web server
        if open_ports & _WEB_PORTS:
            roles.append("web_server")

        # Mail server
        if open_ports & _MAIL_PORTS:
            roles.append("mail_server")

        # File / share server
        if open_ports & _FILE_PORTS:
            roles.append("file_server")

        # Remote access exposure
        if open_ports & _REMOTE_PORTS:
            roles.append("remote_access")

        # Network device
        if os_family == "Network":
            roles.append("network_device")

        if not roles:
            continue

        kev_count  = attrs.get("kev_count", 0) or 0
        max_epss   = attrs.get("max_epss", 0.0) or 0.0
        top_weight = max(_ROLE_WEIGHT.get(r, 0) for r in roles)
        kev_bonus  = min(kev_count, 5)  # up to +5 for confirmed active exploits
        risk_score = top_weight + max_cvss + kev_bonus

        targets.append(HighValueTarget(
            ip=ip,
            os_family=os_family,
            os_name=os_name,
            hostnames=hostnames,
            roles=roles,
            max_cvss=max_cvss,
            open_ports=sorted(open_ports),
            risk_score=risk_score,
            kev_count=kev_count,
            max_epss=max_epss,
        ))

    targets.sort(key=lambda t: t.risk_score, reverse=True)
    return targets


def find_legacy_systems(G: nx.Graph) -> list[LegacySystem]:
    """Identify hosts running end-of-life operating systems."""
    legacy: list[LegacySystem] = []

    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        os_name = (attrs.get("os_name") or "").lower()

        label = None
        for pattern, eol_label in _EOL_PATTERNS:
            if os_name and pattern in os_name:
                label = eol_label
                break

        # Fall back to the flag set by vuln-based detection in build_graph()
        # (e.g. "Unsupported Version" / "Unsupported OS" Nessus plugin hits)
        if label is None and attrs.get("is_legacy"):
            label = "Unsupported OS/Software (detected via scan)"

        if label:
            kev_count = attrs.get("kev_count", 0) or 0
            max_epss  = attrs.get("max_epss", 0.0) or 0.0
            legacy.append(LegacySystem(
                ip=ip,
                os_family=attrs.get("os_family", "Unknown"),
                os_name=attrs.get("os_name") or "",
                hostnames=attrs.get("hostnames", []),
                eol_label=label,
                max_cvss=attrs.get("max_cvss", 0.0),
                open_ports=sorted(attrs.get("open_ports", [])),
                kev_count=kev_count,
                max_epss=max_epss,
            ))

    # KEV-confirmed legacy systems are highest priority
    legacy.sort(key=lambda s: (-(s.kev_count > 0), -s.max_cvss))
    return legacy


def find_network_segments(G: nx.Graph) -> list[list[str]]:
    """Return connected components as lists of IPs."""
    return [
        sorted(component)
        for component in nx.connected_components(G)
        if len(component) > 0
    ]


# ── SPN-typical service ports (Windows service accounts register SPNs for these)
_SPN_PORTS: dict[int, str] = {
    80:   "HTTP/IIS",
    443:  "HTTPS/IIS",
    1433: "MSSQL",
    1521: "Oracle DB",
    25:   "SMTP/Exchange",
    587:  "SMTP/Exchange",
    465:  "SMTPS/Exchange",
    8080: "HTTP/Tomcat",
    8443: "HTTPS/Tomcat",
    5985: "WinRM/HTTP",
    5986: "WinRM/HTTPS",
    3269: "LDAP Global Catalog",
}

_CLEARTEXT_PORTS: dict[int, str] = {
    21:  "FTP",
    23:  "Telnet",
    25:  "SMTP",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
}

_ADMIN_PORTS: dict[int, str] = {
    22:   "SSH",
    23:   "Telnet",
    512:  "rexec",
    513:  "rlogin",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}


def find_kerberoastable_indicators(G: nx.Graph) -> list[KerberoastIndicator]:
    """
    Multi-signal Kerberoastable detection. Requires a confirmed Kerberos
    environment (DC with port 88). For non-DC hosts, requires explicit
    Windows OS confirmation OR multiple corroborating Windows signals
    (domain tag, SMB port, AD LDAP ports). Never assumes Kerberoastable
    based on a single port observation alone.
    """
    dc_present = any(
        (attrs.get("is_dc") or 88 in attrs.get("open_ports", []))
        for _, attrs in G.nodes(data=True)
        if attrs.get("node_type") == "host"
    )
    if not dc_present:
        return []

    results: list[KerberoastIndicator] = []
    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        open_ports = set(attrs.get("open_ports", []))
        os_family  = (attrs.get("os_family") or "").strip()
        os_name    = (attrs.get("os_name") or "").strip()
        is_dc      = attrs.get("is_dc", False)
        tags       = attrs.get("tags", []) or []
        has_domain = any(t.lower().startswith("domain:") for t in tags)

        # Confirmed DC — always Kerberoastable (krbtgt + all SPNs)
        if is_dc or 88 in open_ports:
            results.append(KerberoastIndicator(
                ip=ip,
                os_name=os_name or os_family,
                hostnames=attrs.get("hostnames", []),
                spn_services=["krbtgt + all registered SPNs"],
                is_dc=True,
                max_cvss=attrs.get("max_cvss", 0.0),
                confidence="confirmed",
            ))
            continue

        # Non-DC: require Windows evidence before flagging
        is_windows_os = os_family == "Windows" or "windows" in os_name.lower()

        # Count corroborating Windows signals
        signals = sum([
            bool(is_windows_os),
            has_domain,
            445 in open_ports,                        # SMB — common on Windows
            bool({389, 636, 3268, 3269} & open_ports),  # AD LDAP ports
        ])

        # Skip if OS unknown and we lack supporting evidence
        if not is_windows_os and signals < 2:
            continue

        spn_svcs = [lbl for port, lbl in _SPN_PORTS.items()
                    if port in open_ports]
        if not spn_svcs:
            continue

        results.append(KerberoastIndicator(
            ip=ip,
            os_name=os_name or os_family or "Unknown (Windows signals present)",
            hostnames=attrs.get("hostnames", []),
            spn_services=spn_svcs,
            is_dc=False,
            max_cvss=attrs.get("max_cvss", 0.0),
            confidence="confirmed" if is_windows_os else "likely",
        ))

    results.sort(key=lambda x: (not x.is_dc, x.confidence != "confirmed", -x.max_cvss))
    return results


def find_cleartext_services(G: nx.Graph) -> list[CleartextHost]:
    """
    List hosts exposing protocols that transmit credentials in cleartext
    (FTP, Telnet, HTTP, SNMP, SMTP, POP3, IMAP, LDAP, r-services).
    """
    results: list[CleartextHost] = []
    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        open_ports = set(attrs.get("open_ports", []))
        exposed = [
            f"{label}:{port}"
            for port, label in sorted(_CLEARTEXT_PORTS.items())
            if port in open_ports
        ]
        if not exposed:
            continue

        results.append(CleartextHost(
            ip=ip,
            os_name=attrs.get("os_name") or attrs.get("os_family", "Unknown"),
            hostnames=attrs.get("hostnames", []),
            cleartext_ports=exposed,
            max_cvss=attrs.get("max_cvss", 0.0),
        ))

    # High-risk first: Telnet/rservices, then by CVSS
    def _risk(h: CleartextHost) -> tuple:
        high_risk = any(p in h.cleartext_ports[0] for p in
                        ("Telnet", "rexec", "rlogin", "rsh"))
        return (not high_risk, -h.max_cvss, -len(h.cleartext_ports))

    results.sort(key=_risk)
    return results


def find_admin_interfaces(G: nx.Graph) -> list[AdminInterface]:
    """
    List hosts with remote administration ports exposed
    (SSH, RDP, WinRM, VNC, Telnet, r-services).
    """
    results: list[AdminInterface] = []
    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        open_ports = set(attrs.get("open_ports", []))
        exposed = [
            f"{label}:{port}"
            for port, label in sorted(_ADMIN_PORTS.items())
            if port in open_ports
        ]
        if not exposed:
            continue

        try:
            is_external = not ipaddress.ip_address(ip).is_private
        except ValueError:
            is_external = False

        results.append(AdminInterface(
            ip=ip,
            os_name=attrs.get("os_name") or attrs.get("os_family", "Unknown"),
            hostnames=attrs.get("hostnames", []),
            admin_ports=exposed,
            max_cvss=attrs.get("max_cvss", 0.0),
            is_external=is_external,
        ))

    results.sort(key=lambda x: (not x.is_external, -x.max_cvss))
    return results


def find_smb_spread_risk(G: nx.Graph) -> list[SmbSpreadHost]:
    """
    Identify hosts that maximise SMB-based lateral movement potential.

    For each SMB-enabled host, count how many of its network neighbours
    also have SMB open (port 445). Higher count = broader blast radius.
    """
    smb_ips: set[str] = {
        ip for ip, attrs in G.nodes(data=True)
        if attrs.get("node_type") == "host" and 445 in attrs.get("open_ports", [])
    }
    if not smb_ips:
        return []

    results: list[SmbSpreadHost] = []
    for ip in smb_ips:
        attrs = G.nodes[ip]
        smb_neighbors = sum(
            1 for nbr in G.neighbors(ip)
            if nbr in smb_ips and nbr != ip
        )
        max_cvss  = attrs.get("max_cvss", 0.0)
        risk_score = (smb_neighbors + 1) * (max_cvss + 1.0)

        results.append(SmbSpreadHost(
            ip=ip,
            os_name=attrs.get("os_name") or attrs.get("os_family", "Unknown"),
            hostnames=attrs.get("hostnames", []),
            smb_neighbor_count=smb_neighbors,
            max_cvss=max_cvss,
            risk_score=risk_score,
        ))

    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results


def find_domain_enum(G: nx.Graph) -> list[DomainEnumHost]:
    """
    Return hosts where SMB/domain enumeration data is present.
    A host qualifies if it has a domain: tag (from enum4linux) or
    has port 445 open (SMB — potential enumeration target).
    The UI layer queries the DB for actual user/group counts.
    """
    results: list[DomainEnumHost] = []
    for ip, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue
        tags = attrs.get("tags", []) or []
        domain_tags = [
            t[len("domain:"):] for t in tags
            if t.lower().startswith("domain:")
        ]
        if not domain_tags and 445 not in attrs.get("open_ports", []):
            continue
        results.append(DomainEnumHost(
            ip=ip,
            os_name=(attrs.get("os_name") or attrs.get("os_family") or ""),
            hostnames=attrs.get("hostnames", []),
            domain=domain_tags[0] if domain_tags else "",
            max_cvss=attrs.get("max_cvss", 0.0),
        ))
    results.sort(key=lambda x: -x.max_cvss)
    return results


def find_path_to_nearest_hvt(
    G: nx.Graph, src_ip: str
) -> tuple[list[str], str] | tuple[None, None]:
    """
    Return (path, target_ip) for the shortest path from src_ip to any
    high-value target. Returns (None, None) if no path found.
    """
    hvts = {t.ip for t in find_high_value_targets(G)}
    if src_ip not in G or not hvts:
        return None, None

    best_path: list[str] | None = None
    best_target: str | None = None

    for tgt in hvts:
        if tgt == src_ip or tgt not in G:
            continue
        try:
            path = nx.shortest_path(G, src_ip, tgt)
            if best_path is None or len(path) < len(best_path):
                best_path = path
                best_target = tgt
        except nx.NetworkXNoPath:
            continue

    return best_path, best_target


# ── Internal helpers ──────────────────────────────────────────────────────────

def _dc_hostname(hostnames: list[str]) -> bool:
    """Return True if any hostname matches a Domain Controller pattern."""
    for hn in hostnames:
        parts = hn.lower().replace("-", ".").replace("_", ".").split(".")
        for p in parts:
            if p == "dc":
                return True
            if len(p) > 2 and p.startswith("dc") and p[2:].isdigit():
                return True
            if "domaincontroller" in p:
                return True
    return False
