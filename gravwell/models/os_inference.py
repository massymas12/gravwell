"""Centralised OS detection logic.

All parsers call ``infer_os()`` to raise the confidence of their OS guess
using every available signal.  A confidence score (0–100) travels with each
host so the ingestion layer can pick the most authoritative value when two
scan files describe the same IP.

Confidence constants (use these when setting ``explicit_confidence``):
    CONF_EXPLICIT_EXACT   95   nmap osmatch ≥ 90 accuracy
    CONF_EXPLICIT_HIGH    85   nmap osmatch 70-89, enum4linux SMB OS, nessus property
    CONF_EXPLICIT_MEDIUM  75   nmap osmatch 50-69, nessus fallback 'os' tag
    CONF_INFERRED_STRONG  68   3+ Windows ports, BGP/SNMP present, etc.
    CONF_INFERRED_MEDIUM  52   1-2 Windows ports, product name hint
    CONF_INFERRED_WEAK    32   MAC vendor, single ambiguous port
    CONF_NONE              0   no information
"""
from __future__ import annotations

from gravwell.models.dataclasses import Service, Vulnerability

# ── confidence constants ──────────────────────────────────────────────────────
CONF_EXPLICIT_EXACT   = 95
CONF_EXPLICIT_HIGH    = 85
CONF_EXPLICIT_MEDIUM  = 75
CONF_INFERRED_STRONG  = 68
CONF_INFERRED_MEDIUM  = 52
CONF_INFERRED_WEAK    = 32
CONF_NONE             = 0

# ── Windows port fingerprints ─────────────────────────────────────────────────
# Port → base confidence for "Windows" guess
_WIN_PORTS: dict[int, int] = {
    88:    65,   # Kerberos          (Windows DC — near-exclusive)
    135:   58,   # MS-RPC
    139:   54,   # NetBIOS session
    445:   72,   # SMB/CIFS          (very strong indicator)
    593:   48,   # HTTP RPC endpoint
    1433:  54,   # MS-SQL Server
    3268:  70,   # LDAP Global Catalog  (DC only)
    3269:  70,   # LDAP GC SSL          (DC only)
    3389:  67,   # RDP — Windows Remote Desktop
    5722:  54,   # DFSR
    5985:  60,   # WinRM HTTP
    5986:  60,   # WinRM HTTPS
    47001: 56,   # WinRM alt
}

# ── Linux/Unix port fingerprints ─────────────────────────────────────────────
_LINUX_PORTS: dict[int, int] = {
    111:   52,   # rpcbind / portmapper
    2049:  58,   # NFS
    631:   46,   # CUPS printing
    4369:  44,   # Erlang EPMD (Linux-common services like RabbitMQ)
    6443:  44,   # Kubernetes API
    10250: 44,   # kubelet
}

# ── Network device port fingerprints ─────────────────────────────────────────
_NET_PORTS: dict[int, int] = {
    23:    44,   # Telnet (still common on network mgmt interfaces)
    69:    54,   # TFTP
    161:   60,   # SNMP
    162:   60,   # SNMP trap
    179:   75,   # BGP              (routers only)
    520:   68,   # RIPv1
    521:   68,   # RIPng
    830:   64,   # NETCONF over SSH
    2000:  48,   # Cisco SCCP
    2001:  48,   # Cisco
}

# ── Windows service name fingerprints ────────────────────────────────────────
_WIN_SVCNAMES: frozenset[str] = frozenset({
    "microsoft-ds", "msrpc", "ms-wbt-server", "netbios-ssn",
    "netbios-ns", "kerberos-sec", "epmap", "ms-sql-s", "ms-sql-m",
})

# ── Network service name fingerprints ────────────────────────────────────────
_NET_SVCNAMES: frozenset[str] = frozenset({
    "snmp", "bgp", "rip", "telnet", "tftp", "netconf",
    "cisco-sccp", "cisco-fna", "cisco-tna", "cisco-sys",
})

# ── Product name hints ────────────────────────────────────────────────────────
# Ordered from most-specific to least-specific so the first match wins.
_PRODUCT_HINTS: list[tuple[list[str], str, int]] = [
    (["Cisco IOS", "Cisco NX-OS", "Cisco IOS-XE", "JunOS", "Junos", "FortiGate",
      "pfSense", "OpenWRT", "DD-WRT", "MikroTik"], "Network", 72),
    (["Microsoft-IIS", "Microsoft HTTPAPI", "Microsoft FTP", "Exchange",
      "MSSQL", "MS-SQL", "Windows RPC"], "Windows", 68),
    (["OpenSSH for Windows", "WinSSH", "Microsoft SFTP"], "Windows", 65),
    (["IIS"], "Windows", 60),
    (["OpenSSH", "vsftpd", "ProFTPD", "Samba", "Postfix", "Dovecot",
      "Exim", "lighttpd", "nginx", "Apache httpd", "Apache", "OpenBSD Secure Shell",
      "Linux rpcbind"], "Linux", 48),
]

# ── MAC vendor hints ──────────────────────────────────────────────────────────
_MAC_VENDOR_HINTS: list[tuple[list[str], str, int]] = [
    (["Cisco", "Juniper", "Aruba Networks", "Palo Alto", "Fortinet",
      "Extreme Networks", "Brocade", "MikroTik", "Ubiquiti", "Meraki",
      "Huawei", "Zyxel", "D-Link", "Netgear"], "Network", 48),
    # VMware: virtual NIC — family says nothing about guest OS
]

# ── Vulnerability keyword hints ───────────────────────────────────────────────
_WIN_VULN_KW: frozenset[str] = frozenset([
    "windows", "microsoft", " iis", "remote desktop", "active directory",
    " smb", " wmi", "winrm", "ms-", "mssql", "exchange",
    "ntlm", ".net framework", "internet explorer",
])
_LINUX_VULN_KW: frozenset[str] = frozenset([
    "linux", "unix", "ubuntu", "debian", "centos", "red hat", "fedora",
    "apache", "nginx", "openssh", "samba", "nfs", "rpcbind", "glibc",
])


# ── Public interface ──────────────────────────────────────────────────────────

def infer_os(
    services: list[Service],
    vulnerabilities: list[Vulnerability],
    mac_vendor: str | None,
    *,
    explicit_os_name: str | None = None,
    explicit_os_family: str | None = None,
    explicit_confidence: int = CONF_NONE,
) -> tuple[str | None, str | None, int]:
    """Return ``(os_name, os_family, confidence)`` where confidence is 0-100.

    If the caller already has scanner-supplied OS data, pass it via the
    keyword-only arguments.  Heuristic signals are applied only when they
    would improve confidence above the supplied value.

    The returned ``os_name`` is the caller's ``explicit_os_name`` unless it
    was None, in which case it falls back to the inferred os_family string.
    The returned ``os_family`` is always one of: Windows, Linux, Network, Unknown.
    """
    best_name   = explicit_os_name
    best_family = explicit_os_family
    best_conf   = explicit_confidence

    def _try(family: str, conf: int, name: str | None = None) -> None:
        nonlocal best_name, best_family, best_conf
        if conf > best_conf:
            best_conf   = conf
            best_family = family
            if name:
                best_name = name
            elif not best_name:
                best_name = family

    open_svcs  = [s for s in services if s.state == "open"]
    open_ports = {s.port for s in open_svcs}

    # ── Port-based scoring ────────────────────────────────────────────────
    win_hits = 0
    for svc in open_svcs:
        p = svc.port
        if p in _WIN_PORTS:
            win_hits += 1
            _try("Windows", _WIN_PORTS[p])
        elif p in _LINUX_PORTS:
            _try("Linux", _LINUX_PORTS[p])
        elif p in _NET_PORTS:
            _try("Network", _NET_PORTS[p])

    # Multi-port Windows bonus
    if win_hits >= 4:
        _try("Windows", CONF_INFERRED_STRONG + 5)
    elif win_hits >= 2:
        _try("Windows", CONF_INFERRED_MEDIUM + 8)

    # ── Service name scoring ──────────────────────────────────────────────
    for svc in open_svcs:
        sn = (svc.service_name or "").lower()
        if sn in _WIN_SVCNAMES:
            _try("Windows", CONF_INFERRED_MEDIUM + 6)
        elif sn in _NET_SVCNAMES:
            _try("Network", CONF_INFERRED_MEDIUM + 4)

        # Banner scanning
        banner = (svc.banner or "").lower()
        if "windows" in banner or "microsoft" in banner:
            _try("Windows", CONF_INFERRED_MEDIUM + 4)
        if "openssh" in banner and "windows" not in banner:
            _try("Linux", CONF_INFERRED_WEAK + 12)

        # Product name
        if svc.product:
            prod_lower = svc.product.lower()
            for fragments, family, conf in _PRODUCT_HINTS:
                if any(f.lower() in prod_lower for f in fragments):
                    _try(family, conf)
                    break

    # ── MAC vendor ────────────────────────────────────────────────────────
    if mac_vendor:
        mv_lower = mac_vendor.lower()
        for fragments, family, conf in _MAC_VENDOR_HINTS:
            if any(f.lower() in mv_lower for f in fragments):
                _try(family, conf)
                break

    # ── Vulnerability keyword scoring ─────────────────────────────────────
    for vuln in vulnerabilities:
        text = " " + (vuln.name + " " + vuln.description).lower() + " "
        if any(kw in text for kw in _WIN_VULN_KW):
            _try("Windows", CONF_INFERRED_MEDIUM + 2)
        elif any(kw in text for kw in _LINUX_VULN_KW):
            _try("Linux", CONF_INFERRED_WEAK + 14)

    # ── Normalise family ──────────────────────────────────────────────────
    if best_family:
        best_family = normalize_os_family(best_family)

    return best_name, best_family, best_conf


def normalize_os_family(raw: str) -> str:
    """Map any OS family/name string to Windows | Linux | Network | Unknown."""
    r = (raw or "").lower()
    if any(x in r for x in ("windows", "microsoft", "winnt", "win32", "win2k")):
        return "Windows"
    if any(x in r for x in ("linux", "unix", "bsd", "macos", "mac os", "darwin",
                              "solaris", "aix", "hpux", "irix")):
        return "Linux"
    if any(x in r for x in ("cisco", "junos", "network", "router", "switch",
                              "firewall", "printer", "appliance", "nx-os",
                              "iosxe", "fortios", "panos")):
        return "Network"
    return "Unknown"


def os_family_from_name(os_name: str | None) -> str:
    """Derive os_family from a full OS name string (e.g. 'Windows 10 Enterprise')."""
    if not os_name:
        return "Unknown"
    return normalize_os_family(os_name)
