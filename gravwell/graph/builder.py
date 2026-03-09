from __future__ import annotations
import ipaddress
import math
import networkx as nx
from sqlalchemy import func
from sqlalchemy.orm import Session
from gravwell.models.orm import HostORM, ServiceORM, VulnerabilityORM, CVERefORM, CVEEnrichmentORM

# (bg_color, border_color) pairs — one per subnet, cycling
_SUBNET_PALETTE = [
    ("#0d2137", "#2980B9"),   # blue
    ("#0d3320", "#27AE60"),   # green
    ("#2d1a0d", "#E67E22"),   # orange
    ("#1d0d2d", "#8E44AD"),   # purple
    ("#2d2d0d", "#F1C40F"),   # yellow
    ("#0d2d2d", "#16A085"),   # teal
    ("#2d0d0d", "#E74C3C"),   # red
    ("#1a1a2d", "#5DADE2"),   # light blue
]

# Ports that strongly suggest a network device (router/switch/firewall)
_ROUTER_PORTS = {23, 69, 161, 162, 179, 520, 521, 830, 2000, 2001}

# Ports that strongly indicate a Windows Domain Controller
_DC_PORTS = {
    88,    # Kerberos — almost exclusive to DCs
    3268,  # Global Catalog LDAP — exclusive to DCs
    3269,  # Global Catalog LDAPS — exclusive to DCs
}

# MAC vendor substrings that indicate network hardware
_NETWORK_VENDORS = {
    "cisco", "juniper", "aruba", "palo alto", "fortinet",
    "extreme", "brocade", "huawei", "mikrotik",
    "ubiquiti", "meraki", "netgear", "d-link", "zyxel",
}


def build_graph(session: Session) -> nx.Graph:
    """Build a NetworkX graph from all hosts in the DB."""
    G = nx.Graph()

    hosts = session.query(HostORM).all()

    # Batch-fetch KEV count per host and max EPSS — two queries total.
    try:
        _kev_q = (
            session.query(
                VulnerabilityORM.host_id,
                func.count(VulnerabilityORM.id.distinct()).label("kev_count"),
            )
            .join(CVERefORM, CVERefORM.vuln_id == VulnerabilityORM.id)
            .join(CVEEnrichmentORM, CVEEnrichmentORM.cve_id == CVERefORM.cve_id)
            .filter(CVEEnrichmentORM.in_kev.is_(True))
            .group_by(VulnerabilityORM.host_id)
            .all()
        )
        kev_count_map: dict[int, int] = {r.host_id: r.kev_count for r in _kev_q}
        _epss_q = (
            session.query(
                VulnerabilityORM.host_id,
                func.max(CVEEnrichmentORM.epss_score).label("max_epss"),
            )
            .join(CVERefORM, CVERefORM.vuln_id == VulnerabilityORM.id)
            .join(CVEEnrichmentORM, CVEEnrichmentORM.cve_id == CVERefORM.cve_id)
            .filter(CVEEnrichmentORM.epss_score.isnot(None))
            .group_by(VulnerabilityORM.host_id)
            .all()
        )
        epss_map: dict[int, float] = {r.host_id: r.max_epss or 0.0 for r in _epss_q}
    except Exception:
        kev_count_map = {}
        epss_map = {}

    # Batch-fetch only the columns needed from open services
    _all_svcs = session.query(
        ServiceORM.host_id, ServiceORM.port, ServiceORM.protocol,
        ServiceORM.service_name, ServiceORM.product,
    ).filter(ServiceORM.state == "open").all()
    services_by_host: dict[int, list] = {}
    for _s in _all_svcs:
        services_by_host.setdefault(_s.host_id, []).append(_s)

    # Batch-fetch host_ids with any "unsupported" vuln (avoids N per-host queries)
    unsupported_host_ids: set[int] = {
        row[0]
        for row in session.query(VulnerabilityORM.host_id)
        .filter(VulnerabilityORM.name.ilike("%unsupported%"))
        .distinct()
        .all()
    }

    # Snapshot data while session is open
    host_data: list[dict] = []
    for h in hosts:
        services = services_by_host.get(h.id, [])
        open_ports = [s.port for s in services]
        svc_list = [
            {"port": s.port, "protocol": s.protocol,
             "service_name": s.service_name or "", "product": s.product or ""}
            for s in services
        ]
        port_set = set(open_ports)
        is_dc   = _is_domain_controller({"open_ports": open_ports,
                                          "hostnames": h.hostnames})
        roles   = _classify_roles(port_set, h.os_family or "Unknown",
                                   h.mac_vendor or "", h.hostnames, is_dc)
        is_leg  = _is_legacy(h.os_name or "", h.id in unsupported_host_ids)
        host_data.append({
            "id": h.id,
            "ip": h.ip,
            "hostnames": h.hostnames,
            "os_name": h.os_name or "",
            "os_family": h.os_family or "Unknown",
            "mac": h.mac or "",
            "mac_vendor": h.mac_vendor or "",
            "status": h.status,
            "max_cvss": h.max_cvss,
            "vuln_count_critical": h.vuln_count_critical,
            "vuln_count_high": h.vuln_count_high,
            "vuln_count_medium": h.vuln_count_medium,
            "vuln_count_low": h.vuln_count_low,
            "source_files": h.source_files,
            "open_ports": open_ports,
            "services": svc_list,
            "is_dc": is_dc,
            "is_legacy": is_leg,
            "host_roles": roles,
            "kev_count": kev_count_map.get(h.id, 0),
            "max_epss": epss_map.get(h.id, 0.0),
            "additional_ips": h.additional_ips,
            "tags": list(h.tags),
        })

    # Add nodes
    for hd in host_data:
        G.add_node(hd["ip"], node_type="host", **hd)

    # Compute subnet map once — include secondary IPs so multi-homed hosts
    # are correctly assigned to all subnets they participate in.
    all_ips = []
    for hd in host_data:
        all_ips.append(hd["ip"])
        all_ips.extend(hd.get("additional_ips", []))
    ip_to_subnet = _infer_subnets(all_ips)
    G.graph["ip_to_subnet"] = ip_to_subnet

    # Add edges: same /24 subnet (reuse precomputed map)
    _add_subnet_edges(G, host_data, ip_to_subnet)

    # Add edges: shared interesting ports (potential lateral movement)
    _add_shared_service_edges(G, host_data)

    return G


def _add_subnet_edges(
    G: nx.Graph,
    host_data: list[dict],
    ip_subnet: dict[str, str] | None = None,
) -> None:
    """Connect hosts in the same inferred subnet.

    Multi-homed hosts (with additional_ips) participate in every subnet their
    IPs belong to — the node key is always the primary IP.
    """
    if ip_subnet is None:
        all_ips = []
        for hd in host_data:
            all_ips.append(hd["ip"])
            all_ips.extend(hd.get("additional_ips", []))
        ip_subnet = _infer_subnets(all_ips)

    # Build subnet → [primary node_ids], mapping all IPs to their host's node
    subnet_members: dict[str, list[str]] = {}
    for hd in host_data:
        for ip in [hd["ip"]] + hd.get("additional_ips", []):
            subnet = ip_subnet.get(ip)
            if subnet:
                lst = subnet_members.setdefault(subnet, [])
                if hd["ip"] not in lst:
                    lst.append(hd["ip"])

    for subnet, nodes in subnet_members.items():
        if len(nodes) < 2:
            continue
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                if not G.has_edge(nodes[i], nodes[j]):
                    G.add_edge(nodes[i], nodes[j], edge_type="subnet", subnet=subnet)


def _add_shared_service_edges(G: nx.Graph, host_data: list[dict]) -> None:
    """Connect hosts that share interesting open ports (potential pivot paths)."""
    # Ports that indicate shared service / lateral movement potential
    INTERESTING_PORTS = {
        22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
        465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
    }
    port_hosts: dict[int, list[str]] = {}
    for hd in host_data:
        for p in hd["open_ports"]:
            if p in INTERESTING_PORTS:
                port_hosts.setdefault(p, []).append(hd["ip"])

    for port, ips in port_hosts.items():
        if len(ips) < 2:
            continue
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                if not G.has_edge(ips[i], ips[j]):
                    G.add_edge(ips[i], ips[j],
                               edge_type="shared_service", port=port)


def _infer_subnets(ips: list[str]) -> dict[str, str]:
    """
    Map each IP to its best subnet CIDR.

    Strategy:
    - A /24 with 2+ hosts is a *real* subnet — always kept at /24.
    - If a /16 contains at least one real /24, every host in that /16 uses /24.
    - Singleton hosts (alone in their /24) are grouped at /16 only when their
      /16 spans 2+ distinct /24s AND contains no real /24s (flat /16 topology).
    - All other singletons stay at /24.
    """
    ip_to: dict[str, dict] = {}
    by_24: dict[str, list[str]] = {}
    sixteen_24s: dict[str, set[str]] = {}

    for ip in ips:
        try:
            n24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            n16 = str(ipaddress.ip_network(f"{ip}/16", strict=False))
        except ValueError:
            ip_to[ip] = {"24": "unknown", "16": "unknown"}
            continue
        ip_to[ip] = {"24": n24, "16": n16}
        by_24.setdefault(n24, []).append(ip)
        sixteen_24s.setdefault(n16, set()).add(n24)

    # /24s with 2+ hosts are real subnets — never collapsed into a /16
    real_24s: set[str] = {n24 for n24, grp in by_24.items() if len(grp) >= 2}

    # Promote singletons to /16 only when the /16 has no real /24s and spans 2+
    promote_to_16: set[str] = {
        n16
        for n16, n24s in sixteen_24s.items()
        if len(n24s) >= 2 and not any(n24 in real_24s for n24 in n24s)
    }

    result: dict[str, str] = {}
    for ip in ips:
        nets = ip_to.get(ip, {})
        n16 = nets.get("16", "unknown")
        n24 = nets.get("24", "unknown")
        result[ip] = n16 if n16 in promote_to_16 else n24
    return result


_EOL_SUBSTRINGS = (
    # Windows desktop
    "windows xp", "windows vista", "windows 7", "windows 8",
    # Windows Server (2012 EOL Oct 2023, 2008 EOL Jan 2020, 2003/2000 long EOL)
    "server 2003", "server 2008", "server 2012",
    # NT kernel version strings (XP=5.1, Server2003=5.2, Vista=6.0, 7=6.1,
    #   8/2012=6.2, 8.1/2012R2=6.3) — appear in nmap OS fingerprints
    "5.1.", "5.2.", "6.0.", "6.1.", "6.2.", "6.3.",
    # CentOS (8 EOL Dec 2021, 7 EOL Jun 2024)
    "centos 6", "centos 7", "centos 8",
    # Ubuntu LTS (20.04 EOL Apr 2025 — past as of 2026)
    "ubuntu 14.04", "ubuntu 16.04", "ubuntu 18.04", "ubuntu 20.04",
    # Debian (10 EOL Jun 2024, 9 EOL Jun 2022)
    "debian 7", "debian 8", "debian 9", "debian 10",
    # RHEL (6 EOL Nov 2020, 7 EOL Jun 2024)
    "rhel 6", "rhel 7",
    "red hat enterprise linux 6", "red hat enterprise linux 7",
)

_HVT_PORT_SETS = {
    "dc":     {88, 3268, 3269},
    "db":     {1433, 1521, 3306, 5432, 6379, 9200, 27017},
    "web":    {80, 443, 8080, 8443},
    "rdp":    {3389},
    "smb":    {445},
}


def _is_legacy(os_name: str, has_unsupported_vuln: bool = False) -> bool:
    """Return True if the OS is known end-of-life or an 'unsupported' vuln exists."""
    if has_unsupported_vuln:
        return True
    low = os_name.lower()
    return any(s in low for s in _EOL_SUBSTRINGS)


def _classify_roles(
    open_ports: set[int],
    os_family: str,
    mac_vendor: str,
    hostnames: list[str],
    is_dc: bool,
) -> list[str]:
    roles: list[str] = []
    if is_dc:
        roles.append("dc")
    if open_ports & _HVT_PORT_SETS["db"]:
        roles.append("db")
    if open_ports & _HVT_PORT_SETS["web"]:
        roles.append("web")
    if open_ports & _HVT_PORT_SETS["rdp"]:
        roles.append("rdp")
    if open_ports & _HVT_PORT_SETS["smb"] and "dc" not in roles:
        roles.append("smb")
    if os_family == "Network":
        roles.append("router")
    return roles


def _node_role(attrs: dict) -> str:
    """Classify a host as 'router', 'gateway', or 'host'."""
    os_family = attrs.get("os_family", "Unknown")
    open_ports = set(attrs.get("open_ports", []))
    mac_vendor = (attrs.get("mac_vendor") or "").lower()

    if os_family == "Network":
        return "router"
    if any(v in mac_vendor for v in _NETWORK_VENDORS):
        return "router"
    if open_ports & _ROUTER_PORTS:
        return "router"
    try:
        last_octet = int(attrs.get("ip", "").split(".")[-1])
        if last_octet in (1, 254):
            return "gateway"
    except (ValueError, IndexError):
        pass
    return "host"


def _is_genuine_bridge(attrs: dict) -> bool:
    """Return True if this host should float outside subnet compound groups.

    Only genuine network devices (routers, firewalls, L3 switches) that span
    multiple subnets are visualised as floating bridge nodes.  Regular
    Windows / Linux hosts stay in their primary subnet even when they have
    secondary IPs — VPN addresses, Docker bridges, extra NICs, etc.
    """
    if attrs.get("os_family") == "Network":
        return True
    return _node_role(attrs) == "router"


def _is_domain_controller(attrs: dict) -> bool:
    """Return True if the host is likely a Windows Domain Controller.

    Uses port-based and hostname-based heuristics:
    - Port 88  (Kerberos)       — almost exclusive to DCs
    - Port 3268/3269 (Global Catalog) — exclusive to DCs
    - Hostname word component 'dc' or 'dc<digits>' (e.g. dc01, dc-prod, dc.corp.local)
    - Hostname contains 'domaincontroller'
    """
    open_ports = set(attrs.get("open_ports", []))
    if open_ports & _DC_PORTS:
        return True
    for hn in (attrs.get("hostnames") or []):
        parts = hn.lower().replace("-", ".").replace("_", ".").split(".")
        for p in parts:
            if p == "dc":
                return True
            if len(p) > 2 and p.startswith("dc") and p[2:].isdigit():
                return True
            if "domaincontroller" in p:
                return True
    return False


def _subnet_net16(subnet: str) -> str:
    """Return the /16 parent of a subnet CIDR string, or 'unknown'."""
    try:
        n = ipaddress.ip_network(subnet, strict=False)
        return str(ipaddress.ip_network(f"{n.network_address}/16", strict=False))
    except ValueError:
        return "unknown"


def _compute_preset_positions(
    elements: list[dict],
    subnet_ips: dict[str, list[str]],
    subnet_hub: dict[str, str],
    multi_subnet_nodes: set[str] | None = None,
    node_subnets: dict[str, set[str]] | None = None,
    saved_positions: dict[str, tuple[float, float]] | None = None,
    subnet_domain: dict[str, str] | None = None,
    domain_depth: dict[str, int] | None = None,
) -> list[dict]:
    """
    Assign non-overlapping positions to every leaf node.

    Layout strategy (guarantees zero subnet-box overlap AND minimises edge
    crossings between subnets):

    1. Group subnets by their /16.  Each /16 group becomes a horizontal band.
       Inter-subnet edges only connect siblings in the same /16, so they are
       short horizontal lines that never cross over other bands.

    2. Within each band, subnets are arranged in a compact sub-grid (up to
       _MAX_COLS wide), sorted largest-first.

    3. Bands are stacked vertically with _GROUP_GAP extra space between them so
       inter-band edges are visually distinct from intra-band ones.

    The positions are written into element["position"] so that:
      - The "preset" layout uses them directly (zero overlap guaranteed).
      - Cose-bilkent with randomize:false uses them as warm-start positions.
    """
    _GAP = 25         # gap between subnet box edges within a domain/band
    _GROUP_GAP = 180  # vertical gap between depth bands (larger = clearer hierarchy)
    _PAD = 40         # internal padding allowance (stylesheet: 30px padding + label)
    _MAX_COLS = 8     # max columns per domain/band grid

    def _node_sz(n_hosts: int) -> int:
        if n_hosts > 30:
            return 12
        if n_hosts > 14:
            return 20
        return 32

    def _spoke_r(k: int, sz: int) -> float:
        if k == 0:
            return 0.0
        return max(60.0, (k * sz) / (2 * math.pi))

    # Estimate compound bounding-box side for each subnet
    subnet_box: dict[str, float] = {}
    for subnet, ips in subnet_ips.items():
        hub = subnet_hub.get(subnet, "")
        k = sum(1 for ip in ips if ip != hub)
        sz = _node_sz(len(ips))
        r = _spoke_r(k, sz)
        subnet_box[subnet] = max(120.0, 2 * r + 2 * _PAD + sz * 2)

    # ── Domain-depth layout ───────────────────────────────────────────────────
    # Group subnets by their domain, then group domains by depth.
    # Each depth level occupies a full horizontal band so all top-level domains
    # (depth 0) share the same y row, depth-1 subdomains appear on the row
    # below, and so on.  Undomained subnets fall to the bottom via /16 grouping.

    _DOMAIN_GAP = 120  # horizontal gap between adjacent domain boxes (wider = clearer parent-child lines)

    def _sort_subs(subs: list[str]) -> list[str]:
        return sorted(subs, key=lambda s: (
            ipaddress.ip_network(s, strict=False).network_address
            if s != "unknown"
            else ipaddress.ip_network("0.0.0.0/0").network_address
        ))

    def _place_subnet_grid(
        subs: list[str], x_start: float, y_start: float
    ) -> tuple[dict[str, tuple[float, float]], float, float]:
        """Place subnets in a compact grid starting at (x_start, y_start).

        Returns (subnet_centers_dict, total_width, total_height).
        """
        n = len(subs)
        # Prefer wide single-row layout; only add rows when n > _MAX_COLS.
        # This keeps domain boxes short and wide rather than tall and narrow.
        ncols = min(_MAX_COLS, n)
        nrows = math.ceil(n / ncols)

        grid: list[list[str | None]] = [
            [subs[r * ncols + c] if r * ncols + c < n else None
             for c in range(ncols)]
            for r in range(nrows)
        ]
        col_widths = [
            max((subnet_box[grid[r][c]] for r in range(nrows) if grid[r][c]),
                default=120.0)
            for c in range(ncols)
        ]
        row_heights = [
            max((subnet_box[grid[r][c]] for c in range(ncols) if grid[r][c]),
                default=120.0)
            for r in range(nrows)
        ]

        col_x: list[float] = []
        x = x_start
        for w in col_widths:
            col_x.append(x + w / 2)
            x += w + _GAP

        row_y: list[float] = []
        y = y_start
        for h in row_heights:
            row_y.append(y + h / 2)
            y += h + _GAP

        centers: dict[str, tuple[float, float]] = {}
        for r in range(nrows):
            for c in range(ncols):
                s = grid[r][c]
                if s:
                    centers[s] = (col_x[c], row_y[r])

        total_w = sum(col_widths) + _GAP * max(0, ncols - 1)
        total_h = sum(row_heights) + _GAP * max(0, nrows - 1)
        return centers, total_w, total_h

    # domain → sorted subnets
    domain_to_subs: dict[str, list[str]] = {}
    for sn, dom in (subnet_domain or {}).items():
        if sn in subnet_ips:
            domain_to_subs.setdefault(dom, []).append(sn)
    for dom in domain_to_subs:
        domain_to_subs[dom] = _sort_subs(domain_to_subs[dom])

    # depth → ordered list of domain names.
    # Ordering goal: minimise edge length and crossings.
    #   Depth 0: alphabetical (arbitrary tie-break, no parent to align to).
    #   Depth N: sort by (parent's position in the depth-N-1 band, then name).
    #     This groups all children of CORP.COM together, directly below CORP.COM,
    #     and all children of EXTERNAL.COM together below EXTERNAL.COM — so the
    #     edges from subdomains to their parent never cross each other.
    all_dom_names = list(domain_to_subs.keys())

    def _dom_parent(dom: str) -> str | None:
        """Most-specific parent domain (longest suffix that is a known domain)."""
        candidates = [d for d in all_dom_names if d != dom and dom.endswith("." + d)]
        return max(candidates, key=len) if candidates else None

    depth_to_doms: dict[int, list[str]] = {}
    for dom, dep in (domain_depth or {}).items():
        if dom in domain_to_subs:
            depth_to_doms.setdefault(dep, []).append(dom)

    # ── Compute each domain's own grid width ─────────────────────────────────
    def _dom_own_width(dom: str) -> float:
        subs = domain_to_subs[dom]
        n = len(subs)
        ncols = min(_MAX_COLS, n)          # match _place_subnet_grid formula
        nrows = math.ceil(n / ncols)
        col_ws = []
        for c in range(ncols):
            cw = max(
                (subnet_box[subs[r * ncols + c]] for r in range(nrows)
                 if r * ncols + c < n),
                default=120.0,
            )
            col_ws.append(cw)
        return sum(col_ws) + _GAP * max(0, ncols - 1)

    dom_own_w: dict[str, float] = {d: _dom_own_width(d) for d in domain_to_subs}

    # ── Order each depth band: children grouped under their parent ────────────
    ordered_at: dict[int, list[str]] = {}
    for dep in sorted(depth_to_doms.keys()):
        doms = depth_to_doms[dep]
        if dep == 0:
            ordered_at[dep] = sorted(doms)
        else:
            parent_rank = {d: i for i, d in enumerate(ordered_at.get(dep - 1, []))}
            ordered_at[dep] = sorted(
                doms,
                key=lambda d: (parent_rank.get(_dom_parent(d), 999), d),
            )
        depth_to_doms[dep] = ordered_at[dep]

    # ── Build children list per domain (ordered) ──────────────────────────────
    dom_children: dict[str, list[str]] = {d: [] for d in domain_to_subs}
    for dep in sorted(depth_to_doms.keys()):
        for dom in depth_to_doms[dep]:
            par = _dom_parent(dom)
            if par and par in dom_children:
                dom_children[par].append(dom)

    # ── Bottom-up: subtree width = space needed by domain + all descendants ───
    subtree_w: dict[str, float] = {}

    def _subtree_width(dom: str) -> float:
        if dom in subtree_w:
            return subtree_w[dom]
        children = dom_children[dom]
        if not children:
            subtree_w[dom] = dom_own_w[dom]
        else:
            ch_total = (sum(_subtree_width(c) for c in children)
                        + _DOMAIN_GAP * (len(children) - 1))
            subtree_w[dom] = max(dom_own_w[dom], ch_total)
        return subtree_w[dom]

    for dom in domain_to_subs:
        _subtree_width(dom)

    # ── Top-down: assign x allocation ranges ─────────────────────────────────
    # Root domains (depth 0) are placed left-to-right with subtree_w spacing
    # so each root gets enough room for itself AND all its descendants.
    # Each domain's children are then centered within the parent's allocation.
    alloc_x: dict[str, float] = {}
    alloc_w: dict[str, float] = {}

    x_cursor = 0.0
    for root in depth_to_doms.get(0, []):
        alloc_x[root] = x_cursor
        alloc_w[root] = subtree_w[root]
        x_cursor += subtree_w[root] + _DOMAIN_GAP

    def _assign_alloc(dom: str) -> None:
        children = dom_children[dom]
        if not children:
            return
        ch_total = (sum(subtree_w[c] for c in children)
                    + _DOMAIN_GAP * (len(children) - 1))
        # Center child block within parent's allocated range
        child_x = alloc_x[dom] + alloc_w[dom] / 2 - ch_total / 2
        for child in children:
            alloc_x[child] = child_x
            alloc_w[child] = subtree_w[child]
            child_x += subtree_w[child] + _DOMAIN_GAP
            _assign_alloc(child)

    for root in depth_to_doms.get(0, []):
        _assign_alloc(root)

    # ── Compute per-depth y positions (all domains at same depth share y) ─────
    depth_y: dict[int, float] = {}
    y_cursor = 0.0
    for dep in sorted(depth_to_doms.keys()):
        depth_y[dep] = y_cursor
        max_h = max(
            (_place_subnet_grid(domain_to_subs[d], 0, 0)[2]
             for d in depth_to_doms[dep]),
            default=0.0,
        )
        y_cursor += max_h + _GROUP_GAP

    # ── Place each domain's subnets centered in its allocated x range ─────────
    subnet_center: dict[str, tuple[float, float]] = {}
    for dep in sorted(depth_to_doms.keys()):
        y_start = depth_y[dep]
        for dom in depth_to_doms[dep]:
            x_alloc = alloc_x.get(dom, 0.0)
            w_alloc = alloc_w.get(dom, dom_own_w[dom])
            x_start = x_alloc + (w_alloc - dom_own_w[dom]) / 2
            centers, _, _ = _place_subnet_grid(
                domain_to_subs[dom], x_start, y_start
            )
            subnet_center.update(centers)

    # Subnets with no domain: placed at the bottom using /16 grouping
    domained_set = set(subnet_domain.keys()) if subnet_domain else set()
    undomained = [s for s in subnet_ips if s not in domained_set]
    if undomained:
        ugroups: dict[str, list[str]] = {}
        for s in undomained:
            ugroups.setdefault(_subnet_net16(s), []).append(s)
        for g in ugroups.values():
            g[:] = _sort_subs(g)
        ugroups_sorted = sorted(ugroups.values(), key=lambda g: g[0])
        # Place /16 groups side-by-side horizontally (same row), not stacked.
        x_cursor = 0.0
        max_band_h = 0.0
        for group_subs in ugroups_sorted:
            centers, grp_w, grp_h = _place_subnet_grid(group_subs, x_cursor, y_cursor)
            subnet_center.update(centers)
            x_cursor += grp_w + _DOMAIN_GAP
            max_band_h = max(max_band_h, grp_h)
        if max_band_h > 0:
            y_cursor += max_band_h + _GROUP_GAP

    # Compute leaf-node positions (hub at centre, hosts on spoke circle).
    # If the user has previously saved positions (by dragging), those are used
    # so manual layout adjustments persist across page refreshes.  The
    # algorithmic subnet_center is only used as fallback when no saved
    # position exists for a given node.
    node_positions: dict[str, dict[str, float]] = {}
    for subnet, ips in subnet_ips.items():
        hub_id = subnet_hub.get(subnet)
        algo_cx, algo_cy = subnet_center.get(subnet, (0.0, 0.0))

        # Derive the effective hub centre:
        # 1. Use saved hub position if present.
        # 2. Otherwise use centroid of saved spoke positions if most are saved.
        # 3. Fall back to algorithmic centre.
        cx, cy = algo_cx, algo_cy
        if saved_positions and hub_id and hub_id in saved_positions:
            cx, cy = saved_positions[hub_id]
        elif saved_positions:
            saved_spokes = [
                saved_positions[ip]
                for ip in ips
                if ip != hub_id and ip in saved_positions
            ]
            if len(saved_spokes) >= max(1, len(ips) // 2):
                cx = sum(p[0] for p in saved_spokes) / len(saved_spokes)
                cy = sum(p[1] for p in saved_spokes) / len(saved_spokes)

        sz = _node_sz(len(ips))
        non_hub = [ip for ip in ips if ip != hub_id]
        k = len(non_hub)
        r = _spoke_r(k, sz)

        if hub_id:
            node_positions[hub_id] = {"x": cx, "y": cy}

        for i, ip in enumerate(non_hub):
            if saved_positions and ip in saved_positions:
                sx, sy = saved_positions[ip]
                node_positions[ip] = {"x": sx, "y": sy}
            else:
                angle = (2 * math.pi * i) / max(k, 1)
                node_positions[ip] = {
                    "x": round(cx + r * math.cos(angle), 1),
                    "y": round(cy + r * math.sin(angle), 1),
                }

    # Position floating bridge nodes above the actual bounding boxes of the
    # subnets they bridge.  Using the real top-edge of the compound boxes
    # (not a fixed pixel offset) prevents overlap with the subnet groups.
    # Bridge nodes connecting the same subnet pair are spread horizontally.
    if multi_subnet_nodes and node_subnets:
        bridge_groups: dict[tuple, list] = {}
        # Extra clearance beyond the estimated box edge — accounts for
        # Cytoscape compound-node padding and label height.
        _CLEAR = 40
        for node_id in multi_subnet_nodes:
            subnets = node_subnets.get(node_id, set())
            valid = [s for s in subnets if s in subnet_center]
            if not valid:
                continue
            centers_v = [subnet_center[s] for s in valid]
            # Start at the centroid of the connected subnet centres — for
            # two adjacent subnets this already lands in the gap.
            cx = sum(c[0] for c in centers_v) / len(centers_v)
            cy = sum(c[1] for c in centers_v) / len(centers_v)
            # Iteratively push the position outside every subnet box it
            # overlaps.  Needed when 3+ subnets from different /16 bands
            # are bridged and the centroid falls inside the middle band.
            for _ in range(10):
                pushed = False
                for s in valid:
                    scx, scy = subnet_center[s]
                    h = subnet_box.get(s, 120.0) / 2 + _CLEAR
                    dx, dy = cx - scx, cy - scy
                    if abs(dx) < h and abs(dy) < h:
                        pushed = True
                        # Exit through whichever axis we're already further
                        # along — this picks the shortest escape route.
                        if abs(dx) >= abs(dy):
                            cx = scx + h * (math.copysign(1, dx) if dx else 1.0)
                        else:
                            cy = scy + h * (math.copysign(1, dy) if dy else 1.0)
                if not pushed:
                    break
            key = tuple(sorted(valid))
            bridge_groups.setdefault(key, []).append((node_id, cx, cy))

        _BRIDGE_SPREAD = 70  # px between co-located bridge nodes
        for node_list in bridge_groups.values():
            n = len(node_list)
            for i, (node_id, cx, cy) in enumerate(node_list):
                x_off = (i - (n - 1) / 2) * _BRIDGE_SPREAD
                node_positions[node_id] = {
                    "x": round(cx + x_off, 1),
                    "y": round(cy, 1),
                }

        # Push apart bridge nodes that ended up too close to each other
        # (happens when several switches share many of the same subnets).
        bridge_ids = [n for n in multi_subnet_nodes if n in node_positions]
        _MIN_SEP = 80
        for _ in range(30):
            moved = False
            for i in range(len(bridge_ids)):
                for j in range(i + 1, len(bridge_ids)):
                    a, b = bridge_ids[i], bridge_ids[j]
                    ax, ay = node_positions[a]["x"], node_positions[a]["y"]
                    bx, by = node_positions[b]["x"], node_positions[b]["y"]
                    dx, dy = bx - ax, by - ay
                    dist = math.sqrt(dx * dx + dy * dy) or 0.01
                    if dist < _MIN_SEP:
                        moved = True
                        push = (_MIN_SEP - dist) / 2 + 1
                        ux, uy = dx / dist, dy / dist
                        node_positions[a]["x"] = round(ax - ux * push, 1)
                        node_positions[a]["y"] = round(ay - uy * push, 1)
                        node_positions[b]["x"] = round(bx + ux * push, 1)
                        node_positions[b]["y"] = round(by + uy * push, 1)
            if not moved:
                break

    # Inject positions into leaf-node elements (not compound nodes, not edges)
    result: list[dict] = []
    for el in elements:
        data = el.get("data", {})
        node_id = data.get("id", "")
        if (
            node_id in node_positions
            and "source" not in data
            and data.get("node_type") != "subnet_group"
        ):
            el = {**el, "position": node_positions[node_id]}
        result.append(el)
    return result


def get_cytoscape_elements(
    G: nx.Graph,
    hidden_edge_ids: set[str] | None = None,
    custom_edges: list[dict] | None = None,
    subnet_labels: dict[str, str] | None = None,
    subnet_overrides: dict[str, str] | None = None,
    saved_positions: dict[str, tuple[float, float]] | None = None,
    subnet_paddings: dict[str, int] | None = None,
) -> list[dict]:
    """
    Produce Cytoscape elements with:
    - Compound subnet boxes grouping each /24
    - Hub-and-spoke topology within each subnet (real gateway or virtual switch as hub)
    - Inter-subnet edges connecting hubs of different subnets
    - Custom manually-added edges between host IPs
    - Respects hidden_edge_ids to suppress specific auto-generated edges
    """
    elements: list[dict] = []

    # 1. Map hosts to subnets — reuse cached result from build_graph() if present.
    #    The cache already covers secondary IPs (built_graph feeds all IPs in).
    ip_to_subnet: dict[str, str] = G.graph.get("ip_to_subnet") or _infer_subnets([
        ip
        for node_id, attrs in G.nodes(data=True)
        if attrs.get("node_type") == "host"
        for ip in [attrs.get("ip", node_id)] + attrs.get("additional_ips", [])
    ])

    # Build per-node subnet sets (primary + secondary IPs may span multiple subnets)
    node_subnets: dict[str, set[str]] = {}
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue
        subnets: set[str] = set()
        for ip in [attrs.get("ip", node_id)] + attrs.get("additional_ips", []):
            s = ip_to_subnet.get(ip)
            if s:
                subnets.add(s)
        node_subnets[node_id] = subnets or {"unknown"}

    # Only genuine network devices (routers, firewalls, L3 switches) float
    # outside compound groups when their IPs span multiple subnets.
    # Regular Windows/Linux hosts stay in their primary subnet even if they
    # have secondary IPs in other subnets (VPN, Docker, dual-NIC, etc.).
    multi_subnet_nodes: set[str] = {
        n for n, s in node_subnets.items()
        if len(s) > 1 and _is_genuine_bridge(G.nodes[n])
    }

    # host_subnets: non-floating nodes → primary-IP's subnet (compound parent)
    # subnet_ips:   subnet → node_ids that visually belong to that subnet
    #
    # Bridge nodes are deliberately NOT added to subnet_ips.  Adding them
    # caused two compounding problems:
    #   1. They became hubs of their own subnets, so the bridge-edge loop hit
    #      `hub_id == node_id` and skipped every edge → device showed no
    #      connections at all.
    #   2. Subnets that contained only the bridge node got compound boxes with
    #      the bridge device as their sole hub — then the bridge node was
    #      repositioned outside the box, leaving an empty compound.
    # Keeping bridge nodes out of subnet_ips means:
    #   • Subnets with other hosts get virtual-switch or gateway hubs.
    #   • Bridge edges always resolve to a hub that is NOT the bridge node.
    #   • Subnets whose only member is a bridge node produce no compound box.
    host_subnets: dict[str, str] = {}
    subnet_ips: dict[str, list[str]] = {}
    for node_id, subnets in node_subnets.items():
        if node_id in multi_subnet_nodes:
            pass  # floats freely; connected via bridge edges below
        else:
            # Regular host: place in the subnet of its primary IP only.
            # Secondary IPs are still stored in additional_ips and shown in
            # the detail panel, but don't affect visual subnet membership.
            primary_ip = G.nodes[node_id].get("ip", node_id)
            primary_subnet = (
                (subnet_overrides or {}).get(primary_ip)
                or ip_to_subnet.get(primary_ip)
                or next(iter(subnets), "unknown")
            )
            host_subnets[node_id] = primary_subnet
            lst = subnet_ips.setdefault(primary_subnet, [])
            if node_id not in lst:
                lst.append(node_id)

    # 2. Assign colors
    subnets_sorted = sorted(subnet_ips.keys())
    subnet_colors: dict[str, tuple[str, str]] = {
        subnet: _SUBNET_PALETTE[i % len(_SUBNET_PALETTE)]
        for i, subnet in enumerate(subnets_sorted)
    }

    # 3. Identify hub (real gateway/router > virtual switch)
    #    Respects manual_role override set by the user.
    subnet_hub: dict[str, str] = {}
    virtual_switches: list[str] = []

    def _effective_role(ip: str) -> str:
        """Return manual_role if set, else auto-detected role."""
        attrs = G.nodes[ip]
        return attrs.get("manual_role") or _node_role(attrs)

    for subnet, ips in subnet_ips.items():
        router = next(
            (ip for ip in ips if _effective_role(ip) == "router"), None
        )
        gateway = next(
            (ip for ip in ips if _effective_role(ip) == "gateway"), None
        )
        hub = router or gateway
        if hub:
            subnet_hub[subnet] = hub
        elif len(ips) > 1:
            subnet_hub[subnet] = f"vsw_{subnet}"
            virtual_switches.append(subnet)
        else:
            subnet_hub[subnet] = ips[0]

    # 4. Determine domain grouping: assign each subnet to the majority domain
    #    of its member hosts (>= 50% must share the same domain tag).
    _DOMAIN_PALETTE = [
        ("#050f1e", "#5DADE2"),   # blue
        ("#051408", "#2ECC71"),   # green
        ("#1a0d05", "#E67E22"),   # orange
        ("#100514", "#9B59B6"),   # purple
        ("#141405", "#F1C40F"),   # yellow
        ("#05141a", "#16A085"),   # teal
    ]
    subnet_domain: dict[str, str] = {}
    for subnet, ips in subnet_ips.items():
        votes: dict[str, int] = {}
        for ip in ips:
            for t in (G.nodes[ip].get("tags") or []):
                if t.lower().startswith("domain:"):
                    d = t[len("domain:"):].upper()
                    votes[d] = votes.get(d, 0) + 1
        if votes:
            best = max(votes, key=votes.get)  # type: ignore[arg-type]
            if votes[best] >= max(1, len(ips) * 0.5):
                subnet_domain[subnet] = best

    domain_subnets: dict[str, list[str]] = {}
    for subnet, domain in subnet_domain.items():
        domain_subnets.setdefault(domain, []).append(subnet)

    # Compute domain hierarchy depth so the layout can seed y-positions.
    # BRANCH.CORP.COM is a subdomain of CORP.COM → depth 1.
    # Top-level (or unrelated) domains get depth 0.
    all_domain_names = sorted(domain_subnets)

    def _domain_depth(name: str) -> int:
        """Return how many other known domains are strict parents of *name*."""
        return sum(
            1 for other in all_domain_names
            if other != name and name.endswith("." + other)
        )

    # Domain compound nodes must be added before subnet nodes (their children).
    # Include a `domain_depth` attribute so downstream JS / layout seeds can
    # place parent domains above their subdomains.
    for i, domain_name in enumerate(all_domain_names):
        bg, border = _DOMAIN_PALETTE[i % len(_DOMAIN_PALETTE)]
        elements.append({
            "data": {
                "id": f"domain_{domain_name}",
                "label": domain_name,
                "node_type": "domain_group",
                "bg_color": bg,
                "border_color": border,
                "domain_depth": _domain_depth(domain_name),
            },
            "classes": "domain-group",
        })

    # 4b. Subnet compound parent nodes (must precede children)
    for subnet in subnets_sorted:
        if not subnet_ips.get(subnet):
            continue
        bg, border = subnet_colors[subnet]
        display_label = (subnet_labels or {}).get(subnet) or subnet
        box_padding = (subnet_paddings or {}).get(subnet, 30)
        node_data: dict = {
            "id": f"sub_{subnet}",
            "label": display_label,
            "subnet_cidr": subnet,       # always the raw CIDR
            "node_type": "subnet_group",
            "bg_color": bg,
            "border_color": border,
            "host_count": sum(1 for n in subnet_ips[subnet] if n not in multi_subnet_nodes),
            "box_padding": box_padding,
        }
        if subnet in subnet_domain:
            node_data["parent"] = f"domain_{subnet_domain[subnet]}"
        elements.append({"data": node_data, "classes": "subnet-group"})

    # 5. Virtual switch nodes
    for subnet in virtual_switches:
        _, border = subnet_colors[subnet]
        elements.append({
            "data": {
                "id": f"vsw_{subnet}",
                "label": "SW",
                "node_type": "virtual_switch",
                "ip": f"vsw_{subnet}",
                "parent": f"sub_{subnet}",
                "border_color": border,
            },
            "classes": "virtual-switch",
        })

    # 6. Host nodes
    for node_id, attrs in G.nodes(data=True):
        if attrs.get("node_type") != "host":
            continue

        subnet = host_subnets.get(node_id, "unknown")
        role = _effective_role(node_id)   # respects manual_role override
        os_family = attrs.get("os_family", "Unknown")
        max_cvss = attrs.get("max_cvss", 0.0)

        classes = ["host"]
        if role == "router":
            classes.append("router")
        elif role == "gateway":
            classes.append("gateway")

        if os_family == "Windows":
            classes.append("os-windows")
        elif os_family == "Linux":
            classes.append("os-linux")
        elif os_family == "macOS":
            classes.append("os-macos")
        elif os_family == "Network":
            classes.append("os-network")
        else:
            classes.append("os-unknown")

        # Respect manual override: if is_dc is explicitly False don't re-detect
        is_dc_effective = attrs.get("is_dc")
        if is_dc_effective is None:
            is_dc_effective = _is_domain_controller(attrs)
        if is_dc_effective:
            classes.append("domain-controller")

        if attrs.get("is_legacy"):
            classes.append("legacy-os")

        for role in (attrs.get("host_roles") or []):
            if role in ("db", "web", "rdp"):
                classes.append(f"role-{role}")

        if max_cvss >= 9.0:
            classes.append("severity-critical")
        elif max_cvss >= 7.0:
            classes.append("severity-high")
        elif max_cvss >= 4.0:
            classes.append("severity-medium")

        # Reduce visual size in dense subnets so the layout math works out.
        # A hub-and-spoke ring needs radius ≥ (N × node_size) / (2π):
        #   N=32px nodes need 12+ hosts for the ring to fit at nestingFactor=0.6.
        #   Shrink to 20px / 12px to keep subnets readable at higher densities.
        subnet_size = len(subnet_ips.get(subnet, []))
        if subnet_size > 30:
            classes.append("very-dense-subnet")
        elif subnet_size > 14:
            classes.append("dense-subnet")

        hostnames = attrs.get("hostnames", [])
        label = hostnames[0] if hostnames else attrs.get("ip", node_id)

        # For floating bridge nodes, append all IPs so the user can see
        # which interfaces belong to this physical device.
        if node_id in multi_subnet_nodes:
            all_ips = [attrs.get("ip", node_id)] + attrs.get("additional_ips", [])
            label = f"{label}\n{' | '.join(all_ips)}"
            # Bridge-node class makes them visually larger so they're not dwarfed
            # by the compound subnet boxes they sit between.
            classes.append("bridge-node")

        element_data: dict = {**attrs, "id": node_id, "label": label}
        if node_id not in multi_subnet_nodes:
            element_data["parent"] = f"sub_{host_subnets.get(node_id, 'unknown')}"
        elements.append({"data": element_data, "classes": " ".join(classes)})

    # 7. Intra-subnet spoke edges: every host -> hub
    #    Multi-subnet nodes are excluded here; they get bridge edges instead.
    seen_intra: set[tuple] = set()
    for subnet, ips in subnet_ips.items():
        hub_id = subnet_hub.get(subnet)
        if not hub_id:
            continue
        for ip in ips:
            if ip == hub_id or ip in multi_subnet_nodes:
                continue
            key = tuple(sorted([ip, hub_id]))
            if key not in seen_intra:
                seen_intra.add(key)
                edge_id = f"intra_{ip}_{hub_id}"
                if hidden_edge_ids and edge_id in hidden_edge_ids:
                    continue
                edge_classes = "intra-subnet dense-intra" if len(ips) > 14 else "intra-subnet"
                elements.append({
                    "data": {
                        "id": edge_id,
                        "source": ip,
                        "target": hub_id,
                        "edge_type": "intra_subnet",
                    },
                    "classes": edge_classes,
                })

    # 7b. Bridge edges: multi-subnet nodes → hub of every subnet they touch.
    #     These replace the intra-subnet spokes and visually float the node
    #     between its subnet boxes.
    seen_bridge: set[tuple] = set()
    for node_id in multi_subnet_nodes:
        node_attrs = G.nodes[node_id]
        all_node_ips = [node_attrs.get("ip", node_id)] + node_attrs.get("additional_ips", [])
        for subnet in node_subnets[node_id]:
            hub_id = subnet_hub.get(subnet)
            if not hub_id or hub_id == node_id:
                continue
            key = tuple(sorted([node_id, hub_id]))
            if key in seen_bridge:
                continue
            seen_bridge.add(key)
            edge_id = f"bridge_{node_id}_{subnet.replace('/', '_')}"
            if hidden_edge_ids and edge_id in hidden_edge_ids:
                continue
            # Label with the specific IP on this interface so the user can see
            # which address connects to which subnet.
            bridge_ip = next(
                (ip for ip in all_node_ips if ip_to_subnet.get(ip) == subnet), ""
            )
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": node_id,
                    "target": hub_id,
                    "edge_type": "multi_ip_bridge",
                    "label": bridge_ip,
                },
                "classes": "multi-ip-link",
            })

    # 8. Inter-subnet edges: chain topology within each /16
    # Subnets are sorted by CIDR address and each connected to the next one —
    # O(n) edges instead of O(n²) full-mesh.  Combined with the /16-grouped
    # grid layout this keeps inter-subnet lines short and local to their band.
    # Skip pairs where *both* hubs are virtual switches — no evidence of routing.
    seen_inter: set[tuple] = set()
    by_16: dict[str, list[str]] = {}
    for subnet in subnet_ips:
        by_16.setdefault(_subnet_net16(subnet), []).append(subnet)

    for _n16, subnets_in_16 in by_16.items():
        # Sort by network address so the chain follows numerical IP order
        subnets_in_16.sort(
            key=lambda s: ipaddress.ip_network(s, strict=False).network_address
            if s != "unknown" else 0
        )
        for i in range(len(subnets_in_16) - 1):
            s1 = subnets_in_16[i]
            s2 = subnets_in_16[i + 1]
            h1 = subnet_hub.get(s1)
            h2 = subnet_hub.get(s2)
            if not h1 or not h2 or h1 == h2:
                continue
            if h1.startswith("vsw_") and h2.startswith("vsw_"):
                continue
            key = tuple(sorted([h1, h2]))
            if key not in seen_inter:
                seen_inter.add(key)
                id_src, id_dst = sorted([h1, h2])
                edge_id = f"inter_{id_src}_{id_dst}"
                if hidden_edge_ids and edge_id in hidden_edge_ids:
                    continue
                elements.append({
                    "data": {
                        "id": edge_id,
                        "source": h1,
                        "target": h2,
                        "edge_type": "inter_subnet",
                    },
                    "classes": "inter-subnet",
                })

    # 9. Pre-compute non-overlapping grid positions for every leaf node.
    #    Doing this here means the *preset* layout (and cose-bilkent with
    #    randomize:false) will start from a guaranteed non-overlapping state.
    # Build domain_depth map for position seeding (parent domains placed higher)
    _all_domain_names = list(domain_subnets.keys())
    _domain_depth_map = {
        d: sum(1 for other in _all_domain_names if other != d and d.endswith("." + other))
        for d in _all_domain_names
    }

    elements = _compute_preset_positions(
        elements, subnet_ips, subnet_hub, multi_subnet_nodes, node_subnets,
        saved_positions=saved_positions,
        subnet_domain=subnet_domain,
        domain_depth=_domain_depth_map,
    )

    # 10. Custom manually-added edges between host IPs
    if custom_edges:
        host_ips: set[str] = set()
        for node_id, attrs in G.nodes(data=True):
            if attrs.get("node_type") == "host":
                host_ips.add(attrs.get("ip", node_id))
                host_ips.update(attrs.get("additional_ips", []))
        for ce in custom_edges:
            src = ce.get("source", "")
            tgt = ce.get("target", "")
            if not src or not tgt or src == tgt:
                continue
            if src not in host_ips or tgt not in host_ips:
                continue
            edge_id = f"custom_{src}_{tgt}"
            if hidden_edge_ids and edge_id in hidden_edge_ids:
                continue
            elements.append({
                "data": {
                    "id": edge_id,
                    "source": src,
                    "target": tgt,
                    "edge_type": "custom",
                    "label": ce.get("label", ""),
                },
                "classes": "custom-edge",
            })

    return elements
