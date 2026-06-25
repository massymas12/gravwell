"""Generate draw.io (.drawio) XML from the current network map.

Produces a diagram file that opens directly in diagrams.net (free) or the
draw.io desktop app.  From there customers can re-export to Visio, PDF, SVG,
or PNG and freely edit labels / layout.

File format:
  <mxfile> envelope wrapping an <mxGraphModel> with <mxCell> elements.
  Subnet groups use swimlane containers.  Host nodes are HTML-labelled
  rectangles (or rhombuses for network devices).  Physical / LLDP links and
  custom edges are included as annotated connectors.
"""
from __future__ import annotations

import ipaddress
import math
import xml.etree.ElementTree as ET

# ── Layout constants (all in draw.io pixels) ─────────────────────────────────
_NODE_W     = 140   # host node width
_NODE_H     = 65    # host node height
_GW_SIZE    = 64    # network-device icon (square)
_SWIM_TITLE = 30    # swimlane header bar height
_PAD        = 28    # padding inside container around child nodes
_CANVAS_PAD = 80    # canvas border offset
_GRID_W     = _NODE_W + 24   # column stride within a container
_GRID_H     = _NODE_H + 40   # row stride — extra height for gateway labels below icon
_GRID_COLS  = 6              # max columns per subnet container
_GAP_X      = 40             # horizontal gap between containers
_GAP_Y      = 60             # vertical gap between rows of containers
_BRIDGE_GAP = 80             # clearance above first container row for bridge nodes

# Ports that mark appliance-class devices — Network OS but NOT a routing hub
_APPLIANCE_PORTS = frozenset({515, 9100, 9101, 9102, 5060, 5061, 1720})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sid(s: str) -> str:
    """Return a string safe for use as an XML / draw.io cell id."""
    return (s.replace("/", "_").replace(".", "_")
             .replace(":", "_").replace(" ", "_").replace("-", "_"))


def _hesc(s: str) -> str:
    """Escape a plain-text string for safe embedding inside an HTML label."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def _os_fill(os_family: str | None) -> tuple[str, str]:
    """Return (fillColor, strokeColor) keyed on OS family — dark theme."""
    f = (os_family or "").lower()
    if "windows" in f: return "#1a3050", "#4a9eda"   # dark navy / bright blue
    if "linux"   in f: return "#1a3520", "#5cb85c"   # dark green / lime
    if "mac"     in f: return "#1a2e25", "#00c853"   # dark teal  / bright green
    if "network" in f: return "#2e2200", "#ffc107"   # dark amber / yellow
    return "#1a1a2e", "#5a6a8a"                       # dark navy  / grey-blue


def _node_style(os_family: str | None, max_cvss: float, is_gw: bool) -> str:
    fill, stroke = _os_fill(os_family)
    if max_cvss >= 9.0:
        stroke, sw = "#CC0000", "strokeWidth=3;"
    elif max_cvss >= 7.0:
        stroke, sw = "#E65100", "strokeWidth=2;"
    elif max_cvss >= 4.0:
        stroke, sw = "#B8860B", "strokeWidth=2;"
    else:
        sw = ""
    if is_gw:
        # Cisco router icon with label rendered below the shape
        return (
            f"shape=mxgraph.cisco.routers.router;sketch=0;html=1;dashed=0;"
            f"fillColor={fill};strokeColor={stroke};fontColor=#ffffff;"
            f"fontSize=10;fontStyle=1;align=center;"
            f"verticalLabelPosition=bottom;verticalAlign=top;{sw}"
        )
    return (
        f"rounded=1;whiteSpace=wrap;html=1;fontSize=10;align=center;"
        f"fillColor={fill};strokeColor={stroke};fontColor=#ffffff;{sw}"
    )


def _node_label(h, services: list, max_cvss: float, vuln_count: int) -> str:
    """Build a compact HTML label for a host node."""
    ip = h.ip
    hostnames = h.hostnames or []
    os_name   = h.os_name or ""

    parts: list[str] = []
    primary = hostnames[0] if hostnames else ip
    if primary != ip:
        parts.append(f"<b>{_hesc(primary)}</b>")
        parts.append(_hesc(ip))
    else:
        parts.append(f"<b>{_hesc(ip)}</b>")

    if os_name:
        parts.append(f"<font color='#aaaacc'><i>{_hesc(os_name)}</i></font>")

    open_ports = sorted(
        {s.port for s in services if s.state == "open" and s.port}
    )[:6]
    if open_ports:
        parts.append(f"<font color='#8899bb'>{', '.join(str(p) for p in open_ports)}</font>")

    if max_cvss >= 9.0:
        parts.append(f"<font color='#ff4444'><b>&#9888; Critical ({vuln_count})</b></font>")
    elif max_cvss >= 7.0:
        parts.append(f"<font color='#ff8c42'>&#9888; High ({vuln_count})</font>")
    elif max_cvss >= 4.0 and vuln_count:
        parts.append(f"<font color='#f0c040'>{vuln_count} medium vulns</font>")

    return "<br>".join(parts)


def _legend_xml(root: ET.Element, x: float, y: float) -> None:
    """Append a colour/severity legend box to the XML root."""
    items = [
        ("Windows",         "#1a3050", "#4a9eda"),
        ("Linux",           "#1a3520", "#5cb85c"),
        ("macOS",           "#1a2e25", "#00c853"),
        ("Network Device",  "#2e2200", "#ffc107"),
        ("Unknown OS",      "#1a1a2e", "#5a6a8a"),
    ]
    sev = [
        ("Critical vuln (CVSS ≥9)",   "#CC0000", "3"),
        ("High vuln    (CVSS ≥7)",    "#E65100", "2"),
        ("Medium vuln  (CVSS ≥4)",    "#B8860B", "2"),
    ]
    connectors = [
        ("LLDP / physical link",  "#2E7D32"),
        ("Bridge connection",     "#1ABC9C"),
        ("Inter-VLAN (SNMP FDB)", "#9B59B6"),
        ("Custom / manual edge",  "#0050EF"),
    ]

    # Legend container — dark theme
    lw, lh = 210, 30 + len(items) * 22 + 10 + len(sev) * 22 + 10 + len(connectors) * 22 + 10
    box = ET.SubElement(root, "mxCell", {
        "id": "legend_box",
        "value": "<b>Legend</b>",
        "style": (
            "swimlane;startSize=24;fillColor=#0d1b2e;strokeColor=#334466;"
            "fontColor=#7eb8e8;fontStyle=1;fontSize=11;align=center;"
        ),
        "vertex": "1", "parent": "1",
    })
    ET.SubElement(box, "mxGeometry", {
        "x": str(round(x)), "y": str(round(y)),
        "width": str(lw), "height": str(lh), "as": "geometry",
    })

    row_y = 30
    for label, fill, stroke in items:
        c = ET.SubElement(root, "mxCell", {
            "id": f"leg_{_sid(label)}",
            "value": label,
            "style": (
                f"rounded=1;whiteSpace=wrap;html=1;fontSize=10;align=left;"
                f"fillColor={fill};strokeColor={stroke};fontColor=#ffffff;spacingLeft=6;"
            ),
            "vertex": "1", "parent": "legend_box",
        })
        ET.SubElement(c, "mxGeometry", {
            "x": "10", "y": str(row_y),
            "width": str(lw - 20), "height": "18", "as": "geometry",
        })
        row_y += 22

    row_y += 6
    for label, stroke, sw in sev:
        c = ET.SubElement(root, "mxCell", {
            "id": f"leg_sev_{_sid(label)}",
            "value": label,
            "style": (
                f"rounded=1;whiteSpace=wrap;html=1;fontSize=10;align=left;"
                f"fillColor=#1a1a2e;strokeColor={stroke};strokeWidth={sw};"
                f"fontColor=#ffffff;spacingLeft=6;"
            ),
            "vertex": "1", "parent": "legend_box",
        })
        ET.SubElement(c, "mxGeometry", {
            "x": "10", "y": str(row_y),
            "width": str(lw - 20), "height": "18", "as": "geometry",
        })
        row_y += 22

    row_y += 6
    for label, colour in connectors:
        c = ET.SubElement(root, "mxCell", {
            "id": f"leg_conn_{_sid(label)}",
            "value": label,
            "style": (
                f"endArrow=block;endFill=1;html=1;fontSize=10;align=left;"
                f"strokeColor={colour};fontColor=#ffffff;spacingLeft=6;"
            ),
            "edge": "1", "parent": "legend_box",
            "source": "", "target": "",
        })
        geo = ET.SubElement(c, "mxGeometry", {
            "x": "10", "y": str(row_y),
            "width": str(lw - 20), "height": "18",
            "relative": "1", "as": "geometry",
        })
        ET.SubElement(geo, "Array", {"as": "points"})
        row_y += 22


# ── Main export ───────────────────────────────────────────────────────────────

def export_drawio(db_path: str) -> str:
    """Return draw.io XML (as a UTF-8 string) for the current project."""
    from gravwell.database import get_session
    from gravwell.models.orm import (
        HostORM, ServiceORM, VulnerabilityORM, NodePositionORM,
        CustomEdgeORM, PhysicalLinkORM, SubnetLabelORM,
    )

    with get_session(db_path) as session:
        from gravwell.models.orm import HostRoleOverrideORM, HostVlanORM
        import json as _json

        hosts = {h.ip: h for h in session.query(HostORM).all()}

        svcs_by_host: dict[int, list] = {}
        for s in session.query(ServiceORM).all():
            svcs_by_host.setdefault(s.host_id, []).append(s)

        vulns_by_host: dict[int, list] = {}
        for v in session.query(VulnerabilityORM).all():
            vulns_by_host.setdefault(v.host_id, []).append(v)

        # Include virtual-switch positions for hub-centre estimation,
        # but exclude them from the host-node loop below.
        saved_pos: dict[str, tuple[float, float]] = {
            r.node_ip: (r.x, r.y)
            for r in session.query(NodePositionORM).all()
        }

        custom_edges = list(session.query(CustomEdgeORM).all())
        phys_links   = list(session.query(PhysicalLinkORM).all())
        subnet_labels: dict[str, str] = {
            r.subnet_cidr: r.label or ""
            for r in session.query(SubnetLabelORM).all()
        }

        role_overrides: dict[str, list[str]] = {}
        for r in session.query(HostRoleOverrideORM).all():
            try:
                role_overrides[r.host_ip] = _json.loads(r.roles_json or "[]")
            except Exception:
                pass

        host_vlans = list(session.query(HostVlanORM).all())

    # ── Subnet assignment ──────────────────────────────────────────────────
    ip_to_subnet: dict[str, str] = {}
    subnet_ips: dict[str, list[str]] = {}
    for ip, h in hosts.items():
        if h.subnet_override:
            net = h.subnet_override
        else:
            try:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                net = "unassigned"
        ip_to_subnet[ip] = net
        subnet_ips.setdefault(net, []).append(ip)

    # ── Bridge detection ──────────────────────────────────────────────────
    # A genuine bridge is a Network-OS (or router-role-overridden) host with
    # additional_ips that land in at least one *other* subnet.  These nodes
    # float outside every container in Cytoscape; replicate that here.

    def _is_genuine_bridge(h) -> bool:
        if not h.additional_ips:
            return False
        of = (h.os_family or "").strip()
        if of == "Network":
            svc_ports = {s.port for s in svcs_by_host.get(h.id, []) if s.state == "open"}
            return not (svc_ports & _APPLIANCE_PORTS)
        return "router" in role_overrides.get(h.ip, [])

    # bridge_ip → frozenset of subnet CIDRs the bridge straddles
    bridge_subnets: dict[str, frozenset[str]] = {}
    for ip, h in hosts.items():
        if not _is_genuine_bridge(h):
            continue
        touched: set[str] = set()
        for aip in [ip] + h.additional_ips:
            try:
                net = str(ipaddress.ip_network(f"{aip}/24", strict=False))
            except ValueError:
                continue
            if net in subnet_ips:
                touched.add(net)
        if len(touched) >= 2:
            bridge_subnets[ip] = frozenset(touched)

    # Remove bridge nodes from subnet containers so they don't get gridded inside
    for bip, nets in bridge_subnets.items():
        primary = ip_to_subnet.get(bip)
        if primary and primary in subnet_ips:
            try:
                subnet_ips[primary].remove(bip)
            except ValueError:
                pass
            if not subnet_ips[primary]:
                del subnet_ips[primary]

    # ── Topology-preserving layout ────────────────────────────────────────
    # Goal: subnet containers appear in the same relative positions as in
    # Gravwell, with individual nodes in clean grids (not radial patterns).
    #
    # Method:
    #  1. Each subnet's container is CENTRED on its vsw/hub Cytoscape position.
    #  2. A single global scale is derived from the 10th-percentile pair
    #     distance, so the closest subnets have room for their containers
    #     without blowing up the canvas for everyone else.
    #  3. Nodes inside each container are laid out in a ceil(√n) grid.

    host_saved = {ip: saved_pos[ip] for ip in hosts if ip in saved_pos}

    def _grid_dims(n: int) -> tuple[int, int]:
        cols = max(1, min(_GRID_COLS, math.ceil(math.sqrt(n))))
        return cols, math.ceil(n / cols)

    def _container_wh(n: int) -> tuple[float, float]:
        cols, rows = _grid_dims(n)
        return (cols * _GRID_W + 2 * _PAD,
                rows * _GRID_H + 2 * _PAD + _SWIM_TITLE)

    def _subnet_cyto_center(net: str) -> tuple[float, float]:
        vsw_key = f"vsw_{net}"
        if vsw_key in saved_pos:
            return saved_pos[vsw_key]
        pts = [host_saved[ip] for ip in subnet_ips[net] if ip in host_saved]
        if pts:
            return (sum(p[0] for p in pts) / len(pts),
                    sum(p[1] for p in pts) / len(pts))
        return 0.0, 0.0

    cyto_centers    = {net: _subnet_cyto_center(net)         for net in subnet_ips}
    container_sizes = {net: _container_wh(len(subnet_ips[net])) for net in subnet_ips}

    # ── Compute a single scale from the 10th-percentile inter-center dist ─
    nets = list(subnet_ips.keys())
    pair_dists: list[float] = []
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            cx1, cy1 = cyto_centers[nets[i]]
            cx2, cy2 = cyto_centers[nets[j]]
            d = math.hypot(cx2 - cx1, cy2 - cy1)
            if d > 0:
                pair_dists.append(d)

    if pair_dists:
        pair_dists.sort()
        # 10th-percentile — outlier-close pairs don't blow up the scale
        ref_dist = pair_dists[max(0, len(pair_dists) // 10)]
        max_cw   = max(cw for cw, _ in container_sizes.values())
        max_ch   = max(ch for _, ch in container_sizes.values())
        target   = math.hypot(max_cw, max_ch) / 2 + _GAP_X
        _SCALE   = max(1.0, min(4.5, target / ref_dist))
    else:
        _SCALE = 2.0

    # ── Translate origin so top-left container starts at _CANVAS_PAD ─────
    all_cx = [cyto_centers[net][0] for net in nets]
    all_cy = [cyto_centers[net][1] for net in nets]
    orig_x = min(all_cx) if all_cx else 0.0
    orig_y = min(all_cy) if all_cy else 0.0

    def _to_canvas(cx: float, cy: float) -> tuple[float, float]:
        return (
            round((cx - orig_x) * _SCALE + _CANVAS_PAD),
            round((cy - orig_y) * _SCALE + _CANVAS_PAD),
        )

    # ── Place containers centred on scaled vsw positions ──────────────────
    containers: dict[str, tuple[float, float, float, float]] = {}
    abs_pos:    dict[str, tuple[float, float]]               = {}

    for net in nets:
        ccx, ccy = _to_canvas(*cyto_centers[net])
        cw, ch   = container_sizes[net]
        bx = ccx - cw / 2
        by = ccy - ch / 2
        containers[net] = (bx, by, cw, ch)

        cols, _ = _grid_dims(len(subnet_ips[net]))
        for k, ip in enumerate(sorted(subnet_ips[net])):
            abs_pos[ip] = (
                bx + _PAD + (k % cols) * _GRID_W,
                by + _SWIM_TITLE + _PAD + (k // cols) * _GRID_H,
            )

    # ── Bridge nodes: float above centroid of connected subnets ───────────
    if bridge_subnets and containers:
        top_y = min(y for x, y, w, h in containers.values())
        bridge_y = top_y - _GW_SIZE - _BRIDGE_GAP

        def _bridge_cx(bip: str) -> float:
            xs = [containers[n][0] + containers[n][2] / 2
                  for n in bridge_subnets[bip] if n in containers]
            return sum(xs) / len(xs) if xs else float(_CANVAS_PAD)

        sorted_bridges = sorted(bridge_subnets, key=_bridge_cx)
        prev_right = float(_CANVAS_PAD) - _GW_SIZE - 20
        for bip in sorted_bridges:
            bx = max(_bridge_cx(bip) - _GW_SIZE / 2, prev_right + 20)
            abs_pos[bip] = (bx, bridge_y)
            prev_right = bx + _GW_SIZE

    # ── Build XML ──────────────────────────────────────────────────────────
    model = ET.Element("mxGraphModel", {
        "dx": "1422", "dy": "762",
        "grid": "1", "gridSize": "10",
        "guides": "1", "tooltips": "1",
        "connect": "1", "arrows": "1",
        "fold": "1", "page": "1",
        "pageScale": "1", "pageWidth": "1654", "pageHeight": "1169",
        "math": "0", "shadow": "0",
    })
    xml_root = ET.SubElement(model, "root")
    ET.SubElement(xml_root, "mxCell", {"id": "0"})
    ET.SubElement(xml_root, "mxCell", {"id": "1", "parent": "0"})

    _edge_n = [0]

    def _cell(id_: str, value: str, style: str, parent: str,
               x: float, y: float, w: float, h: float) -> None:
        c = ET.SubElement(xml_root, "mxCell", {
            "id": id_, "value": value, "style": style,
            "vertex": "1", "parent": parent,
        })
        ET.SubElement(c, "mxGeometry", {
            "x": str(round(x)), "y": str(round(y)),
            "width": str(round(w)), "height": str(round(h)),
            "as": "geometry",
        })

    def _edge(src: str, tgt: str, label: str = "", style: str = "") -> None:
        _edge_n[0] += 1
        c = ET.SubElement(xml_root, "mxCell", {
            "id": f"e{_edge_n[0]}", "value": label,
            "style": style or "edgeStyle=orthogonalEdgeStyle;",
            "edge": "1", "source": src, "target": tgt, "parent": "1",
        })
        ET.SubElement(c, "mxGeometry", {"relative": "1", "as": "geometry"})

    # Subnet swimlane containers — dark theme to match Cytoscape UI
    swim_style = (
        "swimlane;startSize=30;fillColor=#0d1b2e;strokeColor=#334466;"
        "fontStyle=1;fontSize=11;fontColor=#7eb8e8;align=center;"
        "whiteSpace=wrap;html=1;swimlaneLine=1;"
        "swimlaneHead=0;swimlaneLine=1;"
    )
    for net, (cx, cy, cw, ch) in sorted(containers.items()):
        title = f"<b>{_hesc(subnet_labels[net])}</b><br>{net}" if subnet_labels.get(net) else net
        _cell(f"sub_{_sid(net)}", title, swim_style, "1", cx, cy, cw, ch)

    # Host nodes
    for ip, h in sorted(hosts.items()):
        if ip not in abs_pos:
            continue
        svcs      = svcs_by_host.get(h.id, [])
        vs        = vulns_by_host.get(h.id, [])
        max_cvss  = max((v.cvss_score or 0.0 for v in vs), default=0.0)
        vcount    = len(vs)
        is_gw     = bool(h.os_family and "network" in h.os_family.lower())
        style     = _node_style(h.os_family, max_cvss, is_gw)
        if is_gw:
            # Short label rendered below the router icon
            primary = h.hostnames[0] if h.hostnames else h.ip
            gw_parts = [f"<b>{_hesc(primary)}</b>"]
            if primary != h.ip:
                gw_parts.append(_hesc(h.ip))
            if max_cvss >= 7.0:
                gw_parts.append(f"<font color='#ff4444'>&#9888; {vcount}</font>")
            label = "<br>".join(gw_parts)
        else:
            label = _node_label(h, svcs, max_cvss, vcount)
        hid       = f"h_{_sid(ip)}"
        ax, ay    = abs_pos[ip]
        net       = ip_to_subnet.get(ip, "unassigned")
        node_w    = _GW_SIZE if is_gw else _NODE_W
        node_h    = _GW_SIZE if is_gw else _NODE_H

        if ip in bridge_subnets:
            # Bridge node floats at root level — not inside any subnet container
            _cell(hid, label, style, "1", ax, ay, node_w, node_h)
        elif net in containers:
            cx, cy, _, _ = containers[net]
            _cell(
                hid, label, style, f"sub_{_sid(net)}",
                ax - cx,
                ay - (cy + _SWIM_TITLE),
                node_w, node_h,
            )
        else:
            _cell(hid, label, style, "1", ax, ay, node_w, node_h)

    # Physical / LLDP edges (green, solid)
    seen: set[frozenset] = set()
    for lnk in phys_links:
        if lnk.host_ip not in hosts or lnk.peer_ip not in hosts:
            continue
        key = frozenset([lnk.host_ip, lnk.peer_ip])
        if key in seen:
            continue
        seen.add(key)
        _edge(
            f"h_{_sid(lnk.host_ip)}", f"h_{_sid(lnk.peer_ip)}",
            _hesc(lnk.port_id or ""),
            "edgeStyle=orthogonalEdgeStyle;strokeColor=#2E7D32;"
            "strokeWidth=2;fontColor=#2E7D32;fontSize=9;",
        )

    # Custom edges (blue, dashed)
    for ce in custom_edges:
        if ce.source_ip not in hosts or ce.target_ip not in hosts:
            continue
        key = frozenset([ce.source_ip, ce.target_ip])
        if key in seen:
            continue
        seen.add(key)
        _edge(
            f"h_{_sid(ce.source_ip)}", f"h_{_sid(ce.target_ip)}",
            _hesc(ce.label or ""),
            "edgeStyle=orthogonalEdgeStyle;dashed=1;strokeColor=#0050EF;"
            "strokeWidth=2;fontColor=#0050EF;fontSize=9;",
        )

    # Inter-VLAN edges — drawn only when switch FDB data exists (HostVlanORM).
    # For each (switch, VLAN) that spans multiple subnets, draw one edge between
    # each pair of involved subnet containers/hubs, labelled "VLAN N".
    # This is real discovery data, not a routing-table guess.
    if host_vlans:
        # switch+vlan → set of host IPs seen on that VLAN
        vlan_hosts: dict[tuple, set[str]] = {}
        for hv in host_vlans:
            if hv.host_ip and hv.host_ip in hosts:
                vlan_hosts.setdefault((hv.switch_ip, hv.vlan_id), set()).add(hv.host_ip)

        vlan_seen: set[frozenset] = set()
        for (switch_ip, vlan_id), member_ips in vlan_hosts.items():
            # Collect the distinct subnets covered by this VLAN
            nets_in_vlan = {ip_to_subnet[ip] for ip in member_ips if ip in ip_to_subnet}
            nets_in_vlan = [n for n in nets_in_vlan if n in containers]
            if len(nets_in_vlan) < 2:
                continue
            # For VLANs spanning many subnets, fan out from the switch if it's a
            # known host; otherwise draw pairwise edges between subnet containers.
            switch_cell = f"h_{_sid(switch_ip)}" if switch_ip in hosts else None
            vlan_label = _hesc(f"VLAN {vlan_id}")
            vlan_style = (
                "edgeStyle=orthogonalEdgeStyle;strokeColor=#9B59B6;"
                "strokeWidth=2;dashed=1;fontColor=#9B59B6;fontSize=9;"
            )
            for net in sorted(nets_in_vlan):
                target = f"sub_{_sid(net)}"
                if switch_cell:
                    key = frozenset([switch_cell, target, str(vlan_id)])
                    if key not in vlan_seen:
                        vlan_seen.add(key)
                        _edge(switch_cell, target, vlan_label, vlan_style)
                else:
                    # No switch node — connect the first subnet to this one
                    first = f"sub_{_sid(sorted(nets_in_vlan)[0])}"
                    if first == target:
                        continue
                    key = frozenset([first, target, str(vlan_id)])
                    if key not in vlan_seen:
                        vlan_seen.add(key)
                        _edge(first, target, vlan_label, vlan_style)

    # Bridge edges — teal solid lines from bridge node to each subnet it straddles
    bridge_style = (
        "edgeStyle=orthogonalEdgeStyle;strokeColor=#1ABC9C;"
        "strokeWidth=2;fontColor=#1ABC9C;fontSize=9;"
    )
    for bip, nets in bridge_subnets.items():
        if bip not in abs_pos:
            continue
        src = f"h_{_sid(bip)}"
        for net in sorted(nets):
            if net in containers:
                _edge(src, f"sub_{_sid(net)}", "", bridge_style)

    # Legend (right of all containers, aligned with top row)
    if containers:
        leg_x = max(x + w for x, y, w, h in containers.values()) + 40
        leg_y = min(y for x, y, w, h in containers.values())
    else:
        leg_x, leg_y = _CANVAS_PAD, _CANVAS_PAD
    _legend_xml(xml_root, leg_x, leg_y)

    # ── Serialize ──────────────────────────────────────────────────────────
    xml_str = ET.tostring(model, encoding="unicode")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="gravwell" type="device" version="21.0.0">\n'
        '  <diagram name="Network Map">\n'
        f'    {xml_str}\n'
        '  </diagram>\n'
        '</mxfile>\n'
    )
