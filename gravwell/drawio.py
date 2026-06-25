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

    # Legend container — dark theme
    lw, lh = 210, 30 + len(items) * 22 + 10 + len(sev) * 22 + 10
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


# ── Main export ───────────────────────────────────────────────────────────────

def export_drawio(db_path: str) -> str:
    """Return draw.io XML (as a UTF-8 string) for the current project."""
    from gravwell.database import get_session
    from gravwell.models.orm import (
        HostORM, ServiceORM, VulnerabilityORM, NodePositionORM,
        CustomEdgeORM, PhysicalLinkORM, SubnetLabelORM,
    )

    with get_session(db_path) as session:
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

    # ── Two-level grid layout ─────────────────────────────────────────────
    # Level 1: subnets are sorted by their Cytoscape centre (Y then X) so the
    #          relative topology is preserved, then arranged in draw.io rows.
    # Level 2: nodes within each subnet are placed in a clean grid — Cytoscape
    #          positions are NOT used for individual nodes (they would overlap
    #          because Cytoscape nodes are 32 px circles, draw.io nodes are
    #          140 px wide rectangles).

    def _grid_dims(n: int) -> tuple[int, int]:
        cols = max(1, min(_GRID_COLS, math.ceil(math.sqrt(n))))
        return cols, math.ceil(n / cols)

    def _container_wh(n: int) -> tuple[float, float]:
        cols, rows = _grid_dims(n)
        return (
            cols * _GRID_W + 2 * _PAD,
            rows * _GRID_H + 2 * _PAD + _SWIM_TITLE,
        )

    def _subnet_cyto_center(net: str) -> tuple[float, float]:
        vsw_key = f"vsw_{net}"
        if vsw_key in saved_pos:
            return saved_pos[vsw_key]
        pts = [saved_pos[ip] for ip in subnet_ips[net] if ip in saved_pos]
        if pts:
            return (
                sum(p[0] for p in pts) / len(pts),
                sum(p[1] for p in pts) / len(pts),
            )
        return 0.0, 0.0

    cyto_centers = {net: _subnet_cyto_center(net) for net in subnet_ips}

    # Band subnets by Cytoscape Y so rows roughly match the Cytoscape layout
    cy_vals  = [v[1] for v in cyto_centers.values()]
    cy_min   = min(cy_vals) if cy_vals else 0.0
    cy_range = max(1.0, (max(cy_vals) if cy_vals else 1.0) - cy_min)
    n_bands  = max(1, round(math.sqrt(len(subnet_ips))))
    band_h   = cy_range / n_bands

    def _sort_key(net: str) -> tuple[int, float]:
        scx, scy = cyto_centers[net]
        band = int((scy - cy_min) / band_h) if cy_range > 0 else 0
        return band, scx

    sorted_nets = sorted(subnet_ips.keys(), key=_sort_key)

    rows_of_nets: list[list[str]] = []
    prev_band: int | None = None
    for net in sorted_nets:
        _, scy = cyto_centers[net]
        band = int((scy - cy_min) / band_h) if cy_range > 0 else 0
        if band != prev_band:
            rows_of_nets.append([])
            prev_band = band
        rows_of_nets[-1].append(net)

    if not rows_of_nets:
        rows_of_nets = [sorted_nets]

    # Place containers in rows; grid-lay nodes within each container
    containers: dict[str, tuple[float, float, float, float]] = {}
    abs_pos:    dict[str, tuple[float, float]]               = {}

    cur_y = float(_CANVAS_PAD)
    for row_nets in rows_of_nets:
        cur_x = float(_CANVAS_PAD)
        row_h = 0.0
        for net in row_nets:
            ips_sorted = sorted(subnet_ips[net])
            cw, ch = _container_wh(len(ips_sorted))
            containers[net] = (cur_x, cur_y, cw, ch)

            cols, _ = _grid_dims(len(ips_sorted))
            for j, ip in enumerate(ips_sorted):
                col   = j % cols
                row_j = j // cols
                abs_pos[ip] = (
                    cur_x + _PAD + col * _GRID_W,
                    cur_y + _SWIM_TITLE + _PAD + row_j * _GRID_H,
                )

            cur_x += cw + _GAP_X
            row_h  = max(row_h, ch)
        cur_y += row_h + _GAP_Y

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

        if net in containers:
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
