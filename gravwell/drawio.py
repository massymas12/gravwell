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
_NODE_W      = 140   # host node width
_NODE_H      = 65    # host node height
_GW_SIZE     = 80    # network-device rhombus (square bounding box)
_SWIM_TITLE  = 30    # swimlane header bar height
_PAD         = 28    # padding inside container around child nodes
_CANVAS_PAD  = 80    # canvas border offset
_GRID_W      = _NODE_W + 24   # auto-grid column stride
_GRID_H      = _NODE_H + 20   # auto-grid row stride
_GRID_COLS   = 4              # columns when auto-placing un-positioned nodes

# Cytoscape host nodes are 32×32 px circles.  The cose-bilkent layout spaces
# them ~45 px apart centre-to-centre.  draw.io nodes are 140 px wide, so we
# need to scale saved Cytoscape coordinates up so nodes don't overlap.
# 140 / 32 ≈ 4.4 — use 4.5 to leave a comfortable gap between nodes.
_POSITION_SCALE = 4.5


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
    """Return (fillColor, strokeColor) keyed on OS family."""
    f = (os_family or "").lower()
    if "windows" in f: return "#dae8fc", "#6c8ebf"
    if "linux"   in f: return "#d5e8d4", "#82b366"
    if "mac"     in f: return "#d5e8d4", "#009966"
    if "network" in f: return "#fff2cc", "#d6b656"
    return "#f5f5f5", "#666666"


def _node_style(os_family: str | None, max_cvss: float, is_gw: bool) -> str:
    fill, stroke = _os_fill(os_family)
    shape = "rhombus;" if is_gw else "rounded=1;"
    if max_cvss >= 9.0:
        stroke, sw = "#CC0000", "strokeWidth=3;"
    elif max_cvss >= 7.0:
        stroke, sw = "#E65100", "strokeWidth=2;"
    elif max_cvss >= 4.0:
        stroke, sw = "#B8860B", "strokeWidth=2;"
    else:
        sw = ""
    return (
        f"{shape}whiteSpace=wrap;html=1;fontSize=10;align=center;"
        f"fillColor={fill};strokeColor={stroke};{sw}"
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
        parts.append(f"<font color='#888888'><i>{_hesc(os_name)}</i></font>")

    open_ports = sorted(
        {s.port for s in services if s.state == "open" and s.port}
    )[:6]
    if open_ports:
        parts.append(f"<font color='#555555'>{', '.join(str(p) for p in open_ports)}</font>")

    if max_cvss >= 9.0:
        parts.append(f"<font color='#CC0000'><b>&#9888; Critical ({vuln_count})</b></font>")
    elif max_cvss >= 7.0:
        parts.append(f"<font color='#E65100'>&#9888; High ({vuln_count})</font>")
    elif max_cvss >= 4.0 and vuln_count:
        parts.append(f"<font color='#B8860B'>{vuln_count} medium vulns</font>")

    return "<br>".join(parts)


def _legend_xml(root: ET.Element, x: float, y: float) -> None:
    """Append a colour/severity legend box to the XML root."""
    items = [
        ("Windows",         "#dae8fc", "#6c8ebf"),
        ("Linux",           "#d5e8d4", "#82b366"),
        ("macOS",           "#d5e8d4", "#009966"),
        ("Network Device",  "#fff2cc", "#d6b656"),
        ("Unknown OS",      "#f5f5f5", "#666666"),
    ]
    sev = [
        ("Critical vuln (CVSS ≥9)",   "#CC0000", "3"),
        ("High vuln    (CVSS ≥7)",    "#E65100", "2"),
        ("Medium vuln  (CVSS ≥4)",    "#B8860B", "2"),
    ]

    # Legend container
    lw, lh = 210, 30 + len(items) * 22 + 10 + len(sev) * 22 + 10
    box = ET.SubElement(root, "mxCell", {
        "id": "legend_box",
        "value": "<b>Legend</b>",
        "style": (
            "swimlane;startSize=24;fillColor=#1a1a2e;strokeColor=#444;"
            "fontColor=#ffffff;fontStyle=1;fontSize=11;align=center;"
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
                f"fillColor={fill};strokeColor={stroke};spacingLeft=6;"
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
                f"fillColor=#f5f5f5;strokeColor={stroke};strokeWidth={sw};spacingLeft=6;"
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

    # ── Coordinate transform (Cytoscape → draw.io canvas) ─────────────────
    # Only host-IP keys matter for positioning; vsw_* are used purely as
    # fallback hub-centre hints and are not placed as nodes.
    host_saved = {ip: pos for ip, pos in saved_pos.items() if ip in hosts}

    if host_saved:
        min_x = min(p[0] for p in host_saved.values())
        min_y = min(p[1] for p in host_saved.values())
    else:
        min_x, min_y = 0.0, 0.0

    def _canvas(cx: float, cy: float) -> tuple[float, float]:
        return (
            round((cx - min_x) * _POSITION_SCALE + _CANVAS_PAD),
            round((cy - min_y) * _POSITION_SCALE + _CANVAS_PAD),
        )

    # Absolute draw.io positions for positioned hosts
    abs_pos: dict[str, tuple[float, float]] = {}
    for ip, (cx, cy) in host_saved.items():
        abs_pos[ip] = _canvas(cx, cy)

    # For subnets whose hub is a virtual switch, estimate the subnet centre
    # from the vsw position so un-positioned spokes auto-grid around it.
    vsw_canvas: dict[str, tuple[float, float]] = {}
    for net in subnet_ips:
        vsw_key = f"vsw_{net}"   # matches what NodePositionORM stores
        if vsw_key in saved_pos:
            vsw_canvas[net] = _canvas(*saved_pos[vsw_key])

    # Auto-place hosts that have no saved position
    right_edge = (
        max(p[0] for p in abs_pos.values()) + _NODE_W + 100
        if abs_pos else _CANVAS_PAD
    )
    unpos_groups: dict[str, list[str]] = {}
    for ip in hosts:
        if ip not in abs_pos:
            unpos_groups.setdefault(ip_to_subnet[ip], []).append(ip)

    fallback_y = _CANVAS_PAD
    for net, ips in sorted(unpos_groups.items()):
        # Centre the auto-grid on the vsw position if available
        if net in vsw_canvas:
            base_x, base_y = vsw_canvas[net]
            # Offset so the grid is centred around the vsw centre
            grid_w = _GRID_COLS * _GRID_W
            base_x = base_x - grid_w // 2
            base_y = base_y - _GRID_H
        else:
            base_x, base_y = right_edge, fallback_y

        for i, ip in enumerate(sorted(ips)):
            col, row = i % _GRID_COLS, i // _GRID_COLS
            abs_pos[ip] = (base_x + col * _GRID_W, base_y + row * _GRID_H)

        rows = math.ceil(len(ips) / _GRID_COLS)
        fallback_y += rows * _GRID_H + 60

    # ── Container bounding boxes ───────────────────────────────────────────
    containers: dict[str, tuple[float, float, float, float]] = {}
    for net, ips in subnet_ips.items():
        pts = [abs_pos[ip] for ip in ips if ip in abs_pos]
        if not pts:
            continue
        bx  = min(p[0] for p in pts) - _PAD
        by  = min(p[1] for p in pts) - _SWIM_TITLE - _PAD
        bx2 = max(p[0] for p in pts) + _NODE_W + _PAD
        by2 = max(p[1] for p in pts) + _NODE_H + _PAD
        containers[net] = (bx, by, bx2 - bx, by2 - by)

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

    # Subnet swimlane containers
    swim_style = (
        "swimlane;startSize=30;fillColor=#f5f5f5;strokeColor=#aaaaaa;"
        "fontStyle=1;fontSize=11;fontColor=#333333;align=center;"
        "whiteSpace=wrap;html=1;swimlaneLine=1;"
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
        label     = _node_label(h, svcs, max_cvss, vcount)
        style     = _node_style(h.os_family, max_cvss, is_gw)
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

    # Legend (bottom-right of bounding box + 40px gap)
    if abs_pos:
        leg_x = max(p[0] for p in abs_pos.values()) + _NODE_W + 40
        leg_y = min(p[1] for p in abs_pos.values())
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
