from __future__ import annotations
import json as _json
import re as _re
import dash
from dash import Input, Output, State, html, dcc, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.graph.builder import build_graph
from gravwell.graph import analysis


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("bottom-tab-content", "children"),
        Input("bottom-tabs", "value"),
        Input("apply-filters-btn", "n_clicks"),
        Input("refresh-interval", "n_intervals"),
        prevent_initial_call=False,
    )
    def update_bottom_tab(tab, _, __):
        from dash import ctx
        triggered = ctx.triggered_id

        # Never re-render the paths tab on interval or filter refresh — it
        # would wipe any analysis results the user just ran.
        if tab == "tab-paths" and triggered in ("refresh-interval", "apply-filters-btn"):
            return no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]

        if tab == "tab-hosts":
            return _render_hosts_table(db_path)
        elif tab == "tab-services":
            return _render_services_table(db_path)
        elif tab == "tab-vulns":
            return _render_vulns_table(db_path)
        elif tab == "tab-paths":
            return _render_paths_ui()
        return html.Div()

    @app.callback(
        Output("path-results-display", "children"),
        # ── Path queries ──────────────────────────────────────────────
        Input("find-paths-btn",    "n_clicks"),
        Input("path-to-hvt-btn",   "n_clicks"),
        # ── Graph-wide queries ─────────────────────────────────────────
        Input("find-pivots-btn",   "n_clicks"),
        Input("critical-exp-btn",  "n_clicks"),
        Input("key-terrain-btn",   "n_clicks"),
        Input("legacy-sys-btn",    "n_clicks"),
        Input("kerberoast-btn",    "n_clicks"),
        Input("cleartext-btn",     "n_clicks"),
        Input("admin-if-btn",      "n_clicks"),
        Input("smb-spread-btn",    "n_clicks"),
        Input("ad-enum-btn",       "n_clicks"),
        State("path-src-ip", "value"),
        State("path-dst-ip", "value"),
        prevent_initial_call=True,
    )
    def run_analysis(
        path_c, hvt_c, pivot_c, exposure_c, terrain_c, legacy_c,
        kerb_c, clear_c, admin_c, smb_c, ad_enum_c,
        src_ip, dst_ip,
    ):
        from dash import ctx
        triggered = ctx.triggered_id
        db_path = current_app.config["GRAVWELL_DB_PATH"]

        with get_session(db_path) as session:
            G = build_graph(session)

        if triggered == "find-paths-btn":
            return _render_attack_paths(G, src_ip, dst_ip)
        elif triggered == "path-to-hvt-btn":
            return _render_path_to_hvt(G, src_ip)
        elif triggered == "find-pivots-btn":
            return _render_pivot_candidates(G)
        elif triggered == "critical-exp-btn":
            return _render_critical_exposure(G)
        elif triggered == "key-terrain-btn":
            return _render_high_value_targets(G)
        elif triggered == "legacy-sys-btn":
            return _render_legacy_systems(G)
        elif triggered == "kerberoast-btn":
            return _render_kerberoastable(G)
        elif triggered == "cleartext-btn":
            return _render_cleartext_services(G)
        elif triggered == "admin-if-btn":
            return _render_admin_interfaces(G)
        elif triggered == "smb-spread-btn":
            return _render_smb_spread(G)
        elif triggered == "ad-enum-btn":
            return _render_domain_enum(G, db_path)
        return no_update

    # ── Focus callbacks: path table host cells, services table, vulns table ──

    @app.callback(
        Output("node-focus-store",    "data", allow_duplicate=True),
        Output("selected-node-store", "data", allow_duplicate=True),
        Input("_path-host-focus-trigger", "value"),
        prevent_initial_call=True,
    )
    def focus_from_path_table(trigger_value):
        if not trigger_value:
            return no_update, no_update
        try:
            ip = _json.loads(trigger_value).get("ip", "").strip()
        except Exception:
            return no_update, no_update
        return ({"ip": ip}, {"ip": ip}) if ip else (no_update, no_update)

    @app.callback(
        Output("node-focus-store",    "data", allow_duplicate=True),
        Output("selected-node-store", "data", allow_duplicate=True),
        Input("services-table", "active_cell"),
        State("services-table", "derived_virtual_data"),
        prevent_initial_call=True,
    )
    def focus_from_services_table(active_cell, virtual_data):
        if not active_cell or not virtual_data:
            return no_update, no_update
        row = active_cell.get("row", -1)
        ip  = virtual_data[row].get("ip") if 0 <= row < len(virtual_data) else None
        return ({"ip": ip}, {"ip": ip}) if ip else (no_update, no_update)

    @app.callback(
        Output("node-focus-store",    "data", allow_duplicate=True),
        Output("selected-node-store", "data", allow_duplicate=True),
        Input("vulns-table", "active_cell"),
        State("vulns-table", "derived_virtual_data"),
        prevent_initial_call=True,
    )
    def focus_from_vulns_table(active_cell, virtual_data):
        if not active_cell or not virtual_data:
            return no_update, no_update
        row = active_cell.get("row", -1)
        ip  = virtual_data[row].get("ip") if 0 <= row < len(virtual_data) else None
        return ({"ip": ip}, {"ip": ip}) if ip else (no_update, no_update)


# ── Bottom-tab renderers ──────────────────────────────────────────────────────

def _render_hosts_table(db_path: str):
    from dash import dash_table
    from sqlalchemy import func
    from gravwell.models.orm import HostORM, ServiceORM
    with get_session(db_path) as session:
        # Single GROUP BY subquery replaces N per-host count queries
        port_subq = (
            session.query(
                ServiceORM.host_id,
                func.count(ServiceORM.id).label("open_count"),
            )
            .filter(ServiceORM.state == "open")
            .group_by(ServiceORM.host_id)
            .subquery()
        )
        results = (
            session.query(HostORM, port_subq.c.open_count)
            .outerjoin(port_subq, HostORM.id == port_subq.c.host_id)
            .order_by(HostORM.max_cvss.desc())
            .all()
        )
        rows = [
            {
                "ip":         h.ip,
                "hostname":   (h.hostnames or [""])[0] if h.hostnames else "",
                "os":         h.os_name or h.os_family or "",
                "ports":      str(open_count or 0),
                "max_cvss":   f"{h.max_cvss:.1f}",
                "critical":   str(h.vuln_count_critical),
                "high":       str(h.vuln_count_high),
                "medium":     str(h.vuln_count_medium),
                "sources":    ", ".join(h.source_files),
                "note":       "\u2713" if h.notes else "",
            }
            for h, open_count in results
        ]
    return dash_table.DataTable(
        id="hosts-table",
        data=rows,
        columns=[
            {"name": "IP",         "id": "ip"},
            {"name": "Hostname",   "id": "hostname"},
            {"name": "OS",         "id": "os"},
            {"name": "Open Ports", "id": "ports"},
            {"name": "Max CVSS",   "id": "max_cvss"},
            {"name": "Crit",       "id": "critical"},
            {"name": "High",       "id": "high"},
            {"name": "Med",        "id": "medium"},
            {"name": "Sources",    "id": "sources"},
            {"name": "Note",       "id": "note"},
        ],
        filter_action="native", sort_action="native", sort_mode="multi",
        page_size=20,
        style_table={"overflowX": "auto"},
        style_cell={"fontSize": "12px", "padding": "3px 6px",
                    "backgroundColor": "#1e1e1e", "color": "#ccc",
                    "cursor": "pointer"},
        style_header={"backgroundColor": "#2d2d2d", "color": "#fff",
                      "fontWeight": "bold"},
        style_data_conditional=[
            {"if": {"filter_query": '{critical} > "0"'},
             "backgroundColor": "#3d1a1a"},
        ],
    )


def _render_services_table(db_path: str):
    from dash import dash_table
    from gravwell.models.orm import ServiceORM, HostORM
    with get_session(db_path) as session:
        # Single JOIN replaces N per-service host-lookup queries
        results = (
            session.query(ServiceORM, HostORM.ip)
            .join(HostORM, ServiceORM.host_id == HostORM.id)
            .filter(ServiceORM.state == "open")
            .order_by(ServiceORM.port)
            .all()
        )
        rows = [
            {
                "ip":      ip,
                "port":    str(s.port),
                "proto":   s.protocol,
                "service": s.service_name or "",
                "product": s.product or "",
                "version": s.version or "",
                "banner":  (s.banner or "")[:60],
            }
            for s, ip in results
        ]
    return dash_table.DataTable(
        id="services-table",
        data=rows,
        columns=[
            {"name": "IP",      "id": "ip"},
            {"name": "Port",    "id": "port"},
            {"name": "Proto",   "id": "proto"},
            {"name": "Service", "id": "service"},
            {"name": "Product", "id": "product"},
            {"name": "Version", "id": "version"},
            {"name": "Banner",  "id": "banner"},
        ],
        filter_action="native", sort_action="native", page_size=25,
        style_table={"overflowX": "auto"},
        style_cell={"fontSize": "12px", "padding": "3px 6px",
                    "backgroundColor": "#1e1e1e", "color": "#ccc",
                    "cursor": "pointer"},
        style_header={"backgroundColor": "#2d2d2d", "color": "#fff"},
    )


_VULN_LIMIT = 2000


def _render_vulns_table(db_path: str):
    from dash import dash_table
    from sqlalchemy import func
    from gravwell.models.orm import VulnerabilityORM, HostORM, CVERefORM, CVEEnrichmentORM
    from gravwell.models.enrichment import exploit_label
    sev_colors = {
        "critical": "#3d1a1a", "high": "#3d2a1a",
        "medium": "#2d2a1a",   "low": "#1a2d1a",
    }
    with get_session(db_path) as session:
        total = session.query(func.count(VulnerabilityORM.id)).scalar() or 0

        # ── Tier 1: ALL KEV-flagged vulns (no limit — CISA KEV has ~1,100 entries) ──
        # A vuln is KEV-flagged if any of its CVE refs appears in the KEV catalog.
        kev_vuln_subq = (
            session.query(CVERefORM.vuln_id)
            .join(CVEEnrichmentORM, CVEEnrichmentORM.cve_id == CVERefORM.cve_id)
            .filter(CVEEnrichmentORM.in_kev == True)
            .distinct()
        )
        kev_rows = (
            session.query(VulnerabilityORM, HostORM.ip)
            .join(HostORM, VulnerabilityORM.host_id == HostORM.id)
            .filter(VulnerabilityORM.id.in_(kev_vuln_subq))
            .order_by(VulnerabilityORM.cvss_score.desc())
            .all()
        )
        kev_ids = {v.id for v, _ in kev_rows}

        # ── Tier 2: Top remaining vulns by CVSS, excluding KEV ones already shown ──
        remaining = max(0, _VULN_LIMIT - len(kev_rows))
        if remaining > 0:
            q = (
                session.query(VulnerabilityORM, HostORM.ip)
                .join(HostORM, VulnerabilityORM.host_id == HostORM.id)
                .order_by(VulnerabilityORM.cvss_score.desc())
            )
            if kev_ids:
                q = q.filter(VulnerabilityORM.id.notin_(kev_ids))
            top_rows = q.limit(remaining).all()
        else:
            top_rows = []

        # Batch-load CVE refs (one IN query)
        vuln_ids = [v.id for v, _ in kev_rows + top_rows]
        cve_map: dict[int, list[str]] = {}
        if vuln_ids:
            for cve in session.query(CVERefORM).filter(
                CVERefORM.vuln_id.in_(vuln_ids)
            ).all():
                cve_map.setdefault(cve.vuln_id, []).append(cve.cve_id)

        # Batch-load KEV/EPSS enrichment for all referenced CVE IDs (one IN query)
        all_cve_ids = {c for ids in cve_map.values() for c in ids}
        enrich_map: dict = {}
        if all_cve_ids:
            for rec in session.query(CVEEnrichmentORM).filter(
                CVEEnrichmentORM.cve_id.in_(all_cve_ids)
            ).all():
                enrich_map[rec.cve_id.upper()] = rec

        # Re-sort KEV tier by EPSS descending (most likely to be exploited NOW first),
        # then CVSS as tiebreaker.  KEV 90% is far more urgent than KEV 2%.
        # Non-KEV tier stays CVSS-ordered.  Python sort over <=1,100 KEV entries is fast.
        def _vuln_max_epss(v) -> float:
            return max(
                (getattr(enrich_map.get(c.upper()), "epss_score", None) or 0.0)
                for c in cve_map.get(v.id, [])
            ) if cve_map.get(v.id) else 0.0

        if kev_rows:
            kev_rows.sort(key=lambda pair: (-_vuln_max_epss(pair[0]), -pair[0].cvss_score))

        vuln_rows = kev_rows + top_rows

        rows = [
            {
                "ip":       ip,
                "severity": v.severity,
                "cvss":     f"{v.cvss_score:.1f}",
                "exploit":  exploit_label(cve_map.get(v.id, []), enrich_map),
                "name":     v.name[:80],
                "port":     str(v.port or ""),
                "cves":     ", ".join(cve_map.get(v.id, [])),
                "solution": (v.solution or "")[:60],
            }
            for v, ip in vuln_rows
        ]

    kev_count = len(kev_rows)
    shown = len(rows)
    if kev_count and total > _VULN_LIMIT:
        label = (
            f"Showing {shown:,} of {total:,} vulnerabilities "
            f"({kev_count:,} KEV-confirmed shown first by EPSS, "
            f"then top CVSS)"
        )
    elif total > _VULN_LIMIT:
        label = (
            f"Showing top {shown:,} of {total:,} vulnerabilities (by CVSS)"
            f" — run Enrich CVEs for KEV priority"
        )
    else:
        label = f"{total:,} vulnerabilities"
    has_enrichment = any(r["exploit"] for r in rows)
    hint = "" if has_enrichment else " — use 'Enrich CVEs' in sidebar to add KEV/EPSS"
    return html.Div([
        html.Div(label + hint,
                 style={"fontSize": "11px", "color": "#888",
                        "marginBottom": "4px", "padding": "2px 0"}),
        dash_table.DataTable(
            id="vulns-table",
            data=rows,
            columns=[
                {"name": "IP",       "id": "ip"},
                {"name": "Severity", "id": "severity"},
                {"name": "CVSS",     "id": "cvss"},
                {"name": "Exploit",  "id": "exploit"},
                {"name": "Name",     "id": "name"},
                {"name": "Port",     "id": "port"},
                {"name": "CVEs",     "id": "cves"},
                {"name": "Solution", "id": "solution"},
            ],
            filter_action="native", sort_action="native", page_size=25,
            style_table={"overflowX": "auto"},
            style_cell={"fontSize": "12px", "padding": "3px 6px",
                        "backgroundColor": "#1e1e1e", "color": "#ccc",
                        "cursor": "pointer"},
            style_header={"backgroundColor": "#2d2d2d", "color": "#fff"},
            style_data_conditional=[
                *[
                    {"if": {"filter_query": f'{{severity}} = "{sev}"'},
                     "backgroundColor": color}
                    for sev, color in sev_colors.items()
                ],
                # KEV confirmed-exploited rows: override severity color with red
                {"if": {"filter_query": '{exploit} contains "KEV"'},
                 "backgroundColor": "#5a0a0a", "color": "#ff9090"},
            ],
        ),
    ])


def _render_paths_ui():
    def _grp(label, *children):
        return html.Div(
            [html.Span(label, className="qg-label")] + list(children),
            className="query-group",
        )

    return html.Div([
        html.Div([
            _grp(
                "TOPOLOGY",
                html.Button("Pivot Points",     id="find-pivots-btn",
                            className="btn btn-sm btn-secondary"),
                html.Button("Key Terrain",      id="key-terrain-btn",
                            className="btn btn-sm btn-warning"),
                html.Button("Critical Exposure", id="critical-exp-btn",
                            className="btn btn-sm btn-danger"),
                html.Button("Legacy OS",        id="legacy-sys-btn",
                            className="btn btn-sm btn-secondary"),
            ),
            _grp(
                "ATTACK SURFACE",
                html.Button("Kerberoastable",   id="kerberoast-btn",
                            className="btn btn-sm btn-primary"),
                html.Button("Cleartext",        id="cleartext-btn",
                            className="btn btn-sm btn-secondary"),
                html.Button("Admin Interfaces", id="admin-if-btn",
                            className="btn btn-sm btn-danger"),
                html.Button("SMB Spread",       id="smb-spread-btn",
                            className="btn btn-sm btn-secondary"),
                html.Button("AD Enum",          id="ad-enum-btn",
                            className="btn btn-sm btn-primary"),
            ),
            _grp(
                "PATH ANALYSIS",
                dcc.Input(id="path-src-ip", placeholder="Source IP",
                          className="path-input"),
                dcc.Input(id="path-dst-ip", placeholder="Target IP",
                          className="path-input"),
                html.Button("Find Paths",       id="find-paths-btn",
                            className="btn btn-sm btn-primary"),
                html.Button("Path to HVT",      id="path-to-hvt-btn",
                            className="btn btn-sm btn-warning"),
            ),
        ], className="query-toolbar"),
        html.Div(id="path-results-display", className="query-results"),
    ], style={"display": "flex", "flexDirection": "column", "height": "100%"})


# ── Analysis renderers ────────────────────────────────────────────────────────

def _render_attack_paths(G, src_ip, dst_ip):
    if not src_ip or not dst_ip:
        return _msg("Enter source and target IPs.")
    paths = analysis.find_attack_paths(G, src_ip.strip(), dst_ip.strip())
    if not paths:
        return _msg(f"No paths found from {src_ip} to {dst_ip}.", "#E74C3C")

    items = []
    for i, ap in enumerate(paths, 1):
        hops = []
        for step in ap.steps:
            color = ("#E74C3C" if step.max_cvss >= 9 else
                     "#E67E22" if step.max_cvss >= 7 else
                     "#F39C12" if step.max_cvss >= 4 else "#ccc")
            if step.kev_count > 0:
                color = "#ff9090"  # override with KEV red
            arrow = f" -[{step.edge_to_next}]-> " if step.edge_to_next else ""
            label = step.hostnames[0] if step.hostnames else step.ip
            hops.append(html.Span([
                html.Span(label,
                          className="g-host-link",
                          title=step.ip,
                          style={"color": color, "fontWeight": "bold",
                                 "cursor": "pointer"}),
                html.Span(f"({step.ip})" if step.hostnames else "",
                          style={"fontSize": "10px", "color": "#666"}),
                html.Span(f" cvss:{step.max_cvss:.1f}",
                          style={"fontSize": "10px", "color": "#888"}),
                html.Span(" ") if step.kev_count else None,
                _kev_badge(step.kev_count, step.max_epss) if step.kev_count else None,
                html.Span(arrow, style={"color": "#555"}),
            ]))
        items.append(html.Div([
            html.B(f"Path {i}: {ap.hop_count} hops, risk={ap.total_risk_score:.1f}  "),
            html.Span(hops),
        ], style={"marginBottom": "6px", "fontSize": "12px"}))

    return html.Div([
        _heading(f"Attack Paths: {src_ip} -> {dst_ip} ({len(paths)} found)"),
        html.Div(items, style={"marginTop": "6px"}),
    ])


def _render_path_to_hvt(G, src_ip):
    if not src_ip or not src_ip.strip():
        return _msg("Enter a source IP to find the nearest high-value target.")
    path, tgt = analysis.find_path_to_nearest_hvt(G, src_ip.strip())
    if path is None:
        return _msg(f"No path from {src_ip} to any high-value target.", "#E74C3C")

    steps = []
    for i, ip in enumerate(path):
        attrs = G.nodes[ip]
        label = (attrs.get("hostnames") or [None])[0] or ip
        cvss  = attrs.get("max_cvss", 0.0)
        color = ("#E74C3C" if cvss >= 9 else "#E67E22" if cvss >= 7 else
                 "#F1C40F" if cvss >= 4 else "#ccc")
        sep   = html.Span(" -> ", style={"color": "#555"}) if i < len(path)-1 else None
        steps.append(html.Span([
            html.Span(label,
                      className="g-host-link",
                      title=ip,
                      style={"color": color, "fontWeight": "bold",
                             "cursor": "pointer"}),
            html.Span(f" ({ip})" if label != ip else "",
                      style={"fontSize": "10px", "color": "#666"}),
            sep,
        ]))

    return html.Div([
        _heading(f"Shortest path to HVT: {src_ip} -> {tgt}  ({len(path)-1} hops)"),
        html.Div(steps, style={"fontSize": "12px", "marginTop": "6px",
                               "flexWrap": "wrap", "display": "flex"}),
    ])


def _render_pivot_candidates(G):
    candidates = analysis.find_pivot_candidates(G)
    if not candidates:
        return _msg("No pivot candidates found.")
    rows = []
    for c in candidates:
        label = c.hostnames[0] if c.hostnames else c.ip
        rows.append(html.Tr([
            html.Td(_host_cell(label, c.ip if c.hostnames else "", ip=c.ip)),
            html.Td(c.os_name or c.os_family, style={"fontSize": "11px"}),
            html.Td(f"{c.betweenness:.4f}"),
            html.Td(str(c.subnet_count)),
            html.Td(f"{c.max_cvss:.1f}"),
            html.Td(f"{c.risk_score:.2f}"),
            html.Td(_kev_badge(c.kev_count, c.max_epss)),
            html.Td(", ".join(c.pivot_reasons),
                    style={"fontSize": "10px", "color": "#aaa"}),
        ]))
    return _table(
        f"Pivot Candidates ({len(candidates)})",
        ["Host", "OS", "Betweenness", "Subnets", "CVSS", "Risk", "Exploit", "Reasons"],
        rows,
    )


def _render_critical_exposure(G):
    exposed = analysis.get_critical_exposure(G, min_cvss=7.0)
    if not exposed:
        return _msg("No hosts with CVSS >= 7.0.", "#27AE60")
    rows = []
    for e in exposed:
        ext = html.Span("EXT", style={"color": "#E74C3C", "fontWeight": "bold"}) \
            if e.reachable_from_external else html.Span("int")
        label = e.hostnames[0] if e.hostnames else e.ip
        kev_style = {"backgroundColor": "#3d0a0a"} if e.kev_count > 0 else {}
        rows.append(html.Tr([
            html.Td(_host_cell(label, e.ip if e.hostnames else "", ip=e.ip)),
            html.Td(e.os_name or e.os_family, style={"fontSize": "11px"}),
            html.Td(f"{e.max_cvss:.1f}", style={"color": "#E74C3C"}),
            html.Td(str(e.critical_vuln_count), style={"color": "#E74C3C"}),
            html.Td(str(e.high_vuln_count),     style={"color": "#E67E22"}),
            html.Td(_kev_badge(e.kev_count, e.max_epss)),
            html.Td(ext),
            html.Td(str(sorted(e.open_ports)[:8]), style={"fontSize": "10px"}),
        ], style=kev_style))
    return _table(
        f"Critical Exposure (CVSS >= 7.0) -- {len(exposed)} hosts  [KEV hosts shown first]",
        ["Host", "OS", "Max CVSS", "Critical", "High", "Exploit", "External?", "Open Ports"],
        rows,
    )


_ROLE_ICONS = {
    "domain_controller": "DC",
    "credential_store":  "Creds",
    "database":          "DB",
    "web_server":        "Web",
    "mail_server":       "Mail",
    "file_server":       "Files",
    "remote_access":     "RDP/VNC",
    "network_device":    "Net",
}


def _render_high_value_targets(G):
    targets = analysis.find_high_value_targets(G)
    if not targets:
        return _msg("No high-value targets identified.")
    rows = []
    for t in targets:
        label  = t.hostnames[0] if t.hostnames else t.ip
        badges = html.Span([
            html.Span(
                _ROLE_ICONS.get(r, r),
                style={"background": "#2a2a5a", "color": "#A78BFA",
                       "borderRadius": "3px", "padding": "1px 5px",
                       "marginRight": "3px", "fontSize": "10px"},
            )
            for r in t.roles
        ])
        cvss_color = ("#E74C3C" if t.max_cvss >= 9 else
                      "#E67E22" if t.max_cvss >= 7 else
                      "#F1C40F" if t.max_cvss >= 4 else "#aaa")
        kev_style = {"backgroundColor": "#3d0a0a"} if t.kev_count > 0 else {}
        rows.append(html.Tr([
            html.Td(_host_cell(label, t.ip if t.hostnames else "", ip=t.ip)),
            html.Td(t.os_name or t.os_family, style={"fontSize": "11px"}),
            html.Td(badges),
            html.Td(f"{t.max_cvss:.1f}", style={"color": cvss_color}),
            html.Td(f"{t.risk_score:.1f}"),
            html.Td(_kev_badge(t.kev_count, t.max_epss)),
            html.Td(str(sorted(t.open_ports)[:8]), style={"fontSize": "10px"}),
        ], style=kev_style))
    return _table(
        f"Key Terrain -- High-Value Targets ({len(targets)})",
        ["Host", "OS", "Roles", "CVSS", "Priority", "Exploit", "Open Ports"],
        rows,
    )


def _render_legacy_systems(G):
    systems = analysis.find_legacy_systems(G)
    if not systems:
        return _msg("No end-of-life systems detected.", "#27AE60")
    rows = []
    for s in systems:
        label = s.hostnames[0] if s.hostnames else s.ip
        # Legacy OS + KEV-confirmed exploit = critical double risk
        kev_style = {"backgroundColor": "#3d0a0a"} if s.kev_count > 0 else {}
        rows.append(html.Tr([
            html.Td(_host_cell(label, s.ip if s.hostnames else "", ip=s.ip)),
            html.Td(s.os_name, style={"fontSize": "11px", "color": "#E67E22"}),
            html.Td(s.eol_label, style={"color": "#E74C3C", "fontSize": "11px"}),
            html.Td(f"{s.max_cvss:.1f}"),
            html.Td(_kev_badge(s.kev_count, s.max_epss)),
            html.Td(str(sorted(s.open_ports)[:8]), style={"fontSize": "10px"}),
        ], style=kev_style))
    return _table(
        f"End-of-Life Systems ({len(systems)})  [KEV-confirmed shown first]",
        ["Host", "Detected OS", "EOL Notice", "CVSS", "Exploit", "Open Ports"],
        rows,
        heading_color="#E74C3C",
    )


def _render_kerberoastable(G):
    targets = analysis.find_kerberoastable_indicators(G)
    if not targets:
        return _msg("No Kerberos environment detected (no host with port 88 found).")
    rows = []
    for t in targets:
        label = t.hostnames[0] if t.hostnames else t.ip
        dc_badge = html.Span(" DC", style={
            "background": "#6C3483", "color": "#D7BDE2",
            "borderRadius": "3px", "padding": "1px 4px",
            "fontSize": "10px", "marginLeft": "4px",
        }) if t.is_dc else None
        conf_color = "#27AE60" if t.confidence == "confirmed" else "#F39C12"
        rows.append(html.Tr([
            html.Td(html.Span([
                html.Span(label, style={"color": "#5DADE2"}),
                dc_badge,
                html.Br(),
                html.Span(t.ip if t.hostnames else "",
                          style={"fontSize": "10px", "color": "#666"}),
            ], className="g-host-link", title=t.ip, style={"cursor": "pointer"})),
            html.Td(t.os_name, style={"fontSize": "11px"}),
            html.Td(", ".join(t.spn_services),
                    style={"fontSize": "10px", "color": "#A78BFA"}),
            html.Td(html.Span(t.confidence,
                              style={"color": conf_color, "fontSize": "10px"})),
            html.Td(f"{t.max_cvss:.1f}"),
        ]))
    confirmed = sum(1 for t in targets if t.confidence == "confirmed")
    likely    = len(targets) - confirmed
    note = f" ({confirmed} confirmed, {likely} likely)" if likely else ""
    return _table(
        f"Kerberoastable Indicators ({len(targets)}){note} -- Windows Kerberos environment",
        ["Host", "OS", "Likely SPNs", "Confidence", "CVSS"],
        rows,
    )


def _render_cleartext_services(G):
    hosts = analysis.find_cleartext_services(G)
    if not hosts:
        return _msg("No cleartext protocol exposure found.", "#27AE60")
    rows = []
    for h in hosts:
        label = h.hostnames[0] if h.hostnames else h.ip
        high = any(p in ",".join(h.cleartext_ports) for p in
                   ("Telnet", "rexec", "rlogin", "rsh"))
        risk_color = "#E74C3C" if high else "#E67E22"
        rows.append(html.Tr([
            html.Td(_host_cell(label, h.ip if h.hostnames else "", ip=h.ip)),
            html.Td(h.os_name, style={"fontSize": "11px"}),
            html.Td(html.Span(", ".join(h.cleartext_ports),
                              style={"color": risk_color, "fontSize": "11px"})),
            html.Td(f"{h.max_cvss:.1f}"),
        ]))
    return _table(
        f"Cleartext Credential Exposure ({len(hosts)} hosts)",
        ["Host", "OS", "Protocols", "CVSS"],
        rows,
    )


def _render_admin_interfaces(G):
    hosts = analysis.find_admin_interfaces(G)
    if not hosts:
        return _msg("No remote admin interfaces found.", "#27AE60")
    rows = []
    for h in hosts:
        label = h.hostnames[0] if h.hostnames else h.ip
        ext_badge = html.Span(" EXT", style={
            "color": "#E74C3C", "fontWeight": "bold",
        }) if h.is_external else None
        rows.append(html.Tr([
            html.Td(html.Span([
                html.Span(label, style={"color": "#5DADE2"}),
                ext_badge,
                html.Br(),
                html.Span(h.ip if h.hostnames else "",
                          style={"fontSize": "10px", "color": "#666"}),
            ], className="g-host-link", title=h.ip, style={"cursor": "pointer"})),
            html.Td(h.os_name, style={"fontSize": "11px"}),
            html.Td(", ".join(h.admin_ports),
                    style={"fontSize": "11px", "color": "#E67E22"}),
            html.Td(f"{h.max_cvss:.1f}"),
        ]))
    return _table(
        f"Exposed Admin Interfaces ({len(hosts)} hosts) -- lateral movement entry points",
        ["Host", "OS", "Interfaces", "CVSS"],
        rows,
    )


def _render_smb_spread(G):
    hosts = analysis.find_smb_spread_risk(G)
    if not hosts:
        return _msg("No SMB-enabled hosts found.")
    rows = []
    for h in hosts:
        label = h.hostnames[0] if h.hostnames else h.ip
        rows.append(html.Tr([
            html.Td(_host_cell(label, h.ip if h.hostnames else "", ip=h.ip)),
            html.Td(h.os_name, style={"fontSize": "11px"}),
            html.Td(str(h.smb_neighbor_count),
                    style={"color": "#E67E22" if h.smb_neighbor_count > 2 else "#ccc"}),
            html.Td(f"{h.max_cvss:.1f}"),
            html.Td(f"{h.risk_score:.1f}"),
        ]))
    return _table(
        f"SMB Lateral Movement Risk ({len(hosts)} hosts with port 445)",
        ["Host", "OS", "SMB Neighbours", "CVSS", "Risk Score"],
        rows,
    )


def _render_domain_enum(G, db_path: str):
    """Show hosts with domain/SMB enumeration data from enum4linux."""
    from gravwell.models.orm import VulnerabilityORM, HostORM

    hosts = analysis.find_domain_enum(G)
    if not hosts:
        return _msg(
            "No domain/SMB enumeration data found. "
            "Ingest enum4linux output (gravwell ingest <file>) to populate this view."
        )

    _ENUM_PLUGINS = {
        "enum4linux-users-enumerable",
        "enum4linux-groups-enumerable",
        "enum4linux-password-policy",
        "enum4linux-smb-signing-disabled",
    }
    with get_session(db_path) as session:
        vuln_rows = (
            session.query(
                VulnerabilityORM.plugin_id,
                HostORM.ip,
                VulnerabilityORM.description,
            )
            .join(HostORM, VulnerabilityORM.host_id == HostORM.id)
            .filter(VulnerabilityORM.plugin_id.in_(_ENUM_PLUGINS))
            .all()
        )

    # index: ip → {plugin_id: description}
    by_ip: dict[str, dict[str, str]] = {}
    for plugin_id, ip, desc in vuln_rows:
        by_ip.setdefault(ip, {})[plugin_id] = desc or ""

    def _count_from_desc(desc: str) -> int:
        m = _re.match(r"(\d+)\s+\w+\(s\)", desc)
        return int(m.group(1)) if m else 0

    rows = []
    for h in hosts:
        data         = by_ip.get(h.ip, {})
        user_count   = _count_from_desc(data.get("enum4linux-users-enumerable", ""))
        group_count  = _count_from_desc(data.get("enum4linux-groups-enumerable", ""))
        signing_vuln = "enum4linux-smb-signing-disabled" in data
        weak_policy  = "enum4linux-password-policy" in data
        label        = h.hostnames[0] if h.hostnames else h.ip

        signing_cell = (
            html.Span("RELAY RISK",
                      style={"color": "#E74C3C", "fontWeight": "bold",
                             "fontSize": "10px"})
            if signing_vuln
            else html.Span("-", style={"color": "#444", "fontSize": "10px"})
        )
        policy_cell = (
            html.Span("WEAK",
                      style={"color": "#E67E22", "fontWeight": "bold",
                             "fontSize": "10px"})
            if weak_policy
            else html.Span("-", style={"color": "#444", "fontSize": "10px"})
        )

        rows.append(html.Tr([
            html.Td(_host_cell(label, h.ip if h.hostnames else "", ip=h.ip)),
            html.Td(h.os_name or "-", style={"fontSize": "11px"}),
            html.Td(h.domain or "-",
                    style={"fontSize": "11px", "color": "#A78BFA"}),
            html.Td(str(user_count)  if user_count  else "-"),
            html.Td(str(group_count) if group_count else "-"),
            html.Td(signing_cell),
            html.Td(policy_cell),
            html.Td(f"{h.max_cvss:.1f}"),
        ]))

    return _table(
        f"AD Enumeration Summary ({len(rows)} hosts with SMB/domain data)",
        ["Host", "OS", "Domain", "Users", "Groups",
         "SMB Signing", "Pwd Policy", "CVSS"],
        rows,
    )


# ── Shared UI helpers ─────────────────────────────────────────────────────────

def _kev_badge(kev_count: int, max_epss: float):
    """Red KEV badge + EPSS percentage for attack-paths tables."""
    parts = []
    if kev_count > 0:
        parts.append(html.Span(
            f"KEV:{kev_count}",
            style={"background": "#5a0a0a", "color": "#ff9090",
                   "borderRadius": "3px", "padding": "1px 4px",
                   "fontSize": "10px", "marginRight": "3px"},
        ))
    if max_epss >= 0.01:
        color = "#E74C3C" if max_epss >= 0.5 else "#E67E22" if max_epss >= 0.1 else "#888"
        parts.append(html.Span(
            f"{max_epss:.0%}",
            style={"color": color, "fontSize": "10px"},
        ))
    return html.Span(parts) if parts else html.Span("-", style={"color": "#444", "fontSize": "10px"})


def _msg(text: str, color: str = "#888") -> html.Div:
    return html.Div(text, style={"color": color, "fontSize": "12px",
                                 "padding": "8px"})


def _heading(text: str, color: str = "#5DADE2") -> html.B:
    return html.B(text, style={"color": color, "fontSize": "12px"})


def _host_cell(label: str, sub: str = "", ip: str = "") -> html.Span:
    """Clickable host cell. Clicking pans the graph to the node."""
    actual_ip = ip or sub or label
    return html.Span([
        html.Span(label, style={"color": "#5DADE2"}),
        html.Br() if sub else None,
        html.Span(sub, style={"fontSize": "10px", "color": "#666"}),
    ], className="g-host-link", title=actual_ip, style={"cursor": "pointer"})


def _table(
    title: str,
    headers: list[str],
    rows: list,
    heading_color: str = "#5DADE2",
) -> html.Div:
    return html.Div([
        html.B(title, style={"color": heading_color, "fontSize": "12px"}),
        html.Table(
            [html.Tr([html.Th(h) for h in headers])] + rows,
            style={"fontSize": "12px", "borderCollapse": "collapse",
                   "marginTop": "6px", "width": "100%"},
        ),
    ])
