from __future__ import annotations
import fnmatch
import ipaddress
import json
import re
import time
import dash
from dash import Input, Output, State, no_update, html
from flask import current_app
from sqlalchemy.orm import selectinload
from gravwell.database import get_session
from gravwell.graph.builder import build_graph, get_cytoscape_elements, _node_role
from gravwell.models.orm import HostORM, ServiceORM, VulnerabilityORM, \
    CustomEdgeORM, HiddenEdgeORM, SubnetLabelORM, HostRoleOverrideORM, \
    CVEEnrichmentORM, NodePositionORM
from gravwell.models.enrichment import exploit_label


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("network-graph", "elements"),
        Output("graph-host-count", "children"),
        Output("graph-edge-count", "children"),
        Output("graph-data-store", "data"),
        Input("refresh-interval", "n_intervals"),
        Input("apply-filters-btn", "n_clicks"),
        Input("project-switch-trigger", "data"),
        State("filter-hostname", "value"),
        State("filter-subnet", "value"),
        State("filter-os", "value"),
        State("filter-severity", "value"),
        State("filter-port-service", "value"),
        State("graph-data-store", "data"),
        prevent_initial_call=False,
    )
    def update_graph(n_intervals, n_clicks, _trigger, hostname, subnet,
                     os_families, severity, port_service,
                     current_graph_data):
        import logging as _log
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                G = build_graph(session)
                hidden_edge_ids = {
                    r.edge_id for r in session.query(HiddenEdgeORM).all()
                }
                custom_edges = [
                    {"source": r.source_ip, "target": r.target_ip,
                     "label": r.label or ""}
                    for r in session.query(CustomEdgeORM).all()
                ]
                _subnet_records = session.query(SubnetLabelORM).all()
                subnet_labels = {r.subnet_cidr: r.label or "" for r in _subnet_records}
                subnet_paddings = {r.subnet_cidr: r.box_padding or 30 for r in _subnet_records}
                role_overrides = {
                    r.host_ip: json.loads(r.roles_json or "[]")
                    for r in session.query(HostRoleOverrideORM).all()
                }
                noted_ips = {
                    row[0] for row in session.query(HostORM.ip).filter(
                        HostORM.notes.isnot(None), HostORM.notes != ""
                    ).all()
                }
                saved_positions = {
                    r.node_ip: (r.x, r.y)
                    for r in session.query(NodePositionORM).all()
                }
                subnet_overrides = {
                    h.ip: h.subnet_override
                    for h in session.query(HostORM.ip, HostORM.subnet_override).all()
                    if h.subnet_override
                }
        except Exception as exc:
            _log.error("update_graph DB error: %s", exc, exc_info=True)
            return no_update, no_update, no_update, no_update

        # Apply role overrides to graph nodes before rendering
        for node_id, attrs in G.nodes(data=True):
            if attrs.get("node_type") != "host":
                continue
            ip = attrs.get("ip")
            if ip not in role_overrides:
                continue
            manual_roles = role_overrides[ip]
            # Override host_roles list (analysis-facing roles)
            G.nodes[node_id]["host_roles"] = [
                r for r in manual_roles if r not in ("router", "legacy", "dc")
            ]
            G.nodes[node_id]["is_dc"] = "dc" in manual_roles
            G.nodes[node_id]["is_legacy"] = "legacy" in manual_roles
            # Determine visual/hub role override
            if "router" in manual_roles:
                G.nodes[node_id]["manual_role"] = "router"
            elif _node_role(attrs) == "router":
                # User explicitly did not include router — suppress it
                G.nodes[node_id]["manual_role"] = "host"

        # Sanitize free-text filter inputs
        hostname     = _sanitize_text(hostname)
        subnet       = _sanitize_text(subnet)
        port_service = _sanitize_text(port_service)

        # Filter nodes
        nodes_to_remove = []
        for node_id, attrs in G.nodes(data=True):
            if attrs.get("node_type") != "host":
                continue

            # ── Hostname / IP filter ──────────────────────────────────────
            # "quoted" → exact match; unquoted → substring; */?  → wildcard
            if hostname:
                raw = hostname.strip()
                exact_match = (
                    (raw.startswith('"') and raw.endswith('"') and len(raw) > 1) or
                    (raw.startswith("'") and raw.endswith("'") and len(raw) > 1)
                )
                if exact_match:
                    pat = raw[1:-1].lower()
                else:
                    pat = raw.lower()
                host_names = [h.lower() for h in (attrs.get("hostnames") or [])]
                ip_str = attrs.get("ip", "")
                if exact_match:
                    match = pat in host_names or pat == ip_str
                elif "*" in pat or "?" in pat:
                    match = (any(fnmatch.fnmatch(h, pat) for h in host_names)
                             or fnmatch.fnmatch(ip_str, pat))
                else:
                    match = any(pat in h for h in host_names) or pat in ip_str
                if not match:
                    nodes_to_remove.append(node_id)
                    continue

            # ── Subnet filter (CIDR / wildcard / plain IP) ─────────────────
            if subnet:
                if not _ip_matches_subnet_filter(attrs.get("ip", ""), subnet):
                    nodes_to_remove.append(node_id)
                    continue

            # ── OS family filter ───────────────────────────────────────────
            if os_families:
                if attrs.get("os_family") not in os_families:
                    nodes_to_remove.append(node_id)
                    continue

            # ── Severity filter ────────────────────────────────────────────
            if severity:
                min_score = {
                    "critical": 9.0, "high": 7.0,
                    "medium": 4.0, "low": 0.1, "info": 0.0
                }.get(severity, 0.0)
                if attrs.get("max_cvss", 0.0) < min_score:
                    nodes_to_remove.append(node_id)
                    continue

            # ── Port / service filter (number, substring, or wildcard) ─────
            if port_service:
                open_ports = attrs.get("open_ports", [])
                services   = attrs.get("services", [])
                try:
                    port_num = int(port_service)
                    if port_num not in open_ports:
                        nodes_to_remove.append(node_id)
                        continue
                except ValueError:
                    pat = port_service.lower()
                    if "*" in pat or "?" in pat:
                        match = any(
                            fnmatch.fnmatch((s.get("service_name") or "").lower(), pat)
                            for s in services
                        )
                    else:
                        match = any(
                            pat in (s.get("service_name") or "").lower()
                            for s in services
                        )
                    if not match:
                        nodes_to_remove.append(node_id)
                        continue

        G.remove_nodes_from(nodes_to_remove)

        elements = get_cytoscape_elements(G,
                                          hidden_edge_ids=hidden_edge_ids,
                                          custom_edges=custom_edges,
                                          subnet_labels=subnet_labels,
                                          subnet_overrides=subnet_overrides,
                                          saved_positions=saved_positions or None,
                                          subnet_paddings=subnet_paddings or None)

        # Mark nodes that have analyst notes with has-note class
        if noted_ips:
            for el in elements:
                if el.get("data", {}).get("ip") in noted_ips:
                    el["classes"] = (el.get("classes", "") + " has-note").strip()

        host_count = sum(
            1 for _, d in G.nodes(data=True) if d.get("node_type") == "host"
        )
        edge_count = G.number_of_edges()

        # On interval ticks only: skip the element update if graph structure
        # is unchanged (same node + edge IDs).  This prevents a blank-flash
        # each minute and stops positions resetting mid-drag.
        from dash import ctx
        if ctx.triggered_id == "refresh-interval" and current_graph_data:
            prev_els = current_graph_data.get("elements", [])
            prev_ids = {
                el["data"]["id"]
                for el in prev_els
                if "data" in el and "id" in el.get("data", {})
            }
            new_ids = {
                el["data"]["id"]
                for el in elements
                if "data" in el and "id" in el.get("data", {})
            }
            if prev_ids == new_ids:
                return no_update, str(host_count), str(edge_count), no_update

        return elements, str(host_count), str(edge_count), \
               {"elements": elements}

    @app.callback(
        Output("network-graph", "layout"),
        Input("layout-selector", "value"),
        prevent_initial_call=True,
    )
    def update_layout(layout_name: str):
        # ── Cose-Bilkent — default, compound-aware spring embedder ──────────
        # nestingFactor: ideal edge length MULTIPLIER for intra-compound edges.
        #   0.1 (old) → 8 px spacing inside subnets — everything packed tight.
        #   0.6 (new) → 72 px spacing — nodes breathe inside their subnet box.
        # nodeRepulsion: repulsion between ALL nodes (including compound boxes).
        #   8 000 (old) was far too weak for maps with 10+ subnets.
        # gravity: pull toward the centre.  Lower = more spread-out layout.
        _cb = {
            "name": "cose-bilkent", "animate": True,
            "nodeRepulsion": 45000,
            "idealEdgeLength": 120,
            "edgeElasticity": 0.45,
            "nestingFactor": 0.6,
            "gravity": 0.08,
            "numIter": 5000,
            "padding": 60,
            "nodeDimensionsIncludeLabels": True,
            "randomize": False,  # use pre-computed positions as warm start
        }
        # ── Cose-Bilkent Spread — push even harder apart (very dense maps) ──
        _cb_spread = {
            **_cb,
            "nodeRepulsion": 100000,
            "idealEdgeLength": 200,
            "nestingFactor": 0.9,
            "gravity": 0.04,
            "numIter": 8000,
            "padding": 80,
        }
        configs = {
            "preset": {
                "name": "preset",
                "animate": False,
                "fit": True,
                "padding": 60,
            },
            "cose-bilkent": _cb,
            "cose-bilkent-spread": _cb_spread,
            "cola": {
                "name": "cola", "animate": True,
                "maxSimulationTime": 8000,
                # nodeSpacing adds a uniform gap between every node bounding box
                "nodeSpacing": 80,
                "padding": 50,
                "randomize": True,
                "fit": True,
            },
            "concentric": {
                "name": "concentric", "animate": True,
                "spacingFactor": 2.5,
                "minNodeSpacing": 50,
                "padding": 50,
            },
            "breadthfirst": {
                "name": "breadthfirst", "animate": True,
                "spacingFactor": 2.5,
                "padding": 50,
            },
            "grid": {
                "name": "grid", "animate": True,
                "spacingFactor": 1.8,
                "padding": 50,
            },
            "circle": {
                "name": "circle", "animate": True,
                "spacingFactor": 2.0,
                "padding": 50,
            },
        }
        return configs.get(layout_name, {"name": layout_name, "animate": True})

    @app.callback(
        Output("network-graph", "zoom"),
        Output("network-graph", "pan"),
        Input("fit-graph-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def fit_graph(_):
        # Return to defaults — cytoscape will refit
        return 1, {"x": 0, "y": 0}

    @app.callback(
        Output("selected-node-store", "data"),
        Output("selected-subnet-store", "data", allow_duplicate=True),
        Input("network-graph", "tapNodeData"),
        prevent_initial_call=True,
    )
    def store_selected_node(node_data):
        if not node_data:
            return no_update, no_update
        node_type = node_data.get("node_type")
        if node_type == "host":
            # Clear subnet panel when switching to a host
            return {"ip": node_data.get("ip"), "db_id": node_data.get("id")}, {}
        if node_type == "subnet_group":
            return no_update, {"cidr": node_data.get("subnet_cidr", "")}
        return no_update, no_update

    @app.callback(
        Output("selected-edge-store", "data"),
        Output("selected-subnet-store", "data", allow_duplicate=True),
        Input("network-graph", "tapEdgeData"),
        prevent_initial_call=True,
    )
    def store_selected_edge(edge_data):
        if edge_data:
            return {
                "id": edge_data.get("id", ""),
                "source": edge_data.get("source", ""),
                "target": edge_data.get("target", ""),
                "edge_type": edge_data.get("edge_type", ""),
            }, {}  # also clear subnet panel
        return no_update, no_update

    @app.callback(
        Output("detail-panel", "children"),
        Output("node-notes-section", "style"),
        Output("node-notes-textarea", "value"),
        Input("selected-node-store", "data"),
        Input("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def update_detail_panel(node_store, _trigger):
        from dash import html, dash_table
        if not node_store:
            return "Select a node to view details.", {"display": "none"}, ""
        ip = node_store.get("ip")
        if not ip:
            return no_update, no_update, no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if not host:
                return f"Host {ip} not found.", {"display": "none"}, ""

            svcs = session.query(ServiceORM).filter_by(
                host_id=host.id, state="open"
            ).order_by(ServiceORM.port).all()
            vulns = (
                session.query(VulnerabilityORM)
                .options(selectinload(VulnerabilityORM.cve_refs))
                .filter_by(host_id=host.id)
                .order_by(VulnerabilityORM.cvss_score.desc())
                .limit(50)
                .all()
            )

            hd = {
                "ip": host.ip,
                "hostnames": host.hostnames or [],
                "os_name": host.os_name or "Unknown",
                "os_family": host.os_family or "Unknown",
                "mac": host.mac or "",
                "mac_vendor": host.mac_vendor or "",
                "max_cvss": host.max_cvss,
                "crit": host.vuln_count_critical,
                "high": host.vuln_count_high,
                "med": host.vuln_count_medium,
                "source_files": host.source_files or [],
                "notes": host.notes or "",
            }
            svc_rows = [
                {"port": s.port, "proto": s.protocol,
                 "service": s.service_name or "",
                 "product": f"{s.product or ''} {s.version or ''}".strip()}
                for s in svcs
            ]
            # Batch-load enrichment for the vuln CVE refs
            all_cve_ids = {r.cve_id for v in vulns for r in v.cve_refs}
            enrich_map: dict = {}
            if all_cve_ids:
                for rec in session.query(CVEEnrichmentORM).filter(
                    CVEEnrichmentORM.cve_id.in_(all_cve_ids)
                ).all():
                    enrich_map[rec.cve_id.upper()] = rec

            vuln_rows = [
                {
                    "severity": v.severity.upper(),
                    "cvss": f"{v.cvss_score:.1f}",
                    "exploit": exploit_label([r.cve_id for r in v.cve_refs],
                                             enrich_map),
                    "name": v.name[:70],
                    "port": str(v.port or ""),
                    "cves": ", ".join(r.cve_id for r in v.cve_refs)[:40],
                }
                for v in vulns
            ]

        sev_colors = {
            "CRITICAL": "#E74C3C", "HIGH": "#E67E22",
            "MEDIUM": "#F39C12", "LOW": "#27AE60", "INFO": "#95A5A6"
        }

        return html.Div([
            html.Div([
                html.B("OS: "),
                f"{hd['os_name']} ({hd['os_family']})", html.Br(),
                html.B("MAC: "), f"{hd['mac']} {hd['mac_vendor']}", html.Br(),
                html.B("Hostnames: "),
                ", ".join(hd["hostnames"]) if hd["hostnames"] else "none",
                html.Br(),
                html.B("CVSS: "), f"{hd['max_cvss']:.1f}  |  ",
                html.Span(f"Crit:{hd['crit']} ", style={"color": "#E74C3C"}),
                html.Span(f"High:{hd['high']} ", style={"color": "#E67E22"}),
                f"Med:{hd['med']}",
            ], style={"fontSize": "12px", "marginBottom": "8px"}),

            html.H4("Open Services", style={"marginBottom": "4px"}),
            dash_table.DataTable(
                data=svc_rows,
                columns=[
                    {"name": "Port", "id": "port"},
                    {"name": "Proto", "id": "proto"},
                    {"name": "Service", "id": "service"},
                    {"name": "Product/Version", "id": "product"},
                ],
                style_table={"maxHeight": "160px", "overflowY": "auto"},
                style_cell={"fontSize": "11px", "padding": "2px 5px",
                            "backgroundColor": "#1e1e1e", "color": "#ccc"},
                style_header={"backgroundColor": "#2d2d2d", "color": "#fff"},
                page_size=50,
            ),

            html.H4("Vulnerabilities",
                    style={"marginTop": "8px", "marginBottom": "4px"}),
            dash_table.DataTable(
                data=vuln_rows,
                columns=[
                    {"name": "Sev",     "id": "severity"},
                    {"name": "CVSS",    "id": "cvss"},
                    {"name": "Exploit", "id": "exploit"},
                    {"name": "Name",    "id": "name"},
                    {"name": "Port",    "id": "port"},
                    {"name": "CVEs",    "id": "cves"},
                ],
                style_table={"maxHeight": "200px", "overflowY": "auto"},
                style_cell={"fontSize": "11px", "padding": "2px 5px",
                            "backgroundColor": "#1e1e1e", "color": "#ccc"},
                style_header={"backgroundColor": "#2d2d2d", "color": "#fff"},
                style_data_conditional=[
                    *[
                        {
                            "if": {"filter_query": f'{{severity}} = "{sev}"'},
                            "backgroundColor": color,
                            "color": "#fff" if sev in ("CRITICAL", "HIGH") else "#111",
                        }
                        for sev, color in sev_colors.items()
                    ],
                    {"if": {"filter_query": '{exploit} contains "KEV"'},
                     "backgroundColor": "#5a0a0a", "color": "#ff9090"},
                ],
                page_size=50,
            ),
            html.Small(
                f"Source: {', '.join(hd['source_files'])}",
                style={"color": "#666", "marginTop": "6px", "display": "block"}
            ),
        ]), {"display": "block"}, hd["notes"]


    @app.callback(
        Output("selected-node-store", "data", allow_duplicate=True),
        Output("node-focus-store", "data"),
        Input("hosts-table", "active_cell"),
        State("hosts-table", "derived_virtual_data"),
        prevent_initial_call=True,
    )
    def focus_host_from_table(active_cell, virtual_data):
        """Clicking a row in the Hosts table selects that host and pans to it."""
        if not active_cell or not virtual_data:
            return no_update, no_update
        row = active_cell.get("row", -1)
        if row < 0 or row >= len(virtual_data):
            return no_update, no_update
        ip = virtual_data[row].get("ip")
        if not ip:
            return no_update, no_update
        return {"ip": ip}, {"ip": ip}

    # Clientside callback: when node-focus-store changes, pan the Cytoscape graph
    # to centre on the target node.  Uses cy.animate() so Cytoscape computes the
    # correct pan itself — avoids blank-graph from stale/in-progress layout positions.
    dash.clientside_callback(
        """
        function(focusData, graphData) {
            var nu = window.dash_clientside.no_update;
            if (!focusData || !focusData.ip) return [nu, nu];
            var ip = focusData.ip;

            /* Primary: live cy instance — cy.animate handles compound nodes and
               in-progress layouts correctly; no manual pan calculation needed. */
            var cy = window._gravwell_cy;
            if (cy && (!cy.destroyed || !cy.destroyed())) {
                try {
                    var node = cy.getElementById(ip);
                    if (node && node.length > 0) {
                        cy.animate({ center: { eles: node }, zoom: 1.8 },
                                   { duration: 250 });
                        return [nu, nu];
                    }
                } catch(e) {}
            }

            /* Fallback: saved positions in graph-data-store (preset layout only).
               Guard against zero/NaN positions from an unfinished layout. */
            if (graphData && graphData.elements) {
                var els = graphData.elements;
                for (var i = 0; i < els.length; i++) {
                    var el = els[i];
                    if (el.data && el.data.id === ip && el.position) {
                        var px = el.position.x, py = el.position.y;
                        if (!isFinite(px) || !isFinite(py) ||
                            (px === 0 && py === 0)) break;
                        var container = document.getElementById('network-graph');
                        var vw = (container && container.offsetWidth)  || 800;
                        var vh = (container && container.offsetHeight) || 600;
                        var zoom = 1.8;
                        return [zoom, {x: vw/2 - px*zoom, y: vh/2 - py*zoom}];
                    }
                }
            }

            return [nu, nu];
        }
        """,
        Output("network-graph", "zoom",  allow_duplicate=True),
        Output("network-graph", "pan",   allow_duplicate=True),
        Input("node-focus-store", "data"),
        State("graph-data-store", "data"),
        prevent_initial_call=True,
    )


    @app.callback(
        Output("save-note-status", "children"),
        Input("save-note-btn", "n_clicks"),
        State("node-notes-textarea", "value"),
        State("selected-node-store", "data"),
        prevent_initial_call=True,
    )
    def save_note(n_clicks, note_text, node_store):
        if not n_clicks or not node_store:
            return no_update
        ip = node_store.get("ip")
        if not ip:
            return no_update
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if host:
                host.notes = note_text or ""
        return "Saved"


    # ── Save Layout: clientside reads cy positions → node-positions-store ───
    # Uses window._gravwell_cy which is populated by the inline JS in app.py.
    dash.clientside_callback(
        """
        function(n_clicks) {
            if (!n_clicks) return window.dash_clientside.no_update;
            var cy = window._gravwell_cy;
            if (!cy) return {};
            var positions = {};
            cy.nodes().forEach(function(node) {
                var data = node.data();
                if (data.node_type === 'host' && data.ip) {
                    var pos = node.position();
                    positions[data.ip] = {
                        x: Math.round(pos.x * 10) / 10,
                        y: Math.round(pos.y * 10) / 10
                    };
                }
            });
            return positions;
        }
        """,
        Output("node-positions-store", "data"),
        Input("save-layout-btn", "n_clicks"),
        prevent_initial_call=True,
    )

    # ── Auto-save: capture positions after a drag ends ────────────────────
    dash.clientside_callback(
        """
        function(trigger) {
            if (!trigger) return window.dash_clientside.no_update;
            var cy = window._gravwell_cy;
            if (!cy) return window.dash_clientside.no_update;
            var positions = {};
            cy.nodes().forEach(function(node) {
                var data = node.data();
                if (data.node_type === 'host' && data.ip) {
                    var pos = node.position();
                    positions[data.ip] = {
                        x: Math.round(pos.x * 10) / 10,
                        y: Math.round(pos.y * 10) / 10
                    };
                }
            });
            return positions;
        }
        """,
        Output("node-positions-store", "data", allow_duplicate=True),
        Input("_autosave-positions-trigger", "value"),
        prevent_initial_call=True,
    )

    # ── Persist captured positions to DB ─────────────────────────────────
    @app.callback(
        Output("save-layout-status", "children"),
        Input("node-positions-store", "data"),
        prevent_initial_call=True,
    )
    def persist_node_positions(positions_data):
        if not positions_data:
            return no_update
        import math
        # Drop any positions with NaN/Infinity (can come from in-flight layouts)
        clean = {
            ip: pos for ip, pos in positions_data.items()
            if isinstance(pos, dict)
            and isinstance(pos.get("x"), (int, float))
            and isinstance(pos.get("y"), (int, float))
            and math.isfinite(pos["x"]) and math.isfinite(pos["y"])
        }
        if not clean:
            return no_update
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                existing = {
                    r.node_ip: r
                    for r in session.query(NodePositionORM).all()
                }
                for ip, pos in clean.items():
                    x, y = pos["x"], pos["y"]
                    if ip in existing:
                        existing[ip].x = x
                        existing[ip].y = y
                    else:
                        session.add(NodePositionORM(node_ip=ip, x=x, y=y))
        except Exception as e:
            return f"Error saving: {e}"
        return html.Span([
            f"Layout saved ({len(clean)} nodes)",
            html.Span(str(time.time()), style={"display": "none"}),
        ])


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _sanitize_text(s: str | None, max_len: int = 200) -> str | None:
    """Strip whitespace, strip control characters, truncate. Returns None if empty."""
    if not s:
        return None
    s = re.sub(r"[\x00-\x1f\x7f]", "", s).strip()[:max_len]
    return s or None


def _ip_matches_subnet_filter(ip: str, subnet_filter: str) -> bool:
    """Match an IP against a subnet filter.

    Supports three forms:
      - CIDR notation:  192.168.1.0/24  → standard network containment check
      - Wildcard:       192.168.1.*     → fnmatch glob on the IP string
      - Plain IP:       10.0.0.5        → exact equality
    Returns True (don't filter) when the filter string is malformed.
    """
    if not ip or not subnet_filter:
        return True
    if "*" in subnet_filter or "?" in subnet_filter:
        return fnmatch.fnmatch(ip, subnet_filter)
    if "/" in subnet_filter:
        return _ip_in_cidr(ip, subnet_filter)
    # Plain IP — exact match
    try:
        ipaddress.ip_address(subnet_filter)  # validate it's a real IP
        return ip == subnet_filter
    except ValueError:
        return True  # malformed input → don't filter anything
