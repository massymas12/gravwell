"""Callbacks for the built-in active discovery panel."""
from __future__ import annotations
import dash
from dash import Input, Output, State, html, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.ingestion import ingest_parse_result


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("discover-status", "children"),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("discover-btn", "n_clicks"),
        State("discover-target", "value"),
        State("discover-methods", "value"),
        State("discover-snmp-community", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def run_discovery(n_clicks, target, methods, community, trigger):
        if not target or not target.strip():
            return html.Span("Enter a target CIDR or IP.", style={"color": "#E74C3C"}), no_update

        from gravwell.discovery.runner import discover, DiscoveryConfig

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        methods = methods or ["ping", "arp", "tcp"]
        comm = (community or "public").strip() or "public"

        cfg = DiscoveryConfig(
            target=target.strip(),
            methods=methods,
            snmp_community=comm,
        )

        try:
            result = discover(cfg)
        except ValueError as e:
            return html.Span(str(e), style={"color": "#E74C3C"}), no_update
        except Exception as e:
            return html.Span(f"Discovery error: {e}", style={"color": "#E74C3C"}), no_update

        if not result.hosts:
            return html.Span("No hosts found.", style={"color": "#888"}), no_update

        pr = result.to_parse_result()
        try:
            with get_session(db_path) as session:
                h_count, v_count, already = ingest_parse_result(session, pr)
        except Exception as e:
            return html.Span(f"Ingest error: {e}", style={"color": "#E74C3C"}), no_update

        counts = "  ".join(f"{k}={v}" for k, v in result.method_counts.items())
        msg = (
            f"{'Already ingested' if already else 'Ingested'}: "
            f"{h_count} hosts, {v_count} vulns  ({counts})"
        )
        warnings_div = html.Div(
            [html.Div(w, style={"color": "#E67E22", "fontSize": "10px"})
             for w in result.warnings],
        ) if result.warnings else None
        return (
            html.Div([
                html.Div(f"✓ {msg}", style={"color": "#27AE60"}),
                html.Div(
                    f"{len(result.hosts)} total discovered",
                    style={"color": "#888", "fontSize": "10px"},
                ),
                warnings_div,
            ]),
            (trigger or 0) + 1,
        )

    # ── Passive listener — separate blocking callback ─────────────────────
    @app.callback(
        Output("passive-listen-status", "children"),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("passive-listen-btn", "n_clicks"),
        State("passive-interface", "value"),
        State("passive-duration", "value"),
        State("discover-target", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def run_passive_listen(n_clicks, interface, duration, target, trigger):
        if not interface or not interface.strip():
            return html.Span(
                "Enter a network interface name.",
                style={"color": "#E74C3C"},
            ), no_update

        from gravwell.discovery.passive import passive_listen
        from gravwell.models.dataclasses import ParseResult

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        dur = float(duration or 30)
        net = (target or "").strip() or None

        try:
            hosts = passive_listen(interface.strip(), duration=dur, target_net=net)
        except RuntimeError as e:
            return html.Span(str(e), style={"color": "#E74C3C",
                                            "whiteSpace": "pre-wrap"}), no_update
        except Exception as e:
            return html.Span(f"Passive listen error: {e}",
                             style={"color": "#E74C3C"}), no_update

        if not hosts:
            return html.Span(
                f"No hosts observed in {dur:.0f}s on '{interface.strip()}'.",
                style={"color": "#888"},
            ), no_update

        pr = ParseResult(
            hosts=hosts,
            source_file="discovery:passive",
            parser_name="discovery",
        )
        try:
            with get_session(db_path) as session:
                h_count, _, already = ingest_parse_result(session, pr)
        except Exception as e:
            return html.Span(f"Ingest error: {e}",
                             style={"color": "#E74C3C"}), no_update

        msg = (f"{'Already ingested' if already else 'Ingested'}: "
               f"{h_count} of {len(hosts)} hosts from passive listen")
        return (
            html.Div(f"✓ {msg}", style={"color": "#27AE60"}),
            (trigger or 0) + 1,
        )
