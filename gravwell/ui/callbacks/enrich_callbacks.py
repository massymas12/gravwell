"""Callbacks for on-demand CVE enrichment (CISA KEV + FIRST.org EPSS)."""
from __future__ import annotations
import threading
import dash
from dash import Input, Output, html, no_update
from flask import current_app
from gravwell.models.enrichment import enrich_cves

_lock = threading.Lock()
_state: dict = {"running": False, "message": ""}


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("enrich-status", "children"),
        Input("enrich-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def start_enrich(n_clicks):
        if not n_clicks:
            return no_update
        with _lock:
            if _state["running"]:
                return html.Span("Already running...", style={"color": "#888",
                                                              "fontSize": "11px"})
            _state["running"] = True
            _state["message"] = "Starting..."

        db_path = current_app.config["GRAVWELL_DB_PATH"]

        def _run():
            def _cb(msg: str) -> None:
                with _lock:
                    _state["message"] = msg
            try:
                stats = enrich_cves(db_path, progress_cb=_cb)
                msg = (
                    f"Done: {stats['kev_count']} KEV, "
                    f"{stats['epss_count']} EPSS "
                    f"of {stats['cve_count']:,} CVEs"
                )
                with _lock:
                    _state["message"] = msg
            except Exception as e:
                with _lock:
                    _state["message"] = f"Error: {e}"
            finally:
                with _lock:
                    _state["running"] = False

        threading.Thread(target=_run, daemon=True).start()
        return html.Span("Fetching KEV + EPSS data...",
                         style={"color": "#5DADE2", "fontSize": "11px"})

    @app.callback(
        Output("enrich-status", "children", allow_duplicate=True),
        Input("refresh-interval", "n_intervals"),
        prevent_initial_call=True,
    )
    def poll_enrich(_):
        with _lock:
            msg = _state["message"]
            running = _state["running"]
        if not msg:
            return no_update
        color = "#5DADE2" if running else "#27AE60"
        return html.Span(msg, style={"color": color, "fontSize": "11px"})
