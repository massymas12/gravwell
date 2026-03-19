from __future__ import annotations
import dash
from dash import Input, Output
from sqlalchemy import func
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import HostORM, VulnerabilityORM


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("filter-hostname", "value"),
        Output("filter-subnet", "value"),
        Output("filter-os", "value"),
        Output("filter-severity", "value"),
        Output("filter-port-service", "value"),
        Input("reset-filters-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def reset_filters(_):
        return None, None, None, None, None

    @app.callback(
        Output("topbar-stats", "children"),
        Input("refresh-interval", "n_intervals"),
        Input("apply-filters-btn", "n_clicks"),
        Input("project-switch-trigger", "data"),
    )
    def update_stats(_, __, ___):
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                host_count = session.query(func.count(HostORM.id)).scalar() or 0
                vuln_count = session.query(
                    func.count(VulnerabilityORM.id)
                ).scalar() or 0
                crit_count = session.query(
                    func.count(VulnerabilityORM.id)
                ).filter_by(severity="critical").scalar() or 0
            return (f" | {host_count} hosts | {vuln_count} vulns "
                    f"({crit_count} critical)")
        except Exception:
            return " | No data"
