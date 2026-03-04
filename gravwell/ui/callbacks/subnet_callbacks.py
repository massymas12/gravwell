"""Callbacks for subnet compound-node label and size management."""
from __future__ import annotations
import dash
from dash import Input, Output, State, html, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import SubnetLabelORM

_DEFAULT_PADDING = 30


def _upsert_subnet_record(session, cidr: str, label: str | None = None,
                           box_padding: int | None = None) -> None:
    """Create or update a SubnetLabelORM row for cidr."""
    record = session.query(SubnetLabelORM).filter_by(subnet_cidr=cidr).first()
    if record is None:
        record = SubnetLabelORM(
            subnet_cidr=cidr,
            label=label or "",
            box_padding=box_padding if box_padding is not None else _DEFAULT_PADDING,
        )
        session.add(record)
    else:
        if label is not None:
            record.label = label
        if box_padding is not None:
            record.box_padding = box_padding


def register(app: dash.Dash) -> None:

    # ------------------------------------------------------------------
    # Show subnet panel and pre-fill inputs when a subnet is tapped
    # ------------------------------------------------------------------
    @app.callback(
        Output("subnet-selected-panel", "style"),
        Output("subnet-selected-info", "children"),
        Output("subnet-label-input", "value"),
        Output("subnet-padding-slider", "value"),
        Input("selected-subnet-store", "data"),
    )
    def show_subnet_panel(subnet_data):
        hidden = {"display": "none"}
        visible = {
            "display": "block",
            "background": "#1e2a2e",
            "border": "1px solid #444",
            "borderRadius": "4px",
            "padding": "6px 8px",
            "marginBottom": "6px",
        }
        if not subnet_data or not subnet_data.get("cidr"):
            return hidden, "", "", _DEFAULT_PADDING

        cidr = subnet_data["cidr"]
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            record = session.query(SubnetLabelORM).filter_by(
                subnet_cidr=cidr
            ).first()
            current_label = record.label if record else ""
            current_padding = record.box_padding if record else _DEFAULT_PADDING

        info = html.Span(
            f"Subnet: {cidr}",
            style={"fontSize": "11px", "color": "#888"},
        )
        return visible, info, current_label, current_padding

    # ------------------------------------------------------------------
    # Save (or clear) the label, trigger a graph refresh, close panel
    # ------------------------------------------------------------------
    @app.callback(
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Output("selected-subnet-store", "data", allow_duplicate=True),
        Input("save-subnet-label-btn", "n_clicks"),
        State("subnet-label-input", "value"),
        State("selected-subnet-store", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def save_subnet_label(n_clicks, label_value, subnet_data, trigger):
        if not n_clicks or not subnet_data:
            return no_update, no_update

        cidr = subnet_data.get("cidr")
        if not cidr:
            return no_update, no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            label_value = (label_value or "").strip()
            _upsert_subnet_record(session, cidr, label=label_value)
            session.commit()

        return (trigger or 0) + 1, {}  # {} clears store → hides panel

    # ------------------------------------------------------------------
    # Persist padding when the slider is released; live-update the graph
    # ------------------------------------------------------------------
    @app.callback(
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("subnet-padding-slider", "value"),
        State("selected-subnet-store", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def save_subnet_padding(padding_value, subnet_data, trigger):
        if padding_value is None or not subnet_data:
            return no_update

        cidr = subnet_data.get("cidr")
        if not cidr:
            return no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            _upsert_subnet_record(session, cidr,
                                  box_padding=int(padding_value))
            session.commit()

        return (trigger or 0) + 1
