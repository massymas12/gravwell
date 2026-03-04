"""Callbacks for manually adding a host node via the right-click context menu."""
from __future__ import annotations
import ipaddress
import json
import dash
from dash import Input, Output, State, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import HostORM, NodePositionORM, ServiceORM, VulnerabilityORM

_HIDDEN = {"display": "none"}
_SHOWN  = {"display": "flex"}


def register(app: dash.Dash) -> None:

    # ── Open modal when JS writes position to the hidden trigger input ────
    @app.callback(
        Output("add-node-modal-overlay", "style"),
        Output("add-node-position-store", "data"),
        Output("add-node-ip",        "value"),
        Output("add-node-hostnames", "value"),
        Output("add-node-os-family", "value"),
        Output("add-node-status",    "value"),
        Output("add-node-subnet",    "value"),
        Output("add-node-error",     "children"),
        Input("_add-node-js-trigger", "value"),
        prevent_initial_call=True,
    )
    def open_add_node_modal(trigger_value):
        if not trigger_value:
            return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
        try:
            raw = json.loads(trigger_value)
            pos = {"x": raw["x"], "y": raw["y"]}  # strip the _t timestamp field
        except Exception:
            pos = None
        return _SHOWN, pos, "", "", "Unknown", "up", "", ""

    # ── Close via × or Cancel ─────────────────────────────────────────────
    @app.callback(
        Output("add-node-modal-overlay", "style", allow_duplicate=True),
        Input("add-node-modal-close", "n_clicks"),
        Input("cancel-add-node-btn",  "n_clicks"),
        prevent_initial_call=True,
    )
    def close_add_node_modal(_close, _cancel):
        return _HIDDEN

    # ── Save new host ─────────────────────────────────────────────────────
    @app.callback(
        Output("add-node-modal-overlay",  "style",    allow_duplicate=True),
        Output("add-node-error",          "children", allow_duplicate=True),
        Output("project-switch-trigger",  "data",     allow_duplicate=True),
        Input("confirm-add-node-btn", "n_clicks"),
        State("add-node-ip",            "value"),
        State("add-node-hostnames",     "value"),
        State("add-node-os-family",     "value"),
        State("add-node-status",        "value"),
        State("add-node-subnet",        "value"),
        State("add-node-position-store", "data"),
        State("project-switch-trigger",  "data"),
        prevent_initial_call=True,
    )
    def save_new_node(n_clicks, ip_raw, hostnames_raw, os_family, status,
                      subnet_raw, pos, trigger):
        if not n_clicks:
            return no_update, no_update, no_update

        ip = (ip_raw or "").strip()
        if not ip:
            return no_update, "IP address is required.", no_update

        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return no_update, f"'{ip}' is not a valid IP address.", no_update

        # Validate optional CIDR
        subnet_override = (subnet_raw or "").strip() or None
        if subnet_override:
            try:
                ipaddress.ip_network(subnet_override, strict=False)
            except ValueError:
                return no_update, f"'{subnet_override}' is not a valid CIDR.", no_update

        hostnames = [h.strip() for h in (hostnames_raw or "").split(",")
                     if h.strip()]

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                if session.query(HostORM).filter_by(ip=ip).first():
                    return no_update, f"{ip} already exists in the graph.", no_update

                host = HostORM(
                    ip=ip,
                    os_family=os_family or "Unknown",
                    status=status or "up",
                    subnet_override=subnet_override,
                )
                host.hostnames = hostnames
                session.add(host)
                session.flush()   # get host.id without committing yet

                if pos and pos.get("x") is not None and pos.get("y") is not None:
                    session.add(NodePositionORM(
                        node_ip=ip,
                        x=float(pos["x"]),
                        y=float(pos["y"]),
                    ))

                session.commit()
        except Exception as e:
            return no_update, f"Error: {e}", no_update

        return _HIDDEN, "", (trigger or 0) + 1

    # ── Show/hide delete section when a node is selected ─────────────────
    @app.callback(
        Output("delete-node-section", "style"),
        Output("delete-node-confirm-row", "style"),
        Input("selected-node-store", "data"),
        prevent_initial_call=False,
    )
    def toggle_delete_section(node_store):
        hidden_section = {"display": "none", "marginTop": "10px",
                          "borderTop": "1px solid #333", "paddingTop": "8px"}
        hidden_confirm = {"display": "none", "marginTop": "4px", "gap": "4px"}
        if not node_store or node_store.get("node_type") != "host":
            return hidden_section, hidden_confirm
        return {**hidden_section, "display": "block"}, hidden_confirm

    # ── Show confirmation row when Delete Node is clicked ────────────────
    @app.callback(
        Output("delete-node-confirm-row", "style", allow_duplicate=True),
        Input("delete-node-btn", "n_clicks"),
        Input("cancel-delete-node-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def show_delete_confirm(_del, _cancel):
        from dash import ctx
        if ctx.triggered_id == "delete-node-btn":
            return {"display": "flex", "marginTop": "4px", "gap": "4px",
                    "alignItems": "center"}
        return {"display": "none", "marginTop": "4px", "gap": "4px"}

    # ── Confirm deletion ──────────────────────────────────────────────────
    @app.callback(
        Output("selected-node-store", "data", allow_duplicate=True),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("confirm-delete-node-btn", "n_clicks"),
        State("selected-node-store", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def confirm_delete_node(n_clicks, node_store, trigger):
        if not n_clicks or not node_store:
            return no_update, no_update
        ip = node_store.get("ip")
        if not ip:
            return no_update, no_update
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if host:
                # NodePositionORM has no FK cascade — delete manually
                session.query(NodePositionORM).filter_by(node_ip=ip).delete()
                session.delete(host)
        return None, (trigger or 0) + 1

    # ── Delete node via JS right-click trigger ────────────────────────────
    @app.callback(
        Output("selected-node-store", "data", allow_duplicate=True),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("_delete-node-js-trigger", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def delete_node_from_js(trigger_value, graph_trigger):
        if not trigger_value:
            return no_update, no_update
        try:
            ip = json.loads(trigger_value).get("ip", "").strip()
        except Exception:
            return no_update, no_update
        if not ip:
            return no_update, no_update
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if host:
                session.query(NodePositionORM).filter_by(node_ip=ip).delete()
                session.delete(host)
        return None, (graph_trigger or 0) + 1
