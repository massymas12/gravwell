"""Callbacks for manual edge manipulation (add / hide / restore connections)."""
from __future__ import annotations
import dash
from dash import Input, Output, State, html, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import CustomEdgeORM, HiddenEdgeORM


def register(app: dash.Dash) -> None:

    # ------------------------------------------------------------------
    # Add-edge mode state machine
    #
    # Triggered by:
    #   • "+ Edge" button    → activate mode (source_ip = None)
    #   • "Cancel" button    → deactivate mode
    #   • tapNodeData        → record source on first click, create edge on second
    # ------------------------------------------------------------------
    @app.callback(
        Output("edge-add-mode", "data"),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("add-edge-btn", "n_clicks"),
        Input("cancel-add-edge-btn", "n_clicks"),
        Input("network-graph", "tapNodeData"),
        State("edge-add-mode", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def handle_add_edge(add_clicks, cancel_clicks, tap_node, mode, trigger):
        ctx = dash.callback_context
        if not ctx.triggered:
            return no_update, no_update

        trigger_id = ctx.triggered[0]["prop_id"].split(".")[0]

        if trigger_id == "add-edge-btn":
            return {"active": True, "source_ip": None}, no_update

        if trigger_id == "cancel-add-edge-btn":
            return {"active": False, "source_ip": None}, no_update

        # tapNodeData — only act if add mode is active
        if trigger_id == "network-graph":
            if not mode or not mode.get("active"):
                return no_update, no_update
            if not tap_node or tap_node.get("node_type") != "host":
                return no_update, no_update

            ip = tap_node.get("ip")
            if not ip:
                return no_update, no_update

            source_ip = mode.get("source_ip")
            if not source_ip:
                # First click — record source
                return {"active": True, "source_ip": ip}, no_update

            # Second click — create the edge
            if source_ip == ip:
                return no_update, no_update  # same node, ignore

            db_path = current_app.config["GRAVWELL_DB_PATH"]
            with get_session(db_path) as session:
                exists = session.query(CustomEdgeORM).filter_by(
                    source_ip=source_ip, target_ip=ip
                ).first()
                if not exists:
                    session.add(CustomEdgeORM(source_ip=source_ip, target_ip=ip))
                    session.commit()

            return {"active": False, "source_ip": None}, (trigger or 0) + 1

        return no_update, no_update

    # ------------------------------------------------------------------
    # Update toolbar status text and Cancel button visibility
    # ------------------------------------------------------------------
    @app.callback(
        Output("edge-add-status", "children"),
        Output("cancel-add-edge-btn", "style"),
        Input("edge-add-mode", "data"),
    )
    def update_add_edge_ui(mode):
        hidden = {"display": "none"}
        visible = {}
        if not mode or not mode.get("active"):
            return "", hidden
        source_ip = mode.get("source_ip")
        if not source_ip:
            return "Click source node...", visible
        return f"From {source_ip} \u2192 click target...", visible

    # ------------------------------------------------------------------
    # Show / hide the edge-selected panel when an edge is tapped
    # ------------------------------------------------------------------
    @app.callback(
        Output("edge-selected-panel", "style"),
        Output("edge-selected-info", "children"),
        Input("selected-edge-store", "data"),
    )
    def show_edge_panel(edge_data):
        hidden = {"display": "none"}
        visible = {
            "display": "block",
            "background": "#1e2a1e",
            "border": "1px solid #2E7D32",
            "borderRadius": "4px",
            "padding": "6px 8px",
            "marginBottom": "6px",
        }
        if not edge_data or not edge_data.get("id"):
            return hidden, ""

        src = edge_data.get("source", "?")
        tgt = edge_data.get("target", "?")
        etype = edge_data.get("edge_type", "")
        type_label = {
            "custom": "Custom edge",
            "intra_subnet": "Intra-subnet link",
            "inter_subnet": "Inter-subnet link",
        }.get(etype, "Connection")

        info = html.Div([
            html.B(f"{type_label}: ", style={"color": "#81C784"}),
            html.Span(f"{src}"),
            html.Span(" \u2192 ", style={"color": "#888"}),
            html.Span(f"{tgt}"),
        ], style={"fontSize": "12px"})

        return visible, info

    # ------------------------------------------------------------------
    # Delete / hide edge — also clears the selection so the panel closes
    # ------------------------------------------------------------------
    @app.callback(
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Output("selected-edge-store", "data", allow_duplicate=True),
        Input("delete-edge-btn", "n_clicks"),
        State("selected-edge-store", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def delete_edge(n_clicks, edge_data, trigger):
        if not n_clicks or not edge_data:
            return no_update, no_update

        edge_id = edge_data.get("id", "")
        source = edge_data.get("source", "")
        target = edge_data.get("target", "")
        if not edge_id:
            return no_update, no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]

        if edge_id.startswith("custom_"):
            with get_session(db_path) as session:
                session.query(CustomEdgeORM).filter_by(
                    source_ip=source, target_ip=target
                ).delete()
                session.commit()
        else:
            with get_session(db_path) as session:
                exists = session.query(HiddenEdgeORM).filter_by(
                    edge_id=edge_id
                ).first()
                if not exists:
                    session.add(HiddenEdgeORM(
                        edge_id=edge_id,
                        source_id=source,
                        target_id=target,
                    ))
                    session.commit()

        # Clear selection → hides the panel
        return (trigger or 0) + 1, {}

    # ------------------------------------------------------------------
    # Restore all hidden edges — also clears selection
    # ------------------------------------------------------------------
    @app.callback(
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Output("selected-edge-store", "data", allow_duplicate=True),
        Input("restore-edges-btn", "n_clicks"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def restore_all_hidden(n_clicks, trigger):
        if not n_clicks:
            return no_update, no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            session.query(HiddenEdgeORM).delete()
            session.commit()

        return (trigger or 0) + 1, {}
