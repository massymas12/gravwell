from __future__ import annotations
import json
import dash
from dash import Input, Output, State, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import HostORM, HostRoleOverrideORM
from gravwell.models.ingestion import _update_host_aggregates
from gravwell.graph.builder import _classify_roles, _is_domain_controller, _is_legacy

_MODAL_SHOWN  = {"display": "flex"}
_MODAL_HIDDEN = {"display": "none"}


def register(app: dash.Dash) -> None:

    # ── Show/hide the "Edit Node" button based on selection ───────────────
    @app.callback(
        Output("edit-btn", "style"),
        Input("selected-node-store", "data"),
        prevent_initial_call=False,
    )
    def toggle_edit_button(node_store):
        if node_store and node_store.get("ip"):
            return {"display": "inline-block"}
        return {"display": "none"}

    # ── Open modal and populate fields ────────────────────────────────────
    @app.callback(
        Output("edit-modal-overlay",    "style"),
        Output("edit-modal-ip",         "children"),
        Output("edit-hostnames",        "value"),
        Output("edit-os-name",          "value"),
        Output("edit-os-family",        "value"),
        Output("edit-status",           "value"),
        Output("edit-mac",              "value"),
        Output("edit-mac-vendor",       "value"),
        Output("edit-additional-ips",   "value"),
        Output("edit-domain",           "value"),
        Output("edit-tags",             "value"),
        Output("edit-roles",            "value"),
        Output("edit-subnet-override",  "value"),
        Output("edit-save-status",      "children"),
        Input("edit-btn", "n_clicks"),
        State("selected-node-store", "data"),
        prevent_initial_call=True,
    )
    def open_edit_modal(n_clicks, node_store):
        _nu = no_update
        _empty = (_nu,) * 14
        if not n_clicks or not node_store:
            return _empty
        ip = node_store.get("ip")
        if not ip:
            return _empty

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if not host:
                return _empty
            hostnames       = ", ".join(host.hostnames or [])
            os_name         = host.os_name or ""
            os_family       = host.os_family or "Unknown"
            status          = host.status or "up"
            mac             = host.mac or ""
            mac_vendor      = host.mac_vendor or ""
            all_tags        = host.tags or []
            domain_tags     = [t[len("domain:"):] for t in all_tags
                               if t.lower().startswith("domain:")]
            domain          = domain_tags[0] if domain_tags else ""
            other_tags      = [t for t in all_tags
                               if not t.lower().startswith("domain:")]
            tags            = ", ".join(other_tags)
            additional_ips  = ", ".join(host.additional_ips or [])
            subnet_override = host.subnet_override or ""

            # Load role override if present, else compute auto-detected roles
            override = session.query(HostRoleOverrideORM).filter_by(
                host_ip=ip
            ).first()
            if override:
                effective_roles = json.loads(override.roles_json or "[]")
            else:
                from gravwell.models.orm import ServiceORM
                open_ports = [
                    s.port for s in
                    session.query(ServiceORM).filter_by(host_id=host.id, state="open").all()
                ]
                port_set = set(open_ports)
                is_dc = _is_domain_controller(
                    {"open_ports": open_ports, "hostnames": host.hostnames}
                )
                auto_roles = _classify_roles(
                    port_set, os_family, mac_vendor, host.hostnames or [], is_dc
                )
                if is_dc and "dc" not in auto_roles:
                    auto_roles.append("dc")
                if _is_legacy(os_name):
                    auto_roles.append("legacy")
                effective_roles = auto_roles

        return (
            _MODAL_SHOWN, ip, hostnames, os_name, os_family, status,
            mac, mac_vendor, additional_ips, domain, tags, effective_roles,
            subnet_override, "",
        )

    # ── Close modal (× or Cancel) ─────────────────────────────────────────
    @app.callback(
        Output("edit-modal-overlay", "style", allow_duplicate=True),
        Input("edit-modal-close", "n_clicks"),
        Input("cancel-edit-btn",  "n_clicks"),
        prevent_initial_call=True,
    )
    def close_edit_modal(_close, _cancel):
        return _MODAL_HIDDEN

    # ── Save changes ──────────────────────────────────────────────────────
    @app.callback(
        Output("edit-modal-overlay",    "style",    allow_duplicate=True),
        Output("edit-save-status",      "children", allow_duplicate=True),
        Output("project-switch-trigger", "data",    allow_duplicate=True),
        Input("save-edit-btn", "n_clicks"),
        State("edit-hostnames",       "value"),
        State("edit-os-name",         "value"),
        State("edit-os-family",       "value"),
        State("edit-status",          "value"),
        State("edit-mac",             "value"),
        State("edit-mac-vendor",      "value"),
        State("edit-additional-ips",  "value"),
        State("edit-domain",          "value"),
        State("edit-tags",            "value"),
        State("edit-roles",             "value"),
        State("edit-subnet-override",   "value"),
        State("selected-node-store",    "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def save_node_edits(n_clicks, hostnames_str, os_name, os_family, status,
                        mac, mac_vendor, additional_ips_str, domain_str,
                        tags_str, roles, subnet_override_str, node_store, trigger):
        if not n_clicks or not node_store:
            return no_update, no_update, no_update
        ip = node_store.get("ip")
        if not ip:
            return no_update, no_update, no_update

        def _split(s: str | None) -> list[str]:
            if not s:
                return []
            return [item.strip() for item in s.replace("\n", ",").split(",")
                    if item.strip()]

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                host = session.query(HostORM).filter_by(ip=ip).first()
                if not host:
                    return no_update, f"Host {ip} not found.", no_update
                host.hostnames      = _split(hostnames_str)
                host.os_name        = (os_name or "").strip() or None
                host.os_family      = os_family or "Unknown"
                host.status         = status or "up"
                host.mac            = (mac or "").strip() or None
                host.mac_vendor     = (mac_vendor or "").strip() or None
                host.additional_ips  = _split(additional_ips_str)
                other_tags = _split(tags_str)
                domain_clean = (domain_str or "").strip().upper()
                domain_tag = [f"domain:{domain_clean}"] if domain_clean else []
                host.tags = domain_tag + [t for t in other_tags
                                          if not t.lower().startswith("domain:")]
                host.subnet_override = (subnet_override_str or "").strip() or None
                _update_host_aggregates(session, host)

                # Save role overrides
                roles_list = roles or []
                override = session.query(HostRoleOverrideORM).filter_by(
                    host_ip=ip
                ).first()
                if override:
                    override.roles_json = json.dumps(roles_list)
                else:
                    session.add(HostRoleOverrideORM(
                        host_ip=ip,
                        roles_json=json.dumps(roles_list),
                    ))

                session.commit()
        except Exception as e:
            return no_update, f"Error: {e}", no_update

        return _MODAL_HIDDEN, "Saved.", (trigger or 0) + 1
