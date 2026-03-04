"""Callbacks for attaching network device configs to host nodes.

Supports Cisco IOS/NX-OS, Palo Alto PAN-OS, Fortinet FortiOS, and Juniper JunOS
configs. The appropriate parser is auto-selected based on the host's OS name.
"""
from __future__ import annotations
import base64
import json
import dash
from dash import Input, Output, State, html, no_update
from flask import current_app
from gravwell.database import get_session
from gravwell.models.orm import HostORM, ServiceORM, HostConfigORM, HostRoleOverrideORM
from gravwell.models.ingestion import _upsert_service, _update_host_aggregates
from gravwell.parsers.cisco import CiscoParser
from gravwell.parsers.paloalto import PaloAltoParser
from gravwell.parsers.fortinet import FortinetParser
from gravwell.parsers.juniper import JuniperParser


# ── OS-to-parser mapping ──────────────────────────────────────────────────────

_VENDOR_PARSERS = [
    # (os_name substrings,  mac_vendor substrings,  parser,       label)
    (["palo alto", "pan-os", "panos"],
     ["palo alto"],
     PaloAltoParser,
     "Drop / click to attach PAN-OS config"),

    (["fortinet", "fortios", "fortigate"],
     ["fortinet"],
     FortinetParser,
     "Drop / click to attach FortiOS config"),

    (["juniper", "junos", "juniper networks"],
     ["juniper"],
     JuniperParser,
     "Drop / click to attach JunOS config"),

    (["cisco", "ios", "nx-os", "ios-xe", "ios-xr"],
     ["cisco"],
     CiscoParser,
     "Drop / click to attach Cisco config"),
]
_DEFAULT_LABEL = "Drop / click to attach device config"


def _detect_parser(os_name: str | None, mac_vendor: str | None):
    """Return (parser_cls, upload_label) based on device OS / vendor strings."""
    os_lower  = (os_name  or "").lower()
    mac_lower = (mac_vendor or "").lower()
    for os_hints, mac_hints, parser_cls, label in _VENDOR_PARSERS:
        if any(h in os_lower for h in os_hints):
            return parser_cls, label
        if any(h in mac_lower for h in mac_hints):
            return parser_cls, label
    return CiscoParser, _DEFAULT_LABEL


def register(app: dash.Dash) -> None:

    # ------------------------------------------------------------------
    # Show/hide panel, set upload label, and show current file on selection
    # Only shown for network devices (os_family="Network" or router role)
    # ------------------------------------------------------------------
    @app.callback(
        Output("config-attach-panel", "style"),
        Output("config-current-file", "children"),
        Output("attach-config-status", "children"),
        Output("attach-config-label", "children"),
        Input("selected-node-store", "data"),
    )
    def show_config_panel(node_store):
        hidden = {"display": "none"}
        visible = {
            "display": "block",
            "background": "#1a2a1a",
            "border": "1px solid #2E7D32",
            "borderRadius": "4px",
            "padding": "6px 8px",
            "marginBottom": "6px",
        }
        if not node_store or not node_store.get("ip"):
            return hidden, "", "", _DEFAULT_LABEL

        ip = node_store["ip"]
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            host = session.query(HostORM).filter_by(ip=ip).first()
            if not host:
                return hidden, "", "", _DEFAULT_LABEL

            # Show for network devices (by OS family)
            is_network = (host.os_family or "").strip().lower() == "network"

            # Also show if the user has manually assigned "router" role
            if not is_network:
                override = session.query(HostRoleOverrideORM).filter_by(
                    host_ip=ip
                ).first()
                if override:
                    roles = json.loads(override.roles_json or "[]")
                    is_network = "router" in roles

            # Also show if MAC vendor matches a known routing device manufacturer
            if not is_network:
                mac_lower = (host.mac_vendor or "").lower()
                is_network = bool(mac_lower) and any(
                    any(h in mac_lower for h in mac_hints)
                    for _, mac_hints, _, _ in _VENDOR_PARSERS
                )

            if not is_network:
                return hidden, "", "", _DEFAULT_LABEL

            _, upload_label = _detect_parser(host.os_name, host.mac_vendor)

            record = session.query(HostConfigORM).filter_by(host_ip=ip).first()
            if record:
                file_label = html.Span(
                    f"Config: {record.filename}",
                    style={"color": "#27AE60"},
                )
            else:
                file_label = html.Span("No config attached", style={"color": "#555"})

        return visible, file_label, "", upload_label

    # ------------------------------------------------------------------
    # Parse and merge the uploaded config into the selected host
    # ------------------------------------------------------------------
    @app.callback(
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Output("attach-config-status", "children", allow_duplicate=True),
        Output("config-current-file", "children", allow_duplicate=True),
        Input("attach-config-upload", "contents"),
        State("attach-config-upload", "filename"),
        State("selected-node-store", "data"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def attach_config(contents, filename, node_store, trigger):
        if not contents or not node_store:
            return no_update, no_update, no_update

        selected_ip = node_store.get("ip")
        if not selected_ip:
            return no_update, no_update, no_update

        # Decode the upload
        try:
            _header, encoded = contents.split(",", 1)
            config_text = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        except Exception as e:
            return no_update, f"Decode error: {e}", no_update

        if not config_text.strip():
            return no_update, "Empty file.", no_update

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        try:
            with get_session(db_path) as session:
                host = session.query(HostORM).filter_by(ip=selected_ip).first()
                if not host:
                    return no_update, f"Host {selected_ip} not found.", no_update

                # Pick the right parser based on the host's known OS / vendor
                parser_cls, _ = _detect_parser(host.os_name, host.mac_vendor)
                parsed_hosts = parser_cls._parse_config(
                    config_text, filename or "config.txt"
                )

                # Find best matching host entry (by IP) or fall back to first
                parsed = next(
                    (h for h in parsed_hosts if h.ip == selected_ip),
                    parsed_hosts[0] if parsed_hosts else None,
                )

                if parsed:
                    # Merge OS info (config may refine the version string)
                    if parsed.os_name:
                        host.os_name = parsed.os_name
                        host.os_family = parsed.os_family or "Network"
                    if parsed.mac_vendor and not host.mac_vendor:
                        host.mac_vendor = parsed.mac_vendor

                    # Prepend device hostname if not already present
                    existing_hostnames = set(host.hostnames)
                    new_hostnames = host.hostnames[:]
                    for hn in parsed.hostnames:
                        if hn and hn not in existing_hostnames:
                            new_hostnames.insert(0, hn)
                    host.hostnames = new_hostnames

                    # Union tags
                    existing_tags = set(host.tags)
                    host.tags = host.tags + [
                        t for t in parsed.tags if t not in existing_tags
                    ]

                    # Upsert services discovered from config
                    for svc in parsed.services:
                        _upsert_service(session, host.id, svc)

                    _update_host_aggregates(session, host)

                # Store / replace the raw config
                record = session.query(HostConfigORM).filter_by(
                    host_ip=selected_ip
                ).first()
                if record:
                    record.config_text = config_text
                    record.filename = filename or "config.txt"
                else:
                    session.add(HostConfigORM(
                        host_ip=selected_ip,
                        filename=filename or "config.txt",
                        config_text=config_text,
                    ))
                session.commit()

        except Exception as e:
            return no_update, f"Error: {e}", no_update

        label = html.Span(
            f"Config: {filename}",
            style={"color": "#27AE60"},
        )
        return (trigger or 0) + 1, "Config attached.", label
