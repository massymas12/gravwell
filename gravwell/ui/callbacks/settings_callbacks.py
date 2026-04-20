from __future__ import annotations
import dash
from dash import Input, Output, State, no_update, html
from flask import current_app
from flask_login import current_user

_ALL_PERMS = ["edit", "import", "discover", "export"]
_PERM_LABELS = {
    "edit":     "Edit",
    "import":   "Import",
    "discover": "Discover",
    "export":   "Export",
}


def _badge(text: str, color: str, bg: str) -> html.Span:
    return html.Span(text, style={
        "display": "inline-block", "padding": "1px 7px",
        "borderRadius": "10px", "fontSize": "10px", "fontWeight": "600",
        "color": color, "background": bg, "marginRight": "3px",
    })


def _render_users_table() -> html.Div:
    """Build the RBAC user table from the current keystore."""
    import gravwell.keystore as ks_mod
    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    ks = ks_mod.load(db_path)
    users = ks.get("users", [])

    if not users:
        return html.Div("No users found.", style={"color": "#666", "fontSize": "12px"})

    # Table header
    header = html.Tr([
        html.Th(col, style={"padding": "6px 10px", "fontSize": "11px",
                             "color": "#5DADE2", "background": "#1a1a2e",
                             "borderBottom": "1px solid #333",
                             "whiteSpace": "nowrap"})
        for col in ("Username", "Role", "Permissions", "Projects", "Last Login", "")
    ])

    rows = []
    for u in users:
        uname     = u.get("username", "")
        is_admin  = u.get("is_admin", False)
        perms     = u.get("permissions") or (
            _ALL_PERMS if is_admin else ["edit", "import"]
        )
        projects  = u.get("allowed_projects") or ["*"]
        last_seen = (u.get("last_login") or "Never")[:16].replace("T", " ")

        # Role badge
        if is_admin:
            role_cell = _badge("Admin", "#1a1a2e", "#A78BFA")
        else:
            role_cell = _badge("User", "#1a1a2e", "#5DADE2")

        # Permission badges
        perm_badges = []
        for p in _ALL_PERMS:
            if is_admin or p in perms:
                perm_badges.append(_badge(_PERM_LABELS[p], "#fff", "#27AE60"))
            else:
                perm_badges.append(_badge(_PERM_LABELS[p], "#555", "#222"))
        perm_cell = html.Td(perm_badges,
                            style={"padding": "6px 10px", "whiteSpace": "nowrap"})

        # Project access
        if "*" in projects:
            proj_cell = html.Td(_badge("All", "#fff", "#2980B9"),
                                style={"padding": "6px 10px"})
        else:
            proj_cell = html.Td(
                [_badge(p, "#ccc", "#333") for p in projects],
                style={"padding": "6px 10px"},
            )

        # Delete button (prevent self-deletion)
        logged_in = current_user.username if current_user.is_authenticated else ""
        del_btn = html.Button(
            "×",
            id={"type": "delete-user-btn", "username": uname},
            n_clicks=0,
            title=f"Delete {uname}",
            disabled=(uname == logged_in),
            style={"background": "none", "border": "1px solid #555",
                   "color": "#E74C3C" if uname != logged_in else "#444",
                   "cursor": "pointer" if uname != logged_in else "not-allowed",
                   "borderRadius": "3px", "padding": "1px 6px", "fontSize": "13px"},
        )

        td = {"padding": "6px 10px", "borderBottom": "1px solid #222",
              "fontSize": "12px"}
        rows.append(html.Tr([
            html.Td(uname, style={**td, "color": "#ccc", "fontWeight": "500"}),
            html.Td(role_cell, style=td),
            perm_cell,
            proj_cell,
            html.Td(last_seen, style={**td, "color": "#666"}),
            html.Td(del_btn, style={**td, "textAlign": "center"}),
        ]))

    table = html.Table(
        [html.Thead(header), html.Tbody(rows)],
        style={"width": "100%", "borderCollapse": "collapse"},
    )
    note = html.Div(
        "Deleting a user does not affect their saved projects or scan data.",
        style={"fontSize": "10px", "color": "#555", "marginTop": "8px"},
    )
    return html.Div([table, note])


def _render_tokens_table() -> html.Div:
    """Build the agent tokens table for the current project."""
    from gravwell import agent_tokens as at
    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    tokens = at.list_for_project(db_path) if db_path else []

    if not tokens:
        return html.Div("No active tokens for this project.",
                        style={"color": "#666", "fontSize": "12px"})

    header = html.Tr([
        html.Th(col, style={"padding": "6px 10px", "fontSize": "11px",
                             "color": "#5DADE2", "background": "#1a1a2e",
                             "borderBottom": "1px solid #333"})
        for col in ("Label", "Created", "")
    ])
    rows = []
    for tok in tokens:
        label    = tok["label"]
        token_id = tok.get("id") or label   # fall back to label for legacy tokens
        revoke_btn = html.Button(
            "Revoke",
            id={"type": "revoke-token-btn", "token_id": token_id},
            n_clicks=0,
            style={"background": "none", "border": "1px solid #555",
                   "color": "#E74C3C", "cursor": "pointer",
                   "borderRadius": "3px", "padding": "1px 8px",
                   "fontSize": "11px"},
        )
        td = {"padding": "6px 10px", "borderBottom": "1px solid #222",
              "fontSize": "12px"}
        rows.append(html.Tr([
            html.Td(label, style={**td, "color": "#ccc", "fontWeight": "500"}),
            html.Td(str(tok["created_at"])[:16], style={**td, "color": "#666"}),
            html.Td(revoke_btn, style={**td, "textAlign": "center"}),
        ]))

    return html.Table(
        [html.Thead(header), html.Tbody(rows)],
        style={"width": "100%", "borderCollapse": "collapse"},
    )


def register(app: dash.Dash) -> None:

    # ── Populate user store on page load ─────────────────────────────────────

    @app.callback(
        Output("current-user-store", "data"),
        Input("refresh-interval", "n_intervals"),
    )
    def populate_user_store(_n):
        if not current_user.is_authenticated:
            return {"username": "", "is_admin": False, "permissions": []}
        return {
            "username":    current_user.username,
            "is_admin":    current_user.is_admin,
            "permissions": current_user.permissions,
        }

    # ── Hamburger header: username label + show/hide Add User item ────────────

    @app.callback(
        Output("hamburger-username", "children"),
        Output("add-user-menu-item", "style"),
        Output("manage-users-menu-item", "style"),
        Output("agent-tokens-menu-item", "style"),
        Output("export-csv-menu-item", "style"),
        Output("export-xlsx-menu-item", "style"),
        Output("export-png-menu-item", "style"),
        Input("current-user-store", "data"),
    )
    def update_hamburger_content(user_data):
        user_data = user_data or {}
        username = user_data.get("username", "")
        is_admin = user_data.get("is_admin", False)
        perms    = user_data.get("permissions", [])
        label = f"Signed in as {username}" if username else ""
        admin_style  = {"display": "block"} if is_admin else {"display": "none"}
        export_style = {"display": "block"} if (is_admin or "export" in perms) else {"display": "none"}
        return label, admin_style, admin_style, admin_style, export_style, export_style, export_style

    # ── Hamburger toggle (open / close) + backdrop ────────────────────────────

    @app.callback(
        Output("hamburger-menu", "style"),
        Output("hamburger-backdrop", "style"),
        Input("hamburger-btn", "n_clicks"),
        Input("hamburger-backdrop", "n_clicks"),
        State("hamburger-menu", "style"),
        prevent_initial_call=True,
    )
    def toggle_hamburger_menu(btn_clicks, backdrop_clicks, current_style):
        from dash import ctx
        is_open = current_style and current_style.get("display") != "none"
        if ctx.triggered_id == "hamburger-btn" and not is_open:
            return (
                {"display": "block"},
                {"display": "block", "position": "fixed", "top": 0, "left": 0,
                 "width": "100%", "height": "100%", "zIndex": 999},
            )
        return {"display": "none"}, {"display": "none"}

    # ── Open Add User modal, close hamburger, populate project list ───────────

    @app.callback(
        Output("add-user-modal-overlay", "style"),
        Output("hamburger-menu", "style", allow_duplicate=True),
        Output("hamburger-backdrop", "style", allow_duplicate=True),
        Output("add-user-project-list", "options"),
        Output("add-user-project-list", "value"),
        Input("add-user-menu-item", "n_clicks"),
        prevent_initial_call=True,
    )
    def open_add_user_modal(n_clicks):
        if not n_clicks:
            return no_update, no_update, no_update, no_update, no_update
        from gravwell.projects import list_projects
        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        projects = list_projects(db_path)
        options = [{"label": p["name"], "value": p["name"]} for p in projects]
        return (
            {"display": "flex"},
            {"display": "none"},
            {"display": "none"},
            options,
            [],
        )

    # ── Show/hide specific-projects checklist based on radio ─────────────────

    @app.callback(
        Output("add-user-project-list-wrap", "style"),
        Input("add-user-project-access", "value"),
    )
    def toggle_project_list(access):
        base = {"marginLeft": "18px", "marginBottom": "6px",
                "padding": "6px 8px", "background": "#161616",
                "borderRadius": "3px", "border": "1px solid #333"}
        return {**base, "display": "block"} if access == "specific" else {"display": "none"}

    # ── Grey-out permissions when Admin is checked ────────────────────────────

    @app.callback(
        Output("add-user-permissions", "inputStyle"),
        Output("add-user-permissions", "labelStyle"),
        Output("add-user-perms-note", "style"),
        Input("add-user-is-admin", "value"),
    )
    def toggle_perms_for_admin(is_admin_val):
        if is_admin_val:
            # Greyed-out — admin inherits all permissions
            ci = {"marginRight": "6px", "accentColor": "#555", "opacity": "0.4"}
            cl = {"color": "#555", "cursor": "default"}
            note = {"fontSize": "10px", "color": "#666",
                    "marginBottom": "4px", "display": "block"}
        else:
            ci = {"marginRight": "6px", "accentColor": "#5DADE2"}
            cl = {"color": "#ccc", "cursor": "pointer"}
            note = {"display": "none"}
        return ci, cl, note

    # ── Create user ───────────────────────────────────────────────────────────

    @app.callback(
        Output("add-user-modal-overlay", "style", allow_duplicate=True),
        Output("add-user-status", "children"),
        Output("add-user-username-input", "value"),
        Output("add-user-password-input", "value"),
        Output("add-user-is-admin", "value"),
        Output("add-user-permissions", "value"),
        Output("add-user-project-access", "value"),
        Output("add-user-project-list", "value", allow_duplicate=True),
        Input("confirm-add-user-btn", "n_clicks"),
        Input("cancel-add-user-btn", "n_clicks"),
        Input("add-user-modal-close", "n_clicks"),
        State("add-user-username-input", "value"),
        State("add-user-password-input", "value"),
        State("add-user-is-admin", "value"),
        State("add-user-permissions", "value"),
        State("add-user-project-access", "value"),
        State("add-user-project-list", "value"),
        prevent_initial_call=True,
    )
    def handle_add_user(confirm, cancel, close_btn,
                        username, password, is_admin_list,
                        perms, project_access, project_list):
        from dash import ctx
        triggered = ctx.triggered_id

        _reset = ("", "", [], ["edit", "import"], "all", [])

        if not current_user.is_authenticated or not current_user.is_admin:
            return no_update, "Permission denied.", *([no_update] * 6)

        if triggered in ("cancel-add-user-btn", "add-user-modal-close"):
            return {"display": "none"}, "", *_reset

        # Validate
        username = (username or "").strip()
        if not username:
            return no_update, "Username is required.", *([no_update] * 6)
        if not password:
            return no_update, "Password is required.", *([no_update] * 6)

        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        mek = current_app.config.get("GRAVWELL_MEK")
        if not mek:
            return no_update, "Session error — please log in again.", *([no_update] * 6)

        import gravwell.keystore as ks_mod

        is_admin = bool(is_admin_list)
        # Admins get all permissions regardless of checkboxes
        final_perms = ["edit", "import", "discover", "export"] if is_admin else (perms or [])
        final_projects = ["*"] if project_access == "all" else (project_list or ["*"])

        try:
            ks_mod.add_user(db_path, username, password, mek,
                            is_admin=is_admin,
                            permissions=final_perms,
                            allowed_projects=final_projects)
        except ValueError as exc:
            return no_update, str(exc), *([no_update] * 6)
        except Exception as exc:
            return no_update, f"Error: {exc}", *([no_update] * 6)

        return {"display": "none"}, "", *_reset

    # ── Manage Users: open modal, populate table ──────────────────────────────

    @app.callback(
        Output("manage-users-modal-overlay", "style"),
        Output("hamburger-menu", "style", allow_duplicate=True),
        Output("hamburger-backdrop", "style", allow_duplicate=True),
        Output("manage-users-content", "children"),
        Input("manage-users-menu-item", "n_clicks"),
        prevent_initial_call=True,
    )
    def open_manage_users(n_clicks):
        if not current_user.is_authenticated or not current_user.is_admin:
            return no_update, no_update, no_update, no_update
        if not n_clicks:
            return no_update, no_update, no_update, no_update
        content = _render_users_table()
        return (
            {"display": "flex"},
            {"display": "none"},
            {"display": "none"},
            content,
        )

    @app.callback(
        Output("manage-users-modal-overlay", "style", allow_duplicate=True),
        Input("manage-users-modal-close", "n_clicks"),
        Input("manage-users-close-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def close_manage_users(close_x, close_btn):
        return {"display": "none"}

    @app.callback(
        Output("manage-users-content", "children", allow_duplicate=True),
        Output("manage-users-status", "children"),
        Input({"type": "delete-user-btn", "username": dash.ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def delete_user(n_clicks_list):
        from dash import ctx
        if not current_user.is_authenticated or not current_user.is_admin:
            return no_update, no_update
        if not any(n_clicks_list):
            return no_update, no_update
        triggered = ctx.triggered_id
        if not triggered:
            return no_update, no_update
        username = triggered.get("username", "")
        if not username:
            return no_update, no_update
        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        import gravwell.keystore as ks_mod
        try:
            ks_mod.delete_user(db_path, username)
        except Exception as exc:
            return no_update, f"Error: {exc}"
        return _render_users_table(), f"User '{username}' deleted."

    # ── Agent Tokens: open modal ──────────────────────────────────────────────

    @app.callback(
        Output("agent-tokens-modal-overlay", "style"),
        Output("hamburger-menu", "style", allow_duplicate=True),
        Output("hamburger-backdrop", "style", allow_duplicate=True),
        Output("agent-tokens-content", "children"),
        Output("agent-tokens-new-token", "children"),
        Output("agent-tokens-status", "children"),
        Output("agent-server-url", "children"),
        Output("agent-deploy-cmd", "children"),
        Input("agent-tokens-menu-item", "n_clicks"),
        prevent_initial_call=True,
    )
    def open_agent_tokens_modal(n_clicks):
        if not current_user.is_authenticated or not current_user.is_admin:
            return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
        if not n_clicks:
            return no_update, no_update, no_update, no_update, no_update, no_update, no_update, no_update
        from flask import request as flask_request
        server_url = flask_request.host_url.rstrip("/")
        url_div = html.Div([
            html.Span("Server URL: ", style={"color": "#aaa"}),
            html.Code(server_url, style={"color": "#5DADE2", "userSelect": "all"}),
        ])
        cmd_div = html.Div([
            html.Div("Example usage (Python script):",
                     style={"color": "#aaa", "marginBottom": "3px"}),
            html.Code(
                f"python gravwell-collect.py --server {server_url} --key YOUR_TOKEN",
                style={"display": "block", "background": "#0d1117",
                       "color": "#ccc", "padding": "5px 8px",
                       "borderRadius": "3px", "fontSize": "10px",
                       "wordBreak": "break-all"},
            ),
        ])
        return (
            {"display": "flex"},
            {"display": "none"},
            {"display": "none"},
            _render_tokens_table(),
            "",
            "",
            url_div,
            cmd_div,
        )

    @app.callback(
        Output("agent-tokens-modal-overlay", "style", allow_duplicate=True),
        Input("agent-tokens-modal-close", "n_clicks"),
        Input("agent-tokens-close-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def close_agent_tokens_modal(_close, _btn):
        return {"display": "none"}

    @app.callback(
        Output("agent-tokens-content", "children", allow_duplicate=True),
        Output("agent-tokens-new-token", "children", allow_duplicate=True),
        Output("agent-tokens-status", "children", allow_duplicate=True),
        Output("_build-server-store", "children"),
        Output("_build-token-store", "children"),
        Output("build-configured-btn", "style"),
        Output("build-configured-btn", "children"),
        Input("generate-token-btn", "n_clicks"),
        Input({"type": "revoke-token-btn", "token_id": dash.ALL}, "n_clicks"),
        State("new-token-label-input", "value"),
        prevent_initial_call=True,
    )
    def manage_agent_tokens(gen_clicks, revoke_clicks_list, label_value):
        from dash import ctx
        _nu8 = (no_update,) * 8
        if not current_user.is_authenticated or not current_user.is_admin:
            return _nu8

        from gravwell import agent_tokens as at
        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        if not db_path:
            return no_update, no_update, "No active project.", no_update, no_update, no_update, no_update

        triggered = ctx.triggered_id

        # Generate new token — show it once + arm pre-configured download links
        if triggered == "generate-token-btn":
            from flask import request as flask_request
            import urllib.parse
            label = (label_value or "default").strip() or "default"
            plain = at.create_token(label, db_path)
            server_url = flask_request.host_url.rstrip("/")

            py_url = (f"/api/agent/download/py?"
                      f"server={urllib.parse.quote(server_url)}"
                      f"&token={urllib.parse.quote(plain)}")

            _abtn = {"background": "#1a2a1a", "border": "1px solid #27AE60",
                     "color": "#27AE60", "cursor": "pointer", "borderRadius": "3px",
                     "padding": "3px 10px", "fontSize": "11px",
                     "textDecoration": "none", "display": "inline-block"}

            token_display = html.Div([
                html.Div("New token — copy it now, it will not be shown again:",
                         style={"fontSize": "11px", "color": "#E67E22",
                                "marginBottom": "4px"}),
                html.Code(plain, style={
                    "display": "block", "background": "#0d1117",
                    "color": "#27AE60", "padding": "6px 8px",
                    "borderRadius": "3px", "fontSize": "11px",
                    "wordBreak": "break-all", "userSelect": "all",
                }),
                html.Div([
                    html.Span("Pre-configured downloads (token baked in): ",
                              style={"fontSize": "11px", "color": "#aaa"}),
                    html.A("↓ Python script", href=py_url, target="_blank",
                           style=_abtn),
                ], style={"marginTop": "6px", "display": "flex",
                          "alignItems": "center", "gap": "8px"}),
            ])

            build_btn_style = {
                "background": "#1a2a1a", "border": "1px solid #27AE60",
                "color": "#27AE60", "cursor": "pointer", "borderRadius": "3px",
                "padding": "3px 10px", "fontSize": "11px",
            }
            return (_render_tokens_table(), token_display,
                    f"Token '{label}' created.",
                    server_url, plain, build_btn_style,
                    "↓ Build pre-configured binary (this platform)")

        # Revoke token (by unique ID — never revokes more than one)
        if isinstance(triggered, dict) and triggered.get("type") == "revoke-token-btn":
            if not any(revoke_clicks_list):
                return _nu8
            token_id = triggered.get("token_id", "")
            if token_id:
                at.revoke_by_id(token_id, db_path)
            return (_render_tokens_table(), "", f"Token revoked.",
                    no_update, no_update, no_update, no_update)

        return _nu8

    # ── Build binary buttons (local-only and pre-configured) ──────────────────

    @app.callback(
        Output("agent-build-status", "children"),
        Input("build-local-btn", "n_clicks"),
        Input("build-configured-btn", "n_clicks"),
        State("_build-server-store", "children"),
        State("_build-token-store", "children"),
        prevent_initial_call=True,
    )
    def trigger_agent_build(local_clicks, configured_clicks,
                            stored_server, stored_token):
        from dash import ctx
        import base64, json as _json, shutil, subprocess, sys, tempfile
        import pathlib as _pathlib

        if not current_user.is_authenticated or not current_user.is_admin:
            return html.Span("Permission denied.", style={"color": "#E74C3C"})

        triggered = ctx.triggered_id
        if triggered == "build-local-btn" and local_clicks:
            mode, server, token = "local", "", ""
        elif triggered == "build-configured-btn" and configured_clicks:
            mode   = "configured"
            server = stored_server or ""
            token  = stored_token  or ""
        else:
            return no_update

        if not shutil.which("pyinstaller"):
            return html.Span(
                "PyInstaller not installed on this server. "
                "Run: pip install pyinstaller",
                style={"color": "#E74C3C"},
            )

        from gravwell.ui.api import _generate_script, _AGENT_PY
        local_only = (mode == "local")
        source = _generate_script(server=server, token=token, local_only=local_only)
        exe_name = "gravwell-collect-local" if local_only else "gravwell-collect"

        try:
            with tempfile.TemporaryDirectory(prefix="gravwell_build_") as tmp:
                tmp_path = _pathlib.Path(tmp)
                src_file = tmp_path / "collect.py"
                src_file.write_text(source, encoding="utf-8")

                cmd = [
                    sys.executable, "-m", "PyInstaller",
                    "--onefile", "--clean", "--noconfirm",
                    "--name", exe_name,
                    "--distpath", str(tmp_path / "dist"),
                    "--workpath", str(tmp_path / "build"),
                    "--specpath", str(tmp_path),
                    "--hidden-import", "xml.etree.ElementTree",
                    "--hidden-import", "ssl",
                    "--hidden-import", "urllib.request",
                    str(src_file),
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300,
                    cwd=str(tmp_path),
                )
                if result.returncode != 0:
                    return html.Span(
                        f"Build failed: {result.stderr[-200:]}",
                        style={"color": "#E74C3C"},
                    )

                suffix = ".exe" if sys.platform == "win32" else ""
                out_file = tmp_path / "dist" / (exe_name + suffix)
                if not out_file.exists():
                    return html.Span("Build produced no output.",
                                     style={"color": "#E74C3C"})

                fname = exe_name + suffix
                b64 = base64.b64encode(out_file.read_bytes()).decode()
                data_url = f"data:application/octet-stream;base64,{b64}"

            return html.Div([
                html.Span("Build complete! ", style={"color": "#27AE60"}),
                html.A(f"Download {fname}", href=data_url, download=fname,
                       style={"color": "#5DADE2", "fontSize": "11px"}),
            ])
        except subprocess.TimeoutExpired:
            return html.Span("Build timed out after 5 minutes.",
                             style={"color": "#E74C3C"})
        except Exception as exc:
            return html.Span(f"Build error: {exc}", style={"color": "#E74C3C"})
