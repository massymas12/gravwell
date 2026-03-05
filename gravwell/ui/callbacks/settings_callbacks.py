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
        return label, admin_style, admin_style, export_style, export_style, export_style

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
