from __future__ import annotations
import os
import pathlib
import dash
from dash import Input, Output, State, no_update
from flask import current_app
from gravwell.database import init_db, drop_db
from gravwell.projects import list_projects, get_project_path, _DEFAULT_DB


def register(app: dash.Dash) -> None:

    @app.callback(
        Output("project-dropdown", "options"),
        Output("project-dropdown", "value"),
        Input("refresh-interval", "n_intervals"),
        Input("project-switch-trigger", "data"),
        prevent_initial_call=False,
    )
    def populate_projects(_n, _trigger):
        current_path = current_app.config.get("GRAVWELL_DB_PATH")
        projects = list_projects(current_path)
        options = [{"label": p["name"], "value": p["path"]} for p in projects]
        current_value = current_path if current_path else (options[0]["value"] if options else None)
        return options, current_value

    @app.callback(
        Output("project-switch-trigger", "data"),
        Input("project-dropdown", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def switch_project(selected_path, trigger):
        if not selected_path:
            return no_update
        current_path = current_app.config.get("GRAVWELL_DB_PATH")
        if selected_path == current_path:
            return no_update
        init_db(selected_path)
        current_app.config["GRAVWELL_DB_PATH"] = selected_path
        return (trigger or 0) + 1

    @app.callback(
        Output("new-project-row", "style"),
        Input("new-project-btn", "n_clicks"),
        State("new-project-row", "style"),
        prevent_initial_call=True,
    )
    def toggle_new_project_row(n_clicks, current_style):
        if not n_clicks:
            return no_update
        hidden = current_style is None or current_style.get("display") == "none"
        return {"display": "flex", "gap": "4px", "marginTop": "4px"} if hidden else {"display": "none"}

    @app.callback(
        Output("new-project-name", "value"),
        Output("new-project-row", "style", allow_duplicate=True),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("create-project-btn", "n_clicks"),
        Input("new-project-name", "n_submit"),
        State("new-project-name", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def create_project(n_clicks, n_submit, name, trigger):
        if not (n_clicks or n_submit) or not name or not name.strip():
            return no_update, no_update, no_update
        project_name = name.strip().replace(" ", "-").lower()
        db_path = get_project_path(project_name)
        init_db(db_path)
        current_app.config["GRAVWELL_DB_PATH"] = db_path
        return "", {"display": "none"}, (trigger or 0) + 1

    @app.callback(
        Output("delete-project-row", "style"),
        Input("delete-project-btn", "n_clicks"),
        Input("cancel-delete-project-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def toggle_delete_project_row(_del, _cancel):
        from dash import ctx
        if ctx.triggered_id == "delete-project-btn":
            return {"display": "flex", "alignItems": "center",
                    "gap": "4px", "marginTop": "4px"}
        return {"display": "none"}

    @app.callback(
        Output("delete-project-row", "style", allow_duplicate=True),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("confirm-delete-project-btn", "n_clicks"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def confirm_delete_project(n_clicks, trigger):
        if not n_clicks:
            return no_update, no_update

        current_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        # Never delete the default project
        import pathlib
        if pathlib.Path(current_path).resolve() == _DEFAULT_DB.resolve():
            return {"display": "none"}, no_update

        # Find another project to switch to before deleting
        projects = list_projects(current_path)
        remaining = [p for p in projects if p["path"] != current_path]

        if remaining:
            new_path = remaining[0]["path"]
        else:
            # Fall back to (or create) default project
            new_path = str(_DEFAULT_DB)
            init_db(new_path)

        # Switch to the new project first, then drop the old one.
        # drop_db() disposes the SQLAlchemy engine (required on Windows before
        # a file can be deleted) and removes the DB + WAL/SHM sibling files.
        current_app.config["GRAVWELL_DB_PATH"] = new_path
        drop_db(current_path)

        return {"display": "none"}, (trigger or 0) + 1

    @app.callback(
        Output("rename-project-row", "style"),
        Output("rename-project-name", "value"),
        Input("rename-project-btn", "n_clicks"),
        Input("cancel-rename-project-btn", "n_clicks"),
        State("project-dropdown", "value"),
        prevent_initial_call=True,
    )
    def toggle_rename_project_row(_ren, _cancel, current_path):
        from dash import ctx
        if ctx.triggered_id == "rename-project-btn":
            # Pre-fill with current project name; block rename of default
            if current_path and pathlib.Path(current_path).resolve() != _DEFAULT_DB.resolve():
                from gravwell.projects import project_name_from_path
                return ({"display": "flex", "gap": "4px", "marginTop": "4px"},
                        project_name_from_path(current_path))
        return {"display": "none"}, no_update

    @app.callback(
        Output("rename-project-name", "value", allow_duplicate=True),
        Output("rename-project-row", "style", allow_duplicate=True),
        Output("project-switch-trigger", "data", allow_duplicate=True),
        Input("confirm-rename-project-btn", "n_clicks"),
        Input("rename-project-name", "n_submit"),
        State("rename-project-name", "value"),
        State("project-switch-trigger", "data"),
        prevent_initial_call=True,
    )
    def confirm_rename_project(n_clicks, n_submit, new_name, trigger):
        if not (n_clicks or n_submit) or not new_name or not new_name.strip():
            return no_update, no_update, no_update

        current_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        if not current_path or pathlib.Path(current_path).resolve() == _DEFAULT_DB.resolve():
            return "", {"display": "none"}, no_update

        slug = new_name.strip().replace(" ", "-").lower()
        new_path = get_project_path(slug)

        if pathlib.Path(new_path).resolve() == pathlib.Path(current_path).resolve():
            return "", {"display": "none"}, no_update

        # Dispose engine before renaming on Windows (file lock)
        drop_db(current_path)
        # Rename the .db file (WAL/SHM already cleaned up by drop_db)
        os.replace(current_path, new_path)
        # Rename any SQLCipher keystore sibling if present
        for suffix in ("-wal", "-shm"):
            old_sib = current_path + suffix
            new_sib = new_path + suffix
            if pathlib.Path(old_sib).exists():
                os.replace(old_sib, new_sib)

        init_db(new_path)
        current_app.config["GRAVWELL_DB_PATH"] = new_path

        return "", {"display": "none"}, (trigger or 0) + 1
