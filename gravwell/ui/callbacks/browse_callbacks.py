"""Server-side file browser callbacks."""
from __future__ import annotations

import os
from pathlib import Path

import dash
from dash import Input, Output, State, html, no_update
from dash.exceptions import PreventUpdate

# Scan file extensions to show (directories always shown)
_SCAN_EXTS = {".xml", ".nessus", ".json", ".gnmap", ".txt"}


def _home_dir() -> str:
    return str(Path.home())


def _list_dir(path: str):
    """Return (dirs, files) for path, sorted; silently fallback to parent on error."""
    try:
        p = Path(path)
        if not p.is_dir():
            p = p.parent
        entries = list(p.iterdir())
    except PermissionError:
        return [], []

    dirs = sorted(
        [e for e in entries if e.is_dir()],
        key=lambda e: e.name.lower(),
    )
    files = sorted(
        [e for e in entries if e.is_file() and e.suffix.lower() in _SCAN_EXTS],
        key=lambda e: e.name.lower(),
    )
    return dirs, files


def _render_listing(dirs, files, current_path: str) -> list:
    """Build the file listing rows for the modal."""
    rows = []

    # Parent directory link
    parent = str(Path(current_path).parent)
    if parent != current_path:
        rows.append(
            html.Div(
                html.Button(
                    ".. (up)",
                    id={"type": "browse-dir-btn", "path": parent},
                    n_clicks=0,
                    style={
                        "background": "none",
                        "border": "none",
                        "color": "#5DADE2",
                        "cursor": "pointer",
                        "fontSize": "12px",
                        "padding": "4px 8px",
                        "width": "100%",
                        "textAlign": "left",
                        "fontFamily": "monospace",
                    },
                ),
                style={"borderBottom": "1px solid #2a2a2a"},
            )
        )

    for d in dirs:
        rows.append(
            html.Div(
                html.Button(
                    f"[D]  {d.name}",
                    id={"type": "browse-dir-btn", "path": str(d)},
                    n_clicks=0,
                    style={
                        "background": "none",
                        "border": "none",
                        "color": "#A78BFA",
                        "cursor": "pointer",
                        "fontSize": "12px",
                        "padding": "4px 8px",
                        "width": "100%",
                        "textAlign": "left",
                        "fontFamily": "monospace",
                    },
                ),
                style={"borderBottom": "1px solid #1e1e1e"},
            )
        )

    for f in files:
        rows.append(
            html.Div(
                html.Button(
                    f"      {f.name}",
                    id={"type": "browse-file-btn", "path": str(f)},
                    n_clicks=0,
                    style={
                        "background": "none",
                        "border": "none",
                        "color": "#ccc",
                        "cursor": "pointer",
                        "fontSize": "12px",
                        "padding": "4px 8px",
                        "width": "100%",
                        "textAlign": "left",
                        "fontFamily": "monospace",
                    },
                ),
                style={"borderBottom": "1px solid #1e1e1e"},
            )
        )

    if not dirs and not files:
        rows.append(
            html.Div(
                "No scan files found here.",
                style={"fontSize": "11px", "color": "#555",
                       "padding": "8px", "textAlign": "center"},
            )
        )

    return rows


def register(app: dash.Dash) -> None:

    # ── Open modal ──────────────────────────────────────────────────────────
    @app.callback(
        Output("browse-modal-overlay", "style"),
        Output("browse-dir-store", "data"),
        Input("open-browse-btn", "n_clicks"),
        State("import-path-input", "value"),
        prevent_initial_call=True,
    )
    def open_browser(n_clicks, current_input):
        if not n_clicks:
            raise PreventUpdate
        # Start in the directory of whatever is already typed, else home
        start = _home_dir()
        if current_input:
            p = Path(current_input)
            candidate = p.parent if p.is_file() else p
            if candidate.is_dir():
                start = str(candidate)
        return {"display": "flex"}, start

    # ── Close modal ─────────────────────────────────────────────────────────
    @app.callback(
        Output("browse-modal-overlay", "style", allow_duplicate=True),
        Input("browse-modal-close", "n_clicks"),
        prevent_initial_call=True,
    )
    def close_browser(_):
        return {"display": "none"}

    # ── Render listing when dir-store changes ───────────────────────────────
    @app.callback(
        Output("browse-file-list", "children"),
        Output("browse-current-path", "children"),
        Input("browse-dir-store", "data"),
        prevent_initial_call=True,
    )
    def render_listing(path):
        if not path:
            path = _home_dir()
        dirs, files = _list_dir(path)
        listing = _render_listing(dirs, files, path)
        return listing, path

    # ── Navigate into a directory ────────────────────────────────────────────
    @app.callback(
        Output("browse-dir-store", "data", allow_duplicate=True),
        Input({"type": "browse-dir-btn", "path": dash.ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def navigate_dir(n_clicks_list):
        # Dash fires pattern-matched callbacks when new components are added
        # to the DOM (with n_clicks=0). Guard against that.
        if not n_clicks_list or not any(n_clicks_list):
            raise PreventUpdate
        ctx = dash.callback_context
        if not ctx.triggered or not ctx.triggered_id:
            raise PreventUpdate
        # Only act on an actual click (value > 0)
        if ctx.triggered[0]["value"] == 0:
            raise PreventUpdate
        tid = ctx.triggered_id
        if isinstance(tid, dict) and tid.get("type") == "browse-dir-btn":
            return tid["path"]
        raise PreventUpdate

    # ── Select a file ────────────────────────────────────────────────────────
    @app.callback(
        Output("import-path-input", "value", allow_duplicate=True),
        Output("import-path-section", "style", allow_duplicate=True),
        Output("browse-modal-overlay", "style", allow_duplicate=True),
        Input({"type": "browse-file-btn", "path": dash.ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def select_file(n_clicks_list):
        if not n_clicks_list or not any(n_clicks_list):
            raise PreventUpdate
        ctx = dash.callback_context
        if not ctx.triggered or not ctx.triggered_id:
            raise PreventUpdate
        if ctx.triggered[0]["value"] == 0:
            raise PreventUpdate
        tid = ctx.triggered_id
        if isinstance(tid, dict) and tid.get("type") == "browse-file-btn":
            return (
                tid["path"],
                {"display": "block", "marginTop": "4px"},
                {"display": "none"},
            )
        raise PreventUpdate
