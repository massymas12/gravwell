from __future__ import annotations
import base64
import gc
import os
import tempfile
import threading
from pathlib import Path

import dash
from dash import Input, Output, State, html, no_update
from flask import current_app

from gravwell.database import get_session
from gravwell.parsers.registry import ParserRegistry
from gravwell.models.ingestion import ingest_parse_result
from gravwell.models.orm import ScanFileORM, HostORM


# ── Module-level ingest state (shared between upload and polling callbacks) ────
_lock = threading.Lock()
_state: dict = {
    "total":    0,
    "done":     0,
    "current":  "",
    "messages": [],     # list of (text, color) tuples
    "finished": False,
    "db_path":  "",
}


def _reset(total: int, db_path: str) -> None:
    with _lock:
        _state.update(
            total=total, done=0, current="", messages=[], finished=False, db_path=db_path
        )


def _advance(filename: str) -> None:
    with _lock:
        _state["current"] = filename


def _complete_file(msg: str, color: str) -> None:
    with _lock:
        _state["done"] += 1
        _state["messages"].append((msg, color))
        _state["current"] = ""


def _finish() -> None:
    with _lock:
        _state["finished"] = True
        _state["current"]  = ""


def _snapshot() -> dict:
    with _lock:
        return dict(_state)


# ── Background ingestion threads ──────────────────────────────────────────────

def _ingest_thread_path(file_paths: list[tuple[str, str]], db_path: str) -> None:
    """Ingest files directly from server-side disk paths.

    Unlike _ingest_thread there is no base64 decode and no temp file —
    the parser reads the file in-place.  This is the right path for large
    files (100 MB+) where browser upload would create 3× memory copies.
    """
    for _i, (filepath, display_name) in enumerate(file_paths):
        _advance(display_name)
        try:
            result = ParserRegistry.parse(Path(filepath), format=None)
            result.source_file = filepath  # keep real path so checksum works

            with get_session(db_path) as session:
                h_count, v_count, already = ingest_parse_result(session, result)

            if already:
                _complete_file(f"{display_name} — already ingested (skipped)", "#888")
            else:
                _complete_file(
                    f"{display_name} ({result.parser_name}) — "
                    f"{h_count} hosts, {v_count} vulns",
                    "#27AE60",
                )
        except MemoryError:
            _complete_file(f"{display_name}: file too large to process", "#E74C3C")
        except ValueError as e:
            _complete_file(f"{display_name}: {e}", "#E74C3C")
        except Exception as e:
            _complete_file(f"{display_name}: {type(e).__name__}: {e}", "#E74C3C")

    _finish()


def _ingest_thread(files_data: list[tuple[str, str]], db_path: str) -> None:
    """
    Process each (contents_b64, filename) pair sequentially and update _state.
    Runs in a daemon thread so it doesn't block the UI.
    Memory strategy: release base64 and decoded bytes immediately after writing
    to the temp file, before the parser loads the file.
    """
    for i, (contents, filename) in enumerate(files_data):
        # Release the reference in the list so the GC can reclaim the memory
        # of already-processed files as we work through the list.
        files_data[i] = (None, filename)  # type: ignore[assignment]

        _advance(filename)
        tmp_path = None
        try:
            _, content_string = contents.split(",", 1)
            del contents  # free the full data-URL string ASAP

            decoded = base64.b64decode(content_string)
            del content_string  # free base64 string before writing to disk

            suffix = Path(filename).suffix or ".xml"
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=suffix, prefix="gravwell_"
            ) as tmp:
                tmp.write(decoded)
                tmp_path = tmp.name
            del decoded  # free decoded bytes before parsing
            gc.collect()

            result = ParserRegistry.parse(Path(tmp_path), format=None)
            result.source_file = filename
            for host in result.hosts:
                host.source_files = [filename]

            with get_session(db_path) as session:
                h_count, v_count, already = ingest_parse_result(session, result)

            if already:
                _complete_file(
                    f"{filename} — already ingested (skipped)", "#888"
                )
            else:
                _complete_file(
                    f"{filename} ({result.parser_name}) — "
                    f"{h_count} hosts, {v_count} vulns",
                    "#27AE60",
                )

        except MemoryError:
            _complete_file(
                f"{filename}: file too large to process in memory", "#E74C3C"
            )
        except ValueError as e:
            _complete_file(f"{filename}: {e}", "#E74C3C")
        except Exception as e:
            _complete_file(f"{filename}: {type(e).__name__}: {e}", "#E74C3C")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    _finish()


# ── Progress bar renderer ──────────────────────────────────────────────────────

def _render_bar(snap: dict) -> tuple[dict, list]:
    """Return (div style, div children) for the progress bar element."""
    total   = snap["total"]
    done    = snap["done"]
    current = snap["current"]
    pct     = int(100 * done / total) if total > 0 else 0

    label_parts = [f"{done}/{total}"]
    if current:
        short = current if len(current) <= 28 else "..." + current[-26:]
        label_parts.append(short)

    children = [
        html.Div(
            html.Div(style={
                "width": f"{pct}%",
                "height": "4px",
                "background": "#27AE60",
                "borderRadius": "2px",
                "transition": "width 0.25s ease",
            }),
            style={
                "background": "#1a3a1a",
                "borderRadius": "2px",
                "height": "4px",
                "marginBottom": "3px",
                "overflow": "hidden",
            },
        ),
        html.Div(
            "  ".join(label_parts),
            style={
                "fontSize": "10px",
                "color": "#888",
                "overflow": "hidden",
                "textOverflow": "ellipsis",
                "whiteSpace": "nowrap",
            },
        ),
    ]
    style = {"display": "block", "marginBottom": "4px"}
    return style, children


def _render_final(messages: list[tuple[str, str]]) -> html.Div:
    return html.Div([
        html.Div(text, style={"color": color, "fontSize": "12px"})
        for text, color in messages
    ])


# ── Constants ──────────────────────────────────────────────────────────────────

# base64 is ~4/3× the raw size; 70 M chars ≈ 50 MB on disk.
# Files larger than this should use the path-import route to avoid OOM.
_LARGE_FILE_B64_CHARS = 70_000_000


# ── Dash callbacks ────────────────────────────────────────────────────────────

def register(app: dash.Dash) -> None:

    @app.callback(
        Output("upload-status", "children", allow_duplicate=True),
        Output("import-path-section", "style", allow_duplicate=True),
        Output("import-path-input", "value", allow_duplicate=True),
        Input("file-upload", "reject"),
        prevent_initial_call=True,
    )
    def handle_rejected_upload(rejected):
        """Fires when a file is rejected by dcc.Upload (e.g. exceeds max_size).
        The rejection happens at the JS level — readAsDataURL is never called,
        so no OOM risk. We just reveal the path-import section."""
        if not rejected:
            return no_update, no_update, no_update
        # rejected = [{"file": {"name": ..., "size": ...}, "errors": [...]}, ...]
        try:
            name = rejected[0]["file"]["name"]
            size_mb = rejected[0]["file"]["size"] // (1024 * 1024)
            hint = name
        except (KeyError, IndexError, TypeError):
            name, size_mb, hint = "file", 0, ""

        msg = html.Div([
            html.Div(
                f"'{name}' is too large for browser upload (~{size_mb} MB).",
                style={"color": "#E67E22", "fontSize": "12px",
                       "fontWeight": "bold"},
            ),
            html.Div(
                "Enter the full server path below and click Import.",
                style={"color": "#aaa", "fontSize": "11px", "marginTop": "2px"},
            ),
        ])
        return msg, {"display": "block", "marginTop": "4px"}, hint

    @app.callback(
        Output("upload-status", "children", allow_duplicate=True),
        Output("ingest-progress-interval", "disabled", allow_duplicate=True),
        Output("ingest-progress-bar", "style", allow_duplicate=True),
        Output("ingest-progress-bar", "children", allow_duplicate=True),
        Output("import-path-section", "style", allow_duplicate=True),
        Input("import-path-btn", "n_clicks"),
        State("import-path-input", "value"),
        prevent_initial_call=True,
    )
    def handle_path_import(n_clicks, filepath):
        """Import a file directly from a server-side path (no base64 overhead)."""
        if not n_clicks or not filepath:
            return no_update, no_update, no_update, no_update, no_update

        filepath = filepath.strip()
        if not os.path.isfile(filepath):
            return (
                html.Div(
                    f"File not found: {filepath}",
                    style={"fontSize": "12px", "color": "#E74C3C"},
                ),
                no_update, no_update, no_update, no_update,
            )

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        display_name = os.path.basename(filepath)
        _reset(1, db_path)

        t = threading.Thread(
            target=_ingest_thread_path,
            args=([(filepath, display_name)], db_path),
            daemon=True,
        )
        t.start()

        snap = _snapshot()
        bar_style, bar_children = _render_bar(snap)
        return (
            html.Div(
                f"Ingesting {display_name}...",
                style={"fontSize": "12px", "color": "#5DADE2"},
            ),
            False,
            bar_style,
            bar_children,
            {"display": "none"},  # hide path section once import starts
        )

    @app.callback(
        Output("upload-status", "children"),
        Output("ingest-progress-interval", "disabled"),
        Output("ingest-progress-bar", "style"),
        Output("ingest-progress-bar", "children"),
        Output("import-path-input", "value", allow_duplicate=True),
        Output("import-path-section", "style", allow_duplicate=True),
        Input("file-upload", "contents"),
        State("file-upload", "filename"),
        prevent_initial_call=True,
    )
    def handle_upload(contents_list, filenames):
        if not contents_list:
            return no_update, no_update, no_update, no_update, no_update, no_update

        # Split into small (browser-safe) and large files.
        small, large = [], []
        for contents, filename in zip(contents_list, filenames):
            if len(contents) > _LARGE_FILE_B64_CHARS:
                large.append(filename)
            else:
                small.append((contents, filename))

        _show_path = {"display": "block", "marginTop": "4px"}

        if large:
            # Can't safely process large files via base64 in-browser.
            # Reveal the path-import field so the user can paste the full path.
            names = ", ".join(large)
            size_mb = len(contents_list[filenames.index(large[0])]) // 1_400_000
            msg = html.Div([
                html.Div(
                    f"'{names}' is too large for browser upload (~{size_mb} MB).",
                    style={"color": "#E67E22", "fontSize": "12px",
                           "fontWeight": "bold"},
                ),
                html.Div(
                    "Enter the full server path below and click Import.",
                    style={"color": "#aaa", "fontSize": "11px",
                           "marginTop": "2px"},
                ),
            ])
            if not small:
                return msg, no_update, no_update, no_update, large[0], _show_path

            # Also process any small files that came along.

        db_path = current_app.config["GRAVWELL_DB_PATH"]
        n = len(small)
        _reset(n, db_path)

        files_data = list(small)
        t = threading.Thread(
            target=_ingest_thread,
            args=(files_data, db_path),
            daemon=True,
        )
        t.start()

        snap = _snapshot()
        bar_style, bar_children = _render_bar(snap)

        status_text = f"Ingesting {n} file{'s' if n != 1 else ''}..."
        section_style = no_update
        if large:
            status_text += f"  (skipped {len(large)} large file(s) — use path import)"
            section_style = _show_path

        return (
            html.Div(status_text, style={"fontSize": "12px", "color": "#5DADE2"}),
            False,
            bar_style,
            bar_children,
            no_update,
            section_style,
        )

    @app.callback(
        Output("ingest-progress-bar", "style",    allow_duplicate=True),
        Output("ingest-progress-bar", "children", allow_duplicate=True),
        Output("ingest-progress-interval", "disabled", allow_duplicate=True),
        Output("upload-status", "children",       allow_duplicate=True),
        Output("scan-file-list", "children",      allow_duplicate=True),
        Input("ingest-progress-interval", "n_intervals"),
        prevent_initial_call=True,
    )
    def poll_ingest_progress(_n):
        snap = _snapshot()

        if not snap["finished"]:
            bar_style, bar_children = _render_bar(snap)
            return bar_style, bar_children, False, no_update, no_update

        # Ingestion complete — hide bar, stop interval, show results
        db_path = snap["db_path"]
        return (
            {"display": "none"},
            [],
            True,           # disable the interval
            _render_final(snap["messages"]),
            _build_scan_file_list(db_path),
        )

    @app.callback(
        Output("scan-file-list", "children", allow_duplicate=True),
        Input("refresh-interval", "n_intervals"),
        Input("project-switch-trigger", "data"),
        prevent_initial_call="initial_duplicate",
    )
    def refresh_scan_list(_n, _trigger):
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        return _build_scan_file_list(db_path)

    @app.callback(
        Output("scan-file-list", "children", allow_duplicate=True),
        Input({"type": "delete-scan-btn", "index": dash.ALL}, "n_clicks"),
        prevent_initial_call=True,
    )
    def delete_scan_file(n_clicks_list):
        from dash import ctx
        if not any(n_clicks_list):
            return no_update
        triggered = ctx.triggered_id
        if not triggered:
            return no_update

        filename = triggered["index"]
        db_path = current_app.config["GRAVWELL_DB_PATH"]
        with get_session(db_path) as session:
            rec = session.query(ScanFileORM).filter_by(filename=filename).first()
            if rec:
                session.delete(rec)
            # Remove this file from all host source_files lists
            for host in session.query(HostORM).all():
                if filename in host.source_files:
                    host.source_files = [f for f in host.source_files if f != filename]
            session.commit()
        return _build_scan_file_list(db_path)


def _build_scan_file_list(db_path: str):
    try:
        with get_session(db_path) as session:
            files = session.query(ScanFileORM).order_by(
                ScanFileORM.ingested_at.desc()
            ).limit(15).all()
            rows = [
                {
                    "filename": f.filename,
                    "parser":   f.parser_name,
                    "hosts":    f.host_count,
                    "ts":       f.ingested_at.strftime("%m/%d %H:%M")
                                if f.ingested_at else "",
                }
                for f in files
            ]
    except Exception:
        return html.Div("No files yet.", style={"fontSize": "11px", "color": "#666"})

    if not rows:
        return html.Div("No files ingested yet.",
                        style={"fontSize": "11px", "color": "#666"})

    return html.Div([
        html.Div([
            html.Div([
                html.Div(r["filename"],
                         style={"fontWeight": "bold", "fontSize": "11px",
                                "overflow": "hidden", "textOverflow": "ellipsis",
                                "whiteSpace": "nowrap", "flex": "1",
                                "minWidth": "0"}),
                html.Button(
                    "×",
                    id={"type": "delete-scan-btn", "index": r["filename"]},
                    title=f"Remove {r['filename']}",
                    style={"background": "none", "border": "none",
                           "color": "#666", "cursor": "pointer",
                           "fontSize": "14px", "padding": "0 2px",
                           "lineHeight": "1", "flexShrink": "0"},
                    n_clicks=0,
                ),
            ], style={"display": "flex", "alignItems": "center", "gap": "4px"}),
            html.Div(
                f"{r['parser']} | {r['hosts']} hosts | {r['ts']}",
                style={"fontSize": "10px", "color": "#888"}
            ),
        ], style={"padding": "4px 0", "borderBottom": "1px solid #333"})
        for r in rows
    ])
