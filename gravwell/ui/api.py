"""Flask API routes for the GravWell collection agent receiver.

Registered as a Blueprint on the Dash app's underlying Flask server.

Endpoints
---------
POST /api/agent/submit
    Accept a JSON payload from a running collect.py agent.
    Header: X-Gravwell-Key: <token>

    Each token is bound to exactly one project database at creation time.
    Submission ALWAYS ingests into that bound project — it is unaffected by
    whichever project the web UI currently has open.

GET  /api/agent/tokens
    List active tokens for the current project (label + date, no secret values).
    Requires an authenticated browser session (same login as the web UI).
"""
from __future__ import annotations

import json
import logging
import pathlib
import tempfile

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user

from gravwell import agent_tokens
from gravwell.database import get_session
from gravwell.models.ingestion import ingest_parse_result
from gravwell.parsers.agent import AgentParser

logger = logging.getLogger(__name__)

api_bp = Blueprint("agent_api", __name__)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@api_bp.route("/api/agent/submit", methods=["POST"])
def agent_submit():
    """Receive a collect.py payload and ingest it into the token's bound project.

    The destination project is determined by the token itself — not by
    GRAVWELL_DB_PATH — so submission is immune to users switching projects
    in the web UI between agent calls.
    """
    key = request.headers.get("X-Gravwell-Key", "")
    db_path = agent_tokens.validate_token(key)
    if not db_path:
        # Return the same message for missing and invalid tokens to avoid
        # leaking whether a key exists at all.
        logger.warning("Agent submit rejected: invalid or missing key (remote=%s)", request.remote_addr)
        return jsonify(error="Invalid or missing API key"), 401

    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 400

    data = request.get_json(force=True, silent=True)
    if not data or not data.get("gravwell_agent"):
        return jsonify(error="Not a GravWell agent payload"), 400

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".agent.json", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            tmp_path = fh.name

        parse_result = AgentParser.parse(pathlib.Path(tmp_path))
        pathlib.Path(tmp_path).unlink(missing_ok=True)

        if parse_result.errors:
            return jsonify(error="; ".join(parse_result.errors)), 422

        with get_session(db_path) as session:
            hosts_added, vulns_added, already = ingest_parse_result(session, parse_result)

        agent_host = (data.get("self") or {}).get("hostname", "unknown")
        logger.info(
            "Agent submit from %s → project %s: +%d hosts, +%d vulns",
            agent_host, pathlib.Path(db_path).stem, hosts_added, vulns_added,
        )
        return jsonify(
            status="ok",
            agent_host=agent_host,
            hosts_added=hosts_added,
            vulns_added=vulns_added,
            already_ingested=already,
        )

    except Exception:
        logger.exception("Agent submit failed")
        return jsonify(error="Internal server error"), 500


@api_bp.route("/api/agent/tokens", methods=["GET"])
def list_tokens():
    """List active tokens for the current project.

    Requires an authenticated web UI session — unauthenticated requests
    receive 401 without any token information.
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    if not db_path:
        return jsonify(tokens=[])

    return jsonify(tokens=agent_tokens.list_for_project(db_path))


@api_bp.route("/api/agent/tokens", methods=["POST"])
def create_token():
    """Create a new agent token for the current project.

    Admin only. The plain token is returned once in the response — it
    cannot be recovered later (only the hash is stored).
    """
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify(error="Admin access required"), 403

    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    if not db_path:
        return jsonify(error="No active project"), 400

    body = request.get_json(silent=True) or {}
    label = (body.get("label") or "default").strip() or "default"

    token = agent_tokens.create_token(label, db_path)
    logger.info("Agent token created: label=%r project=%s by %s",
                label, pathlib.Path(db_path).stem, current_user.username)
    return jsonify(token=token, label=label), 201


@api_bp.route("/api/agent/tokens/<label>", methods=["DELETE"])
def revoke_token(label: str):
    """Revoke all tokens with the given label for the current project.

    Admin only.
    """
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify(error="Admin access required"), 403

    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    if not db_path:
        return jsonify(error="No active project"), 400

    changed = agent_tokens.revoke(label, db_path)
    if not changed:
        return jsonify(error=f"No active token with label '{label}'"), 404

    logger.info("Agent token revoked: label=%r project=%s by %s",
                label, pathlib.Path(db_path).stem, current_user.username)
    return jsonify(status="revoked", label=label)


# ── Agent binary / script download ────────────────────────────────────────────

_AGENT_PY = pathlib.Path(__file__).parent.parent / "agent" / "collect.py"

# Platform-specific pre-built binary locations (built by gravwell/agent/build.py)
_DIST_DIR = pathlib.Path(__file__).parent.parent.parent / "dist"


@api_bp.route("/api/agent/download/<fmt>", methods=["GET"])
def download_agent(fmt: str):
    """Download the collection agent.

    Requires an authenticated browser session.

    fmt=py   → collect.py Python script (always available)
    fmt=exe  → Windows .exe built by PyInstaller (if present in dist/)
    fmt=bin  → Linux/macOS binary built by PyInstaller (if present in dist/)
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    if fmt == "py":
        if not _AGENT_PY.exists():
            return jsonify(error="Agent script not found on server"), 404
        return send_file(
            _AGENT_PY,
            as_attachment=True,
            download_name="gravwell-collect.py",
            mimetype="text/x-python",
        )

    if fmt == "exe":
        exe = _DIST_DIR / "gravwell-collect.exe"
        if not exe.exists():
            return jsonify(error="Windows binary not found — run gravwell/agent/build.py on a Windows host first"), 404
        return send_file(
            exe,
            as_attachment=True,
            download_name="gravwell-collect.exe",
            mimetype="application/octet-stream",
        )

    if fmt == "bin":
        binary = _DIST_DIR / "gravwell-collect"
        if not binary.exists():
            return jsonify(error="Linux/macOS binary not found — run gravwell/agent/build.py on the target platform first"), 404
        return send_file(
            binary,
            as_attachment=True,
            download_name="gravwell-collect",
            mimetype="application/octet-stream",
        )

    return jsonify(error=f"Unknown format '{fmt}'. Use: py, exe, bin"), 400
