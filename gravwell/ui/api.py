"""Flask API routes for the GravWell collection agent receiver.

Registered as a Blueprint on the Dash app's underlying Flask server.

Endpoints
---------
POST /api/agent/submit
    Accept a JSON payload from a running collect.py agent.
    Header: X-Gravwell-Key: <token>

GET  /api/agent/tokens
    List active API tokens (name + creation date, no raw values).
"""
from __future__ import annotations

import json
import logging
import pathlib
import tempfile

from flask import Blueprint, current_app, jsonify, request

from gravwell.database import get_session
from gravwell.models.ingestion import ingest_parse_result
from gravwell.models.orm import AgentTokenORM
from gravwell.parsers.agent import AgentParser

logger = logging.getLogger(__name__)

api_bp = Blueprint("agent_api", __name__)


# ── Auth helper ───────────────────────────────────────────────────────────────

def _validate_key(db_path: str, key: str) -> bool:
    if not key:
        return False
    with get_session(db_path) as session:
        return bool(
            session.query(AgentTokenORM)
            .filter_by(token=key, active=True)
            .first()
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@api_bp.route("/api/agent/submit", methods=["POST"])
def agent_submit():
    """Receive a collect.py agent payload and ingest it into the active project."""
    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    if not db_path:
        return jsonify(error="No active project on server"), 503

    key = request.headers.get("X-Gravwell-Key", "")
    if not _validate_key(db_path, key):
        return jsonify(error="Invalid or missing API key"), 401

    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 400

    data = request.get_json(force=True, silent=True)
    if not data or not data.get("gravwell_agent"):
        return jsonify(error="Not a GravWell agent payload"), 400

    # Write to a temp file so the standard parser pipeline can handle it
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
            "Agent submit from %s: +%d hosts, +%d vulns",
            agent_host, hosts_added, vulns_added,
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
    """Return the list of active agent API tokens (labels + dates, not raw values)."""
    db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
    if not db_path:
        return jsonify(tokens=[])
    with get_session(db_path) as session:
        tokens = (
            session.query(AgentTokenORM).filter_by(active=True).all()
        )
        return jsonify(tokens=[
            {"label": t.label, "created_at": str(t.created_at)}
            for t in tokens
        ])
