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

from flask import Blueprint, current_app, jsonify, request
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
