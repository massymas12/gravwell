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

import gzip
import json
import logging
import pathlib
import threading

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_login import current_user

from gravwell import agent_tokens
from gravwell.database import get_session
from gravwell.models.ingestion import ingest_parse_result
from gravwell.parsers.agent import AgentParser

_build_lock = threading.Lock()   # prevents concurrent PyInstaller runs

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

    if request.content_type and "json" not in request.content_type:
        return jsonify(error="Content-Type must be application/json"), 400

    raw = request.get_data()
    if request.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            return jsonify(error="Failed to decompress gzip body"), 400

    try:
        data = json.loads(raw)
    except Exception:
        return jsonify(error="Invalid JSON"), 400

    if not data or not data.get("gravwell_agent"):
        return jsonify(error="Not a GravWell agent payload"), 400

    agent_host = (data.get("self") or {}).get("hostname", "unknown")
    try:
        parse_result = AgentParser.parse_dict(data, source_name=agent_host)

        if parse_result.errors:
            return jsonify(error="; ".join(parse_result.errors)), 422

        with get_session(db_path) as session:
            hosts_added, vulns_added, already = ingest_parse_result(session, parse_result)

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

_AGENT_PY    = pathlib.Path(__file__).parent.parent / "agent" / "collect.py"
_BUILDS_DIR  = pathlib.Path.home() / ".gravwell" / "agent-builds"
_BUNDLED_DIR = pathlib.Path(__file__).parent.parent / "agent" / "binaries"

_PLATFORM_SUFFIX = {"windows": ".exe", "linux": "", "macos": ""}
_ALL_PLATFORMS   = list(_PLATFORM_SUFFIX)


def _current_platform() -> str:
    import sys as _sys
    return {"win32": "windows", "darwin": "macos"}.get(_sys.platform, "linux")


def _cache_path(platform: str) -> pathlib.Path:
    """Return the user cache file path for a given platform."""
    suffix = _PLATFORM_SUFFIX.get(platform, "")
    return _BUILDS_DIR / platform / ("gravwell-collect" + suffix)


def _bundled_path(platform: str) -> pathlib.Path:
    """Return the package-bundled binary path for a given platform."""
    suffix = _PLATFORM_SUFFIX.get(platform, "")
    return _BUNDLED_DIR / platform / ("gravwell-collect" + suffix)


def _resolve_binary(platform: str) -> pathlib.Path | None:
    """Return the best available binary: user cache beats bundled."""
    p = _cache_path(platform)
    if p.exists():
        return p
    p = _bundled_path(platform)
    if p.exists():
        return p
    return None


def _save_to_cache(platform: str, data: bytes) -> None:
    path = _cache_path(platform)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def cached_builds() -> dict:
    """Return {platform: bool} indicating what's available (cache or bundled)."""
    return {plat: _resolve_binary(plat) is not None for plat in _ALL_PLATFORMS}


def _generate_script(server: str = "", token: str = "") -> str:
    """Return a collect.py with server/token defaults pre-filled."""
    from gravwell.agent.build import generate_script
    return generate_script(server=server, token=token)


@api_bp.route("/api/agent/download/py", methods=["GET"])
def download_agent_py():
    """Download a (optionally pre-configured) Python collection agent.

    Requires an authenticated browser session.

    Query params (all optional):
      ?server=URL    Pre-fill the GravWell server URL
      ?token=TOKEN   Pre-fill the API token

    Without params, returns the plain unmodified script.  The agent always
    accepts --server / --key at runtime regardless.
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    if not _AGENT_PY.exists():
        return jsonify(error="Agent script not found on server"), 404

    server = request.args.get("server", "").strip()
    token  = request.args.get("token",  "").strip()

    if server or token:
        source = _generate_script(server=server, token=token)
        buf = __import__("io").BytesIO(source.encode())
        return send_file(buf, as_attachment=True, download_name="gravwell-collect.py",
                         mimetype="text/x-python")

    return send_file(_AGENT_PY, as_attachment=True,
                     download_name="gravwell-collect.py", mimetype="text/x-python")


@api_bp.route("/api/agent/builds", methods=["GET"])
def list_builds():
    """Return which platform binaries are available for download.

    Requires an authenticated browser session.
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401
    return jsonify(builds=cached_builds(), server_platform=_current_platform())


@api_bp.route("/api/agent/download/binary", methods=["GET"])
def download_binary():
    """Download a pre-built binary for the requested platform.

    Requires an authenticated browser session.

    Query params:
      ?platform=windows|linux|macos   (required)
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    platform = request.args.get("platform", "").strip().lower()

    if platform not in _ALL_PLATFORMS:
        return jsonify(error=f"Unknown platform '{platform}'. Use: {', '.join(_ALL_PLATFORMS)}"), 400

    binary = _resolve_binary(platform)
    if not binary:
        return jsonify(
            error=f"No binary available for {platform}. "
                  f"Trigger the GitHub Actions build workflow to generate one."
        ), 404

    import io
    return send_file(
        io.BytesIO(binary.read_bytes()),
        as_attachment=True,
        download_name=binary.name,
        mimetype="application/octet-stream",
    )


def _is_admin_request() -> bool:
    """Return True if the request comes from an authenticated admin.

    Accepts either:
    - A browser session (Flask-Login current_user.is_admin), or
    - X-Gravwell-Admin header containing a valid admin API token stored in
      the keystore under the key "ci_admin_token".  This lets CI pipelines
      upload pre-built binaries without a browser session.
    """
    if current_user.is_authenticated and current_user.is_admin:
        return True
    header_token = request.headers.get("X-Gravwell-Admin", "")
    if header_token:
        import gravwell.keystore as ks_mod
        import hashlib
        db_path = current_app.config.get("GRAVWELL_DB_PATH", "")
        ks = ks_mod.load(db_path)
        stored = ks.get("ci_admin_token_hash", "")
        if stored and hashlib.sha256(header_token.encode()).hexdigest() == stored:
            return True
    return False


@api_bp.route("/api/agent/upload", methods=["POST"])
def upload_binary():
    """Upload a pre-built agent binary for a specific platform.

    Accepts admin browser sessions OR an X-Gravwell-Admin header token
    (set via `gravwell ci-token set` for use in CI pipelines).

    Query params:
      ?platform=windows|linux|macos   (required)
      ?mode=local                     (optional; default: configured)

    Body: multipart file upload with field name 'file'.
    """
    if not _is_admin_request():
        return jsonify(error="Admin access required"), 403

    platform = request.args.get("platform", "").strip().lower()

    if platform not in _ALL_PLATFORMS:
        return jsonify(error=f"Unknown platform '{platform}'. Use: {', '.join(_ALL_PLATFORMS)}"), 400

    if "file" not in request.files:
        return jsonify(error="No file field in request"), 400

    _MAX_BINARY = 100 * 1024 * 1024  # 100 MB — generous for a PyInstaller binary
    f = request.files["file"]
    data = f.read(_MAX_BINARY + 1)
    if not data:
        return jsonify(error="Uploaded file is empty"), 400
    if len(data) > _MAX_BINARY:
        return jsonify(error=f"Upload exceeds {_MAX_BINARY // 1024 // 1024} MB limit"), 413

    _save_to_cache(platform, data)
    actor = getattr(current_user, "username", "ci-token")
    logger.info("Agent binary uploaded: platform=%s size=%d by %s",
                platform, len(data), actor)
    return jsonify(status="stored", platform=platform, size=len(data)), 201


@api_bp.route("/api/agent/build", methods=["POST"])
def build_agent():
    """Build a standalone binary for the current server platform using PyInstaller.

    Admin only. Blocking — takes ~30-60 seconds.
    The result is cached in ~/.gravwell/agent-builds/ for future downloads.
    The binary always accepts --server / --key at runtime for remote reporting.

    Returns the binary as a file download.
    """
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify(error="Admin access required"), 403

    if not _build_lock.acquire(blocking=False):
        return jsonify(error="A build is already in progress — try again shortly"), 409

    import io
    import subprocess
    import sys
    import tempfile

    if not _AGENT_PY.exists():
        _build_lock.release()
        return jsonify(error="Agent script not found on server"), 404

    platform = _current_platform()
    suffix   = _PLATFORM_SUFFIX[platform]
    exe_name = "gravwell-collect"

    try:
        with tempfile.TemporaryDirectory(prefix="gravwell_build_") as tmp:
            tmp_path = pathlib.Path(tmp)
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
                str(_AGENT_PY),
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                cwd=str(tmp_path),
            )
            if result.returncode != 0:
                logger.error("PyInstaller failed:\n%s", result.stderr[-3000:])
                return jsonify(
                    error="Build failed — check server logs for details",
                    detail=result.stderr[-500:],
                ), 500

            out_binary = tmp_path / "dist" / (exe_name + suffix)
            if not out_binary.exists():
                return jsonify(error="Build produced no output file"), 500

            binary_bytes = out_binary.read_bytes()

        _save_to_cache(platform, binary_bytes)

        download_name = exe_name + suffix
        actor = getattr(current_user, "username", "ci-token")
        logger.info("Agent build complete: %s (%d bytes) by %s",
                    download_name, len(binary_bytes), actor)
        return send_file(
            io.BytesIO(binary_bytes),
            as_attachment=True,
            download_name=download_name,
            mimetype="application/octet-stream",
        )

    except subprocess.TimeoutExpired:
        return jsonify(error="Build timed out after 5 minutes"), 500
    except Exception as exc:
        logger.exception("Agent build error")
        return jsonify(error=f"Build error: {exc}"), 500
    finally:
        _build_lock.release()
