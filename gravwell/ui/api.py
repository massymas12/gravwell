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

_AGENT_PY    = pathlib.Path(__file__).parent.parent / "agent" / "collect.py"
_BUILDS_DIR  = pathlib.Path.home() / ".gravwell" / "agent-builds"

_PLATFORM_SUFFIX = {"windows": ".exe", "linux": "", "macos": ""}
_ALL_PLATFORMS   = list(_PLATFORM_SUFFIX)


def _current_platform() -> str:
    import sys as _sys
    return {"win32": "windows", "darwin": "macos"}.get(_sys.platform, "linux")


def _cache_path(platform: str, local_only: bool) -> pathlib.Path:
    """Return the cache file path for a given platform + mode."""
    name = "gravwell-collect-local" if local_only else "gravwell-collect"
    suffix = _PLATFORM_SUFFIX.get(platform, "")
    return _BUILDS_DIR / platform / (name + suffix)


def _save_to_cache(platform: str, local_only: bool, data: bytes) -> None:
    path = _cache_path(platform, local_only)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def cached_builds() -> dict:
    """Return {platform: {mode: bool}} indicating what's cached."""
    result = {}
    for plat in _ALL_PLATFORMS:
        result[plat] = {
            "configured": _cache_path(plat, False).exists(),
            "local":      _cache_path(plat, True).exists(),
        }
    return result


def _generate_script(server: str = "", token: str = "", local_only: bool = False) -> str:
    """Return a customized collect.py source with embedded defaults baked in."""
    source = _AGENT_PY.read_text(encoding="utf-8")

    config_block = (
        "\n# ── Embedded configuration (pre-configured by GravWell server) ──────────────\n"
        f"_EMBEDDED_SERVER: str = {repr(server)}\n"
        f"_EMBEDDED_KEY: str    = {repr(token)}\n"
        f"_LOCAL_ONLY: bool     = {repr(local_only)}\n"
        "# ─────────────────────────────────────────────────────────────────────────────\n"
    )
    source = source.replace('VERSION = "1.0"', 'VERSION = "1.0"' + config_block, 1)

    # Bake server / key into argparse defaults
    source = source.replace(
        'parser.add_argument("--server", "-s", default="", help="GravWell server URL")',
        'parser.add_argument("--server", "-s", default=_EMBEDDED_SERVER, help="GravWell server URL")',
    )
    source = source.replace(
        'parser.add_argument("--key", "-k", default="", help="API key for server upload")',
        'parser.add_argument("--key", "-k", default=_EMBEDDED_KEY, help="API key for server upload")',
    )

    # Local-only: suppress upload even if --server is passed
    if local_only:
        source = source.replace(
            "    # 7. Upload if requested\n    if args.server:",
            "    # 7. Upload if requested\n    if args.server and not _LOCAL_ONLY:",
        )

    return source


@api_bp.route("/api/agent/download/py", methods=["GET"])
def download_agent_py():
    """Download a (optionally pre-configured) Python collection agent.

    Requires an authenticated browser session.

    Query params (all optional):
      ?server=URL    Pre-fill the GravWell server URL
      ?token=TOKEN   Pre-fill the API token
      ?mode=local    Build a local-only variant (never uploads; saves JSON only)
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    if not _AGENT_PY.exists():
        return jsonify(error="Agent script not found on server"), 404

    server = request.args.get("server", "").strip()
    token  = request.args.get("token",  "").strip()
    local_only = request.args.get("mode", "") == "local"

    if server or token or local_only:
        source = _generate_script(server=server, token=token, local_only=local_only)
        buf = __import__("io").BytesIO(source.encode())
        name = "gravwell-collect-local.py" if local_only else "gravwell-collect.py"
        return send_file(buf, as_attachment=True, download_name=name,
                         mimetype="text/x-python")

    # Plain unmodified script
    return send_file(_AGENT_PY, as_attachment=True,
                     download_name="gravwell-collect.py", mimetype="text/x-python")


@api_bp.route("/api/agent/builds", methods=["GET"])
def list_builds():
    """Return which platform binaries are cached and available for download.

    Requires an authenticated browser session.
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401
    return jsonify(builds=cached_builds(), server_platform=_current_platform())


@api_bp.route("/api/agent/download/binary", methods=["GET"])
def download_binary():
    """Download a cached pre-built binary.

    Requires an authenticated browser session.

    Query params:
      ?platform=windows|linux|macos   (required)
      ?mode=local                     (optional; default: configured)
    """
    if not current_user.is_authenticated:
        return jsonify(error="Authentication required"), 401

    platform   = request.args.get("platform", "").strip().lower()
    local_only = request.args.get("mode", "") == "local"

    if platform not in _ALL_PLATFORMS:
        return jsonify(error=f"Unknown platform '{platform}'. Use: {', '.join(_ALL_PLATFORMS)}"), 400

    cached = _cache_path(platform, local_only)
    if not cached.exists():
        mode_label = "local-only" if local_only else "configured"
        return jsonify(
            error=f"No cached {mode_label} binary for {platform}. "
                  f"Build it on a {platform} machine and upload it here."
        ), 404

    import io
    return send_file(
        io.BytesIO(cached.read_bytes()),
        as_attachment=True,
        download_name=cached.name,
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

    platform   = request.args.get("platform", "").strip().lower()
    local_only = request.args.get("mode", "") == "local"

    if platform not in _ALL_PLATFORMS:
        return jsonify(error=f"Unknown platform '{platform}'. Use: {', '.join(_ALL_PLATFORMS)}"), 400

    if "file" not in request.files:
        return jsonify(error="No file field in request"), 400

    f = request.files["file"]
    data = f.read()
    if not data:
        return jsonify(error="Uploaded file is empty"), 400

    _save_to_cache(platform, local_only, data)
    mode_label = "local-only" if local_only else "configured"
    logger.info("Agent binary uploaded: platform=%s mode=%s size=%d by %s",
                platform, mode_label, len(data), current_user.username)
    return jsonify(status="stored", platform=platform, mode=mode_label,
                   size=len(data)), 201


@api_bp.route("/api/agent/build", methods=["POST"])
def build_agent():
    """Build a standalone binary for the current server platform using PyInstaller.

    Admin only. This is a blocking call — building takes ~30-60 seconds.
    The result is cached in ~/.gravwell/agent-builds/ for future downloads.

    JSON body (all optional):
      {"server": "URL", "token": "TOKEN", "mode": "local"}

    Returns the binary as a file download.
    """
    if not current_user.is_authenticated or not current_user.is_admin:
        return jsonify(error="Admin access required"), 403

    import io
    import subprocess
    import sys
    import tempfile

    if not _AGENT_PY.exists():
        return jsonify(error="Agent script not found on server"), 404

    body = request.get_json(silent=True) or {}
    server     = (body.get("server") or "").strip()
    token      = (body.get("token")  or "").strip()
    local_only = (body.get("mode",  "") == "local")

    source = _generate_script(server=server, token=token, local_only=local_only)
    platform = _current_platform()

    try:
        with tempfile.TemporaryDirectory(prefix="gravwell_build_") as tmp:
            tmp_path = pathlib.Path(tmp)
            src_file = tmp_path / "collect.py"
            src_file.write_text(source, encoding="utf-8")

            exe_name = "gravwell-collect-local" if local_only else "gravwell-collect"
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
                logger.error("PyInstaller failed:\n%s", result.stderr[-3000:])
                return jsonify(
                    error="Build failed — check server logs for details",
                    detail=result.stderr[-500:],
                ), 500

            suffix = _PLATFORM_SUFFIX[platform]
            out_binary = tmp_path / "dist" / (exe_name + suffix)
            if not out_binary.exists():
                return jsonify(error="Build produced no output file"), 500

            binary_bytes = out_binary.read_bytes()

        # Cache for future downloads
        _save_to_cache(platform, local_only, binary_bytes)

        download_name = exe_name + suffix
        logger.info("Agent build complete: %s (%d bytes) by %s",
                    download_name, len(binary_bytes), current_user.username)
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
