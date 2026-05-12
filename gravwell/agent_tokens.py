"""Central registry of GravWell agent API tokens.

Stored in ~/.gravwell/agent_tokens.json alongside the keystore.
Each token is bound to exactly one project database path so that:
  - Validation always ingests into the correct project regardless of
    which project the UI currently has open.
  - A token from Project-A cannot be used to submit into Project-B.

Token values are stored as SHA-256 hashes; the plain token is only
ever returned once (at creation) and never stored.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import secrets
import time
from typing import Optional

_TOKENS_FILE = pathlib.Path.home() / ".gravwell" / "agent_tokens.json"

# ── In-memory cache ───────────────────────────────────────────────────────────
# validate_token is called on every agent POST; avoid a file read each time.
# The cache is invalidated (TTL reset to 0) on every write so revocations and
# new tokens take effect on the very next validation request.
_cache: dict[str, str] = {}   # {token_hash: db_path} for active tokens only
_cache_expires: float = 0.0   # monotonic time after which the cache is stale
_CACHE_TTL = 5.0              # seconds


# ── Internal helpers ──────────────────────────────────────────────────────────

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _load() -> list[dict]:
    if not _TOKENS_FILE.exists():
        return []
    try:
        with open(_TOKENS_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: list[dict]) -> None:
    global _cache_expires
    _TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Write to a sibling temp file then rename for an atomic replacement.
    # os.replace() is atomic on POSIX; on Windows it is best-effort
    # (still far safer than truncating the file in-place).
    tmp = _TOKENS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    tmp.replace(_TOKENS_FILE)
    try:
        _TOKENS_FILE.chmod(0o600)
    except OSError:
        pass  # Windows doesn't support chmod; DB encryption compensates
    _cache_expires = 0.0  # invalidate cache so the change is visible immediately


def _rebuild_cache(entries: list[dict]) -> None:
    global _cache, _cache_expires
    _cache = {
        e["hash"]: e["db_path"]
        for e in entries
        if e.get("active") and e.get("hash") and e.get("db_path")
    }
    _cache_expires = time.monotonic() + _CACHE_TTL


# ── Public API ────────────────────────────────────────────────────────────────

def create_token(label: str, db_path: str) -> str:
    """Generate a new 64-character hex token bound to *db_path*.

    Returns the plain token — call site must print/display it; it cannot
    be recovered later (only the hash is stored).
    """
    token = secrets.token_hex(32)
    entries = _load()
    entries.append({
        "id": secrets.token_hex(8),
        "hash": _hash(token),
        "label": label,
        "db_path": str(db_path),
        "active": True,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    _save(entries)
    return token


def validate_token(token: str) -> Optional[str]:
    """Return the db_path bound to *token*, or None if invalid / inactive."""
    global _cache, _cache_expires
    if not token:
        return None
    h = _hash(token)
    if time.monotonic() >= _cache_expires:
        _rebuild_cache(_load())
    return _cache.get(h)


def list_for_project(db_path: str) -> list[dict]:
    """Return id + label + created_at for all active tokens belonging to *db_path*."""
    return [
        {"id": e.get("id", ""), "label": e["label"], "created_at": e["created_at"]}
        for e in _load()
        if e.get("active") and e.get("db_path") == str(db_path)
    ]


def revoke_by_id(token_id: str, db_path: str) -> bool:
    """Deactivate the single token matching *token_id* + *db_path*."""
    entries = _load()
    changed = False
    for e in entries:
        if e.get("id") == token_id and e.get("db_path") == str(db_path) and e.get("active"):
            e["active"] = False
            changed = True
            break
    if changed:
        _save(entries)
    return changed


def revoke(label: str, db_path: str) -> bool:
    """Deactivate all tokens matching *label* + *db_path*. Returns True if any changed."""
    entries = _load()
    changed = False
    for e in entries:
        if e.get("label") == label and e.get("db_path") == str(db_path) and e.get("active"):
            e["active"] = False
            changed = True
    if changed:
        _save(entries)
    return changed
