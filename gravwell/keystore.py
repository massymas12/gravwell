"""User keystore — stores GravWell accounts and per-user encrypted MEK slots.

The keystore is a plain JSON file (not SQLite) so it can be read BEFORE the
encrypted data DB is opened.  It contains no sensitive scan data — only
password hashes (PBKDF2) and AES-256-GCM encrypted copies of the DB master
key (MEK).

Envelope-encryption scheme (same pattern as LUKS / 1Password):
  - DB master encryption key (MEK): random 32 bytes, never written to disk
  - Per user: KEK = PBKDF2-HMAC-SHA256(password, salt, 480 000 iters)
              encrypted_mek = AES-256-GCM(KEK, MEK)
  - Authenticate → decrypt your MEK slot → unlock the DB
  - Change password → re-encrypt MEK slot only (DB content unchanged)
"""
from __future__ import annotations
import json
import os
import secrets
from datetime import datetime as _dt
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import check_password_hash, generate_password_hash

_KDF_ITERATIONS = 480_000


# ── Internal helpers ──────────────────────────────────────────────────────────

def _keystore_path(db_path: str) -> Path:
    return Path(db_path).with_suffix(".keystore.json")


def _derive_kek(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key-encryption key from password + random salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())


# ── Public API ────────────────────────────────────────────────────────────────

def load(db_path: str) -> dict:
    """Return the keystore dict, or an empty one if the file doesn't exist."""
    p = _keystore_path(db_path)
    if not p.exists():
        return {"users": []}
    return json.loads(p.read_text())


def save(db_path: str, ks: dict) -> None:
    """Write keystore to disk with restrictive permissions."""
    p = _keystore_path(db_path)
    p.write_text(json.dumps(ks, indent=2))
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass  # Windows doesn't support chmod


def generate_mek() -> bytes:
    """Generate a new random 32-byte master encryption key."""
    return secrets.token_bytes(32)


def encrypt_mek(password: str, mek: bytes) -> dict:
    """Encrypt MEK with a password-derived key; return the storable slot dict."""
    salt  = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    kek   = _derive_kek(password, salt)
    ct    = AESGCM(kek).encrypt(nonce, mek, None)
    return {
        "mek_salt":      salt.hex(),
        "mek_nonce":     nonce.hex(),
        "encrypted_mek": ct.hex(),
    }


def decrypt_mek(user: dict, password: str) -> bytes | None:
    """Decrypt the user's MEK slot with their password. Returns None on failure."""
    try:
        salt  = bytes.fromhex(user["mek_salt"])
        nonce = bytes.fromhex(user["mek_nonce"])
        ct    = bytes.fromhex(user["encrypted_mek"])
        kek   = _derive_kek(password, salt)
        return AESGCM(kek).decrypt(nonce, ct, None)
    except Exception:
        return None


def find_user(ks: dict, username: str) -> dict | None:
    """Return the user dict for *username*, or None."""
    return next((u for u in ks["users"] if u["username"] == username), None)


def add_user(db_path: str, username: str, password: str,
             mek: bytes, is_admin: bool = False,
             permissions: list[str] | None = None,
             allowed_projects: list[str] | None = None) -> None:
    """Create a new user entry in the keystore.

    permissions:      list of capability strings (e.g. ["edit", "import"]).
                      Defaults to all capabilities for admins, ["edit","import"]
                      for regular users.
    allowed_projects: list of project name slugs the user may access, or ["*"]
                      for unrestricted access.  Defaults to ["*"].
    """
    ks = load(db_path)
    if find_user(ks, username):
        raise ValueError(f"User '{username}' already exists.")
    if permissions is None:
        permissions = ["edit", "import", "discover", "export"] if is_admin else ["edit", "import"]
    if allowed_projects is None:
        allowed_projects = ["*"]
    entry = {
        "username":        username,
        "password_hash":   generate_password_hash(password),
        "is_admin":        is_admin,
        "permissions":     permissions,
        "allowed_projects": allowed_projects,
        "created_at":      _dt.utcnow().isoformat(),
        "last_login":      None,
        **encrypt_mek(password, mek),
    }
    ks["users"].append(entry)
    save(db_path, ks)


def delete_user(db_path: str, username: str) -> None:
    """Remove a user from the keystore."""
    ks = load(db_path)
    before = len(ks["users"])
    ks["users"] = [u for u in ks["users"] if u["username"] != username]
    if len(ks["users"]) == before:
        raise KeyError(f"User '{username}' not found.")
    save(db_path, ks)


def change_password(db_path: str, username: str,
                    new_password: str, mek: bytes) -> None:
    """Re-hash the password and re-encrypt the MEK slot for *username*."""
    ks = load(db_path)
    user = find_user(ks, username)
    if not user:
        raise KeyError(f"User '{username}' not found.")
    user["password_hash"] = generate_password_hash(new_password)
    user.update(encrypt_mek(new_password, mek))
    save(db_path, ks)


def touch_last_login(db_path: str, username: str) -> None:
    """Update the last_login timestamp for *username*."""
    ks = load(db_path)
    user = find_user(ks, username)
    if user:
        user["last_login"] = _dt.utcnow().isoformat()
        save(db_path, ks)


def authenticate(db_path: str, username: str, password: str) -> bytes | None:
    """Verify credentials and return the MEK on success, None on failure."""
    ks = load(db_path)
    user = find_user(ks, username)
    if not user:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return decrypt_mek(user, password)


# ── Server auto-unlock ────────────────────────────────────────────────────────
#
# Priority:
#   Windows  → DPAPI (CryptProtectData/CryptUnprotectData via ctypes).
#              The blob is machine+user bound; stored as hex in the keystore.
#   macOS    → OS Keychain via the `keyring` package.
#   Linux    → libsecret (GNOME Keyring / KWallet) via `keyring` + `secretstorage`.
#   Fallback → AES-256-GCM with a local key file (weakest; last resort only).

_KEYRING_SERVICE = "gravwell"


def _keyring_account(db_path: str) -> str:
    return f"mek:{Path(db_path).stem}"


# ── Windows DPAPI ─────────────────────────────────────────────────────────────

def _dpapi_encrypt(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf   = ctypes.create_string_buffer(data)
    in_b  = _Blob(len(data), buf)
    out_b = _Blob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_b), None, None, None, None, 0x01, ctypes.byref(out_b)
    ):
        raise RuntimeError(f"DPAPI CryptProtectData failed ({ctypes.GetLastError()})")
    result = bytes(ctypes.string_at(out_b.pbData, out_b.cbData))
    ctypes.windll.kernel32.LocalFree(out_b.pbData)
    return result


def _dpapi_decrypt(data: bytes) -> bytes:
    import ctypes
    import ctypes.wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf   = ctypes.create_string_buffer(data)
    in_b  = _Blob(len(data), buf)
    out_b = _Blob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_b), None, None, None, None, 0x01, ctypes.byref(out_b)
    ):
        raise RuntimeError(f"DPAPI CryptUnprotectData failed ({ctypes.GetLastError()})")
    result = bytes(ctypes.string_at(out_b.pbData, out_b.cbData))
    ctypes.windll.kernel32.LocalFree(out_b.pbData)
    return result


# ── Key-file fallback ─────────────────────────────────────────────────────────

def _server_key_path(db_path: str) -> Path:
    return Path(db_path).with_suffix(".server.key")


def _store_keyfile(db_path: str, mek: bytes) -> None:
    key_path = _server_key_path(db_path)
    if not key_path.exists():
        server_key = secrets.token_bytes(32)
        key_path.write_bytes(server_key)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
    else:
        server_key = key_path.read_bytes()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(server_key).encrypt(nonce, mek, None)
    ks = load(db_path)
    ks["server_mek_nonce"] = nonce.hex()
    ks["server_mek_ct"]    = ct.hex()
    save(db_path, ks)


def _load_keyfile(db_path: str) -> bytes | None:
    key_path = _server_key_path(db_path)
    if not key_path.exists():
        return None
    try:
        server_key = key_path.read_bytes()
        ks = load(db_path)
        nonce = bytes.fromhex(ks["server_mek_nonce"])
        ct    = bytes.fromhex(ks["server_mek_ct"])
        return AESGCM(server_key).decrypt(nonce, ct, None)
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def store_server_mek(db_path: str, mek: bytes) -> None:
    """Persist an auto-unlock copy of the MEK in the OS credential store.

    Called on every successful login.  On next restart the server can
    call load_server_mek() to pre-populate the MEK without a browser session.
    """
    import platform
    system = platform.system()

    if system == "Windows":
        try:
            blob = _dpapi_encrypt(mek)
            ks = load(db_path)
            ks["dpapi_mek"] = blob.hex()
            ks.pop("server_mek_nonce", None)   # remove old key-file slot
            ks.pop("server_mek_ct",    None)
            save(db_path, ks)
            old_key = _server_key_path(db_path)   # remove old key file
            if old_key.exists():
                try:
                    old_key.unlink()
                except OSError:
                    pass
            return
        except Exception:
            pass  # fall through to key-file
    else:
        try:
            import keyring as _kr
            _kr.set_password(_KEYRING_SERVICE, _keyring_account(db_path), mek.hex())
            return
        except Exception:
            pass  # fall through to key-file

    _store_keyfile(db_path, mek)


def load_server_mek(db_path: str) -> bytes | None:
    """Return the MEK from the OS credential store, or None if not available."""
    import platform
    system = platform.system()

    if system == "Windows":
        ks = load(db_path)
        if "dpapi_mek" in ks:
            try:
                return _dpapi_decrypt(bytes.fromhex(ks["dpapi_mek"]))
            except Exception:
                pass
        return _load_keyfile(db_path)   # backward-compat with old key-file slot
    else:
        try:
            import keyring as _kr
            val = _kr.get_password(_KEYRING_SERVICE, _keyring_account(db_path))
            if val:
                return bytes.fromhex(val)
        except Exception:
            pass
        return _load_keyfile(db_path)   # headless Linux without D-Bus / no keyring
