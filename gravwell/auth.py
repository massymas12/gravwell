"""Flask-Login authentication layer for GravWell.

Users are stored in a JSON keystore file (gravwell.keystore.json) rather than
the encrypted SQLite DB.  This avoids the bootstrapping problem of needing DB
access to authenticate before the DB encryption key is available.

On successful login the master encryption key (MEK) is decrypted from the
user's keystore slot and stored in ``current_app.config["GRAVWELL_MEK"]``.
All subsequent ``get_session()`` calls in Dash callbacks automatically pick
up the MEK from the Flask app config — no callback changes required.
"""
from __future__ import annotations
import secrets
from pathlib import Path

from flask import make_response, redirect, request
from flask_login import (
    LoginManager, UserMixin,
    current_user, login_user, logout_user,
)

import gravwell.keystore as ks_mod
from gravwell.database import init_db

login_manager = LoginManager()


_ALL_PERMISSIONS = ["edit", "import", "discover"]


class _User(UserMixin):
    def __init__(self, username: str, is_admin: bool,
                 permissions: list[str] | None = None,
                 allowed_projects: list[str] | None = None):
        self.id               = username  # Flask-Login ID = username
        self.username         = username
        self.is_admin         = is_admin
        # Admins implicitly have every permission; fall back for legacy accounts
        self.permissions      = permissions if permissions is not None else (
            _ALL_PERMISSIONS if is_admin else ["edit", "import"]
        )
        self.allowed_projects = allowed_projects if allowed_projects is not None else ["*"]

    def can(self, perm: str) -> bool:
        return self.is_admin or perm in self.permissions

    def can_see_project(self, project_name: str) -> bool:
        return "*" in self.allowed_projects or project_name in self.allowed_projects


def _load_or_create_secret(db_path: str) -> str:
    """Return persistent Flask session secret, generating it on first run."""
    key_file = Path(db_path).with_suffix(".key")
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        key_file.chmod(0o600)
    except Exception:
        pass  # Windows doesn't support chmod
    return key


def init_auth(flask_app, db_path: str) -> None:
    """Attach Flask-Login, auth routes, and before_request guard."""
    flask_app.secret_key = _load_or_create_secret(db_path)
    login_manager.init_app(flask_app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(uid: str):
        ks = ks_mod.load(db_path)
        user = ks_mod.find_user(ks, uid)
        if user:
            return _User(
                user["username"],
                user.get("is_admin", False),
                user.get("permissions"),
                user.get("allowed_projects"),
            )
        return None

    @flask_app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            mek = ks_mod.authenticate(db_path, username, password)
            if mek is not None:
                # Store MEK in memory — never written to disk
                flask_app.config["GRAVWELL_MEK"] = mek
                # Open / create tables now that the MEK is available
                init_db(db_path)
                ks_mod.touch_last_login(db_path, username)
                ks = ks_mod.load(db_path)
                user = ks_mod.find_user(ks, username)
                login_user(_User(
                    username,
                    user.get("is_admin", False),
                    user.get("permissions"),
                    user.get("allowed_projects"),
                ))
                nxt = request.args.get("next") or "/"
                return redirect(nxt)
            return _login_page("Invalid username or password.")
        return _login_page()

    @flask_app.route("/logout")
    def logout():
        logout_user()
        return redirect("/login")

    @flask_app.before_request
    def require_login():
        allowed = ("/login", "/logout", "/assets/", "/_favicon")
        if any(request.path.startswith(p) for p in allowed):
            return None
        if not current_user.is_authenticated:
            return redirect(f"/login?next={request.path}")
        # MEK is lost when the server restarts — force re-login even if the
        # browser still has a valid session cookie.
        if flask_app.config.get("GRAVWELL_MEK") is None:
            logout_user()
            return redirect(f"/login?next={request.path}")


def _login_page(error: str = ""):
    err_html = f'<p class="error">{error}</p>' if error else ""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GravWell \u2014 Login</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0d1117;color:#cdd9e5;font-family:'Segoe UI',system-ui,sans-serif;
         display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
           padding:32px 28px;width:320px}}
    h1{{font-size:20px;font-weight:600;color:#5DADE2;margin-bottom:24px;text-align:center}}
    label{{display:block;font-size:12px;color:#8b949e;margin-bottom:4px;margin-top:14px}}
    input{{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;
           border-radius:5px;color:#cdd9e5;font-size:14px;outline:none}}
    input:focus{{border-color:#5DADE2}}
    button{{margin-top:20px;width:100%;padding:9px;background:#5DADE2;color:#0d1117;
            font-size:14px;font-weight:600;border:none;border-radius:5px;cursor:pointer}}
    button:hover{{background:#4fc3f7}}
    .error{{color:#f85149;font-size:12px;margin-top:12px;text-align:center}}
  </style>
</head>
<body>
  <div class="card">
    <h1>GravWell</h1>
    <form method="POST">
      <label>Username</label>
      <input name="username" type="text" autocomplete="username" autofocus>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
      {err_html}
    </form>
  </div>
</body>
</html>"""
    return make_response(html, 401 if error else 200)
