import os
from pathlib import Path

_DEFAULT_DB_DIR = Path.home() / ".gravwell"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "gravwell.db"


def get_db_path(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("GRAVWELL_DB")
    if env:
        return env
    _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
    return str(_DEFAULT_DB_PATH)
