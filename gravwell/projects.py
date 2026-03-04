"""Project management — each project is a named SQLite database file."""
from __future__ import annotations
from pathlib import Path

_DEFAULT_DB = Path.home() / ".gravwell" / "gravwell.db"
_PROJECTS_DIR = Path.home() / ".gravwell" / "projects"


def get_projects_dir() -> Path:
    _PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    return _PROJECTS_DIR


def list_projects(current_path: str | None = None) -> list[dict]:
    """Return all known projects as a list of {name, path, size_mb} dicts.

    Always includes the default project (if it exists) and any custom
    projects in ~/.gravwell/projects/.  If current_path refers to a DB
    outside those locations it is prepended so it always appears in the list.
    """
    seen: set[str] = set()
    projects: list[dict] = []

    def _add(p: Path) -> None:
        key = str(p.resolve())
        if key in seen:
            return
        seen.add(key)
        name = "default" if p.resolve() == _DEFAULT_DB.resolve() else p.stem
        size = round(p.stat().st_size / 1024 / 1024, 2) if p.exists() else 0.0
        projects.append({"name": name, "path": str(p.resolve()), "size_mb": size})

    if _DEFAULT_DB.exists():
        _add(_DEFAULT_DB)

    d = get_projects_dir()
    for f in sorted(d.glob("*.db")):
        _add(f)

    # Always include current path if it falls outside the known locations
    if current_path:
        cp = Path(current_path)
        key = str(cp.resolve())
        if key not in seen and cp.exists():
            name = "default" if cp.resolve() == _DEFAULT_DB.resolve() else cp.stem
            size = round(cp.stat().st_size / 1024 / 1024, 2)
            projects.insert(0, {"name": name, "path": key, "size_mb": size})

    return projects


def get_project_path(name: str) -> str:
    """Return the filesystem path for a project by name.

    'default' maps to ~/.gravwell/gravwell.db; everything else lives in
    ~/.gravwell/projects/<name>.db.
    """
    if name == "default":
        _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
        return str(_DEFAULT_DB)
    return str(get_projects_dir() / f"{name}.db")


def project_name_from_path(db_path: str) -> str:
    """Derive a short display name from a DB file path."""
    p = Path(db_path).resolve()
    if p == _DEFAULT_DB.resolve():
        return "default"
    return p.stem
