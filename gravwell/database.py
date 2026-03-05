from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from gravwell.models.orm import Base

_engines: dict[str, object] = {}

# Indexes to ensure exist on startup (safe for existing DBs via IF NOT EXISTS)
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_host_id  ON vulnerabilities (host_id)",
    "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_cvss     ON vulnerabilities (cvss_score DESC)",
    "CREATE INDEX IF NOT EXISTS ix_services_host_id         ON services (host_id)",
    "CREATE INDEX IF NOT EXISTS ix_cve_refs_vuln_id         ON cve_refs (vuln_id)",
]

# Column migrations — safe to run on existing DBs (SQLite ignores duplicate columns)
_COLUMN_MIGRATIONS = [
    "ALTER TABLE hosts ADD COLUMN notes TEXT DEFAULT ''",
    "ALTER TABLE hosts ADD COLUMN additional_ips TEXT DEFAULT '[]'",
    "ALTER TABLE hosts ADD COLUMN subnet_override TEXT DEFAULT NULL",
    "ALTER TABLE subnet_labels ADD COLUMN box_padding INTEGER DEFAULT 30",
]

# MEK for CLI context (set via set_cli_mek; web context uses current_app.config)
_cli_mek: bytes | None = None


def _get_mek() -> bytes | None:
    """Return the active MEK.

    In a Flask request context the MEK lives in ``current_app.config``.
    In CLI context it is stored in the module-level ``_cli_mek``.
    """
    try:
        from flask import current_app
        return current_app.config.get("GRAVWELL_MEK")
    except RuntimeError:
        pass
    return _cli_mek


def set_cli_mek(mek: bytes | None) -> None:
    """Set the MEK for CLI use (outside Flask). Clears the engine cache."""
    global _cli_mek
    _cli_mek = mek
    _engines.clear()


def _get_engine(db_path: str):
    if db_path in _engines:
        return _engines[db_path]

    mek = _get_mek()

    if mek:
        from sqlcipher3 import dbapi2 as sqlcipher
        hex_key = mek.hex()

        engine = create_engine(
            "sqlite+pysqlite:///",
            creator=lambda: sqlcipher.connect(db_path, check_same_thread=False),
            poolclass=NullPool,
        )

        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn, _):
            # PRAGMA key MUST be the very first statement on a SQLCipher connection
            dbapi_conn.execute(f"PRAGMA key=\"x'{hex_key}'\"")
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
            dbapi_conn.execute("PRAGMA cache_size=-8192")    # 8 MB page cache
            dbapi_conn.execute("PRAGMA temp_store=MEMORY")
            dbapi_conn.execute("PRAGMA mmap_size=0")          # disable mmap
    else:
        engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            poolclass=NullPool,
        )

        @event.listens_for(engine, "connect")
        def _on_connect_plain(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
            dbapi_conn.execute("PRAGMA cache_size=-8192")
            dbapi_conn.execute("PRAGMA temp_store=MEMORY")
            dbapi_conn.execute("PRAGMA mmap_size=0")

    Base.metadata.create_all(engine)

    with engine.connect() as conn:
        for stmt in _INDEXES:
            conn.execute(text(stmt))
        for stmt in _COLUMN_MIGRATIONS:
            try:
                conn.execute(text(stmt))
            except Exception as _e:
                # Expected when the column already exists; log anything else
                if "duplicate column" not in str(_e).lower() and \
                        "already exists" not in str(_e).lower():
                    import logging as _log
                    _log.warning("Column migration skipped (%s): %s", stmt[:60], _e)
        conn.commit()

    _engines[db_path] = engine
    return engine


def is_encrypted(db_path: str) -> bool:
    """Return True if the file at *db_path* is a SQLCipher-encrypted DB."""
    p = Path(db_path)
    if not p.exists():
        return False
    with open(p, "rb") as f:
        return not f.read(16).startswith(b"SQLite format 3")


def migrate_to_encrypted(db_path: str, mek: bytes) -> None:
    """Encrypt an existing plain SQLite DB file in-place.

    SQLCipher 4 cannot open a plain SQLite file via PRAGMA key / rekey.
    Instead we: dump the plain DB → write a fresh SQLCipher-encrypted copy →
    atomically replace the original file.  WAL/SHM siblings are cleaned up.
    """
    import os
    import sqlite3
    from sqlcipher3 import dbapi2 as sqlcipher

    tmp_path = db_path + ".encrypting"
    hex_key  = mek.hex()

    # 1. Dump the plain SQLite DB to SQL statements using stdlib sqlite3
    plain_conn = sqlite3.connect(db_path)
    sql_dump   = "\n".join(plain_conn.iterdump())
    plain_conn.close()

    # 2. Write a fresh SQLCipher-encrypted copy at a temp path
    if Path(tmp_path).exists():
        os.remove(tmp_path)
    enc_conn = sqlcipher.connect(tmp_path)
    enc_conn.execute(f"PRAGMA key=\"x'{hex_key}'\"")
    enc_conn.executescript(sql_dump)
    enc_conn.commit()
    enc_conn.close()

    # 3. Dispose any cached engine then atomically replace the original file
    engine = _engines.pop(db_path, None)
    if engine is not None:
        try:
            engine.dispose()
        except Exception:
            pass
    for suffix in ("-wal", "-shm"):
        p = Path(db_path + suffix)
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    os.replace(tmp_path, db_path)


def init_db(db_path: str) -> None:
    # Auto-migrate any existing plain SQLite project DB to SQLCipher on first access
    mek = _get_mek()
    if mek and Path(db_path).exists() and not is_encrypted(db_path):
        migrate_to_encrypted(db_path, mek)
    _get_engine(db_path)


def release_engine(db_path: str) -> None:
    """Dispose the engine for db_path, releasing all connections without deleting the file.

    Use this before renaming a DB file so the Windows file lock is released.
    """
    engine = _engines.pop(db_path, None)
    if engine is not None:
        try:
            engine.dispose()
        except Exception:
            pass


def drop_db(db_path: str) -> None:
    """Dispose the engine (releasing all connections) then delete the DB file.

    WAL mode creates ``<db>-wal`` and ``<db>-shm`` sibling files; those are
    removed too.  On Windows an open connection pool prevents file deletion,
    so we must dispose first.
    """
    import pathlib

    release_engine(db_path)

    for suffix in ("", "-wal", "-shm"):
        p = pathlib.Path(db_path + suffix)
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass


@contextmanager
def get_session(db_path: str) -> Session:
    engine = _get_engine(db_path)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
