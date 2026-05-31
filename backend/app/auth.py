"""Per-key API key management.

SQLite database at ``AUTH_DB`` env (default ``/data/auth.db``), WAL mode.
Keys are 32-byte random tokens (hex); only the SHA-256 hash is stored.

Admin endpoints are gated by the existing ``API_TOKEN`` master key.
When per-user keys exist in the DB, they are accepted *in addition to* the master key.
When ``API_TOKEN`` is not set AND no keys are provisioned, remain open (dev mode).
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

_DB_PATH = os.environ.get("AUTH_DB", "/data/auth.db")


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_hash    TEXT PRIMARY KEY,
            label       TEXT NOT NULL UNIQUE,
            project     TEXT,
            created_at  TEXT NOT NULL,
            last_used_at TEXT,
            active      INT DEFAULT 1
        )
    """)
    con.commit()
    return con


_db: sqlite3.Connection = _conn()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_key(label: str, project: Optional[str] = None) -> dict:
    """Generate a new API key; returns the plaintext token (shown once)."""
    token = secrets.token_hex(32)
    key_hash = _hash(token)
    now = datetime.now(timezone.utc).isoformat()
    _db.execute(
        "INSERT INTO api_keys (key_hash, label, project, created_at, active) VALUES (?,?,?,?,1)",
        (key_hash, label, project, now),
    )
    _db.commit()
    return {"key": token, "label": label, "project": project, "createdAt": now}


def list_keys() -> list[dict]:
    _db.row_factory = sqlite3.Row
    rows = _db.execute(
        "SELECT label, project, created_at, last_used_at, active FROM api_keys ORDER BY created_at"
    ).fetchall()
    _db.row_factory = None
    return [
        {
            "label": r["label"],
            "project": r["project"],
            "createdAt": r["created_at"],
            "lastUsedAt": r["last_used_at"],
            "active": bool(r["active"]),
        }
        for r in rows
    ]


def delete_key(label: str) -> bool:
    cur = _db.execute("DELETE FROM api_keys WHERE label = ?", (label,))
    _db.commit()
    return cur.rowcount > 0


def has_any_keys() -> bool:
    """Return True when at least one active key exists in the DB."""
    row = _db.execute("SELECT 1 FROM api_keys WHERE active=1 LIMIT 1").fetchone()
    return row is not None


def lookup_key(token: str) -> Optional[dict]:
    """Return the key record if the token is valid+active, else None.
    Side-effect: updates last_used_at.
    """
    h = _hash(token)
    _db.row_factory = sqlite3.Row
    row = _db.execute(
        "SELECT label, project, active FROM api_keys WHERE key_hash = ?", (h,)
    ).fetchone()
    _db.row_factory = None
    if row is None or not row["active"]:
        return None
    now = datetime.now(timezone.utc).isoformat()
    _db.execute("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (now, h))
    _db.commit()
    return {"label": row["label"], "project": row["project"]}


def _reset_db(path: Optional[str] = None) -> None:
    """Replace the module-level DB connection (used by tests)."""
    global _db, _DB_PATH
    if path is not None:
        _DB_PATH = path
    _db = _conn()
