"""Scan result persistence — SQLite store for POST /api/scan results.

Table: ``scan_results`` at path ``SCANS_DB`` env (default ``/data/scans.db``), WAL mode.
``findings_json`` is stored as gzip-compressed JSON (base64 encoded) to keep
storage lean for large SBOMs.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

_DB_PATH = os.environ.get("SCANS_DB", "/data/scans.db")


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id              TEXT PRIMARY KEY,
            sbom_id         TEXT,
            sbom_name       TEXT,
            sbom_format     TEXT,
            component_count INT,
            created_at      TEXT NOT NULL,
            findings_json   TEXT,
            summary_json    TEXT,
            errors_json     TEXT,
            project         TEXT
        )
    """)
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_created ON scan_results(created_at DESC)"
    )
    con.commit()
    return con


_db: sqlite3.Connection = _conn()


def _compress(obj) -> str:
    """JSON-encode then gzip-compress, return base64 string."""
    raw = json.dumps(obj).encode()
    compressed = gzip.compress(raw, compresslevel=6)
    return base64.b64encode(compressed).decode()


def _decompress(s: str) -> object:
    """Inverse of _compress."""
    data = base64.b64decode(s)
    return json.loads(gzip.decompress(data))


def save_scan(
    *,
    sbom_id: str,
    sbom_name: str,
    sbom_format: str,
    component_count: int,
    findings,        # list[Finding] — serialisable via model_dump
    summary,         # Summary — serialisable via model_dump
    errors: list[str],
    project: Optional[str] = None,
) -> str:
    """Persist a scan result; returns the new scan ID."""
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    findings_list = [f.model_dump() for f in findings]
    summary_dict = summary.model_dump()

    findings_blob = _compress(findings_list)
    summary_blob = json.dumps(summary_dict)
    errors_blob = json.dumps(errors)

    _db.execute(
        """
        INSERT INTO scan_results
            (id, sbom_id, sbom_name, sbom_format, component_count,
             created_at, findings_json, summary_json, errors_json, project)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (scan_id, sbom_id, sbom_name, sbom_format, component_count,
         now, findings_blob, summary_blob, errors_blob, project),
    )
    _db.commit()
    return scan_id


def list_scans(project: Optional[str] = None, limit: int = 50) -> list[dict]:
    """Return the most recent scans (summary only, no findings blob)."""
    q = (
        "SELECT id, sbom_name, sbom_format, component_count, created_at, summary_json "
        "FROM scan_results"
    )
    params: list = []
    if project is not None:
        q += " WHERE project = ?"
        params.append(project)
    q += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    _db.row_factory = sqlite3.Row
    rows = _db.execute(q, params).fetchall()
    _db.row_factory = None
    out = []
    for r in rows:
        summary = json.loads(r["summary_json"]) if r["summary_json"] else {}
        out.append({
            "id": r["id"],
            "sbomName": r["sbom_name"],
            "sbomFormat": r["sbom_format"],
            "componentCount": r["component_count"],
            "createdAt": r["created_at"],
            "summary": summary,
        })
    return out


def get_scan(scan_id: str) -> Optional[dict]:
    """Return a full scan record including decompressed findings, or None."""
    _db.row_factory = sqlite3.Row
    row = _db.execute(
        "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
    ).fetchone()
    _db.row_factory = None
    if row is None:
        return None
    findings = _decompress(row["findings_json"]) if row["findings_json"] else []
    summary = json.loads(row["summary_json"]) if row["summary_json"] else {}
    errors = json.loads(row["errors_json"]) if row["errors_json"] else []
    return {
        "id": row["id"],
        "sbomId": row["sbom_id"],
        "sbomName": row["sbom_name"],
        "sbomFormat": row["sbom_format"],
        "componentCount": row["component_count"],
        "createdAt": row["created_at"],
        "project": row["project"],
        "findings": findings,
        "summary": summary,
        "errors": errors,
    }


def delete_scan(scan_id: str) -> bool:
    cur = _db.execute("DELETE FROM scan_results WHERE id = ?", (scan_id,))
    _db.commit()
    return cur.rowcount > 0


def _reset_db(path: Optional[str] = None) -> None:
    """Replace the module-level DB connection (used by tests to isolate state)."""
    global _db, _DB_PATH
    if path is not None:
        _DB_PATH = path
    _db = _conn()
