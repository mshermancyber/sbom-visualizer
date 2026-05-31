"""VEX (Vulnerability Exploitability eXchange) suppression store.

Operators declare at point-in-time that a specific CVE/component pair is not
exploitable in their context.  Not a tracker — purely annotates a finding at
assessment time.

SQLite database at ``VEX_DB`` env (default ``/data/vex.db``), WAL mode.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

_DB_PATH = os.environ.get("VEX_DB", "/data/vex.db")

_VALID_STATUSES = frozenset(
    {"not_affected", "false_positive", "in_triage", "resolved", "accepted_risk"}
)


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("""
        CREATE TABLE IF NOT EXISTS suppressions (
            id               TEXT PRIMARY KEY,
            cve_id           TEXT NOT NULL,
            component_purl   TEXT,
            component_name   TEXT,
            status           TEXT NOT NULL,
            justification    TEXT,
            note             TEXT,
            author           TEXT,
            created_at       TEXT NOT NULL,
            expires_at       TEXT,
            project          TEXT
        )
    """)
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_sup_cve_purl "
        "ON suppressions(cve_id, component_purl)"
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_sup_cve_name "
        "ON suppressions(cve_id, component_name)"
    )
    con.commit()
    return con


# Module-level connection (WAL is safe for single-process concurrent reads).
_db: sqlite3.Connection = _conn()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def create_suppression(
    *,
    cve_id: str,
    component_purl: Optional[str],
    component_name: Optional[str],
    status: str,
    justification: Optional[str],
    note: Optional[str],
    author: Optional[str],
    expires_at: Optional[str],
    project: Optional[str] = None,
) -> dict:
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status {status!r}; must be one of {sorted(_VALID_STATUSES)}")
    sid = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    _db.execute(
        """
        INSERT INTO suppressions
            (id, cve_id, component_purl, component_name, status, justification,
             note, author, created_at, expires_at, project)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (sid, cve_id, component_purl, component_name, status, justification,
         note, author, now, expires_at, project),
    )
    _db.commit()
    return {
        "id": sid, "cveId": cve_id, "componentPurl": component_purl,
        "componentName": component_name, "status": status,
        "justification": justification, "note": note, "author": author,
        "createdAt": now, "expiresAt": expires_at, "project": project,
    }


def list_suppressions(
    *,
    cve_id: Optional[str] = None,
    component_purl: Optional[str] = None,
    component_name: Optional[str] = None,
    status: Optional[str] = None,
    project: Optional[str] = None,
) -> list[dict]:
    q = "SELECT * FROM suppressions WHERE 1=1"
    params: list = []
    if cve_id:
        q += " AND cve_id = ?"
        params.append(cve_id)
    if component_purl:
        q += " AND component_purl = ?"
        params.append(component_purl)
    if component_name:
        q += " AND component_name = ?"
        params.append(component_name)
    if status:
        q += " AND status = ?"
        params.append(status)
    if project is not None:
        q += " AND project = ?"
        params.append(project)
    _db.row_factory = sqlite3.Row
    rows = _db.execute(q, params).fetchall()
    _db.row_factory = None
    return [
        {
            "id": r["id"], "cveId": r["cve_id"], "componentPurl": r["component_purl"],
            "componentName": r["component_name"], "status": r["status"],
            "justification": r["justification"], "note": r["note"],
            "author": r["author"], "createdAt": r["created_at"],
            "expiresAt": r["expires_at"], "project": r["project"],
        }
        for r in rows
    ]


def delete_suppression(sid: str) -> bool:
    cur = _db.execute("DELETE FROM suppressions WHERE id = ?", (sid,))
    _db.commit()
    return cur.rowcount > 0


def apply_suppressions(
    findings: list,          # list[Finding]
    suppressions: list[dict],
) -> tuple[list, int]:
    """Apply active (non-expired) suppressions to a findings list.

    Returns (patched_findings, suppressed_count).  Matching order:
      1. Exact cveId + component_purl match.
      2. cveId + component_name match (fallback).
    Expired suppressions (expiresAt < now) are ignored.
    """
    from .models import Finding, Vuln  # local import to avoid circularity

    now = datetime.now(timezone.utc).isoformat()

    # Filter expired.
    active = [s for s in suppressions if not s.get("expiresAt") or s["expiresAt"] >= now]

    # Build lookup structures: (cveId, purl) and (cveId, name).
    by_purl: dict[tuple[str, str], dict] = {}
    by_name: dict[tuple[str, str], dict] = {}
    for s in active:
        cid = s.get("cveId", "")
        purl = s.get("componentPurl")
        name = s.get("componentName")
        if purl:
            by_purl[(cid, purl)] = s
        if name:
            by_name[(cid, name)] = s

    suppressed_count = 0
    patched: list[Finding] = []

    for finding in findings:
        new_vulns = []
        for vuln in finding.vulns:
            cve_id = vuln.cveId or vuln.id
            match = None
            # Try purl match first.
            purl = ""
            # We need the component's purl from the SBOM; it is NOT on the vuln.
            # The caller must inject it if they want purl matching.  We store it on
            # the vuln as a non-model extra attribute (_purl) when available.
            comp_purl = getattr(vuln, "_purl", None)
            comp_name = getattr(vuln, "_name", None)
            if comp_purl:
                match = by_purl.get((cve_id, comp_purl))
            if match is None and comp_name:
                match = by_name.get((cve_id, comp_name))
            if match:
                # Mark suppressed (create new Vuln with extra fields).
                suppressed_count += 1
                vuln_data = vuln.model_dump()
                vuln_data["suppressed"] = True
                vuln_data["suppressionStatus"] = match.get("status")
                new_vuln = Vuln(**vuln_data)
            else:
                new_vuln = vuln
            new_vulns.append(new_vuln)
        patched.append(Finding(componentIndex=finding.componentIndex, vulns=new_vulns))

    return patched, suppressed_count


def _reset_db(path: Optional[str] = None) -> None:
    """Replace the module-level DB connection (used by tests to isolate state)."""
    global _db, _DB_PATH
    if path is not None:
        _DB_PATH = path
    _db = _conn()
