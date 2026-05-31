"""SQLite DAO for the feeds mirror.

Schema (per FEEDS_CONTRACT.md):
  kev(cve PK, due_date, name)
  epss(cve PK, epss REAL, percentile REAL)
  nvd(cve PK, score REAL, severity, version, vector, cwes /*json*/, refs /*json*/)
  meta(feed PK, updated_at, row_count, status, detail)

Each feed is **wholesale-replaced** inside a single transaction: ``DELETE FROM <t>`` then
bulk ``INSERT``. No diffing. The ``meta`` row records updated_at / row_count / status.

A short-lived connection is opened per operation. WAL mode lets the API read while a
refresh writes. Lookups are by exact CVE id; empty feeds yield empty results, not errors.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .logging_config import get_logger

log = get_logger("feeds.store")

FEEDS = ("kev", "epss", "nvd", "osv", "enriched")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    due_date TEXT,
    name TEXT
);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL
);
CREATE TABLE IF NOT EXISTS nvd (
    cve TEXT PRIMARY KEY,
    score REAL,
    severity TEXT,
    version TEXT,
    vector TEXT,
    cwes TEXT,
    refs TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    feed TEXT PRIMARY KEY,
    updated_at TEXT,
    row_count INTEGER,
    status TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS cve_enriched (
    cve TEXT PRIMARY KEY,
    kev INTEGER NOT NULL DEFAULT 0,
    kev_due_date TEXT,
    epss REAL,
    epss_percentile REAL,
    score REAL,
    severity TEXT,
    version TEXT,
    vector TEXT,
    cwes TEXT,
    refs TEXT
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    """Thin SQLite DAO. Cheap to construct; opens a connection per operation."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create tables (idempotent) and seed empty meta rows for each feed."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            for feed in FEEDS:
                conn.execute(
                    "INSERT OR IGNORE INTO meta(feed, updated_at, row_count, status, detail) "
                    "VALUES (?, NULL, 0, 'empty', '')",
                    (feed,),
                )
            conn.commit()
        log.info("store ready at %s", self.db_path)

    # ── meta ──────────────────────────────────────────────────
    def set_status(self, feed: str, status: str, detail: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE meta SET status = ?, detail = ? WHERE feed = ?",
                (status, detail, feed),
            )
            conn.commit()

    def stamp_meta(self, feed: str, row_count: int, status: str = "ready",
                   detail: str = "") -> None:
        """Set updated_at=now plus row_count/status/detail for a feed in one call.

        Used by file-based feeds (e.g. ``osv``) that have no SQLite table and so don't
        go through the ``replace_*`` wholesale path that normally stamps ``meta``.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE meta SET updated_at = ?, row_count = ?, status = ?, detail = ? "
                "WHERE feed = ?",
                (_now_iso(), row_count, status, detail, feed),
            )
            conn.commit()

    def get_meta(self, feed: str) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT feed, updated_at, row_count, status, detail FROM meta WHERE feed = ?",
                (feed,),
            ).fetchone()
        if row is None:
            return {"feed": feed, "updated_at": None, "row_count": 0,
                    "status": "empty", "detail": ""}
        return dict(row)

    def all_meta(self) -> dict[str, dict]:
        return {feed: self.get_meta(feed) for feed in FEEDS}

    # ── wholesale replace ─────────────────────────────────────
    def replace_kev(self, rows: Iterable[tuple[str, str | None, str | None]]) -> int:
        """Wholesale-replace KEV. ``rows`` = (cve, due_date, name)."""
        rows = list(rows)
        with self._connect() as conn:
            try:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM kev")
                conn.executemany(
                    "INSERT OR REPLACE INTO kev(cve, due_date, name) VALUES (?, ?, ?)", rows
                )
                self._stamp_meta(conn, "kev", len(rows))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return len(rows)

    def replace_epss(self, rows: Iterable[tuple[str, float, float]]) -> int:
        """Wholesale-replace EPSS. ``rows`` = (cve, epss, percentile)."""
        rows = list(rows)
        with self._connect() as conn:
            try:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM epss")
                conn.executemany(
                    "INSERT OR REPLACE INTO epss(cve, epss, percentile) VALUES (?, ?, ?)", rows
                )
                self._stamp_meta(conn, "epss", len(rows))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return len(rows)

    def replace_nvd(self, records: Iterable[dict]) -> int:
        """Wholesale-replace NVD. Each record: {cve, score, severity, version, vector,
        cwes:[...], refs:[...]}. ``cwes``/``refs`` are stored as JSON text."""
        records = list(records)
        params = [
            (
                r["cve"], r.get("score"), r.get("severity"), r.get("version"),
                r.get("vector"), json.dumps(r.get("cwes") or []),
                json.dumps(r.get("refs") or []),
            )
            for r in records
        ]
        with self._connect() as conn:
            try:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM nvd")
                conn.executemany(
                    "INSERT OR REPLACE INTO nvd(cve, score, severity, version, vector, cwes, refs) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params,
                )
                self._stamp_meta(conn, "nvd", len(params))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return len(params)

    @staticmethod
    def _stamp_meta(conn: sqlite3.Connection, feed: str, count: int) -> None:
        status = "ready" if count > 0 else "empty"
        conn.execute(
            "UPDATE meta SET updated_at = ?, row_count = ?, status = ?, detail = '' "
            "WHERE feed = ?",
            (_now_iso(), count, status, feed),
        )

    # ── lookups (batch, by exact CVE id) ──────────────────────
    def lookup_kev(self, cves: list[str]) -> list[str]:
        cves = [c for c in cves if c]
        if not cves:
            return []
        out: list[str] = []
        with self._connect() as conn:
            for chunk in _chunks(cves, 900):
                q = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT cve FROM kev WHERE cve IN ({q})", chunk
                ).fetchall()
                out.extend(r["cve"] for r in rows)
        return out

    def lookup_epss(self, cves: list[str]) -> dict[str, dict]:
        cves = [c for c in cves if c]
        if not cves:
            return {}
        out: dict[str, dict] = {}
        with self._connect() as conn:
            for chunk in _chunks(cves, 900):
                q = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT cve, epss, percentile FROM epss WHERE cve IN ({q})", chunk
                ).fetchall()
                for r in rows:
                    out[r["cve"]] = {"epss": r["epss"], "percentile": r["percentile"]}
        return out

    def lookup_nvd(self, cves: list[str]) -> dict[str, dict]:
        cves = [c for c in cves if c]
        if not cves:
            return {}
        out: dict[str, dict] = {}
        with self._connect() as conn:
            for chunk in _chunks(cves, 900):
                q = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT cve, score, severity, version, vector, cwes, refs "
                    f"FROM nvd WHERE cve IN ({q})",
                    chunk,
                ).fetchall()
                for r in rows:
                    out[r["cve"]] = {
                        "score": r["score"],
                        "severity": r["severity"] or "",
                        "version": r["version"] or "",
                        "vector": r["vector"] or "",
                        "cwes": json.loads(r["cwes"]) if r["cwes"] else [],
                        "refs": json.loads(r["refs"]) if r["refs"] else [],
                    }
        return out

    # ── denormalized enriched table ───────────────────────────
    def build_enriched(self) -> int:
        """Wholesale-rebuild ``cve_enriched`` from kev/epss/nvd in ONE transaction.

        The CVE universe is the UNION of cve ids across nvd, epss and kev. A single
        ``DELETE`` + ``INSERT ... SELECT`` join pegs each CVE with its KEV flag/due-date,
        EPSS score/percentile and NVD CVSS/CWE columns, so the scanner can do one lookup
        per CVE instead of three. Returns the row count and stamps ``meta['enriched']``.
        """
        with self._connect() as conn:
            try:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM cve_enriched")
                conn.execute(_BUILD_ENRICHED_SQL)
                count = conn.execute("SELECT COUNT(*) FROM cve_enriched").fetchone()[0]
                status = "ready" if count > 0 else "empty"
                detail = f"{count} CVEs pegged with KEV/EPSS/NVD"
                conn.execute(
                    "UPDATE meta SET updated_at = ?, row_count = ?, status = ?, detail = ? "
                    "WHERE feed = ?",
                    (_now_iso(), count, status, detail, "enriched"),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        log.info("cve_enriched rebuilt: %d CVEs", count)
        return count

    def lookup_enriched(self, cves: list[str]) -> dict[str, dict]:
        """Batch lookup against the denormalized table. JSON-decodes cwes/refs."""
        cves = [c for c in cves if c]
        if not cves:
            return {}
        out: dict[str, dict] = {}
        with self._connect() as conn:
            for chunk in _chunks(cves, 900):
                q = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT cve, kev, kev_due_date, epss, epss_percentile, score, "
                    f"severity, version, vector, cwes, refs "
                    f"FROM cve_enriched WHERE cve IN ({q})",
                    chunk,
                ).fetchall()
                for r in rows:
                    out[r["cve"]] = {
                        "kev": bool(r["kev"]),
                        "kevDueDate": r["kev_due_date"],
                        "epss": r["epss"],
                        "percentile": r["epss_percentile"],
                        "score": r["score"],
                        "severity": r["severity"] or "",
                        "version": r["version"] or "",
                        "vector": r["vector"] or "",
                        "cwes": json.loads(r["cwes"]) if r["cwes"] else [],
                        "refs": json.loads(r["refs"]) if r["refs"] else [],
                    }
        return out


# The wholesale-rebuild join. The CVE universe is the UNION of nvd/epss/kev ids;
# LEFT JOINs peg KEV (flag + due_date), EPSS (score + percentile) and NVD (CVSS + CWE).
_BUILD_ENRICHED_SQL = """
INSERT INTO cve_enriched
    (cve, kev, kev_due_date, epss, epss_percentile,
     score, severity, version, vector, cwes, refs)
SELECT
    c.cve,
    CASE WHEN k.cve IS NOT NULL THEN 1 ELSE 0 END AS kev,
    k.due_date,
    e.epss,
    e.percentile,
    n.score,
    n.severity,
    n.version,
    n.vector,
    n.cwes,
    n.refs
FROM (
    SELECT cve FROM nvd
    UNION
    SELECT cve FROM epss
    UNION
    SELECT cve FROM kev
) c
LEFT JOIN kev  k ON k.cve = c.cve
LEFT JOIN epss e ON e.cve = c.cve
LEFT JOIN nvd  n ON n.cve = c.cve
"""


def _chunks(seq: list, n: int) -> Iterator[list]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
