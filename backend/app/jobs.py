"""In-memory async job store for long-running scan jobs.

Jobs expire from memory after 2 hours.  Acceptable for a single-process server.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

# job_id -> {status, created_at, sbom_name?, result?, error?}
_jobs: dict[str, dict] = {}

_JOB_TTL_SECONDS = 2 * 3600  # 2 hours


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_out() -> None:
    """Remove jobs older than TTL."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_JOB_TTL_SECONDS)
    to_del = [
        jid for jid, j in _jobs.items()
        if datetime.fromisoformat(j["createdAt"]) < cutoff
    ]
    for jid in to_del:
        del _jobs[jid]


def create_job(sbom_name: Optional[str] = None) -> str:
    _age_out()
    job_id = uuid.uuid4().hex
    _jobs[job_id] = {
        "jobId": job_id,
        "status": "running",
        "createdAt": _now_iso(),
        "sbomName": sbom_name,
        "result": None,
        "error": None,
    }
    return job_id


def complete_job(job_id: str, result: dict) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result


def fail_job(job_id: str, error: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = error


def get_job(job_id: str) -> Optional[dict]:
    return _jobs.get(job_id)


def list_jobs() -> list[dict]:
    _age_out()
    return [
        {
            "jobId": j["jobId"],
            "status": j["status"],
            "createdAt": j["createdAt"],
            "sbomName": j.get("sbomName"),
        }
        for j in sorted(_jobs.values(), key=lambda x: x["createdAt"], reverse=True)
    ]


def _clear_jobs() -> None:
    """Clear all jobs (used by tests)."""
    _jobs.clear()
