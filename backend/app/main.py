"""FastAPI app — routes per the frozen API contract (docs/API_CONTRACT.md).

Base path is ``/api``. CORS is intentionally OFF: in production nginx serves the frontend
and reverse-proxies ``/api`` same-origin. Parsing / scanning / scoring / reporting all live
server-side; the frontend is a pure consumer.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
import uuid
from urllib.parse import urlparse

import httpx
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

import time

from .config import VERSION, settings
from .feeds_client import FeedsClient, feed_meta, feed_ready
from .hardening import HardeningMiddleware
from .logging_config import get_logger, setup_logging
from .models import (
    AssessRequest, ParseRequest, ReportRequest, SarifRequest, ScanRequest, ScanResponse, Sbom,
    VexApplyRequest, VexSuppression,
)
from .nvd import probe_nvd
from .parsers import ParseError, parse_sbom
from .report import build_html_report
from .sarif import build_sarif
from .scanner import scan_sbom
from .scoring import build_assessment, classify_dependency_depth

# Short-lived cache of source-reachability probes (~60s) so /api/sources is cheap.
_PROBE_CACHE: dict[str, tuple[float, bool | None]] = {}
_PROBE_TTL = 60.0

setup_logging()
log = get_logger("sbom.api")

# Strong references to in-flight background scan tasks. asyncio only holds a weak
# reference to tasks, so a fire-and-forget create_task() can be garbage-collected
# mid-run; keeping the task here until it finishes prevents silent cancellation.
_bg_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    if settings.api_token:
        log.info("auth ENABLED (API_TOKEN set); rate limit %s; max body %d bytes",
                 settings.rate_limit, settings.max_body_bytes)
    else:
        log.warning("auth DISABLED (API_TOKEN unset) — open access; safe for localhost "
                    "dev only. Set API_TOKEN before deploying beyond localhost.")
    log.info("NVD key %s; rate limit %s; max body %d bytes; NVD budget %.0fs",
             "set" if settings.nvd_api_key else "unset (keyless)",
             settings.rate_limit, settings.max_body_bytes, settings.nvd_budget_seconds)
    yield


app = FastAPI(title="SBOM Visualizer Backend", version=VERSION, lifespan=_lifespan)
app.add_middleware(HardeningMiddleware)


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


# ── SSRF-safe URL validation ──────────────────────────────────
def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not parseable → block
    return (addr.is_loopback or addr.is_link_local or addr.is_private
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _validate_fetch_url(url: str) -> str | None:
    """Return an error string if the URL is unsafe to fetch, else None."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL."
    if parsed.scheme not in ("http", "https"):
        return "Only http and https URLs are allowed."
    host = parsed.hostname
    if not host:
        return "URL has no host."
    # Resolve all addresses and reject any that target internal / metadata ranges.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return "Could not resolve host."
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            return "URL resolves to a blocked (internal/link-local/loopback) address."
    return None


# ── Helpers ───────────────────────────────────────────────────
def _apply_depth(sbom: Sbom) -> Sbom:
    """Compute and stamp direct/transitive depth onto each component."""
    depth_map = classify_dependency_depth(sbom)
    for i, c in enumerate(sbom.components):
        c.depth = depth_map.get(i, "unknown")  # type: ignore[assignment]
    return sbom


def _project(request: Request) -> str | None:
    """Return the project associated with the authenticated caller (may be None)."""
    return getattr(request.state, "project", None)


# ── VEX helpers ───────────────────────────────────────────────
def _suppression_to_dict(s: VexSuppression) -> dict:
    return {
        "id": s.id,
        "cveId": s.cveId,
        "componentPurl": s.componentPurl,
        "componentName": s.componentName,
        "status": s.status,
        "justification": s.justification,
        "note": s.note,
        "author": s.author,
        "expiresAt": s.expiresAt,
        "project": s.project,
    }


def _apply_vex_to_scan(findings, summary, suppressions_dicts: list[dict]) -> tuple:
    """Apply VEX suppressions to findings; return (patched_findings, patched_summary)."""
    from .vex import apply_suppressions
    from .models import Summary

    if not suppressions_dicts:
        return findings, summary

    # Attach _purl and _name to each Vuln so apply_suppressions can match.
    # We need the sbom but it is not always available here; the caller injects it.
    patched, suppressed_count = apply_suppressions(findings, suppressions_dicts)

    # Rebuild summary excluding suppressed vulns.
    new_summary = Summary(
        scanned=summary.scanned,
        withPurl=summary.withPurl,
        suppressedCount=suppressed_count,
    )
    for f in patched:
        has_unsuppressed = False
        for v in f.vulns:
            if not v.suppressed:
                sev = v.cvss.severity
                if hasattr(new_summary, sev):
                    setattr(new_summary, sev, getattr(new_summary, sev) + 1)
                new_summary.total += 1
                has_unsuppressed = True
        if has_unsuppressed:
            new_summary.affected += 1

    return patched, new_summary


def _annotate_findings_with_component(findings, sbom: Sbom):
    """Stamp _purl and _name onto each Vuln so VEX matching works."""
    for f in findings:
        idx = f.componentIndex
        if 0 <= idx < len(sbom.components):
            comp = sbom.components[idx]
            for v in f.vulns:
                object.__setattr__(v, "_purl", comp.purl or None)
                object.__setattr__(v, "_name", comp.name or None)


# ── Routes ────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": VERSION}


@app.post("/api/parse")
async def parse_endpoint(req: ParseRequest):
    raw = req.raw
    if raw is None and req.url:
        err = _validate_fetch_url(req.url)
        if err:
            return _error(400, err)
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=15.0,
                                         headers={"User-Agent": "sbom-visualizer/1.0"}) as client:
                resp = await client.get(req.url)
        except httpx.HTTPError as e:
            return _error(400, f"Failed to fetch URL: {e}")
        if resp.status_code != 200:
            return _error(400, f"Fetch returned HTTP {resp.status_code}.")
        if len(resp.content) > settings.max_fetch_bytes:
            return _error(400, "Fetched document exceeds size limit.")
        try:
            raw = resp.json()
        except ValueError:
            return _error(400, "Fetched document is not valid JSON.")
    if raw is None:
        return _error(400, "Provide either 'raw' (SBOM JSON) or 'url'.")

    try:
        sbom, _extra = parse_sbom(raw)
    except ParseError as e:
        return _error(400, str(e))
    except (ValueError, TypeError, AttributeError, KeyError, IndexError) as e:
        # Malformed/hostile SBOM structure (e.g. non-dict array entries) must yield a
        # clean 400, never an uncaught 500 with a stack trace.
        return _error(400, f"Parse failure: {e}")

    sbom.id = uuid.uuid4().hex
    _apply_depth(sbom)
    return {"sbom": sbom.model_dump()}


@app.post("/api/scan", response_model=ScanResponse)
async def scan_endpoint(req: ScanRequest, request: Request):
    from . import scan_store

    opts = req.options
    src = opts.sources
    findings, summary, errors = await scan_sbom(
        req.sbom,
        kev=opts.kev and src.kev,
        epss=opts.epss and src.epss,
        test_mode=opts.testMode,
        mitre=src.mitre,
        nvd=src.nvd,
    )

    # Persist the result.
    sbom = req.sbom
    try:
        scan_id = scan_store.save_scan(
            sbom_id=sbom.id or "",
            sbom_name=sbom.name or sbom.id or "",
            sbom_format=sbom.format,
            component_count=len(sbom.components),
            findings=findings,
            summary=summary,
            errors=errors,
            project=_project(request),
        )
    except Exception:
        log.exception("scan_store.save_scan failed; returning result without scanId")
        scan_id = None

    return ScanResponse(findings=findings, summary=summary, errors=errors, scanId=scan_id)


@app.post("/api/assess")
async def assess_endpoint(req: AssessRequest, request: Request):
    # Depth is already stamped on components by /api/parse; don't re-run the BFS
    # graph traversal on every assess call — it's O(V+E) and blocks the event loop.
    sbom = req.sbom
    findings = req.findings
    summary = req.summary

    # Apply VEX suppressions when the caller supplies them explicitly.
    # Fetching from the DB is done only when the client passes suppressions=None
    # AND the project has suppressions stored — kept as an opt-in to avoid a
    # synchronous SQLite call on every assess.
    if req.suppressions is not None:
        _annotate_findings_with_component(findings, sbom)
        sup_dicts = [_suppression_to_dict(s) for s in req.suppressions]
        findings, summary = _apply_vex_to_scan(findings, summary, sup_dicts)

    # Pass only unsuppressed findings to the assessment engine.
    active_findings = [
        f.__class__(
            componentIndex=f.componentIndex,
            vulns=[v for v in f.vulns if not v.suppressed],
        )
        for f in findings
        if any(not v.suppressed for v in f.vulns)
    ]

    assessment = build_assessment(sbom, active_findings, summary, policy=req.policy,
                                  license_policy=req.licensePolicy)
    return {"assessment": assessment.model_dump()}


@app.post("/api/report")
async def report_endpoint(req: ReportRequest):
    sbom = req.sbom  # depth already stamped by /api/parse
    html = build_html_report(sbom, req.findings, req.summary, req.assessment)
    return HTMLResponse(content=html)


@app.post("/api/export/normalized")
async def export_normalized(req: ParseRequest):
    """Re-emit a normalized SBOM as application/json.

    Accepts the same body as /api/parse (raw or url) so a client can normalize in one call.
    """
    raw = req.raw
    if raw is None and req.url:
        err = _validate_fetch_url(req.url)
        if err:
            return _error(400, err)
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=15.0,
                                         headers={"User-Agent": "sbom-visualizer/1.0"}) as client:
                resp = await client.get(req.url)
            resp.raise_for_status()
            raw = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            return _error(400, f"Failed to fetch/parse URL: {e}")
    if raw is None:
        return _error(400, "Provide either 'raw' (SBOM JSON) or 'url'.")
    try:
        sbom, _extra = parse_sbom(raw)
    except ParseError as e:
        return _error(400, str(e))
    except (ValueError, TypeError, AttributeError, KeyError, IndexError) as e:
        return _error(400, f"Parse failure: {e}")
    sbom.id = uuid.uuid4().hex
    _apply_depth(sbom)
    return Response(content=sbom.model_dump_json(), media_type="application/json")


@app.post("/api/export/sarif")
async def export_sarif(req: SarifRequest):
    """Emit findings as SARIF 2.1.0 (application/json). Pure, no network."""
    sbom = _apply_depth(req.sbom)
    doc = build_sarif(sbom, req.findings)
    return JSONResponse(content=doc)


# ── Data-source connectors ────────────────────────────────────
async def _probe(key: str, coro_factory) -> bool | None:
    """Run a cached (~60s) reachability probe. Returns None on any failure."""
    cached = _PROBE_CACHE.get(key)
    if cached and time.monotonic() - cached[0] < _PROBE_TTL:
        return cached[1]
    result: bool | None
    try:
        result = await coro_factory()
    except Exception:
        result = None
    _PROBE_CACHE[key] = (time.monotonic(), result)
    return result


async def _probe_get_ok(client: httpx.AsyncClient, url: str, timeout: float) -> bool:
    resp = await client.get(url, timeout=timeout,
                            headers={"User-Agent": "sbom-visualizer/1.0"})
    return resp.status_code < 500


@app.get("/api/sources")
async def sources_endpoint():
    nvd_key = bool(settings.nvd_api_key)
    rate = (f"{settings.nvd_rate_keyed}" if nvd_key else f"{settings.nvd_rate_keyless}")
    nvd_detail = (
        f"NVD API 2.0; {'API key set' if nvd_key else 'keyless'} "
        f"(rate {rate} req/{int(settings.nvd_rate_window)}s, "
        f"max {settings.nvd_max_lookups} lookups/scan)"
    )
    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Feeds mirror status (cached ~60s by the probe cache). When USE_FEEDS is off we
        # skip it entirely so KEV/EPSS/NVD report plain "live".
        feeds_status = None
        if settings.use_feeds:
            feeds_status = await _probe("feeds", lambda: FeedsClient(client).status())

        nvd_reachable = await _probe("nvd", lambda: probe_nvd(client))
        osv_reachable = await _probe(
            "osv", lambda: _probe_get_ok(client, settings.osv_vuln + "OSV-2020-111",
                                         settings.osv_vuln_timeout))
        # Only probe MITRE/cve.org when it's actually enabled — otherwise don't reach out.
        mitre_reachable = None
        if settings.enable_mitre:
            mitre_reachable = await _probe(
                "mitre", lambda: _probe_get_ok(client, settings.cve_awg_base + "CVE-2021-44228",
                                               settings.cve_awg_timeout))
        epss_reachable = await _probe(
            "epss", lambda: _probe_get_ok(client, settings.epss_base + "CVE-2021-44228",
                                          settings.epss_timeout))
        kev_reachable = await _probe(
            "kev", lambda: _probe_get_ok(client, settings.kev_url, settings.kev_timeout))

    def _served(source: str, live_detail: str) -> dict:
        """Build the mirror/live/live-fallback fields for a mirrored source (kev/epss/nvd)."""
        if settings.use_feeds and feed_ready(feeds_status, source):
            meta = feed_meta(feeds_status, source) or {}
            updated = meta.get("updatedAt")
            rows = meta.get("rowCount")
            return {
                "servedBy": "mirror",
                "mirror": {"updatedAt": updated, "rowCount": rows},
                "detail": (f"Served from feeds mirror "
                           f"(updated {updated or 'unknown'}, {rows if rows is not None else '?'} rows). "
                           f"{live_detail}"),
            }
        served = "live-fallback" if settings.use_feeds else "live"
        suffix = (" Feeds mirror unavailable/not ready; using live fallback."
                  if settings.use_feeds else "")
        return {"servedBy": served, "mirror": None, "detail": f"{live_detail}{suffix}"}

    def _served_osv(status: dict | None) -> dict:
        """servedBy=offline-mirror when the local osv-scanner cache is ready, else live."""
        from .scanner import offline_binary, offline_cache_ready
        live_detail = "Primary vulnerability discovery (always on)."
        if settings.use_offline_osv and offline_binary() is not None and offline_cache_ready():
            meta = feed_meta(status, "osv") or {}
            updated = meta.get("updatedAt")
            ecosystems = meta.get("rowCount")
            mirror = {"updatedAt": updated, "ecosystems": ecosystems}
            detail = (
                f"Served from offline OSV mirror via osv-scanner "
                f"(updated {updated or 'unknown'}, "
                f"{ecosystems if ecosystems is not None else '?'} ecosystems). {live_detail}"
            )
            return {"servedBy": "offline-mirror", "mirror": mirror, "detail": detail}
        suffix = ""
        if settings.use_offline_osv:
            suffix = " Offline OSV cache unavailable; using live api.osv.dev."
        return {"servedBy": "live", "mirror": None, "detail": f"{live_detail}{suffix}"}

    nvd_served = _served("nvd", nvd_detail)
    epss_served = _served("epss", "Exploit Prediction Scoring System percentiles.")
    kev_served = _served("kev", "Known Exploited Vulnerabilities catalog.")

    # OSV is served from the offline osv-scanner mirror when enabled AND the local DB
    # cache is populated; otherwise from live api.osv.dev (querybatch+hydrate).
    osv_served = _served_osv(feeds_status)

    sources = [
        {"id": "osv", "name": "OSV.dev", "enabled": True, "configured": True,
         "reachable": osv_reachable, "servedBy": osv_served["servedBy"],
         "mirror": osv_served["mirror"], "detail": osv_served["detail"]},
        {"id": "nvd", "name": "NVD API 2.0", "enabled": settings.enable_nvd,
         "configured": True, "reachable": nvd_reachable,
         "servedBy": nvd_served["servedBy"], "mirror": nvd_served["mirror"],
         "detail": nvd_served["detail"]},
        {"id": "mitre", "name": "MITRE CVE Services (cve.org)",
         "enabled": settings.enable_mitre, "configured": True,
         "reachable": mitre_reachable,
         "servedBy": "live" if settings.enable_mitre else "disabled",
         "detail": ("CNA CVSS + CWE enrichment (live top-up)." if settings.enable_mitre
                    else "Disabled — CNA data already provided by the local NVD/cvelistV5 mirror.")},
        {"id": "epss", "name": "FIRST EPSS", "enabled": settings.enable_epss,
         "configured": True, "reachable": epss_reachable,
         "servedBy": epss_served["servedBy"], "mirror": epss_served["mirror"],
         "detail": epss_served["detail"]},
        {"id": "kev", "name": "CISA KEV", "enabled": settings.enable_kev,
         "configured": True, "reachable": kev_reachable,
         "servedBy": kev_served["servedBy"], "mirror": kev_served["mirror"],
         "detail": kev_served["detail"]},
    ]

    # Pre-enrichment fast path: the denormalized cve_enriched table lets the scanner peg
    # KEV+EPSS+NVD per CVE in ONE lookup. Surface its readiness as an indicator.
    if settings.use_feeds:
        enriched_meta = feed_meta(feeds_status, "enriched") or {}
        enriched_ready = feed_ready(feeds_status, "enriched")
        updated = enriched_meta.get("updatedAt")
        rows = enriched_meta.get("rowCount")
        sources.append({
            "id": "enriched", "name": "Feeds enriched (KEV+EPSS+NVD)",
            "enabled": True, "configured": True,
            "reachable": feeds_status is not None,
            "servedBy": "mirror" if enriched_ready else "live-fallback",
            "mirror": {"updatedAt": updated, "rowCount": rows} if enriched_ready else None,
            "detail": (
                f"Denormalized one-lookup pre-enrichment "
                f"(updated {updated or 'unknown'}, {rows if rows is not None else '?'} CVEs)."
                if enriched_ready else
                "Denormalized pre-enrichment table; not ready — using per-source path."
            ),
        })

    return {"sources": sources}


# ── VEX endpoints ─────────────────────────────────────────────
@app.post("/api/vex/suppressions")
async def vex_create_suppression(body: VexSuppression, request: Request):
    from . import vex
    try:
        record = vex.create_suppression(
            cve_id=body.cveId,
            component_purl=body.componentPurl,
            component_name=body.componentName,
            status=body.status,
            justification=body.justification,
            note=body.note,
            author=body.author,
            expires_at=body.expiresAt,
            project=_project(request),
        )
    except ValueError as e:
        return _error(400, str(e))
    return record


@app.get("/api/vex/suppressions")
async def vex_list_suppressions(
    request: Request,
    cveId: str | None = None,
    componentPurl: str | None = None,
    componentName: str | None = None,
    status: str | None = None,
):
    from . import vex
    project = _project(request)
    rows = vex.list_suppressions(
        cve_id=cveId,
        component_purl=componentPurl,
        component_name=componentName,
        status=status,
        project=project,
    )
    return {"suppressions": rows}


@app.delete("/api/vex/suppressions/{sid}")
async def vex_delete_suppression(sid: str):
    from . import vex
    deleted = vex.delete_suppression(sid)
    if not deleted:
        return _error(404, "Suppression not found.")
    return {"deleted": True}


@app.post("/api/vex/apply")
async def vex_apply(req: VexApplyRequest, request: Request):
    """Pure computation endpoint — apply suppressions to a findings list.

    If no suppressions are supplied in the body, fetches all active suppressions
    for the caller's project from the DB.
    """
    from . import vex

    findings = req.findings

    if req.suppressions is not None:
        sup_dicts = [_suppression_to_dict(s) for s in req.suppressions]
    else:
        sup_dicts = vex.list_suppressions(project=_project(request))

    patched, suppressed_count = vex.apply_suppressions(findings, sup_dicts)
    return {
        "findings": [f.model_dump() for f in patched],
        "suppressedCount": suppressed_count,
    }


# ── Scan history endpoints ─────────────────────────────────────
@app.get("/api/scans")
async def list_scans(request: Request):
    from . import scan_store
    scans = scan_store.list_scans(project=_project(request))
    return {"scans": scans}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    from . import scan_store
    record = scan_store.get_scan(scan_id)
    if record is None:
        return _error(404, "Scan not found.")
    # Project isolation: non-admin callers only see their own scans.
    proj = _project(request)
    if proj is not None and record.get("project") != proj:
        return _error(404, "Scan not found.")
    return record


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    from . import scan_store
    # Project isolation check.
    record = scan_store.get_scan(scan_id)
    if record is None:
        return _error(404, "Scan not found.")
    proj = _project(request)
    if proj is not None and record.get("project") != proj:
        return _error(404, "Scan not found.")
    scan_store.delete_scan(scan_id)
    return {"deleted": True}


# ── Async scan job endpoints ───────────────────────────────────
@app.post("/api/scan/async")
async def scan_async(req: ScanRequest, request: Request):
    from . import jobs, scan_store

    sbom = req.sbom
    sbom_name = sbom.name or sbom.id or ""
    job_id = jobs.create_job(sbom_name=sbom_name)
    proj = _project(request)

    async def _run():
        try:
            opts = req.options
            src = opts.sources
            findings, summary, errors = await scan_sbom(
                sbom,
                kev=opts.kev and src.kev,
                epss=opts.epss and src.epss,
                test_mode=opts.testMode,
                mitre=src.mitre,
                nvd=src.nvd,
            )
            try:
                scan_id = scan_store.save_scan(
                    sbom_id=sbom.id or "",
                    sbom_name=sbom_name,
                    sbom_format=sbom.format,
                    component_count=len(sbom.components),
                    findings=findings,
                    summary=summary,
                    errors=errors,
                    project=proj,
                )
            except Exception:
                log.exception("scan_store.save_scan failed in async job %s", job_id)
                scan_id = None
            jobs.complete_job(job_id, {
                "findings": [f.model_dump() for f in findings],
                "summary": summary.model_dump(),
                "errors": errors,
                "scanId": scan_id,
            })
        except Exception as exc:
            jobs.fail_job(job_id, str(exc))
            log.exception("async scan job %s failed", job_id)

    task = asyncio.create_task(_run())
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return {"jobId": job_id, "status": "running"}


@app.get("/api/scan/jobs/{job_id}")
async def get_scan_job(job_id: str):
    from . import jobs
    job = jobs.get_job(job_id)
    if job is None:
        return _error(404, "Job not found.")
    out: dict = {
        "jobId": job["jobId"],
        "status": job["status"],
        "createdAt": job["createdAt"],
    }
    if job.get("result") is not None:
        out["result"] = job["result"]
    if job.get("error") is not None:
        out["error"] = job["error"]
    return out


@app.get("/api/scan/jobs")
async def list_scan_jobs():
    from . import jobs
    return {"jobs": jobs.list_jobs()}


# ── Admin: API key management ─────────────────────────────────
def _require_admin(request: Request):
    """Return an error response if caller is not using the master API_TOKEN, else None."""
    from .hardening import _provided_token
    provided = _provided_token(request)
    if provided != settings.api_token:
        return _error(403, "Admin access requires the master API_TOKEN.")
    return None


@app.post("/api/admin/keys")
async def admin_create_key(request: Request, body: dict):
    err = _require_admin(request)
    if err:
        return err
    label = (body.get("label") or "").strip()
    if not label:
        return _error(400, "label is required.")
    project = body.get("project") or None
    from . import auth
    try:
        record = auth.create_key(label=label, project=project)
    except Exception as e:
        return _error(400, str(e))
    return record


@app.get("/api/admin/keys")
async def admin_list_keys(request: Request):
    err = _require_admin(request)
    if err:
        return err
    from . import auth
    return {"keys": auth.list_keys()}


@app.delete("/api/admin/keys/{label}")
async def admin_delete_key(label: str, request: Request):
    err = _require_admin(request)
    if err:
        return err
    from . import auth
    deleted = auth.delete_key(label)
    if not deleted:
        return _error(404, "Key not found.")
    return {"deleted": True}
