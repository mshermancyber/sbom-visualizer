"""Async vulnerability scanner — OSV querybatch+hydrate, cve.org enrich, KEV, EPSS.

Faithful server-side port of the demo scan pipeline:
  1. Build per-component OSV queries (buildOsvQuery).
  2. querybatch in chunks of 100.
  3. Hydrate unique vuln IDs with bounded concurrency (~10).
  4. Parse each OSV vuln (parseOsvVuln) — severity resolution + CVSS.
  5. Enrich CVE-aliased vulns that lack a numeric score from cve.org (~8 concurrent).
  6. Overlay CISA KEV (fetched once) and EPSS percentiles (batched ~100/req).

In-memory TTL cache keyed by purl-query (OSV vuln-id lists) and by vuln id (parsed detail),
plus a singleton KEV cache. Per-request timeouts; a single upstream failure is collected into
``errors`` and never crashes the whole scan.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time

import httpx

from .cache import TTLCache
from .cache import TTLCache as _TTLCache  # back-compat alias for existing tests
from .config import settings
from .feeds_client import UNAVAILABLE, FeedsClient, feed_ready
from .logging_config import get_logger
from .cvss import (
    cvss2_score, cvss3_score, cvss4_score, extract_osv_cvss,
    score_to_severity2, score_to_severity3, score_to_severity4,
)
from .models import Cvss, Epss, Finding, Sbom, Summary, Vuln
from .nvd import _nvd_cache, enrich_from_nvd
from .scoring import build_osv_query

_SEV_OK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
_SEV_ORD = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

log = get_logger("sbom.scan")
cache_log = get_logger("sbom.cache")


# ── TTL caches (process-GLOBAL, shared across requests/files) ──
_query_cache = TTLCache(settings.cache_ttl, "osv-query")   # purl/query-key -> list[vuln id]
_vuln_cache = TTLCache(settings.cache_ttl, "osv-hydrate")  # vuln id -> parsed dict
_epss_cache = TTLCache(settings.cache_ttl, "epss")         # cve id -> {epss, percentile}|None
_kev_cache = TTLCache(settings.cache_ttl, "kev")           # "__kev__" -> set[str]
# cve.org (mitre) results are now cached process-globally too, keyed by CVE id.
_cve_awg_cache = TTLCache(settings.cache_ttl, "cve.org")   # cve id -> parsed dict|None

_ALL_CACHES = (_query_cache, _vuln_cache, _epss_cache, _kev_cache, _cve_awg_cache, _nvd_cache)


def _log_cache_stats() -> None:
    total_hits = sum(c.hits for c in _ALL_CACHES)
    total = total_hits + sum(c.misses for c in _ALL_CACHES)
    rate = (total_hits / total * 100) if total else 0.0
    parts = " ".join(f"{c.name}={c.hits}/{c.hits + c.misses}" for c in _ALL_CACHES)
    cache_log.info("cache hit-rate %.0f%% (%d/%d) [%s]", rate, total_hits, total, parts)


def _query_key(q: dict) -> str:
    pkg = q.get("package", {})
    if "purl" in pkg:
        return "purl:" + pkg["purl"]
    return f"nv:{pkg.get('ecosystem','')}|{pkg.get('name','')}|{q.get('version','')}"


# ── OSV vuln parsing (port of parseOsvVuln + helpers) ─────────
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _extract_fixed(v: dict) -> list[str]:
    fixed: list[str] = []
    seen = set()
    for aff in v.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            for e in rng.get("events") or []:
                f = e.get("fixed")
                if f and f not in seen:
                    seen.add(f)
                    fixed.append(f)
    return fixed[:6]


def _extract_cwes(v: dict) -> list[str]:
    out: list[str] = []
    seen = set()

    def add(arr):
        for c in arr or []:
            m = _CWE_RE.search(str(c))
            if m:
                cid = m.group(0).upper()
                if cid not in seen:
                    seen.add(cid)
                    out.append(cid)

    add((v.get("database_specific") or {}).get("cwe_ids"))
    for aff in v.get("affected") or []:
        add((aff.get("database_specific") or {}).get("cwe_ids"))
    return out


def parse_osv_vuln(v: dict) -> dict | None:
    if not v:
        return None
    desc = (v.get("details") or v.get("summary") or "").strip()
    aliases = list(v.get("aliases") or [])
    cve_id = next((a for a in aliases if str(a).startswith("CVE-")), v.get("id"))
    refs = [r.get("url") for r in (v.get("references") or [])[:4] if r.get("url")]

    cvss = {"score": None, "severity": "UNKNOWN", "version": None, "vector": None}

    db_sev = ((v.get("database_specific") or {}).get("severity") or "").upper()
    if db_sev in _SEV_OK:
        cvss["severity"] = db_sev

    if cvss["severity"] == "UNKNOWN":
        for aff in v.get("affected") or []:
            es = ((aff.get("ecosystem_specific") or {}).get("severity") or "").upper()
            if es in _SEV_OK:
                cvss["severity"] = es
                break

    from_vec = extract_osv_cvss(v.get("severity"))
    cvss["vector"] = from_vec["vector"]
    cvss["version"] = from_vec["version"]
    cvss["score"] = from_vec["score"]
    if cvss["severity"] == "UNKNOWN" and from_vec["severity"] != "UNKNOWN":
        cvss["severity"] = from_vec["severity"]

    db_cvss = (v.get("database_specific") or {}).get("cvss")
    if db_cvss:
        if db_cvss.get("score") is not None and cvss["score"] is None:
            cvss["score"] = round(db_cvss["score"] * 10) / 10
        if db_cvss.get("vectorString") and not cvss["vector"]:
            cvss["vector"] = db_cvss["vectorString"]
            vec = cvss["vector"]
            cvss["version"] = ("3.1" if vec.startswith("CVSS:3.1")
                               else "3.0" if vec.startswith("CVSS:3.0")
                               else "4.0" if vec.startswith("CVSS:4") else "2.0")
            if cvss["severity"] == "UNKNOWN":
                computed = (cvss4_score(vec) if vec.startswith("CVSS:4")
                            else cvss3_score(vec) if vec.startswith("CVSS:3")
                            else cvss2_score(vec) if vec.startswith("CVSS:2") else None)
                if vec.startswith("CVSS:4"):
                    cvss["severity"] = score_to_severity4(computed)
                elif vec.startswith("CVSS:3"):
                    cvss["severity"] = score_to_severity3(computed)
                elif vec.startswith("CVSS:2"):
                    cvss["severity"] = score_to_severity2(computed)
                if cvss["score"] is None and computed is not None:
                    cvss["score"] = computed

    if cvss["score"] is None and cvss["vector"]:
        vec = cvss["vector"]
        computed = (cvss4_score(vec) if vec.startswith("CVSS:4")
                    else cvss3_score(vec) if vec.startswith("CVSS:3")
                    else cvss2_score(vec) if vec.startswith("CVSS:2") else None)
        if computed is not None:
            cvss["score"] = computed

    vid = v.get("id") or ""
    malicious = (str(vid).startswith("MAL-")
                 or any(str(a).startswith("MAL-") for a in aliases)
                 or (v.get("database_specific") or {}).get("malicious") is True)

    # Provenance: if OSV/GHSA supplied a numeric score, record where it came from.
    score_source = None
    if cvss["score"] is not None:
        score_source = "ghsa" if str(vid).startswith("GHSA-") else "osv"

    return {
        "id": vid,
        "cveId": cve_id,
        "aliases": aliases,
        "desc": desc[:600],
        "cvss": cvss,
        "cwes": _extract_cwes(v),
        "malicious": malicious,
        "refs": refs,
        "published": (v.get("published") or "")[:10],
        "modified": (v.get("modified") or "")[:10],
        "withdrawn": v.get("withdrawn"),
        "fixed": _extract_fixed(v),
        "scoreSource": score_source,
    }


# ── cve.org enrichment (port of parseCveAwgScore) ─────────────
def parse_cve_awg_score(data: dict) -> dict | None:
    if not data:
        return None
    containers = data.get("containers") or {}
    sources = [containers.get("cna")] + list(containers.get("adp") or [])
    sources = [s for s in sources if s]

    cwes: list[str] = []
    seen = set()
    for src in sources:
        for pt in src.get("problemTypes") or []:
            for d in pt.get("descriptions") or []:
                cid = d.get("cweId")
                if not cid:
                    m = _CWE_RE.search(d.get("description") or "")
                    cid = m.group(0) if m else None
                if cid:
                    up = str(cid).upper()
                    if up not in seen:
                        seen.add(up)
                        cwes.append(up)

    for src in sources:
        for m in src.get("metrics") or []:
            candidates = [
                (m.get("cvssV4_0") or {}).get("cvssData"),
                (m.get("cvssV3_1") or {}).get("cvssData"),
                (m.get("cvssV3_0") or {}).get("cvssData"),
                (m.get("cvssV2_0") or {}).get("cvssData"),
            ]
            for c in candidates:
                if not c:
                    continue
                score = c.get("baseScore")
                severity = (c.get("baseSeverity") or "").upper()
                vector = c.get("vectorString") or ""
                version = ("4.0" if vector.startswith("CVSS:4")
                           else "3.1" if vector.startswith("CVSS:3.1")
                           else "3.0" if vector.startswith("CVSS:3.0") else "2.0")
                if score is not None and severity in _SEV_OK:
                    return {"score": round(score * 10) / 10, "severity": severity,
                            "version": version, "vector": vector, "cwes": cwes}

    if cwes:
        return {"score": None, "severity": None, "version": None, "vector": None, "cwes": cwes}
    return None


# ── HTTP helpers ──────────────────────────────────────────────
http_log = get_logger("sbom.scan")


async def _osv_querybatch(client: httpx.AsyncClient, queries: list[dict]) -> dict:
    t0 = time.monotonic()
    resp = await client.post(settings.osv_querybatch, json={"queries": queries},
                             timeout=settings.osv_batch_timeout)
    http_log.debug("HTTP POST %s -> %d %.0fms", settings.osv_querybatch,
                   resp.status_code, (time.monotonic() - t0) * 1000)
    resp.raise_for_status()
    return resp.json()


async def _osv_get_vuln(client: httpx.AsyncClient, vid: str) -> dict | None:
    try:
        t0 = time.monotonic()
        resp = await client.get(settings.osv_vuln + vid, timeout=settings.osv_vuln_timeout)
        http_log.debug("HTTP GET %s%s -> %d %.0fms", settings.osv_vuln, vid,
                       resp.status_code, (time.monotonic() - t0) * 1000)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


async def _fetch_cve_awg(client: httpx.AsyncClient, cve_id: str) -> dict | None:
    """cve.org enrichment with a process-global cache (None negative-cached)."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    cached = _cve_awg_cache.get(cve_id)
    if cached is not None:
        # Sentinel for "looked up, no data".
        return None if cached == "__none__" else cached
    try:
        t0 = time.monotonic()
        resp = await client.get(settings.cve_awg_base + cve_id,
                                headers={"Accept": "application/json"},
                                timeout=settings.cve_awg_timeout)
        http_log.debug("HTTP GET %s%s -> %d %.0fms", settings.cve_awg_base, cve_id,
                       resp.status_code, (time.monotonic() - t0) * 1000)
        if resp.status_code != 200:
            _cve_awg_cache.set(cve_id, "__none__")
            return None
        parsed = parse_cve_awg_score(resp.json())
        _cve_awg_cache.set(cve_id, parsed if parsed is not None else "__none__")
        return parsed
    except Exception:
        return None


async def _fetch_kev(client: httpx.AsyncClient, errors: list[str]) -> set[str]:
    cached = _kev_cache.get("__kev__")
    if cached is not None:
        return cached
    try:
        resp = await client.get(settings.kev_url, timeout=settings.kev_timeout)
        resp.raise_for_status()
        data = resp.json()
        kev = {v.get("cveID") for v in (data.get("vulnerabilities") or []) if v.get("cveID")}
        _kev_cache.set("__kev__", kev)
        return kev
    except Exception as e:  # non-fatal
        errors.append(f"KEV fetch failed: {e}")
        return set()


async def _fetch_epss(client: httpx.AsyncClient, cve_ids: list[str],
                      errors: list[str]) -> dict[str, dict]:
    ids = sorted({c for c in cve_ids if c and c.startswith("CVE-")})
    out: dict[str, dict] = {}
    missing: list[str] = []
    for cid in ids:
        cached = _epss_cache.get(cid)
        if cached is not None:
            if cached:
                out[cid] = cached
        else:
            missing.append(cid)

    for i in range(0, len(missing), settings.epss_chunk):
        chunk = missing[i:i + settings.epss_chunk]
        try:
            resp = await client.get(settings.epss_base + ",".join(chunk),
                                    timeout=settings.epss_timeout)
            resp.raise_for_status()
            data = resp.json()
            found = set()
            for d in data.get("data") or []:
                try:
                    epss = float(d.get("epss"))
                except (TypeError, ValueError):
                    continue
                try:
                    pct = float(d.get("percentile"))
                except (TypeError, ValueError):
                    pct = None
                rec = {"score": epss, "percentile": pct}
                out[d["cve"]] = rec
                _epss_cache.set(d["cve"], rec)
                found.add(d["cve"])
            for cid in chunk:
                if cid not in found:
                    _epss_cache.set(cid, None)  # negative cache
        except Exception as e:
            errors.append(f"EPSS chunk {i}: {e}")
    return out


# ── Orchestrator ──────────────────────────────────────────────
async def scan_sbom(sbom: Sbom, kev: bool = True, epss: bool = True,
                    test_mode: bool = False, mitre: bool = True,
                    nvd: bool = True) -> tuple[list[Finding], Summary, list[str]]:
    errors: list[str] = []
    summary = Summary()
    distro = sbom.distro or ""
    for c in _ALL_CACHES:
        c.reset_stats()
    log.info("scan start: %d components (kev=%s epss=%s mitre=%s nvd=%s test=%s)",
             len(sbom.components), kev, epss, mitre, nvd, test_mode)

    # Build indexed queries
    indexed: list[tuple[int, dict]] = []
    for i, comp in enumerate(sbom.components):
        if test_mode and len(indexed) >= 20:
            break
        q = build_osv_query(comp, distro)
        if not q:
            continue
        if comp.purl:
            summary.withPurl += 1
        summary.scanned += 1
        indexed.append((i, q))

    if not indexed:
        return [], summary, errors

    limits = httpx.Limits(max_connections=20, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, follow_redirects=True,
                                 headers={"User-Agent": "sbom-visualizer/1.0"}) as client:
        # Feeds mirror: decide once per scan whether to use it. The status response is
        # cached briefly inside FeedsClient. Per source, the mirror is used only when
        # feeds is reachable AND that feed's status=="ready"; else live fallback.
        feeds: FeedsClient | None = None
        feeds_status: dict | None = None
        if settings.use_feeds and (kev or epss or nvd):
            feeds = FeedsClient(client)
            feeds_status = await feeds.status()
            if feeds_status is None:
                log.info("feeds mirror unreachable; KEV/EPSS/NVD will use live fallback")

        # OSV discovery: try the offline mirror (osv-scanner) first; on any of the
        # documented fallback conditions it returns None and we run the live path below.
        comp_to_ids: dict[int, set[str]] = {}
        parsed_map: dict[str, dict] = {}
        offline = await _osv_offline_phase(indexed, sbom.components, errors)

        if offline is not None:
            comp_to_ids, parsed_map = offline

        # Phase 1: querybatch (with cache) — LIVE path, skipped when offline succeeded.
        _p0 = time.monotonic()
        err_count = 0
        uncached: list[tuple[int, dict]] = []
        for comp_idx, q in (indexed if offline is None else []):
            key = _query_key(q)
            cached = _query_cache.get(key)
            if cached is not None:
                if cached:
                    comp_to_ids.setdefault(comp_idx, set()).update(cached)
            else:
                uncached.append((comp_idx, q))

        # Accumulate the complete id set per query-key across pages before caching,
        # so a paginated package isn't cached as just its first page.
        ids_by_key: dict[str, set[str]] = {}
        # Queries that still have a next_page_token to follow up on.
        # Each entry: (comp_idx, query_dict, page_token).
        pending_pages: list[tuple[int, dict, str]] = []

        def _absorb(comp_idx: int, q: dict, res: dict) -> None:
            key = _query_key(q)
            ids = [vv.get("id") for vv in (res.get("vulns") or []) if vv.get("id")]
            bucket = ids_by_key.setdefault(key, set())
            bucket.update(ids)
            if ids:
                comp_to_ids.setdefault(comp_idx, set()).update(ids)
            token = res.get("next_page_token")
            if token:
                pending_pages.append((comp_idx, q, token))

        for off in range(0, len(uncached), settings.osv_batch_size):
            chunk = uncached[off:off + settings.osv_batch_size]
            try:
                data = await _osv_querybatch(client, [q for _, q in chunk])
                results = data.get("results") or []
                for ri, res in enumerate(results):
                    comp_idx, q = chunk[ri]
                    _absorb(comp_idx, q, res)
                # Mark queries beyond returned length as empty too
                for ri in range(len(results), len(chunk)):
                    ids_by_key.setdefault(_query_key(chunk[ri][1]), set())
            except Exception as e:
                errors.append(f"OSV batch {off}: {e}")
                err_count += 1
                if err_count >= settings.max_batch_errors:
                    break

        # Follow up on next_page_token results: resend ONLY the affected query
        # object(s) with page_token set, looping until no tokens remain. Capped
        # by OSV_MAX_PAGES rounds to avoid runaway on packages with 1000+ advisories.
        rounds = 0
        while pending_pages:
            if rounds >= settings.osv_max_pages:
                errors.append(
                    f"OSV querybatch pagination cap ({settings.osv_max_pages}) reached "
                    f"with {len(pending_pages)} page(s) still pending; some vulnerabilities "
                    f"may be missing for the affected component(s)."
                )
                break
            rounds += 1
            batch = pending_pages
            pending_pages = []
            for off in range(0, len(batch), settings.osv_batch_size):
                chunk = batch[off:off + settings.osv_batch_size]
                queries = []
                for _, q, token in chunk:
                    pq = dict(q)
                    pq["page_token"] = token
                    queries.append(pq)
                try:
                    data = await _osv_querybatch(client, queries)
                    results = data.get("results") or []
                    for ri, res in enumerate(results):
                        comp_idx, q, _ = chunk[ri]
                        _absorb(comp_idx, q, res)
                except Exception as e:
                    errors.append(f"OSV querybatch page round {rounds}: {e}")
                    err_count += 1
                    if err_count >= settings.max_batch_errors:
                        pending_pages = []
                        break

        # Persist the fully-merged id sets to the query cache.
        for key, idset in ids_by_key.items():
            _query_cache.set(key, sorted(idset))
        log.info("phase OSV querybatch: %d queries (%d uncached) %.0fms",
                 len(indexed), len(uncached), (time.monotonic() - _p0) * 1000)

        # Air-gap safety net: if we routed a (small) SBOM to LIVE OSV but it errored and
        # produced no results (e.g. no network), fall back to the offline mirror even
        # though it's below the speed threshold. This keeps the tool correct offline.
        if (offline is None and uncached and err_count > 0 and not comp_to_ids
                and offline_cache_ready()):
            forced = await _osv_offline_phase(indexed, sbom.components, errors, force=True)
            if forced is not None:
                comp_to_ids, parsed_map = forced
                offline = forced   # downstream + hydrate now treat OSV as offline-served
                log.info("osv [offline-fallback]: live OSV unreachable, used offline mirror")

        # Phase 2: hydrate unique IDs (bounded concurrency, with cache) — LIVE path only.
        # When the offline mirror ran, parsed_map is already fully populated from the
        # osv-scanner records, so we skip hydration entirely.
        if offline is None:
            _p0 = time.monotonic()
            all_ids = sorted({i for s in comp_to_ids.values() for i in s})
            to_fetch: list[str] = []
            for vid in all_ids:
                cached = _vuln_cache.get(vid)
                if cached is not None:
                    parsed_map[vid] = cached
                else:
                    to_fetch.append(vid)

            sem = asyncio.Semaphore(settings.detail_concurrency)

            async def _hydrate(vid: str):
                async with sem:
                    raw = await _osv_get_vuln(client, vid)
                if raw:
                    parsed = parse_osv_vuln(raw)
                    if parsed:
                        _vuln_cache.set(vid, parsed)
                        parsed_map[vid] = parsed

            if to_fetch:
                await asyncio.gather(*[_hydrate(v) for v in to_fetch])
            log.info("phase hydrate: %d ids (%d fetched, %d cached) %.0fms",
                     len(all_ids), len(to_fetch), len(all_ids) - len(to_fetch),
                     (time.monotonic() - _p0) * 1000)

        # Enrichment for CVE-aliased vulns lacking a numeric score.
        # Order: mitre (cve.org) → nvd. scoreSource records which filled it.
        def _needs_score() -> list[str]:
            needs: dict[str, bool] = {}
            for p in parsed_map.values():
                if p.get("withdrawn"):
                    continue
                if p["cvss"]["score"] is None and (p.get("cveId") or "").startswith("CVE-"):
                    needs[p["cveId"]] = True
            return sorted(needs.keys())

        # Phase 2.5: cve.org (mitre) enrichment
        if mitre and settings.enable_mitre:
            _p0 = time.monotonic()
            cve_ids = _needs_score()
            if cve_ids:
                esem = asyncio.Semaphore(settings.cve_awg_concurrency)
                results: dict[str, dict] = {}

                async def _enrich(cid: str):
                    async with esem:
                        r = await _fetch_cve_awg(client, cid)
                    if r:
                        results[cid] = r

                await asyncio.gather(*[_enrich(c) for c in cve_ids])
                log.info("phase cve.org: %d CVEs enriched=%d %.0fms", len(cve_ids),
                         len(results), (time.monotonic() - _p0) * 1000)
                for p in parsed_map.values():
                    cid = p.get("cveId")
                    if not cid or cid not in results:
                        continue
                    enriched = results[cid]
                    if p["cvss"]["score"] is None and enriched.get("score") is not None:
                        p["cvss"]["score"] = enriched["score"]
                        p["cvss"]["severity"] = enriched["severity"]
                        p["cvss"]["version"] = enriched["version"]
                        if not p["cvss"]["vector"]:
                            p["cvss"]["vector"] = enriched["vector"]
                        p["scoreSource"] = "mitre"
                    if (not p.get("cwes")) and enriched.get("cwes"):
                        p["cwes"] = enriched["cwes"]

        # Pre-enrichment fast path: when the feeds mirror has the denormalized ``enriched``
        # table ready, fetch KEV + EPSS + NVD(CVSS/CWE) for EVERY CVE in this scan in ONE
        # call, instead of three separate kev/epss/nvd calls. The per-phase blocks below
        # then consume ``enriched_map`` and skip their own mirror/live calls. When enriched
        # is not ready/unavailable, ``enriched_map`` stays None and the existing 3-call
        # path (each with its own live fallback) runs UNCHANGED.
        all_cves = sorted({p["cveId"] for p in parsed_map.values()
                           if p.get("cveId", "").startswith("CVE-")})
        enriched_map: dict[str, dict] | None = None
        if (feeds is not None and all_cves and (kev or epss or nvd)
                and feed_ready(feeds_status, "enriched")):
            _p0 = time.monotonic()
            mirror = await feeds.enriched(all_cves)
            if mirror is not UNAVAILABLE:
                enriched_map = mirror  # type: ignore[assignment]
                log.info("phase enriched [mirror]: %d CVEs %.0fms", len(enriched_map),
                         (time.monotonic() - _p0) * 1000)

        # Phase 2.6: NVD enrichment for whatever still lacks a score. Prefer the enriched
        # mirror (already fetched above), then the per-source nvd mirror (one batch call);
        # fall back to the live, rate-limited + capped + time-boxed path when neither is
        # available or the nvd feed is not ready.
        if nvd and settings.enable_nvd:
            _p0 = time.monotonic()
            cve_ids = _needs_score()
            if cve_ids:
                nvd_results: dict[str, dict] = {}
                path = "live-fallback"
                if enriched_map is not None:
                    nvd_results = {c: enriched_map[c] for c in cve_ids if c in enriched_map}
                    path = "enriched"
                elif feeds is not None and feed_ready(feeds_status, "nvd"):
                    mirror = await feeds.nvd(cve_ids)
                    if mirror is not UNAVAILABLE:
                        nvd_results = mirror  # type: ignore[assignment]
                        path = "mirror"
                if path not in ("mirror", "enriched"):
                    # Live fallback: rate-limit/time-budget logic applies here only.
                    nvd_results = await enrich_from_nvd(client, cve_ids, errors)
                log.info("phase nvd [%s]: %d CVEs requested, enriched=%d %.0fms", path,
                         len(cve_ids), len(nvd_results), (time.monotonic() - _p0) * 1000)
                for p in parsed_map.values():
                    cid = p.get("cveId")
                    if not cid or cid not in nvd_results:
                        continue
                    enriched = nvd_results[cid]
                    if p["cvss"]["score"] is None and enriched.get("score") is not None:
                        p["cvss"]["score"] = enriched["score"]
                        if enriched.get("severity"):
                            p["cvss"]["severity"] = enriched["severity"]
                        if enriched.get("version"):
                            p["cvss"]["version"] = enriched["version"]
                        if not p["cvss"]["vector"] and enriched.get("vector"):
                            p["cvss"]["vector"] = enriched["vector"]
                        p["scoreSource"] = "nvd"
                    if (not p.get("cwes")) and enriched.get("cwes"):
                        p["cwes"] = enriched["cwes"]
                    if (not p.get("refs")) and enriched.get("refs"):
                        p["refs"] = enriched["refs"]

        # Phase 3: KEV overlay — enriched mirror (already fetched), per-source feeds mirror
        # (one batch), or live fallback.
        _p0 = time.monotonic()
        kev_set: set[str] = set()
        if kev and settings.enable_kev:
            path = "live-fallback"
            if enriched_map is not None:
                kev_set = {c for c, rec in enriched_map.items() if rec.get("kev")}
                path = "enriched"
            elif feeds is not None and all_cves and feed_ready(feeds_status, "kev"):
                mirror = await feeds.kev(all_cves)
                if mirror is not UNAVAILABLE:
                    kev_set = mirror  # type: ignore[assignment]
                    path = "mirror"
            if path not in ("mirror", "enriched"):
                kev_set = await _fetch_kev(client, errors)
            log.info("phase kev [%s]: %d entries %.0fms", path, len(kev_set),
                     (time.monotonic() - _p0) * 1000)

        # Phase 3.5: EPSS overlay — enriched mirror, per-source feeds mirror, or live fallback.
        epss_map: dict[str, dict] = {}
        if epss and settings.enable_epss and all_cves:
            _p0 = time.monotonic()
            path = "live-fallback"
            if enriched_map is not None:
                for c, rec in enriched_map.items():
                    if rec.get("percentile") is not None:
                        epss_map[c] = {"score": rec.get("epss"),
                                       "percentile": rec.get("percentile")}
                path = "enriched"
            elif feeds is not None and feed_ready(feeds_status, "epss"):
                mirror = await feeds.epss(all_cves)
                if mirror is not UNAVAILABLE:
                    epss_map = mirror  # type: ignore[assignment]
                    path = "mirror"
            if path not in ("mirror", "enriched"):
                epss_map = await _fetch_epss(client, all_cves, errors)
            log.info("phase epss [%s]: %d CVEs scored=%d %.0fms", path, len(all_cves),
                     len(epss_map), (time.monotonic() - _p0) * 1000)

    # Phase 4: assemble findings
    findings: list[Finding] = []
    for comp_idx in sorted(comp_to_ids.keys()):
        vulns: list[Vuln] = []
        for vid in comp_to_ids[comp_idx]:
            p = parsed_map.get(vid)
            if not p or p.get("withdrawn"):
                continue
            vulns.append(_parsed_to_vuln(p, kev_set, epss_map))
        if not vulns:
            continue
        vulns.sort(key=lambda v: _SEV_ORD.get(v.cvss.severity, 5))
        findings.append(Finding(componentIndex=comp_idx, vulns=vulns))
        summary.total += len(vulns)
        for v in vulns:
            s = v.cvss.severity
            if hasattr(summary, s):
                setattr(summary, s, getattr(summary, s) + 1)

    summary.affected = len(findings)
    _log_cache_stats()
    log.info("scan done: %d findings, %d vulns, %d errors",
             len(findings), summary.total, len(errors))
    return findings, summary, errors


def _is_kev(parsed: dict, kev_set: set[str]) -> bool:
    if not kev_set:
        return False
    if parsed.get("cveId") in kev_set or parsed.get("id") in kev_set:
        return True
    return any(a in kev_set for a in parsed.get("aliases", []))


def _parsed_to_vuln(p: dict, kev_set: set[str], epss_map: dict[str, dict]) -> Vuln:
    """Build a Vuln model from a parse_osv_vuln() dict + KEV/EPSS overlays."""
    epss_rec = None
    cid = p.get("cveId")
    e = epss_map.get(cid) or epss_map.get(p["id"])
    if e and e.get("percentile") is not None:
        epss_rec = Epss(score=e["score"], percentile=e["percentile"])
    return Vuln(
        id=p["id"],
        cveId=p.get("cveId"),
        aliases=p.get("aliases", []),
        description=p.get("desc", ""),
        cvss=Cvss(**p["cvss"]),
        cwes=p.get("cwes", []),
        fixed=p.get("fixed", []),
        malicious=p.get("malicious", False),
        kev=_is_kev(p, kev_set),
        epss=epss_rec,
        references=p.get("refs", []),
        published=p.get("published", ""),
        modified=p.get("modified", ""),
        scoreSource=p.get("scoreSource"),
    )


# ── Offline OSV discovery (osv-scanner binary against a local DB mirror) ──
def offline_cache_ready() -> bool:
    """True when offline OSV is enabled AND <OSV_CACHE_DIR>/osv-scanner/ is non-empty."""
    if not settings.use_offline_osv:
        return False
    cache = os.path.join(settings.osv_cache_dir, "osv-scanner")
    try:
        return os.path.isdir(cache) and any(os.scandir(cache))
    except OSError:
        return False


def offline_binary() -> str | None:
    """Resolve the osv-scanner binary path (absolute file or on PATH), else None."""
    binary = settings.osv_scanner_bin
    if os.path.isabs(binary) or os.sep in binary:
        return binary if os.path.isfile(binary) and os.access(binary, os.X_OK) else None
    return shutil.which(binary)


def _build_component_lookup(components) -> tuple[dict[str, int], dict[tuple[str, str], int]]:
    """Map purl → index and (lowercased name, version) → index for offline result mapping."""
    by_purl: dict[str, int] = {}
    by_nv: dict[tuple[str, str], int] = {}
    for i, c in enumerate(components):
        purl = (getattr(c, "purl", "") or "").split("?")[0].split("#")[0].strip()
        if purl and purl not in by_purl:
            by_purl[purl] = i
        name = (getattr(c, "name", "") or "").lower()
        ver = getattr(c, "version", "") or ""
        if name:
            by_nv.setdefault((name, ver), i)
    return by_purl, by_nv


# OSV ecosystem string → purl type. osv-scanner reports the OSV ecosystem (e.g. "Maven",
# "npm") but no purl, so we reconstruct one to match precisely against component purls.
_ECO_TO_PURL_TYPE = {
    "maven": "maven", "npm": "npm", "pypi": "pypi", "go": "golang",
    "rubygems": "gem", "packagist": "composer", "nuget": "nuget",
    "cargo": "cargo", "hex": "hex", "pub": "pub", "conan": "conan",
    "cran": "cran", "swifturl": "swift", "alpine": "apk", "debian": "deb",
    "ubuntu": "deb", "red hat": "rpm", "rocky linux": "rpm",
    "alma linux": "rpm", "suse": "rpm", "opensuse": "rpm",
}


def _offline_purl_for_package(pkg: dict) -> str | None:
    """Reconstruct a purl from an osv-scanner package record for component matching.

    osv-scanner records carry {name, version, ecosystem} but no purl, so we build one.
    For Maven the name is ``group:artifact`` → ``pkg:maven/group/artifact@version``.
    """
    purl = pkg.get("purl") or pkg.get("package_url")
    if purl:
        return str(purl).split("?")[0].split("#")[0].strip()

    name = (pkg.get("name") or "").strip()
    version = (pkg.get("version") or "").strip()
    # OSV ecosystem may carry a release suffix, e.g. "Debian:11" — take the base.
    eco = (pkg.get("ecosystem") or "").split(":")[0].strip().lower()
    if not name:
        return None
    ptype = _ECO_TO_PURL_TYPE.get(eco)
    if not ptype:
        return None
    if ptype == "maven" and ":" in name:
        namespace, _, artifact = name.partition(":")
        base = f"pkg:maven/{namespace}/{artifact}"
    elif ptype == "golang":
        base = f"pkg:golang/{name}"
    else:
        base = f"pkg:{ptype}/{name}"
    return f"{base}@{version}" if version else base


def parse_osv_scanner_output(stdout_json: dict, components) -> list[Finding]:
    """Pure parser: osv-scanner JSON → per-component Findings (no enrichment).

    Maps each ``results[].packages[]`` back to a component by purl (when the package
    record carries one) else by (name, version), parses each vulnerability with the
    existing ``parse_osv_vuln``, and aggregates per component (deduped by vuln id,
    withdrawn dropped). Severity-sorted like the live path; no KEV/EPSS overlay.
    """
    by_purl, by_nv = _build_component_lookup(components)
    comp_to_ids, parsed_map, _unmatched = _aggregate_osv_scanner(
        stdout_json, by_purl, by_nv)

    findings: list[Finding] = []
    for comp_idx in sorted(comp_to_ids.keys()):
        vulns: list[Vuln] = []
        for vid in comp_to_ids[comp_idx]:
            p = parsed_map.get(vid)
            if not p or p.get("withdrawn"):
                continue
            vulns.append(_parsed_to_vuln(p, set(), {}))
        if not vulns:
            continue
        vulns.sort(key=lambda v: _SEV_ORD.get(v.cvss.severity, 5))
        findings.append(Finding(componentIndex=comp_idx, vulns=vulns))
    return findings


def _aggregate_osv_scanner(
    stdout_json: dict,
    by_purl: dict[str, int],
    by_nv: dict[tuple[str, str], int],
) -> tuple[dict[int, set[str]], dict[str, dict], int]:
    """Core aggregation: returns (comp_to_ids, parsed_map, unmatched_package_count)."""
    comp_to_ids: dict[int, set[str]] = {}
    parsed_map: dict[str, dict] = {}
    unmatched = 0
    for result in (stdout_json.get("results") or []):
        for pkg_entry in (result.get("packages") or []):
            pkg = pkg_entry.get("package") or {}
            vulns = pkg_entry.get("vulnerabilities") or []
            if not vulns:
                continue
            # Map package back to our component: purl first, else (name, version).
            comp_idx = None
            purl = _offline_purl_for_package(pkg)
            if purl is not None:
                comp_idx = by_purl.get(purl)
            if comp_idx is None:
                name = (pkg.get("name") or "").lower()
                ver = pkg.get("version") or ""
                comp_idx = by_nv.get((name, ver))
            if comp_idx is None:
                unmatched += 1
                continue
            for record in vulns:
                parsed = parse_osv_vuln(record)
                if not parsed:
                    continue
                vid = parsed["id"]
                if not vid:
                    continue
                parsed_map[vid] = parsed
                comp_to_ids.setdefault(comp_idx, set()).add(vid)
    return comp_to_ids, parsed_map, unmatched


def _write_offline_sbom(components, path: str) -> None:
    """Write a minimal CycloneDX 1.5 JSON file for osv-scanner (purl-keyed)."""
    out_components = []
    for i, c in enumerate(components):
        purl = getattr(c, "purl", "") or ""
        name = getattr(c, "name", "") or ""
        version = getattr(c, "version", "") or ""
        ref = (getattr(c, "bomRef", "") or purl or f"comp-{i}")
        entry: dict = {"type": "library", "bom-ref": ref, "name": name, "version": version}
        if purl:
            entry["purl"] = purl
        out_components.append(entry)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": out_components,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)


async def _run_osv_scanner_offline(sbom_path: str) -> tuple[int, str, str]:
    """Run osv-scanner offline; return (returncode, stdout, stderr)."""
    binary = offline_binary()
    if binary is None:
        raise FileNotFoundError("osv-scanner binary not found")
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = settings.osv_cache_dir
    proc = await asyncio.create_subprocess_exec(
        binary, "scan", "--offline-vulnerabilities", "--format", "json", sbom_path,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(),
                                          timeout=settings.osv_scanner_timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def _osv_offline_phase(
    indexed: list[tuple[int, dict]], components, errors: list[str], force: bool = False,
) -> tuple[dict[int, set[str]], dict[str, dict]] | None:
    """Offline OSV discovery. Returns (comp_to_ids, parsed_map) or None to fall back to live.

    None signals the caller to run the existing live querybatch+hydrate path. Unexpected
    failures (subprocess/parse) are appended to ``errors``; the normal "offline disabled"
    case is silent. ``force=True`` bypasses the small-SBOM speed threshold (used by the
    air-gap fallback when live OSV is unreachable).
    """
    if not settings.use_offline_osv:
        log.info("osv [live]: offline disabled (USE_OFFLINE_OSV=false)")
        return None
    if offline_binary() is None:
        log.info("osv [live]: osv-scanner binary not found, using live path")
        return None
    if not offline_cache_ready():
        log.info("osv [live]: OSV cache empty/missing at %s, using live path",
                 settings.osv_cache_dir)
        return None

    # Speed router: small SBOMs are faster via live OSV (~0.6s) than osv-scanner's
    # fixed ~8s zip-load overhead. Use offline only at/above the configured threshold.
    # (force=True skips this — the air-gap fallback path when live OSV failed.)
    threshold = settings.osv_offline_min_components
    if not force and threshold and len(indexed) < threshold:
        log.info("osv [live]: %d queryable comps < offline threshold %d — live is faster",
                 len(indexed), threshold)
        return None

    # Only the queryable components participate (same set the live path queries).
    indices = [i for i, _ in indexed]
    subset = [components[i] for i in indices]

    _p0 = time.monotonic()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".cdx.json", delete=False, encoding="utf-8") as tf:
            tmp_path = tf.name
        _write_offline_sbom(subset, tmp_path)
        rc, stdout, stderr = await _run_osv_scanner_offline(tmp_path)
        if rc not in (0, 1):
            msg = (f"osv-scanner offline exited {rc}; falling back to live OSV. "
                   f"{stderr.strip()[:300]}")
            log.warning("osv [live]: %s", msg)
            errors.append(msg)
            return None
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError as e:
            msg = f"osv-scanner offline JSON parse failed: {e}; falling back to live OSV."
            log.warning("osv [live]: %s", msg)
            errors.append(msg)
            return None
    except FileNotFoundError:
        log.info("osv [live]: osv-scanner binary not found, using live path")
        return None
    except asyncio.TimeoutError:
        msg = "osv-scanner offline timed out; falling back to live OSV."
        log.warning("osv [live]: %s", msg)
        errors.append(msg)
        return None
    except Exception as e:  # noqa: BLE001 — any unexpected failure → live fallback
        msg = f"osv-scanner offline error: {e}; falling back to live OSV."
        log.warning("osv [live]: %s", msg)
        errors.append(msg)
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Map osv-scanner package records back to ABSOLUTE component indices.
    by_purl, by_nv = _build_component_lookup(subset)
    local_to_ids, parsed_map, unmatched = _aggregate_osv_scanner(data, by_purl, by_nv)
    comp_to_ids: dict[int, set[str]] = {}
    for local_idx, ids in local_to_ids.items():
        comp_to_ids[indices[local_idx]] = set(ids)
    log.info("osv [offline-mirror]: %d packages scanned, %d with vulns, %d unmatched %.0fms",
             len(subset), len(comp_to_ids), unmatched, (time.monotonic() - _p0) * 1000)
    return comp_to_ids, parsed_map
