"""NVD API 2.0 connector — authoritative CVSS (v2/3.x/4.0) + CWE + references.

Queries ``services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`` for CVEs that still
lack a numeric CVSS after the OSV + cve.org (mitre) passes. Sends the ``apiKey`` header
when ``NVD_API_KEY`` is set (which raises the rate limit from 5 to 50 req / 30s).

Rate limiting is mandatory: an async token-bucket limiter spaces requests so the public
limits are never exceeded. Lookups are capped per scan (``NVD_MAX_LOOKUPS``). Every
request has a short timeout; any error/unreachable host degrades gracefully — the caller
collects a message into ``errors`` and the scan continues.
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from .cache import TTLCache
from .config import settings
from .logging_config import get_logger

_SEV_OK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

log = get_logger("sbom.nvd")

# Process-GLOBAL NVD result cache, keyed by CVE id (shared across requests/files).
# A parsed dict, or the sentinel "__none__" for "looked up, NVD had no usable record".
_nvd_cache = TTLCache(settings.cache_ttl, "nvd")


class AsyncRateLimiter:
    """Token-bucket limiter: at most ``max_calls`` acquisitions per ``window`` seconds.

    Refills continuously. ``acquire`` awaits until a token is available so concurrent
    callers are serialized below the upstream rate limit.
    """

    def __init__(self, max_calls: int, window: float):
        self.max_calls = max(1, max_calls)
        self.window = max(0.001, window)
        self._tokens = float(self.max_calls)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.max_calls, self._tokens + elapsed * (self.max_calls / self.window))

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Time until the next whole token is available.
                deficit = 1.0 - self._tokens
                wait = deficit * (self.window / self.max_calls)
                await asyncio.sleep(max(wait, 0.01))


def _nvd_rate_limiter() -> AsyncRateLimiter:
    if settings.nvd_api_key:
        return AsyncRateLimiter(settings.nvd_rate_keyed, settings.nvd_rate_window)
    return AsyncRateLimiter(settings.nvd_rate_keyless, settings.nvd_rate_window)


def parse_nvd_cve(data: dict) -> dict | None:
    """Parse a single-CVE NVD API 2.0 response into a normalized enrichment dict.

    Returns ``{score, severity, version, vector, cwes, refs}`` (score/severity/version/
    vector may be None if NVD has no CVSS metrics). Returns None when the response has no
    usable CVE object.
    """
    if not data:
        return None
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = (vulns[0] or {}).get("cve") or {}
    if not cve:
        return None

    metrics = cve.get("metrics") or {}

    score = severity = version = vector = None
    # Preference order: v3.1 → v3.0 → v4.0 → v2 (match the demo's score preference;
    # v3.x is the most broadly comparable, v2 last).
    metric_order = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV2", "2.0"),
    ]
    for key, ver in metric_order:
        entries = metrics.get(key) or []
        chosen = None
        for e in entries:
            if (e.get("type") or "").lower() == "primary":
                chosen = e
                break
        if chosen is None and entries:
            chosen = entries[0]
        if not chosen:
            continue
        cdata = chosen.get("cvssData") or {}
        sc = cdata.get("baseScore")
        if sc is None:
            continue
        # baseSeverity lives on cvssData (v3/v4) or on the entry (v2).
        sev = (cdata.get("baseSeverity") or chosen.get("baseSeverity") or "").upper()
        vec = cdata.get("vectorString") or ""
        if vec.startswith("CVSS:4"):
            ver = "4.0"
        elif vec.startswith("CVSS:3.1"):
            ver = "3.1"
        elif vec.startswith("CVSS:3.0"):
            ver = "3.0"
        score = round(float(sc) * 10) / 10
        severity = sev if sev in _SEV_OK else None
        version = ver
        vector = vec or None
        break

    # CWEs from weaknesses[].description[].value
    cwes: list[str] = []
    seen = set()
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            m = _CWE_RE.search(str(d.get("value") or ""))
            if m:
                cid = m.group(0).upper()
                if cid not in seen:
                    seen.add(cid)
                    cwes.append(cid)

    # References from references[].url
    refs: list[str] = []
    seenr = set()
    for r in cve.get("references") or []:
        url = r.get("url")
        if url and url not in seenr:
            seenr.add(url)
            refs.append(url)

    return {"score": score, "severity": severity, "version": version,
            "vector": vector, "cwes": cwes, "refs": refs[:8]}


async def _fetch_nvd(client: httpx.AsyncClient, limiter: AsyncRateLimiter,
                     cve_id: str) -> dict | None:
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    headers = {"Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    await limiter.acquire()
    t0 = time.monotonic()
    resp = await client.get(settings.nvd_base, params={"cveId": cve_id},
                            headers=headers, timeout=settings.nvd_timeout)
    log.debug("HTTP GET %s?cveId=%s -> %d %.0fms", settings.nvd_base, cve_id,
              resp.status_code, (time.monotonic() - t0) * 1000)
    if resp.status_code != 200:
        raise httpx.HTTPStatusError(f"HTTP {resp.status_code}", request=resp.request,
                                    response=resp)
    return parse_nvd_cve(resp.json())


async def enrich_from_nvd(client: httpx.AsyncClient, cve_ids: list[str],
                          errors: list[str]) -> dict[str, dict]:
    """Look up CVEs in NVD (cached + capped + rate-limited + time-boxed).

    Returns ``{cve_id: parsed}``. Behaviour:

    * **Process-global cache** first — overlapping CVEs across SBOMs do zero repeat work.
    * **Cap**: at most ``NVD_MAX_LOOKUPS`` *uncached* CVEs per scan.
    * **Rate limit**: a shared token-bucket limiter spaces requests below NVD's published
      limit. Within that, lookups are issued concurrently (each blocks on the limiter) so
      we don't serialise artificially beyond the rate.
    * **Time budget** (``NVD_BUDGET_SECONDS``): once exhausted, stop issuing new lookups,
      append a clear note to ``errors``, and return what we have — the scan completes fast.

    Any per-CVE error is collected into ``errors`` and skipped; never crashes the scan.
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c and c.startswith("CVE-")]
    out: dict[str, dict] = {}
    if not ids:
        return out

    # Serve cache hits up front (free, no rate/budget consumed).
    uncached: list[str] = []
    for cid in ids:
        cached = _nvd_cache.get(cid)
        if cached is not None:
            if cached != "__none__":
                out[cid] = cached
        else:
            uncached.append(cid)

    if not uncached:
        return out

    # Bound the worst case: cap the number of upstream lookups this scan.
    capped = uncached[:settings.nvd_max_lookups]
    deferred = len(uncached) - len(capped)

    limiter = _nvd_rate_limiter()
    budget = settings.nvd_budget_seconds
    deadline = time.monotonic() + budget
    stopped = {"flag": False}
    timed_out_count = {"n": 0}

    async def _one(cid: str):
        # Respect the time budget: if we've blown it, don't issue more lookups.
        if time.monotonic() >= deadline:
            stopped["flag"] = True
            timed_out_count["n"] += 1
            return
        try:
            r = await _fetch_nvd(client, limiter, cid)
            _nvd_cache.set(cid, r if r is not None else "__none__")
            if r:
                out[cid] = r
        except Exception as e:  # noqa: BLE001 — degrade gracefully
            errors.append(f"NVD {cid}: {e}")

    # Issue concurrently; the limiter serialises them below the rate limit while letting
    # them overlap network latency. Wrap in an overall time budget so a slow/blocked NVD
    # never dominates the scan.
    tasks = [asyncio.create_task(_one(cid)) for cid in capped]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True),
                               timeout=budget + settings.nvd_timeout)
    except asyncio.TimeoutError:
        stopped["flag"] = True
        for t in tasks:
            if not t.done():
                t.cancel()

    unenriched = (len(capped) - len([c for c in capped if c in out])) + deferred
    if stopped["flag"] and unenriched > 0:
        msg = (f"NVD enrichment time-boxed after {budget:.0f}s; "
               f"{unenriched} CVE(s) unenriched.")
        errors.append(msg)
        log.warning(msg)
    elif deferred > 0:
        msg = (f"NVD lookups capped at {settings.nvd_max_lookups}/scan; "
               f"{deferred} CVE(s) unenriched.")
        errors.append(msg)
        log.warning(msg)
    return out


async def probe_nvd(client: httpx.AsyncClient) -> bool:
    """Cheap reachability probe against NVD (used by /api/sources)."""
    headers = {"Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    resp = await client.get(settings.nvd_base, params={"cveId": "CVE-2021-44228"},
                            headers=headers, timeout=settings.nvd_timeout)
    return resp.status_code == 200
