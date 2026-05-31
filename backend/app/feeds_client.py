"""Async client for the internal feeds mirror service (docs/FEEDS_CONTRACT.md).

The feeds service mirrors the KEV, EPSS, and NVD CVE inventories locally and serves them
over an internal HTTP API at ``FEEDS_URL`` (default ``http://feeds:9000``). The scanner uses
this client to enrich KEV/EPSS/NVD in **one batch call per source** instead of hitting live
upstreams, falling back to the live path when the mirror is unreachable or a feed is empty.

Every call uses a short timeout and degrades gracefully: on ANY error (unreachable host,
timeout, non-200, malformed body) the call returns the ``UNAVAILABLE`` sentinel (for batch
lookups) or ``None`` (for status), signalling the caller to use its live fallback. Errors are
logged at WARNING on ``sbom.feeds``; the feeds service is internal so we never log secrets.
"""
from __future__ import annotations

import time

import httpx

from .config import settings
from .logging_config import get_logger

log = get_logger("sbom.feeds")

# Sentinel meaning "feeds mirror unavailable for this source — use live fallback".
# Distinct from an empty-but-successful result (e.g. set()/{} = mirror reachable, no hits).
UNAVAILABLE = object()

# Short-lived cache of the /feeds/status response so we don't probe it per source per scan.
# Maps "__status__" -> (monotonic_ts, parsed dict | None).
_status_cache: dict[str, tuple[float, dict | None]] = {}


def _reset_status_cache() -> None:
    """Test helper: clear the cached /feeds/status response."""
    _status_cache.clear()


class FeedsClient:
    """Thin async wrapper over the feeds service internal API.

    Pass an existing :class:`httpx.AsyncClient` (the scanner shares one per scan). All POST
    bodies are ``{"cves": [...]}`` and all timeouts use ``FEEDS_TIMEOUT``.
    """

    def __init__(self, client: httpx.AsyncClient):
        self._client = client
        self._base = settings.feeds_url.rstrip("/")
        self._timeout = settings.feeds_timeout

    async def _post(self, path: str, cves: list[str]) -> dict | object:
        url = f"{self._base}{path}"
        try:
            t0 = time.monotonic()
            resp = await self._client.post(url, json={"cves": cves}, timeout=self._timeout)
            log.debug("HTTP POST %s (%d cves) -> %d %.0fms", url, len(cves),
                      resp.status_code, (time.monotonic() - t0) * 1000)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:  # noqa: BLE001 — degrade to live fallback
            log.warning("feeds %s unavailable (%s); will use live fallback", path, e)
            return UNAVAILABLE

    async def status(self) -> dict | None:
        """GET /feeds/status (cached ~FEEDS_STATUS_TTL). Returns None if unavailable."""
        cached = _status_cache.get("__status__")
        if cached and time.monotonic() - cached[0] < settings.feeds_status_ttl:
            return cached[1]
        url = f"{self._base}/feeds/status"
        result: dict | None
        try:
            t0 = time.monotonic()
            resp = await self._client.get(url, timeout=self._timeout)
            log.debug("HTTP GET %s -> %d %.0fms", url, resp.status_code,
                      (time.monotonic() - t0) * 1000)
            resp.raise_for_status()
            result = resp.json()
        except Exception as e:  # noqa: BLE001
            log.warning("feeds /feeds/status unavailable (%s); will use live fallback", e)
            result = None
        _status_cache["__status__"] = (time.monotonic(), result)
        return result

    async def kev(self, cves: list[str]) -> set[str] | object:
        """POST /feeds/kev → set of the input CVEs that ARE KEV, or UNAVAILABLE."""
        data = await self._post("/feeds/kev", cves)
        if data is UNAVAILABLE:
            return UNAVAILABLE
        try:
            return {c for c in (data.get("kev") or []) if c}
        except (AttributeError, TypeError):
            return UNAVAILABLE

    async def epss(self, cves: list[str]) -> dict[str, dict] | object:
        """POST /feeds/epss → {cve: {"score": float, "percentile": float}}, or UNAVAILABLE.

        Normalizes the contract's ``{"epss": ..., "percentile": ...}`` shape to the
        scanner's internal ``{"score": ..., "percentile": ...}`` shape.
        """
        data = await self._post("/feeds/epss", cves)
        if data is UNAVAILABLE:
            return UNAVAILABLE
        try:
            results = data.get("results") or {}
        except AttributeError:
            return UNAVAILABLE
        out: dict[str, dict] = {}
        for cve, rec in results.items():
            if not isinstance(rec, dict):
                continue
            try:
                score = float(rec.get("epss"))
            except (TypeError, ValueError):
                continue
            try:
                pct = float(rec.get("percentile"))
            except (TypeError, ValueError):
                pct = None
            out[cve] = {"score": score, "percentile": pct}
        return out

    async def nvd(self, cves: list[str]) -> dict[str, dict] | object:
        """POST /feeds/nvd → {cve: {score, severity, version, vector, cwes, refs}}, or UNAVAILABLE."""
        data = await self._post("/feeds/nvd", cves)
        if data is UNAVAILABLE:
            return UNAVAILABLE
        try:
            results = data.get("results") or {}
        except AttributeError:
            return UNAVAILABLE
        out: dict[str, dict] = {}
        for cve, rec in results.items():
            if not isinstance(rec, dict):
                continue
            score = rec.get("score")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            out[cve] = {
                "score": score,
                "severity": (rec.get("severity") or "").upper() or None,
                "version": rec.get("version") or None,
                "vector": rec.get("vector") or None,
                "cwes": list(rec.get("cwes") or []),
                "refs": list(rec.get("refs") or []),
            }
        return out


    async def enriched(self, cves: list[str]) -> dict[str, dict] | object:
        """POST /feeds/enriched → ONE denormalized lookup per CVE, or UNAVAILABLE.

        Returns ``{cve: {kev: bool, epss: float|None, percentile: float|None, score, severity,
        version, vector, cwes: [...], refs: [...], kevDueDate}}``. Returns UNAVAILABLE on any
        error OR on an empty result (so the caller uses the existing 3-call fast path instead).
        """
        data = await self._post("/feeds/enriched", cves)
        if data is UNAVAILABLE:
            return UNAVAILABLE
        try:
            results = data.get("results") or {}
        except AttributeError:
            return UNAVAILABLE
        if not results:
            return UNAVAILABLE
        out: dict[str, dict] = {}
        for cve, rec in results.items():
            if not isinstance(rec, dict):
                continue
            epss_v = rec.get("epss")
            try:
                epss_v = float(epss_v) if epss_v is not None else None
            except (TypeError, ValueError):
                epss_v = None
            pct = rec.get("percentile")
            try:
                pct = float(pct) if pct is not None else None
            except (TypeError, ValueError):
                pct = None
            score = rec.get("score")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            out[cve] = {
                "kev": bool(rec.get("kev")),
                "kevDueDate": rec.get("kevDueDate"),
                "epss": epss_v,
                "percentile": pct,
                "score": score,
                "severity": (rec.get("severity") or "").upper() or None,
                "version": rec.get("version") or None,
                "vector": rec.get("vector") or None,
                "cwes": list(rec.get("cwes") or []),
                "refs": list(rec.get("refs") or []),
            }
        return out


def feed_ready(status: dict | None, name: str) -> bool:
    """True if the named feed (kev|epss|nvd) reports ``status=="ready"`` in /feeds/status."""
    if not status:
        return False
    for f in status.get("feeds") or []:
        if f.get("name") == name:
            return (f.get("status") or "") == "ready"
    return False


def feed_meta(status: dict | None, name: str) -> dict | None:
    """Return the raw status entry (updatedAt/rowCount/status/detail) for a feed, or None."""
    if not status:
        return None
    for f in status.get("feeds") or []:
        if f.get("name") == name:
            return f
    return None
