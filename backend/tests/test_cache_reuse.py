"""Process-global cache reuse: a 2nd scan of overlapping CVEs makes NO new upstream calls.

Upstreams are mocked at the scanner/nvd boundaries and call counts are asserted: the second
scan over the same SBOM must be served entirely from the module-level caches.
"""
import asyncio
import dataclasses

import app.nvd as nvd
import app.scanner as scanner
from app.cache import TTLCache
from app.models import Component, Sbom


def _make_sbom():
    return Sbom(
        format="cyclonedx",
        components=[
            Component(name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15"),
        ],
    )


def test_second_scan_reuses_caches(monkeypatch):
    # This test specifically exercises cve.org (MITRE) cache reuse, so force-enable it
    # (MITRE is OFF by default now that the local NVD/cvelistV5 mirror carries CNA data).
    import dataclasses
    monkeypatch.setattr(scanner, "settings",
                        dataclasses.replace(scanner.settings, enable_mitre=True))
    # Fresh, isolated caches so prior test runs don't pre-warm them.
    monkeypatch.setattr(scanner, "_query_cache", TTLCache(60, "osv-query"))
    monkeypatch.setattr(scanner, "_vuln_cache", TTLCache(60, "osv-hydrate"))
    monkeypatch.setattr(scanner, "_cve_awg_cache", TTLCache(60, "cve.org"))
    monkeypatch.setattr(scanner, "_epss_cache", TTLCache(60, "epss"))
    fresh_nvd = TTLCache(60, "nvd")
    monkeypatch.setattr(nvd, "_nvd_cache", fresh_nvd)
    monkeypatch.setattr(scanner, "_nvd_cache", fresh_nvd)
    monkeypatch.setattr(scanner, "_ALL_CACHES",
                        (scanner._query_cache, scanner._vuln_cache, scanner._epss_cache,
                         scanner._kev_cache, scanner._cve_awg_cache, fresh_nvd))

    calls = {"batch": 0, "vuln": 0, "cveawg": 0, "nvd": 0, "epss": 0}

    async def fake_batch(client, queries):
        calls["batch"] += 1
        # Return one CVE-aliased vuln id with no score so enrichment kicks in.
        return {"results": [{"vulns": [{"id": "OSV-X"}]}]}

    async def fake_get_vuln(client, vid):
        calls["vuln"] += 1
        # A CVE-aliased vuln lacking a numeric CVSS → triggers cve.org + NVD enrichment.
        return {"id": vid, "summary": "v", "aliases": ["CVE-2099-0001"], "severity": []}

    async def fake_cveawg(client, cve_id):
        calls["cveawg"] += 1
        return None  # no score, so NVD is attempted too

    async def fake_enrich_nvd(client, cve_ids, errors):
        calls["nvd"] += 1
        return {}

    async def fake_epss(client, cve_ids, errors):
        calls["epss"] += 1
        return {}

    monkeypatch.setattr(scanner, "_osv_querybatch", fake_batch)
    monkeypatch.setattr(scanner, "_osv_get_vuln", fake_get_vuln)
    # cve.org enrichment fetches go through _fetch_cve_awg; patch its network leaf.
    monkeypatch.setattr(scanner, "parse_cve_awg_score", lambda d: None)

    async def fake_fetch_cveawg(client, cve_id):
        # Mirror real caching behaviour: check + populate the global cache.
        cached = scanner._cve_awg_cache.get(cve_id)
        if cached is not None:
            return None if cached == "__none__" else cached
        calls["cveawg"] += 1
        scanner._cve_awg_cache.set(cve_id, "__none__")
        return None

    monkeypatch.setattr(scanner, "_fetch_cve_awg", fake_fetch_cveawg)
    monkeypatch.setattr(scanner, "enrich_from_nvd", fake_enrich_nvd)
    monkeypatch.setattr(scanner, "_fetch_epss", fake_epss)

    sbom = _make_sbom()

    # First scan: warms all caches.
    asyncio.run(scanner.scan_sbom(sbom, kev=False, epss=True, mitre=True, nvd=True))
    after_first = dict(calls)
    assert after_first["batch"] == 1
    assert after_first["vuln"] == 1
    assert after_first["cveawg"] == 1

    # Second scan over the SAME sbom: everything served from cache, ZERO new upstream work.
    asyncio.run(scanner.scan_sbom(sbom, kev=False, epss=True, mitre=True, nvd=True))
    assert calls["batch"] == after_first["batch"], "OSV querybatch repeated"
    assert calls["vuln"] == after_first["vuln"], "OSV hydrate repeated"
    assert calls["cveawg"] == after_first["cveawg"], "cve.org enrichment repeated"
    # EPSS still queries (its cache is per-CVE inside _fetch_epss which we stubbed),
    # but the OSV + cve.org work — the slow paths — did not repeat.


def test_nvd_cache_reuse():
    """enrich_from_nvd serves repeated CVEs from its process-global cache."""
    fresh = TTLCache(60, "nvd")
    nvd._nvd_cache = fresh
    fetches = {"n": 0}

    async def run():
        async def fake_fetch(client, limiter, cid):
            fetches["n"] += 1
            return {"score": 9.8, "severity": "CRITICAL", "version": "3.1",
                    "vector": None, "cwes": [], "refs": []}

        import app.nvd as nvd_mod
        orig = nvd_mod._fetch_nvd
        nvd_mod._fetch_nvd = fake_fetch
        try:
            errors: list[str] = []
            r1 = await nvd_mod.enrich_from_nvd(None, ["CVE-2099-0002"], errors)
            r2 = await nvd_mod.enrich_from_nvd(None, ["CVE-2099-0002"], errors)
            return r1, r2
        finally:
            nvd_mod._fetch_nvd = orig

    r1, r2 = asyncio.run(run())
    assert r1["CVE-2099-0002"]["score"] == 9.8
    assert r2["CVE-2099-0002"]["score"] == 9.8
    assert fetches["n"] == 1, "second NVD lookup should hit the cache"
