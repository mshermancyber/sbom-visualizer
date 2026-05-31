"""Scanner ↔ feeds mirror integration (offline).

Asserts that when the feeds mirror reports a feed ``ready``, the scanner serves KEV/EPSS/NVD
from the mirror and makes NO live KEV/EPSS/NVD calls; and that when the mirror is unreachable
(or a feed is empty) it falls back to the existing live path. All HTTP is mocked.
"""
import asyncio
import dataclasses

import app.nvd as nvd
import app.scanner as scanner
from app.cache import TTLCache
from app.models import Component, Sbom


def _set_use_feeds(monkeypatch, value):
    monkeypatch.setattr(scanner, "settings",
                        dataclasses.replace(scanner.settings, use_feeds=value))


def _make_sbom():
    return Sbom(
        format="cyclonedx",
        components=[Component(name="lodash", version="4.17.15",
                              purl="pkg:npm/lodash@4.17.15")],
    )


def _isolate_caches(monkeypatch):
    monkeypatch.setattr(scanner, "_query_cache", TTLCache(60, "osv-query"))
    monkeypatch.setattr(scanner, "_vuln_cache", TTLCache(60, "osv-hydrate"))
    monkeypatch.setattr(scanner, "_cve_awg_cache", TTLCache(60, "cve.org"))
    monkeypatch.setattr(scanner, "_epss_cache", TTLCache(60, "epss"))
    monkeypatch.setattr(scanner, "_kev_cache", TTLCache(60, "kev"))
    fresh_nvd = TTLCache(60, "nvd")
    monkeypatch.setattr(nvd, "_nvd_cache", fresh_nvd)
    monkeypatch.setattr(scanner, "_nvd_cache", fresh_nvd)


def _stub_discovery(monkeypatch):
    """OSV discovery yields one CVE-aliased vuln lacking a score (triggers nvd enrichment)."""
    async def fake_batch(client, queries):
        return {"results": [{"vulns": [{"id": "OSV-X"}]}]}

    async def fake_get_vuln(client, vid):
        return {"id": vid, "summary": "v", "aliases": ["CVE-2099-0001"], "severity": []}

    monkeypatch.setattr(scanner, "_osv_querybatch", fake_batch)
    monkeypatch.setattr(scanner, "_osv_get_vuln", fake_get_vuln)
    monkeypatch.setattr(scanner, "_fetch_cve_awg",
                        lambda client, cid: _async_none())


async def _async_none():
    return None


def _track_live(monkeypatch):
    """Patch the live KEV/EPSS/NVD leaves to count calls."""
    calls = {"kev": 0, "epss": 0, "nvd": 0}

    async def fake_kev(client, errors):
        calls["kev"] += 1
        return {"CVE-2099-0001"}

    async def fake_epss(client, cve_ids, errors):
        calls["epss"] += 1
        return {"CVE-2099-0001": {"score": 0.1, "percentile": 0.5}}

    async def fake_nvd(client, cve_ids, errors):
        calls["nvd"] += 1
        return {}

    monkeypatch.setattr(scanner, "_fetch_kev", fake_kev)
    monkeypatch.setattr(scanner, "_fetch_epss", fake_epss)
    monkeypatch.setattr(scanner, "enrich_from_nvd", fake_nvd)
    return calls


def _ready_status():
    return {"feeds": [
        {"name": "kev", "updatedAt": "2026-05-30T03:15:00Z", "rowCount": 10, "status": "ready"},
        {"name": "epss", "updatedAt": "2026-05-30T03:15:00Z", "rowCount": 10, "status": "ready"},
        {"name": "nvd", "updatedAt": "2026-05-30T03:15:00Z", "rowCount": 10, "status": "ready"},
    ]}


def _ready_status_with_enriched():
    feeds = _ready_status()["feeds"]
    feeds.append({"name": "enriched", "updatedAt": "2026-05-30T03:15:00Z",
                  "rowCount": 5, "status": "ready"})
    return {"feeds": feeds}


def test_scanner_uses_enriched_fast_path(monkeypatch):
    """When the enriched table is ready, ONE feeds.enriched() call serves KEV+EPSS+NVD;
    the per-source kev()/epss()/nvd() mirror calls AND the live leaves are NOT used."""
    _set_use_feeds(monkeypatch, True)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    mirror_calls = {"kev": 0, "epss": 0, "nvd": 0, "enriched": 0, "status": 0}

    class FakeFeeds:
        def __init__(self, client):
            pass

        async def status(self):
            mirror_calls["status"] += 1
            return _ready_status_with_enriched()

        async def kev(self, cves):
            mirror_calls["kev"] += 1
            raise AssertionError("kev() must not be called on the enriched fast path")

        async def epss(self, cves):
            mirror_calls["epss"] += 1
            raise AssertionError("epss() must not be called on the enriched fast path")

        async def nvd(self, cves):
            mirror_calls["nvd"] += 1
            raise AssertionError("nvd() must not be called on the enriched fast path")

        async def enriched(self, cves):
            mirror_calls["enriched"] += 1
            return {"CVE-2099-0001": {
                "kev": True, "kevDueDate": "2030-01-01",
                "epss": 0.33, "percentile": 0.77,
                "score": 9.1, "severity": "CRITICAL", "version": "3.1",
                "vector": "CVSS:3.1/AV:N", "cwes": ["CWE-79"], "refs": ["https://r"]}}

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))

    # Exactly one enriched call; no per-source mirror calls; no live leaves.
    assert mirror_calls == {"kev": 0, "epss": 0, "nvd": 0, "enriched": 1, "status": 1}
    assert calls == {"kev": 0, "epss": 0, "nvd": 0}

    v = findings[0].vulns[0]
    assert v.kev is True                         # KEV from enriched
    assert v.epss is not None and v.epss.percentile == 0.77  # EPSS from enriched
    assert v.cvss.score == 9.1                   # CVSS filled from enriched (was scoreless)
    assert v.cvss.severity == "CRITICAL"
    assert v.scoreSource == "nvd"                # filled from the mirror
    assert "CWE-79" in v.cwes


def test_scanner_falls_back_when_enriched_unavailable(monkeypatch):
    """enriched ready but the call returns empty/unavailable → existing 3-call path runs."""
    _set_use_feeds(monkeypatch, True)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    mirror_calls = {"kev": 0, "epss": 0, "nvd": 0, "enriched": 0}

    class FakeFeeds:
        def __init__(self, client):
            pass

        async def status(self):
            return _ready_status_with_enriched()

        async def kev(self, cves):
            mirror_calls["kev"] += 1
            return {"CVE-2099-0001"}

        async def epss(self, cves):
            mirror_calls["epss"] += 1
            return {"CVE-2099-0001": {"score": 0.2, "percentile": 0.8}}

        async def nvd(self, cves):
            mirror_calls["nvd"] += 1
            return {}

        async def enriched(self, cves):
            mirror_calls["enriched"] += 1
            return scanner.UNAVAILABLE  # empty/unavailable → fall back to 3-call path

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))

    # enriched attempted once, then the per-source mirror path served all three.
    assert mirror_calls == {"kev": 1, "epss": 1, "nvd": 1, "enriched": 1}
    assert calls == {"kev": 0, "epss": 0, "nvd": 0}  # per-source mirror, not live
    v = findings[0].vulns[0]
    assert v.kev is True
    assert v.epss is not None and v.epss.percentile == 0.8


def test_scanner_uses_mirror_when_ready(monkeypatch):
    _set_use_feeds(monkeypatch, True)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    mirror_calls = {"kev": 0, "epss": 0, "nvd": 0, "status": 0}

    class FakeFeeds:
        def __init__(self, client):
            pass

        async def status(self):
            mirror_calls["status"] += 1
            return _ready_status()

        async def kev(self, cves):
            mirror_calls["kev"] += 1
            return {"CVE-2099-0001"}

        async def epss(self, cves):
            mirror_calls["epss"] += 1
            return {"CVE-2099-0001": {"score": 0.2, "percentile": 0.8}}

        async def nvd(self, cves):
            mirror_calls["nvd"] += 1
            return {}

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))

    # Mirror used for all three; NO live KEV/EPSS/NVD calls.
    assert mirror_calls == {"kev": 1, "epss": 1, "nvd": 1, "status": 1}
    assert calls == {"kev": 0, "epss": 0, "nvd": 0}
    # KEV overlay from the mirror landed on the finding.
    v = findings[0].vulns[0]
    assert v.kev is True
    assert v.epss is not None and v.epss.percentile == 0.8


def test_scanner_falls_back_when_feeds_unreachable(monkeypatch):
    _set_use_feeds(monkeypatch, True)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    class FakeFeeds:
        def __init__(self, client):
            pass

        async def status(self):
            return None  # unreachable

        async def kev(self, cves):
            raise AssertionError("mirror kev should not be called when unreachable")

        async def epss(self, cves):
            raise AssertionError("mirror epss should not be called when unreachable")

        async def nvd(self, cves):
            raise AssertionError("mirror nvd should not be called when unreachable")

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))

    # All three fell back to live.
    assert calls == {"kev": 1, "epss": 1, "nvd": 1}
    v = findings[0].vulns[0]
    assert v.kev is True  # from the live KEV stub


def test_scanner_falls_back_when_feed_empty(monkeypatch):
    """Mirror reachable but a feed is empty -> that source uses live fallback."""
    _set_use_feeds(monkeypatch, True)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    empty_status = {"feeds": [
        {"name": "kev", "updatedAt": None, "rowCount": 0, "status": "empty"},
        {"name": "epss", "updatedAt": None, "rowCount": 0, "status": "empty"},
        {"name": "nvd", "updatedAt": None, "rowCount": 0, "status": "empty"},
    ]}

    class FakeFeeds:
        def __init__(self, client):
            pass

        async def status(self):
            return empty_status

        async def kev(self, cves):
            raise AssertionError("empty feed should not be queried")

        async def epss(self, cves):
            raise AssertionError("empty feed should not be queried")

        async def nvd(self, cves):
            raise AssertionError("empty feed should not be queried")

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    asyncio.run(scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))
    assert calls == {"kev": 1, "epss": 1, "nvd": 1}


def test_scanner_skips_feeds_when_disabled(monkeypatch):
    """USE_FEEDS=false -> mirror never consulted, pure live path."""
    _set_use_feeds(monkeypatch, False)
    _isolate_caches(monkeypatch)
    _stub_discovery(monkeypatch)
    calls = _track_live(monkeypatch)

    class FakeFeeds:
        def __init__(self, client):
            raise AssertionError("FeedsClient must not be constructed when USE_FEEDS=false")

    monkeypatch.setattr(scanner, "FeedsClient", FakeFeeds)

    asyncio.run(scanner.scan_sbom(_make_sbom(), kev=True, epss=True, mitre=False, nvd=True))
    assert calls == {"kev": 1, "epss": 1, "nvd": 1}
