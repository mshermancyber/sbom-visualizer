"""OSV querybatch pagination — follow-up page_token rounds and the page cap.

These exercise scanner.scan_sbom with the network mocked at the
``_osv_querybatch`` boundary (and other upstream fetchers disabled), so the
test stays fully offline.
"""
import asyncio
import dataclasses

import app.scanner as scanner
from app.models import Component, Sbom


def _make_sbom():
    return Sbom(
        format="cyclonedx",
        components=[
            Component(name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15"),
        ],
    )


def _patch_common(monkeypatch, **settings_overrides):
    """Isolate the query cache per test and stub vuln hydration.

    Settings is a frozen dataclass, so any per-test setting tweaks are applied
    by swapping in a ``dataclasses.replace`` copy. Enrichment/overlay HTTP paths
    are disabled via the ``scan_sbom`` keyword args at call time.
    """
    if settings_overrides:
        monkeypatch.setattr(scanner, "settings",
                            dataclasses.replace(scanner.settings, **settings_overrides))
    # Fresh caches so prior runs don't satisfy the query from cache.
    monkeypatch.setattr(scanner, "_query_cache", scanner._TTLCache(60))
    monkeypatch.setattr(scanner, "_vuln_cache", scanner._TTLCache(60))

    async def _fake_get_vuln(client, vid):
        # Minimal parseable OSV vuln so the id survives hydration.
        return {"id": vid, "summary": f"vuln {vid}", "severity": []}

    monkeypatch.setattr(scanner, "_osv_get_vuln", _fake_get_vuln)


_NO_OVERLAYS = dict(kev=False, epss=False, mitre=False, nvd=False)


def test_pagination_merges_follow_up_ids(monkeypatch):
    _patch_common(monkeypatch)
    calls = {"n": 0}

    async def fake_querybatch(client, queries):
        calls["n"] += 1
        if calls["n"] == 1:
            # First page: one vuln + a next_page_token.
            assert "page_token" not in queries[0]
            return {"results": [{"vulns": [{"id": "OSV-PAGE-1"}],
                                 "next_page_token": "tok-abc"}]}
        # Follow-up: must resend the same query with page_token set, no more tokens.
        assert queries[0].get("page_token") == "tok-abc"
        return {"results": [{"vulns": [{"id": "OSV-PAGE-2"}]}]}

    monkeypatch.setattr(scanner, "_osv_querybatch", fake_querybatch)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), **_NO_OVERLAYS))

    assert calls["n"] == 2  # initial + one follow-up
    assert not errors
    ids = {v.id for f in findings for v in f.vulns}
    assert ids == {"OSV-PAGE-1", "OSV-PAGE-2"}


def test_pagination_cap_appends_error(monkeypatch):
    # Cap follow-up rounds low to make the runaway easy to hit.
    _patch_common(monkeypatch, osv_max_pages=3)
    calls = {"n": 0}

    async def fake_querybatch(client, queries):
        calls["n"] += 1
        # Always returns a token -> would loop forever without the cap.
        return {"results": [{"vulns": [{"id": f"OSV-{calls['n']}"}],
                             "next_page_token": f"tok-{calls['n']}"}]}

    monkeypatch.setattr(scanner, "_osv_querybatch", fake_querybatch)

    findings, summary, errors = asyncio.run(
        scanner.scan_sbom(_make_sbom(), **_NO_OVERLAYS))

    # initial call + osv_max_pages follow-up rounds, then stop.
    assert calls["n"] == 1 + 3
    assert any("pagination cap" in e for e in errors)
