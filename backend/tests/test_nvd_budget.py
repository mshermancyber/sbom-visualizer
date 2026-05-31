"""NVD time budget + cap: when the budget is exhausted, stop and note it in errors."""
import asyncio
import dataclasses

import app.nvd as nvd
from app.cache import TTLCache


def test_budget_timeboxes_and_notes_errors(monkeypatch):
    monkeypatch.setattr(nvd, "_nvd_cache", TTLCache(60, "nvd"))
    # Tiny budget; each lookup "takes" longer than the budget allows.
    monkeypatch.setattr(nvd, "settings",
                        dataclasses.replace(nvd.settings, nvd_budget_seconds=0.05,
                                            nvd_max_lookups=25, nvd_timeout=0.1,
                                            nvd_rate_keyless=100))

    async def slow_fetch(client, limiter, cid):
        # Each lookup takes far longer than the whole budget + timeout window, so the
        # overall wait_for cancels them and the time-box note fires.
        await asyncio.sleep(2.0)
        return {"score": 7.0, "severity": "HIGH", "version": "3.1",
                "vector": None, "cwes": [], "refs": []}

    monkeypatch.setattr(nvd, "_fetch_nvd", slow_fetch)

    errors: list[str] = []
    ids = [f"CVE-2099-{i:04d}" for i in range(10)]
    out = asyncio.run(nvd.enrich_from_nvd(None, ids, errors))

    # Not everything got enriched, and a time-box note was appended.
    assert len(out) < len(ids)
    assert any("time-boxed" in e for e in errors)


def test_cap_notes_deferred(monkeypatch):
    monkeypatch.setattr(nvd, "_nvd_cache", TTLCache(60, "nvd"))
    monkeypatch.setattr(nvd, "settings",
                        dataclasses.replace(nvd.settings, nvd_budget_seconds=30.0,
                                            nvd_max_lookups=2, nvd_timeout=0.2,
                                            nvd_rate_keyless=100))

    async def fast_fetch(client, limiter, cid):
        return {"score": 7.0, "severity": "HIGH", "version": "3.1",
                "vector": None, "cwes": [], "refs": []}

    monkeypatch.setattr(nvd, "_fetch_nvd", fast_fetch)

    errors: list[str] = []
    ids = [f"CVE-2099-{i:04d}" for i in range(5)]
    out = asyncio.run(nvd.enrich_from_nvd(None, ids, errors))

    assert len(out) == 2  # capped
    assert any("capped" in e for e in errors)
