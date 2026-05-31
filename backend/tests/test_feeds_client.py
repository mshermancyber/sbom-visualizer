"""Offline tests for the feeds mirror client — batch shape parsing + graceful unavailable.

All HTTP is mocked via a fake httpx.AsyncClient so these run with no network.
"""
import asyncio

import pytest

import app.feeds_client as fc
from app.feeds_client import (
    UNAVAILABLE, FeedsClient, _reset_status_cache, feed_meta, feed_ready,
)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Minimal stand-in: map (method, path-suffix) -> _Resp or Exception."""

    def __init__(self, posts=None, gets=None):
        self._posts = posts or {}
        self._gets = gets or {}
        self.post_calls = []
        self.get_calls = []

    async def post(self, url, json=None, timeout=None):
        self.post_calls.append((url, json))
        for suffix, val in self._posts.items():
            if url.endswith(suffix):
                if isinstance(val, Exception):
                    raise val
                return val
        raise AssertionError(f"unexpected POST {url}")

    async def get(self, url, timeout=None):
        self.get_calls.append(url)
        for suffix, val in self._gets.items():
            if url.endswith(suffix):
                if isinstance(val, Exception):
                    raise val
                return val
        raise AssertionError(f"unexpected GET {url}")


@pytest.fixture(autouse=True)
def _clear_status_cache():
    _reset_status_cache()
    yield
    _reset_status_cache()


def test_kev_batch_shape():
    client = _FakeClient(posts={"/feeds/kev": _Resp({"kev": ["CVE-1", "CVE-2"]})})
    fcl = FeedsClient(client)
    out = asyncio.run(fcl.kev(["CVE-1", "CVE-2", "CVE-3"]))
    assert out == {"CVE-1", "CVE-2"}
    # One batch POST with the full cve list.
    assert len(client.post_calls) == 1
    assert client.post_calls[0][1] == {"cves": ["CVE-1", "CVE-2", "CVE-3"]}


def test_epss_batch_shape_normalized():
    client = _FakeClient(posts={"/feeds/epss": _Resp(
        {"results": {"CVE-1": {"epss": 0.5, "percentile": 0.97},
                     "CVE-2": {"epss": "bad", "percentile": 0.1}}})})
    out = asyncio.run(FeedsClient(client).epss(["CVE-1", "CVE-2"]))
    # epss -> score; bad epss row dropped.
    assert out == {"CVE-1": {"score": 0.5, "percentile": 0.97}}


def test_nvd_batch_shape_normalized():
    client = _FakeClient(posts={"/feeds/nvd": _Resp(
        {"results": {"CVE-1": {"score": 9.8, "severity": "critical", "version": "3.1",
                               "vector": "CVSS:3.1/...", "cwes": ["CWE-79"],
                               "refs": ["https://x"]},
                     "CVE-2": {"score": None, "severity": "", "cwes": [], "refs": []}}})})
    out = asyncio.run(FeedsClient(client).nvd(["CVE-1", "CVE-2"]))
    assert out["CVE-1"]["score"] == 9.8
    assert out["CVE-1"]["severity"] == "CRITICAL"  # uppercased
    assert out["CVE-1"]["cwes"] == ["CWE-79"]
    assert out["CVE-2"]["score"] is None
    assert out["CVE-2"]["severity"] is None


def test_enriched_batch_shape_normalized():
    client = _FakeClient(posts={"/feeds/enriched": _Resp(
        {"results": {
            "CVE-1": {"kev": True, "kevDueDate": "2021-12-24", "epss": 0.94,
                      "percentile": 0.99, "score": 10.0, "severity": "critical",
                      "version": "3.1", "vector": "CVSS:3.1/...", "cwes": ["CWE-79"],
                      "refs": ["https://x"]},
            "CVE-2": {"kev": False, "kevDueDate": None, "epss": None, "percentile": None,
                      "score": None, "severity": "", "cwes": [], "refs": []}}})})
    out = asyncio.run(FeedsClient(client).enriched(["CVE-1", "CVE-2"]))
    assert out["CVE-1"]["kev"] is True
    assert out["CVE-1"]["kevDueDate"] == "2021-12-24"
    assert out["CVE-1"]["epss"] == 0.94
    assert out["CVE-1"]["percentile"] == 0.99
    assert out["CVE-1"]["score"] == 10.0
    assert out["CVE-1"]["severity"] == "CRITICAL"  # uppercased
    assert out["CVE-1"]["cwes"] == ["CWE-79"]
    assert out["CVE-2"]["kev"] is False
    assert out["CVE-2"]["score"] is None
    assert out["CVE-2"]["severity"] is None
    # One batch POST with the full cve list.
    assert len(client.post_calls) == 1
    assert client.post_calls[0][1] == {"cves": ["CVE-1", "CVE-2"]}


def test_enriched_empty_results_returns_unavailable():
    # Empty table → empty results → treated as UNAVAILABLE so caller uses 3-call path.
    client = _FakeClient(posts={"/feeds/enriched": _Resp({"results": {}})})
    assert asyncio.run(FeedsClient(client).enriched(["CVE-1"])) is UNAVAILABLE


def test_enriched_error_returns_unavailable():
    client = _FakeClient(posts={"/feeds/enriched": RuntimeError("down")})
    assert asyncio.run(FeedsClient(client).enriched(["CVE-1"])) is UNAVAILABLE


def test_post_error_returns_unavailable():
    client = _FakeClient(posts={"/feeds/kev": RuntimeError("conn refused")})
    assert asyncio.run(FeedsClient(client).kev(["CVE-1"])) is UNAVAILABLE


def test_non_200_returns_unavailable():
    client = _FakeClient(posts={"/feeds/epss": _Resp({}, status=503)})
    assert asyncio.run(FeedsClient(client).epss(["CVE-1"])) is UNAVAILABLE


def test_malformed_body_returns_unavailable():
    client = _FakeClient(posts={"/feeds/kev": _Resp(["not", "a", "dict"])})
    assert asyncio.run(FeedsClient(client).kev(["CVE-1"])) is UNAVAILABLE


def test_status_and_helpers():
    status_payload = {"feeds": [
        {"name": "kev", "updatedAt": "2026-05-30T03:15:00Z", "rowCount": 1234,
         "status": "ready", "detail": "ok"},
        {"name": "epss", "updatedAt": None, "rowCount": 0, "status": "empty", "detail": ""},
        {"name": "nvd", "updatedAt": "2026-05-30T04:00:00Z", "rowCount": 250000,
         "status": "ready", "detail": "ok"},
    ]}
    client = _FakeClient(gets={"/feeds/status": _Resp(status_payload)})
    st = asyncio.run(FeedsClient(client).status())
    assert feed_ready(st, "kev") is True
    assert feed_ready(st, "epss") is False  # empty
    assert feed_ready(st, "nvd") is True
    assert feed_meta(st, "kev")["rowCount"] == 1234
    assert feed_meta(st, "missing") is None


def test_status_unavailable_returns_none():
    client = _FakeClient(gets={"/feeds/status": RuntimeError("down")})
    assert asyncio.run(FeedsClient(client).status()) is None
    assert feed_ready(None, "kev") is False
    assert feed_meta(None, "kev") is None


def test_status_is_cached():
    client = _FakeClient(gets={"/feeds/status": _Resp({"feeds": []})})
    fcl = FeedsClient(client)
    asyncio.run(fcl.status())
    asyncio.run(fcl.status())
    # Second call served from the short-lived cache → only one GET.
    assert len(client.get_calls) == 1
