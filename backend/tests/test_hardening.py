"""API hardening: auth (401), rate limit (429), body cap (413).

Builds fresh app instances per test so the env-driven middleware config is picked up,
and keeps everything offline (we only touch /api/health which never makes network calls).
"""
import importlib

import pytest
from fastapi.testclient import TestClient

import app.config as config_mod


def _fresh_app(monkeypatch, **env):
    """Rebuild config + main with the given env so middleware reads fresh settings."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    importlib.reload(config_mod)
    import app.hardening as hardening_mod
    import app.main as main_mod
    importlib.reload(hardening_mod)
    importlib.reload(main_mod)
    return main_mod.app


# ── Auth ──────────────────────────────────────────────────────
def test_health_open_even_with_token(monkeypatch):
    app = _fresh_app(monkeypatch, API_TOKEN="secret123", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_protected_route_requires_token_when_set(monkeypatch):
    app = _fresh_app(monkeypatch, API_TOKEN="secret123", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    r = client.post("/api/scan", json=body)
    assert r.status_code == 401
    assert "error" in r.json()


def test_bearer_token_accepted(monkeypatch):
    app = _fresh_app(monkeypatch, API_TOKEN="secret123", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    r = client.post("/api/scan", json=body,
                    headers={"Authorization": "Bearer secret123"})
    assert r.status_code != 401  # no auth rejection (empty SBOM scans fine)


def test_x_api_key_accepted(monkeypatch):
    app = _fresh_app(monkeypatch, API_TOKEN="secret123", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    r = client.post("/api/scan", json=body, headers={"X-API-Key": "secret123"})
    assert r.status_code != 401


def test_invalid_token_rejected(monkeypatch):
    app = _fresh_app(monkeypatch, API_TOKEN="secret123", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    r = client.post("/api/scan", json=body, headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


def test_open_when_token_unset(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _fresh_app(monkeypatch, RATE_LIMIT="1000/minute")
    client = TestClient(app)
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    r = client.post("/api/scan", json=body)
    assert r.status_code != 401


# ── Rate limit ────────────────────────────────────────────────
def test_rate_limit_429_after_burst(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _fresh_app(monkeypatch, RATE_LIMIT="3/minute")
    client = TestClient(app)
    # health is exempt from rate limiting; use a real protected route.
    body = {"sbom": {"format": "cyclonedx", "components": []}}
    statuses = [client.post("/api/scan", json=body).status_code for _ in range(5)]
    assert 429 in statuses
    # First 3 within limit should not be 429.
    assert statuses[:3].count(429) == 0
    # The 429 response carries a Retry-After header.
    last = client.post("/api/scan", json=body)
    assert last.status_code == 429
    assert "retry-after" in {k.lower() for k in last.headers}
    assert "error" in last.json()


# ── Body cap ──────────────────────────────────────────────────
def test_body_cap_413(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _fresh_app(monkeypatch, MAX_BODY_BYTES="500", RATE_LIMIT="1000/minute")
    client = TestClient(app)
    big = {"sbom": {"format": "cyclonedx",
                    "components": [{"name": "x" * 50, "version": "1.0.0"}
                                   for _ in range(100)]}}
    r = client.post("/api/scan", json=big)
    assert r.status_code == 413
    assert "error" in r.json()


@pytest.fixture(autouse=True)
def _restore_modules():
    """Reload config/main back to baseline after each test so other test modules
    see the default (unconfigured) app."""
    yield
    import app.config as c
    importlib.reload(c)
    import app.hardening as h
    importlib.reload(h)
    import app.main as m
    importlib.reload(m)
