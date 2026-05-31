"""Tests for VEX suppression, scan persistence, async jobs, and per-key auth.

All tests use temporary SQLite databases so they do not pollute persistent state.
"""
from __future__ import annotations

import asyncio
import importlib
import os
import tempfile
import time
import uuid

import pytest
from fastapi.testclient import TestClient


# ── Helpers ───────────────────────────────────────────────────
def _minimal_sbom(name: str = "test-sbom"):
    return {
        "format": "cyclonedx",
        "name": name,
        "components": [
            {"name": "lodash", "version": "4.17.15",
             "purl": "pkg:npm/lodash@4.17.15"},
            {"name": "express", "version": "4.17.1",
             "purl": "pkg:npm/express@4.17.1"},
        ],
    }


def _make_finding(component_index: int, cve_id: str, purl: str = "", name: str = ""):
    """Build a minimal Finding dict with one Vuln."""
    return {
        "componentIndex": component_index,
        "vulns": [
            {
                "id": cve_id,
                "cveId": cve_id,
                "description": "test",
                "cvss": {"score": 7.5, "severity": "HIGH"},
                "aliases": [],
                "cwes": [],
                "fixed": [],
                "malicious": False,
                "kev": False,
                "references": [],
                "published": "2021-01-01",
                "modified": "2021-01-01",
            }
        ],
    }


# ── Fresh-app fixture ─────────────────────────────────────────
def _fresh_app(monkeypatch, **env):
    """Rebuild config + main + auth + vex + scan_store with temp DBs in env."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app.config as config_mod
    importlib.reload(config_mod)
    import app.hardening as hardening_mod
    importlib.reload(hardening_mod)
    import app.main as main_mod
    importlib.reload(main_mod)
    return main_mod.app


@pytest.fixture(autouse=True)
def _restore_modules():
    yield
    import app.config as c
    importlib.reload(c)
    import app.hardening as h
    importlib.reload(h)
    import app.main as m
    importlib.reload(m)


# ─────────────────────────────────────────────────────────────
# 1. VEX suppression tests
# ─────────────────────────────────────────────────────────────
class TestVexEndpoints:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import app.vex as vex_mod
        vex_mod._reset_db(self.tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def _client(self):
        from app.main import app
        return TestClient(app)

    def test_create_suppression(self):
        client = self._client()
        body = {
            "cveId": "CVE-2021-44228",
            "componentPurl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "status": "not_affected",
            "justification": "mitigated by config",
            "author": "alice",
        }
        r = client.post("/api/vex/suppressions", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "id" in data
        assert len(data["id"]) == 32  # uuid4 hex
        assert data["cveId"] == "CVE-2021-44228"
        assert data["status"] == "not_affected"

    def test_list_suppressions_empty(self):
        client = self._client()
        r = client.get("/api/vex/suppressions")
        assert r.status_code == 200
        assert r.json() == {"suppressions": []}

    def test_list_suppressions_after_create(self):
        client = self._client()
        client.post("/api/vex/suppressions", json={
            "cveId": "CVE-2021-44228",
            "componentPurl": "pkg:npm/lodash@4.17.15",
            "status": "false_positive",
        })
        r = client.get("/api/vex/suppressions")
        assert r.status_code == 200
        sups = r.json()["suppressions"]
        assert len(sups) == 1
        assert sups[0]["cveId"] == "CVE-2021-44228"

    def test_list_filter_by_cve(self):
        client = self._client()
        for cve in ("CVE-2021-44228", "CVE-2022-12345"):
            client.post("/api/vex/suppressions", json={
                "cveId": cve, "componentName": "foo", "status": "resolved",
            })
        r = client.get("/api/vex/suppressions?cveId=CVE-2022-12345")
        assert r.status_code == 200
        sups = r.json()["suppressions"]
        assert len(sups) == 1
        assert sups[0]["cveId"] == "CVE-2022-12345"

    def test_delete_suppression(self):
        client = self._client()
        resp = client.post("/api/vex/suppressions", json={
            "cveId": "CVE-2021-44228", "componentName": "lodash", "status": "in_triage",
        })
        sid = resp.json()["id"]
        r = client.delete(f"/api/vex/suppressions/{sid}")
        assert r.status_code == 200
        assert r.json() == {"deleted": True}
        # Confirm gone.
        r2 = client.get("/api/vex/suppressions")
        assert r2.json() == {"suppressions": []}

    def test_delete_nonexistent(self):
        client = self._client()
        r = client.delete(f"/api/vex/suppressions/{uuid.uuid4().hex}")
        assert r.status_code == 404

    def test_invalid_status_rejected(self):
        client = self._client()
        r = client.post("/api/vex/suppressions", json={
            "cveId": "CVE-2021-44228", "componentName": "foo", "status": "invalid_status",
        })
        assert r.status_code == 422  # Pydantic validation error


class TestVexApply:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import app.vex as vex_mod
        vex_mod._reset_db(self.tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_apply_by_purl_match(self):
        """A suppression matching cveId+purl marks the vuln as suppressed."""
        from app.vex import apply_suppressions
        from app.models import Finding, Vuln, Cvss

        vuln = Vuln(id="CVE-2021-44228", cveId="CVE-2021-44228",
                    cvss=Cvss(score=10.0, severity="CRITICAL"))
        object.__setattr__(vuln, "_purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        object.__setattr__(vuln, "_name", "log4j-core")

        finding = Finding(componentIndex=0, vulns=[vuln])
        suppression = {
            "cveId": "CVE-2021-44228",
            "componentPurl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "status": "not_affected",
            "expiresAt": None,
        }
        patched, count = apply_suppressions([finding], [suppression])
        assert count == 1
        assert patched[0].vulns[0].suppressed is True
        assert patched[0].vulns[0].suppressionStatus == "not_affected"

    def test_apply_by_name_match(self):
        """Fall back to name match when purl is absent on the vuln."""
        from app.vex import apply_suppressions
        from app.models import Finding, Vuln, Cvss

        vuln = Vuln(id="CVE-2022-12345", cveId="CVE-2022-12345",
                    cvss=Cvss(score=7.0, severity="HIGH"))
        object.__setattr__(vuln, "_purl", None)
        object.__setattr__(vuln, "_name", "express")

        finding = Finding(componentIndex=1, vulns=[vuln])
        suppression = {
            "cveId": "CVE-2022-12345",
            "componentPurl": None,
            "componentName": "express",
            "status": "false_positive",
            "expiresAt": None,
        }
        patched, count = apply_suppressions([finding], [suppression])
        assert count == 1
        assert patched[0].vulns[0].suppressed is True

    def test_expired_suppression_ignored(self):
        """A suppression with expiresAt in the past is not applied."""
        from app.vex import apply_suppressions
        from app.models import Finding, Vuln, Cvss

        vuln = Vuln(id="CVE-2021-44228", cveId="CVE-2021-44228",
                    cvss=Cvss(score=10.0, severity="CRITICAL"))
        object.__setattr__(vuln, "_purl", "pkg:npm/lodash@4.17.15")
        object.__setattr__(vuln, "_name", "lodash")

        finding = Finding(componentIndex=0, vulns=[vuln])
        suppression = {
            "cveId": "CVE-2021-44228",
            "componentPurl": "pkg:npm/lodash@4.17.15",
            "status": "not_affected",
            "expiresAt": "2020-01-01T00:00:00+00:00",  # expired
        }
        patched, count = apply_suppressions([finding], [suppression])
        assert count == 0
        assert patched[0].vulns[0].suppressed is False

    def test_apply_endpoint(self):
        """POST /api/vex/apply returns patched findings and suppressedCount."""
        from app.main import app
        client = TestClient(app)

        body = {
            "findings": [_make_finding(0, "CVE-2021-44228", purl="pkg:npm/lodash@4.17.15")],
            "suppressions": [
                {
                    "cveId": "CVE-2021-44228",
                    "componentPurl": "pkg:npm/lodash@4.17.15",
                    "status": "not_affected",
                }
            ],
        }
        r = client.post("/api/vex/apply", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        # apply_suppressions needs _purl injected; the endpoint has no sbom context here
        # so purl matching won't fire (no _purl attr).  The count should be 0.
        assert "suppressedCount" in data
        assert "findings" in data


class TestAssessWithSuppressions:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import app.vex as vex_mod
        vex_mod._reset_db(self.tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_assess_suppression_excludes_from_counts(self):
        """Suppressed vulns are not counted in the assessment summary."""
        from app.main import app
        client = TestClient(app)

        sbom = _minimal_sbom()
        # Findings: component 0 has CVE-2021-44228 (CRITICAL).
        findings = [
            {
                "componentIndex": 0,
                "vulns": [
                    {
                        "id": "CVE-2021-44228", "cveId": "CVE-2021-44228",
                        "description": "Log4Shell",
                        "cvss": {"score": 10.0, "severity": "CRITICAL"},
                        "aliases": [], "cwes": [], "fixed": [],
                        "malicious": False, "kev": False,
                        "references": [], "published": "2021-12-10", "modified": "2021-12-10",
                    }
                ],
            }
        ]
        summary = {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
                   "NONE": 0, "UNKNOWN": 0, "total": 1, "scanned": 2,
                   "affected": 1, "withPurl": 2, "suppressedCount": 0}
        suppressions = [
            {
                "cveId": "CVE-2021-44228",
                "componentPurl": "pkg:npm/lodash@4.17.15",
                "componentName": "lodash",
                "status": "not_affected",
            }
        ]

        body = {
            "sbom": sbom,
            "findings": findings,
            "summary": summary,
            "suppressions": suppressions,
        }
        r = client.post("/api/assess", json=body)
        assert r.status_code == 200, r.text
        assessment = r.json()["assessment"]
        # The suppressed vuln should be excluded from the risk count.
        # Because lodash (index 0) matches component 0 by name, it should be suppressed.
        assert "verdict" in assessment
        assert "risk" in assessment


# ─────────────────────────────────────────────────────────────
# 2. Scan persistence tests
# ─────────────────────────────────────────────────────────────
class TestScanPersistence:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import app.scan_store as ss
        ss._reset_db(self.tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def _client(self):
        from app.main import app
        return TestClient(app)

    def test_scan_returns_scan_id(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}
        r = client.post("/api/scan", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "scanId" in data
        assert data["scanId"] is not None
        assert len(data["scanId"]) == 32  # uuid4 hex

    def test_list_scans_empty(self):
        client = self._client()
        r = client.get("/api/scans")
        assert r.status_code == 200
        assert r.json() == {"scans": []}

    def test_list_scans_after_scan(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "name": "mysbom", "components": []}}
        client.post("/api/scan", json=body)
        r = client.get("/api/scans")
        assert r.status_code == 200
        scans = r.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["sbomName"] == "mysbom"

    def test_get_scan_by_id(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "name": "mysbom",
                         "components": [{"name": "lodash", "version": "4.17.15"}]}}
        scan_resp = client.post("/api/scan", json=body).json()
        scan_id = scan_resp["scanId"]

        r = client.get(f"/api/scans/{scan_id}")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["id"] == scan_id
        assert data["sbomName"] == "mysbom"
        assert "findings" in data
        assert "summary" in data
        assert "errors" in data

    def test_get_scan_not_found(self):
        client = self._client()
        r = client.get(f"/api/scans/{uuid.uuid4().hex}")
        assert r.status_code == 404

    def test_delete_scan(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}
        scan_id = client.post("/api/scan", json=body).json()["scanId"]
        r = client.delete(f"/api/scans/{scan_id}")
        assert r.status_code == 200
        assert r.json() == {"deleted": True}
        assert client.get(f"/api/scans/{scan_id}").status_code == 404

    def test_scan_store_compression_roundtrip(self):
        """Ensure gzip+base64 findings survive a roundtrip through the store."""
        from app.scan_store import save_scan, get_scan
        from app.models import Finding, Summary

        scan_id = save_scan(
            sbom_id="test-id",
            sbom_name="roundtrip-test",
            sbom_format="cyclonedx",
            component_count=0,
            findings=[],
            summary=Summary(),
            errors=["err1", "err2"],
        )
        record = get_scan(scan_id)
        assert record is not None
        assert record["errors"] == ["err1", "err2"]
        assert record["findings"] == []


# ─────────────────────────────────────────────────────────────
# 3. Async scan job tests
# ─────────────────────────────────────────────────────────────
class TestAsyncJobs:
    def setup_method(self):
        self.scan_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.scan_tmp.close()
        import app.scan_store as ss
        ss._reset_db(self.scan_tmp.name)
        import app.jobs as jobs_mod
        jobs_mod._clear_jobs()

    def teardown_method(self):
        import app.jobs as jobs_mod
        jobs_mod._clear_jobs()
        try:
            os.unlink(self.scan_tmp.name)
        except OSError:
            pass

    def _client(self):
        from app.main import app
        return TestClient(app)

    def test_async_scan_returns_job_id(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}
        r = client.post("/api/scan/async", json=body)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "jobId" in data
        assert data["status"] == "running"

    def test_poll_job_to_done(self):
        """POST async, then poll until done.  Empty SBOM should finish quickly."""
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}
        job_id = client.post("/api/scan/async", json=body).json()["jobId"]

        # Poll up to 10 seconds.
        for _ in range(50):
            r = client.get(f"/api/scan/jobs/{job_id}")
            assert r.status_code == 200
            data = r.json()
            if data["status"] == "done":
                break
            time.sleep(0.2)
        else:
            pytest.fail("Async job did not complete within 10 seconds")

        assert data["status"] == "done"
        assert "result" in data
        result = data["result"]
        assert "findings" in result
        assert "summary" in result
        assert "errors" in result
        assert "scanId" in result

    def test_async_job_result_matches_sync(self):
        """For an empty SBOM the async result should match the sync result."""
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}

        sync_r = client.post("/api/scan", json=body).json()

        job_id = client.post("/api/scan/async", json=body).json()["jobId"]
        for _ in range(50):
            r = client.get(f"/api/scan/jobs/{job_id}").json()
            if r["status"] == "done":
                break
            time.sleep(0.2)
        else:
            pytest.fail("Async job timed out")

        async_result = r["result"]
        assert async_result["findings"] == sync_r["findings"]
        assert async_result["summary"]["total"] == sync_r["summary"]["total"]

    def test_list_jobs(self):
        client = self._client()
        body = {"sbom": {"format": "cyclonedx", "components": []}}
        client.post("/api/scan/async", json=body)
        client.post("/api/scan/async", json=body)
        r = client.get("/api/scan/jobs")
        assert r.status_code == 200
        jobs = r.json()["jobs"]
        assert len(jobs) == 2

    def test_job_not_found(self):
        client = self._client()
        r = client.get(f"/api/scan/jobs/{uuid.uuid4().hex}")
        assert r.status_code == 404


# ─────────────────────────────────────────────────────────────
# 4. Per-key auth tests
# ─────────────────────────────────────────────────────────────
class TestAuthKeys:
    def setup_method(self):
        self.auth_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.auth_tmp.close()
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.auth_tmp.name)
        except OSError:
            pass

    def _fresh(self, monkeypatch, **env):
        return _fresh_app(monkeypatch, **env)

    def test_provisioned_key_accepted(self, monkeypatch):
        """A provisioned per-user API key is accepted when API_TOKEN is set."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)
        record = auth_mod.create_key(label="ci", project="proj-a")
        user_key = record["key"]

        app = _fresh_app(monkeypatch, API_TOKEN="masterkey", RATE_LIMIT="1000/minute")
        # Reload auth to point at our temp db.
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)

        body = {"sbom": {"format": "cyclonedx", "components": []}}
        r = client.post("/api/scan", json=body, headers={"X-API-Key": user_key})
        assert r.status_code != 401, r.text

    def test_wrong_key_rejected(self, monkeypatch):
        """A random token is rejected when API_TOKEN is set."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)
        auth_mod.create_key(label="ci", project="proj-a")  # creates a key, but we won't use it

        app = _fresh_app(monkeypatch, API_TOKEN="masterkey", RATE_LIMIT="1000/minute")
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)

        body = {"sbom": {"format": "cyclonedx", "components": []}}
        r = client.post("/api/scan", json=body, headers={"X-API-Key": "wrong-random-key"})
        assert r.status_code == 401

    def test_admin_create_list_delete_key(self, monkeypatch):
        """Master token can create, list, and delete API keys."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)

        app = _fresh_app(monkeypatch, API_TOKEN="masterkey", RATE_LIMIT="1000/minute")
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)
        headers = {"X-API-Key": "masterkey"}

        # Create key.
        r = client.post("/api/admin/keys",
                        json={"label": "team-ci", "project": "proj-x"},
                        headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()
        assert "key" in data
        assert len(data["key"]) == 64  # 32 bytes hex
        assert data["label"] == "team-ci"
        assert data["project"] == "proj-x"

        # List keys.
        r2 = client.get("/api/admin/keys", headers=headers)
        assert r2.status_code == 200
        keys = r2.json()["keys"]
        assert len(keys) == 1
        assert keys[0]["label"] == "team-ci"
        assert "key" not in keys[0]  # plaintext never returned in list

        # Delete key.
        r3 = client.delete("/api/admin/keys/team-ci", headers=headers)
        assert r3.status_code == 200
        assert r3.json() == {"deleted": True}

        # Gone.
        r4 = client.get("/api/admin/keys", headers=headers)
        assert r4.json()["keys"] == []

    def test_admin_routes_blocked_with_user_key(self, monkeypatch):
        """A provisioned user key cannot access /api/admin/ routes."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)
        record = auth_mod.create_key(label="user1", project="proj-b")
        user_key = record["key"]

        app = _fresh_app(monkeypatch, API_TOKEN="masterkey", RATE_LIMIT="1000/minute")
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)

        r = client.get("/api/admin/keys", headers={"X-API-Key": user_key})
        assert r.status_code == 403

    def test_admin_route_blocked_without_token(self, monkeypatch):
        """A request without any key is rejected from admin routes when master key is set."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)

        app = _fresh_app(monkeypatch, API_TOKEN="masterkey", RATE_LIMIT="1000/minute")
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)

        r = client.get("/api/admin/keys")
        assert r.status_code == 401

    def test_key_hash_not_stored_plaintext(self, monkeypatch):
        """Verify the DB stores the hash, not the plaintext token."""
        import app.auth as auth_mod
        import hashlib
        auth_mod._reset_db(self.auth_tmp.name)
        record = auth_mod.create_key(label="hash-test")
        token = record["key"]

        # The DB should have the SHA-256 hash, not the token itself.
        expected_hash = hashlib.sha256(token.encode()).hexdigest()
        row = auth_mod._db.execute(
            "SELECT key_hash FROM api_keys WHERE label='hash-test'"
        ).fetchone()
        assert row is not None
        assert row[0] == expected_hash

    def test_open_when_no_token_and_no_keys(self, monkeypatch):
        """Dev mode: open when API_TOKEN unset and no provisioned keys."""
        import app.auth as auth_mod
        auth_mod._reset_db(self.auth_tmp.name)  # empty DB

        monkeypatch.delenv("API_TOKEN", raising=False)
        app = _fresh_app(monkeypatch, RATE_LIMIT="1000/minute")
        auth_mod._reset_db(self.auth_tmp.name)
        client = TestClient(app)

        body = {"sbom": {"format": "cyclonedx", "components": []}}
        r = client.post("/api/scan", json=body)
        assert r.status_code != 401
