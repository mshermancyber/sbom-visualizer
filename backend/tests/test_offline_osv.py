"""Offline tests for the offline-OSV discovery path (osv-scanner mirror).

No subprocess, no network: the parser is exercised as a pure function and the
fallback decision is exercised by inspecting the decision helpers.
"""
import app.scanner as scanner
from app.models import Component


# A small hand-authored osv-scanner JSON output in the documented shape:
#   results[].packages[].package = {name, version, ecosystem}
#   results[].packages[].vulnerabilities[] = standard OSV records
SCANNER_OUTPUT = {
    "results": [
        {
            "source": {"path": "/tmp/sbom.cdx.json", "type": "sbom"},
            "packages": [
                {
                    "package": {
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "ecosystem": "Maven",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-jfh8-c2jp-5v3q",
                            "aliases": ["CVE-2021-44228"],
                            "summary": "Log4Shell",
                            "details": "Remote code execution in Apache Log4j2.",
                            "severity": [
                                {"type": "CVSS_V3",
                                 "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
                            ],
                            "database_specific": {"severity": "CRITICAL"},
                            "published": "2021-12-10T00:00:00Z",
                            "modified": "2023-01-01T00:00:00Z",
                        }
                    ],
                    "groups": [{"ids": ["GHSA-jfh8-c2jp-5v3q"]}],
                },
                {
                    "package": {
                        "name": "lodash",
                        "version": "4.17.15",
                        "ecosystem": "npm",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-p6mc-m468-83gw",
                            "aliases": ["CVE-2020-8203"],
                            "summary": "Prototype pollution in lodash",
                            "database_specific": {"severity": "HIGH"},
                        }
                    ],
                },
            ],
        }
    ]
}


def _components():
    return [
        Component(name="log4j-core", version="2.14.1",
                  purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
        Component(name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15"),
        Component(name="express", version="4.17.1", purl="pkg:npm/express@4.17.1"),
    ]


def test_parse_maps_by_name_version():
    """The parser maps each package back to its component and parses the vuln record."""
    findings = scanner.parse_osv_scanner_output(SCANNER_OUTPUT, _components())
    by_idx = {f.componentIndex: f for f in findings}

    # log4j-core (index 0) and lodash (index 1) have findings; express (2) does not.
    assert set(by_idx) == {0, 1}

    log4j = by_idx[0]
    assert len(log4j.vulns) == 1
    v = log4j.vulns[0]
    assert v.id == "GHSA-jfh8-c2jp-5v3q"
    assert v.cveId == "CVE-2021-44228"
    assert v.cvss.severity == "CRITICAL"

    lodash = by_idx[1]
    assert lodash.vulns[0].cveId == "CVE-2020-8203"
    assert lodash.vulns[0].cvss.severity == "HIGH"


def test_parse_maps_by_purl_when_present():
    """When osv-scanner reports a purl, mapping prefers it over name+version."""
    out = {
        "results": [{
            "packages": [{
                "package": {
                    "name": "different-name", "version": "9.9.9", "ecosystem": "npm",
                    "purl": "pkg:npm/lodash@4.17.15",
                },
                "vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-2020-8203"],
                                     "database_specific": {"severity": "HIGH"}}],
            }],
        }]
    }
    findings = scanner.parse_osv_scanner_output(out, _components())
    assert len(findings) == 1
    # Mapped to lodash (index 1) by purl, despite the mismatched name/version.
    assert findings[0].componentIndex == 1
    assert findings[0].vulns[0].id == "GHSA-x"


def test_parse_dedupes_by_vuln_id():
    """Duplicate vuln ids for one package collapse to a single Vuln."""
    out = {
        "results": [{
            "packages": [{
                "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                "vulnerabilities": [
                    {"id": "GHSA-dup", "database_specific": {"severity": "HIGH"}},
                    {"id": "GHSA-dup", "database_specific": {"severity": "HIGH"}},
                ],
            }],
        }]
    }
    findings = scanner.parse_osv_scanner_output(out, _components())
    assert len(findings) == 1
    assert len(findings[0].vulns) == 1


def test_parse_empty_output():
    assert scanner.parse_osv_scanner_output({}, _components()) == []
    assert scanner.parse_osv_scanner_output({"results": []}, _components()) == []


def test_parse_unmatched_package_is_skipped():
    """A package that maps to no component is dropped (no crash)."""
    out = {
        "results": [{
            "packages": [{
                "package": {"name": "ghost", "version": "1.0.0", "ecosystem": "npm"},
                "vulnerabilities": [{"id": "GHSA-z", "database_specific": {"severity": "LOW"}}],
            }],
        }]
    }
    assert scanner.parse_osv_scanner_output(out, _components()) == []


# ── Fallback decision helpers ─────────────────────────────────────
class _SettingsStub:
    """Read-through wrapper over the real Settings with a few overridden attrs."""

    def __init__(self, real, overrides):
        self._real = real
        self._ov = overrides

    def __getattr__(self, name):
        if name in self._ov:
            return self._ov[name]
        return getattr(self._real, name)


def test_offline_skipped_when_disabled(monkeypatch):
    monkeypatch.setattr(scanner, "settings",
                        _SettingsStub(scanner.settings, {"use_offline_osv": False}))
    assert scanner.offline_cache_ready() is False


def test_offline_skipped_when_cache_empty(monkeypatch, tmp_path):
    # Enabled, but the cache dir has no osv-scanner/ subdir → not ready.
    monkeypatch.setattr(scanner, "settings", _SettingsStub(
        scanner.settings, {"use_offline_osv": True, "osv_cache_dir": str(tmp_path)}))
    assert scanner.offline_cache_ready() is False


def test_offline_ready_when_cache_populated(monkeypatch, tmp_path):
    eco = tmp_path / "osv-scanner" / "npm"
    eco.mkdir(parents=True)
    (eco / "all.zip").write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(scanner, "settings", _SettingsStub(
        scanner.settings, {"use_offline_osv": True, "osv_cache_dir": str(tmp_path)}))
    assert scanner.offline_cache_ready() is True


def test_offline_phase_returns_none_when_disabled(monkeypatch):
    """The decision helper short-circuits to live (None) when disabled, no errors."""
    import asyncio
    monkeypatch.setattr(scanner, "settings",
                        _SettingsStub(scanner.settings, {"use_offline_osv": False}))
    errors: list[str] = []
    result = asyncio.run(scanner._osv_offline_phase([], _components(), errors))
    assert result is None
    assert errors == []  # "disabled" is a normal case, not an error


def test_offline_binary_absolute_missing(monkeypatch):
    monkeypatch.setattr(scanner, "settings", _SettingsStub(
        scanner.settings, {"osv_scanner_bin": "/definitely/not/here/osv-scanner"}))
    assert scanner.offline_binary() is None
