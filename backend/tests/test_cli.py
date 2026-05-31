"""CLI gate exit codes and output formats — offline (scan is stubbed)."""
import json

import pytest

import app.cli as cli
from app.models import Finding, Summary, Vuln


def _clean_sbom_path(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.15",
             "purl": "pkg:npm/lodash@4.17.15", "licenses": [{"license": {"id": "MIT"}}]},
        ],
    }
    p = tmp_path / "clean.json"
    p.write_text(json.dumps(sbom))
    return str(p)


def _gpl_sbom_path(tmp_path):
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [
            {"type": "library", "name": "somelib", "version": "1.0.0",
             "purl": "pkg:npm/somelib@1.0.0", "licenses": [{"license": {"id": "GPL-3.0"}}]},
        ],
    }
    p = tmp_path / "gpl.json"
    p.write_text(json.dumps(sbom))
    return str(p)


def _stub_scan(monkeypatch, summary=None, findings=None, errors=None):
    summary = summary or Summary()
    findings = findings or []
    errors = errors or []

    async def fake_scan(sbom, **kwargs):
        return findings, summary, errors

    monkeypatch.setattr(cli, "scan_sbom", fake_scan)


def test_cli_pass_exit_0(monkeypatch, tmp_path, capsys):
    _stub_scan(monkeypatch)  # no findings -> PASS
    code = cli.main([_clean_sbom_path(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "VERDICT: PASS" in out


def test_cli_fail_exit_1_on_critical(monkeypatch, tmp_path):
    summary = Summary(CRITICAL=1, total=1, affected=1)
    findings = [Finding(componentIndex=0, vulns=[
        Vuln(id="CVE-2099-1", cveId="CVE-2099-1",
             cvss={"score": 9.8, "severity": "CRITICAL"})])]
    _stub_scan(monkeypatch, summary=summary, findings=findings)
    # standard policy: CRITICAL is a FAIL signal.
    code = cli.main([_clean_sbom_path(tmp_path)])
    assert code == 1


def test_cli_fail_on_review(monkeypatch, tmp_path):
    # HIGH under standard policy => REVIEW. Without --fail-on review, exit 0.
    summary = Summary(HIGH=1, total=1, affected=1)
    findings = [Finding(componentIndex=0, vulns=[
        Vuln(id="CVE-2099-2", cveId="CVE-2099-2",
             cvss={"score": 7.5, "severity": "HIGH"})])]
    _stub_scan(monkeypatch, summary=summary, findings=findings)
    assert cli.main([_clean_sbom_path(tmp_path)]) == 0
    assert cli.main([_clean_sbom_path(tmp_path), "--fail-on", "review"]) == 1


def test_cli_fail_on_high_signal(monkeypatch, tmp_path):
    summary = Summary(HIGH=2, total=2, affected=1)
    findings = [Finding(componentIndex=0, vulns=[
        Vuln(id="CVE-2099-3", cveId="CVE-2099-3",
             cvss={"score": 7.5, "severity": "HIGH"})])]
    _stub_scan(monkeypatch, summary=summary, findings=findings)
    assert cli.main([_clean_sbom_path(tmp_path), "--fail-on", "high"]) == 1


def test_cli_license_deny_fails(monkeypatch, tmp_path):
    _stub_scan(monkeypatch)  # no vulns
    code = cli.main([_gpl_sbom_path(tmp_path), "--license-deny", "GPL"])
    assert code == 1


def test_cli_runtime_error_exit_2(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    code = cli.main([str(bad)])
    assert code == 2


def test_cli_json_format(monkeypatch, tmp_path, capsys):
    _stub_scan(monkeypatch)
    code = cli.main([_clean_sbom_path(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "assessment" in doc and "findings" in doc
    assert code == 0


def test_cli_sarif_format(monkeypatch, tmp_path, capsys):
    summary = Summary(HIGH=1, total=1, affected=1)
    findings = [Finding(componentIndex=0, vulns=[
        Vuln(id="CVE-2099-4", cveId="CVE-2099-4",
             cvss={"score": 7.5, "severity": "HIGH"})])]
    _stub_scan(monkeypatch, summary=summary, findings=findings)
    cli.main([_clean_sbom_path(tmp_path), "--format", "sarif"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_cli_stdin_json(monkeypatch, capsys):
    _stub_scan(monkeypatch)
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                       "components": []})
    monkeypatch.setattr("sys.stdin", _FakeStdin(sbom))
    code = cli.main(["-", "--format", "json"])
    out = capsys.readouterr().out
    assert json.loads(out)["assessment"]
    assert code == 0


class _FakeStdin:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data
