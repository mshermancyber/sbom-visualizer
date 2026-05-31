"""Offline parser tests — format detection + CycloneDX / SPDX / Syft normalization."""
from app.parsers import detect_format, parse_sbom
from app.scanner import parse_cve_awg_score, parse_osv_vuln


# ── CycloneDX (sample fixture) ────────────────────────────────
def test_detect_cyclonedx(sample_cdx):
    assert detect_format(sample_cdx) == "cyclonedx"


def test_parse_cyclonedx_sample(sample_cdx):
    sbom, extra = parse_sbom(sample_cdx)
    assert sbom.format == "cyclonedx"
    assert sbom.formatVersion == "1.5"
    assert sbom.serialNumber.startswith("urn:uuid:")
    assert sbom.name == "acme-payment-service"
    assert sbom.version == "2.3.0"
    assert sbom.tools == ["syft 1.14.0"]
    assert len(sbom.components) == 6

    log4j = sbom.components[0]
    assert log4j.name == "log4j-core"
    assert log4j.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert log4j.bomRef == log4j.purl
    assert log4j.licenses == ["Apache-2.0"]
    assert log4j.supplier == "org.apache.logging.log4j"
    # hashes preserved in extra for NTIA scoring
    assert extra[0]["hashes"]

    # dependencies
    refs = {d.ref for d in sbom.dependencies}
    assert "acme-app" in refs


def test_cyclonedx_license_expression():
    raw = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"name": "x", "version": "1",
                           "licenses": [{"expression": "(MIT OR Apache-2.0)"}]}]}
    sbom, _ = parse_sbom(raw)
    assert sbom.components[0].licenses == ["(MIT OR Apache-2.0)"]


# ── SPDX ──────────────────────────────────────────────────────
def test_detect_and_parse_spdx():
    raw = {
        "spdxVersion": "SPDX-2.3",
        "name": "doc",
        "documentNamespace": "https://example.com/ubuntu/foo",
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: syft-1.0", "Organization: Acme"]},
        "packages": [
            {"name": "openssl", "versionInfo": "3.0.8", "SPDXID": "SPDXRef-1",
             "licenseConcluded": "Apache-2.0", "licenseDeclared": "NOASSERTION",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/openssl@3.0.8"}],
             "checksums": [{"algorithm": "SHA256", "checksumValue": "deadbeef"}]},
            {"name": "libfoo", "versionInfo": "1.0", "SPDXID": "SPDXRef-2"},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-1", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-2"},
        ],
    }
    assert detect_format(raw) == "spdx"
    sbom, extra = parse_sbom(raw)
    assert sbom.format == "spdx"
    assert sbom.distro == "Ubuntu"
    assert sbom.components[0].purl == "pkg:deb/ubuntu/openssl@3.0.8"
    assert sbom.components[0].type == "os"
    assert sbom.components[0].licenses == ["Apache-2.0"]  # NOASSERTION dropped
    assert sbom.components[0].bomRef == "SPDXRef-1"
    assert "syft-1.0" in sbom.tools
    assert sbom.dependencies[0].ref == "SPDXRef-1"
    assert sbom.dependencies[0].deps == ["SPDXRef-2"]
    assert extra[0]["distro"] == "Ubuntu"


# ── Syft ──────────────────────────────────────────────────────
def test_detect_and_parse_syft():
    raw = {
        "artifacts": [
            {"id": "pkg1", "name": "requests", "version": "2.31.0", "type": "python",
             "language": "python", "purl": "pkg:pypi/requests@2.31.0",
             "cpes": [{"cpe": "cpe:2.3:a:requests:requests:2.31.0"}],
             "licenses": [{"value": "Apache-2.0"}]},
        ],
        "artifactRelationships": [
            {"parent": "pkg1", "child": "pkg2", "type": "dependency-of"},
        ],
        "source": {"type": "image", "metadata": {"userInput": "alpine:3.19"}},
        "distro": {"name": "alpine", "prettyName": "Alpine Linux v3.19", "version": "3.19"},
        "descriptor": {"name": "syft", "version": "1.14.0"},
        "schema": {"version": "16.0.0"},
    }
    assert detect_format(raw) == "syft"
    sbom, _ = parse_sbom(raw)
    assert sbom.format == "syft"
    assert sbom.formatVersion == "16.0.0"
    assert sbom.distro == "Alpine Linux v3.19"
    assert sbom.distroVersion == "3.19"
    assert sbom.components[0].name == "requests"
    assert sbom.components[0].type == "library"
    assert sbom.components[0].language == "python"
    assert sbom.components[0].cpe.startswith("cpe:2.3")
    assert sbom.tools == ["syft 1.14.0"]
    # child depends on parent
    assert sbom.dependencies[0].ref == "pkg2"
    assert sbom.dependencies[0].deps == ["pkg1"]


# ── Unknown ───────────────────────────────────────────────────
def test_unknown_format_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_sbom({"foo": "bar"})


# ── OSV vuln parsing (offline, fixture data) ──────────────────
def test_parse_osv_vuln_computes_cvss_and_fixed():
    raw = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "summary": "Log4Shell",
        "details": "Remote code execution in log4j",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.0"}]}],
                      "database_specific": {"cwe_ids": ["CWE-502"]}}],
        "references": [{"url": "https://example.com/a"}],
        "published": "2021-12-10T00:00:00Z",
    }
    p = parse_osv_vuln(raw)
    assert p["cveId"] == "CVE-2021-44228"
    assert p["cvss"]["score"] == 10.0
    assert p["cvss"]["severity"] == "CRITICAL"
    assert p["fixed"] == ["2.15.0"]
    assert "CWE-502" in p["cwes"]
    assert p["malicious"] is False


def test_parse_osv_malicious():
    p = parse_osv_vuln({"id": "MAL-2024-1", "aliases": []})
    assert p["malicious"] is True


def test_parse_cve_awg_score():
    data = {"containers": {"cna": {
        "metrics": [{"cvssV3_1": {"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
    }}}
    out = parse_cve_awg_score(data)
    assert out["score"] == 9.8
    assert out["severity"] == "CRITICAL"
    assert out["version"] == "3.1"
    assert "CWE-79" in out["cwes"]
