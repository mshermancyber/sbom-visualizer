"""Offline SARIF 2.1.0 export — structure, level mapping, rules/results."""
from app.models import Component, Cvss, Epss, Finding, Sbom, Vuln
from app.sarif import build_sarif


def _sbom():
    return Sbom(format="cyclonedx", components=[
        Component(name="log4j-core", version="2.14.1",
                  purl="pkg:maven/x/log4j-core@2.14.1"),
        Component(name="lodash", version="4.17.15", purl="pkg:npm/lodash@4.17.15"),
    ])


def _findings():
    return [
        Finding(componentIndex=0, vulns=[
            Vuln(id="CVE-2021-44228", cveId="CVE-2021-44228",
                 cvss=Cvss(score=10.0, severity="CRITICAL"),
                 cwes=["CWE-502"], fixed=["2.15.0"], kev=True,
                 epss=Epss(score=0.97, percentile=0.99)),
        ]),
        Finding(componentIndex=1, vulns=[
            Vuln(id="GHSA-x", cvss=Cvss(severity="MEDIUM")),
            Vuln(id="GHSA-y", cvss=Cvss(severity="LOW")),
        ]),
    ]


def test_sarif_top_level_shape():
    doc = build_sarif(_sbom(), _findings())
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SBOM Visualizer"


def test_sarif_one_rule_per_unique_vuln():
    doc = build_sarif(_sbom(), _findings())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == ["CVE-2021-44228", "GHSA-x", "GHSA-y"]
    log4j_rule = rules[0]
    assert log4j_rule["helpUri"] == "https://osv.dev/vulnerability/CVE-2021-44228"
    assert "CWE-502" in log4j_rule["properties"]["tags"]


def test_sarif_level_mapping():
    doc = build_sarif(_sbom(), _findings())
    results = doc["runs"][0]["results"]
    by_rule = {r["ruleId"]: r["level"] for r in results}
    assert by_rule["CVE-2021-44228"] == "error"   # critical -> error
    assert by_rule["GHSA-x"] == "warning"          # medium -> warning
    assert by_rule["GHSA-y"] == "note"             # low -> note


def test_sarif_result_message_mentions_signals():
    doc = build_sarif(_sbom(), _findings())
    results = doc["runs"][0]["results"]
    msg = next(r["message"]["text"] for r in results if r["ruleId"] == "CVE-2021-44228")
    assert "log4j-core@2.14.1" in msg
    assert "2.15.0" in msg          # fixed-in
    assert "KEV" in msg             # KEV signal
    assert "EPSS" in msg            # EPSS signal


def test_sarif_result_count_and_indices():
    doc = build_sarif(_sbom(), _findings())
    results = doc["runs"][0]["results"]
    assert len(results) == 3        # one per (component, vuln)
    for r in results:
        assert r["ruleIndex"] == next(
            i for i, rule in enumerate(doc["runs"][0]["tool"]["driver"]["rules"])
            if rule["id"] == r["ruleId"])
