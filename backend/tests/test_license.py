"""Offline license-policy gate — violation detection + verdict folding."""
from app.models import Component, LicensePolicy, Sbom, Summary
from app.scoring import build_assessment, compute_license_violations


def _sbom():
    return Sbom(format="cyclonedx", components=[
        Component(name="log4j-core", version="2.14.1", licenses=["Apache-2.0"]),
        Component(name="mysql-connector-java", version="8.0.11", licenses=["GPL-2.0"]),
        Component(name="some-lib", version="1.0.0", licenses=["LGPL-3.0"]),
    ])


def test_no_policy_means_no_violations():
    assert compute_license_violations(_sbom(), None) == []
    assert compute_license_violations(_sbom(), LicensePolicy()) == []


def test_deny_gpl_substring_match():
    pol = LicensePolicy(deny=["GPL"], warn=[])
    violations = compute_license_violations(_sbom(), pol)
    # "GPL" substring matches both GPL-2.0 and LGPL-3.0.
    names = {v.name for v in violations}
    assert names == {"mysql-connector-java", "some-lib"}
    assert all(v.rule == "deny" for v in violations)


def test_case_insensitive_and_spdx_match():
    pol = LicensePolicy(deny=["gpl-2.0"])
    violations = compute_license_violations(_sbom(), pol)
    assert len(violations) == 1
    assert violations[0].name == "mysql-connector-java"
    assert violations[0].license == "GPL-2.0"


def test_warn_rule():
    pol = LicensePolicy(deny=[], warn=["apache"])
    violations = compute_license_violations(_sbom(), pol)
    assert len(violations) == 1
    assert violations[0].rule == "warn"
    assert violations[0].name == "log4j-core"


def test_deny_takes_precedence_over_warn():
    pol = LicensePolicy(deny=["GPL-2.0"], warn=["GPL"])
    violations = compute_license_violations(_sbom(), pol)
    mysql = next(v for v in violations if v.name == "mysql-connector-java")
    assert mysql.rule == "deny"


def test_verdict_deny_forces_fail():
    pol = LicensePolicy(deny=["GPL"])
    a = build_assessment(_sbom(), [], Summary(), policy="standard", license_policy=pol)
    assert a.verdict.status == "FAIL"
    assert any("denied license" in r for r in a.verdict.reasons)
    assert len(a.licenseViolations) == 2


def test_verdict_warn_forces_review():
    pol = LicensePolicy(warn=["GPL"])
    a = build_assessment(_sbom(), [], Summary(), policy="standard", license_policy=pol)
    assert a.verdict.status == "REVIEW"
    assert any("flagged license" in r for r in a.verdict.reasons)


def test_verdict_unchanged_without_policy():
    a = build_assessment(_sbom(), [], Summary(), policy="standard")
    assert a.verdict.status == "PASS"
    assert a.licenseViolations == []
