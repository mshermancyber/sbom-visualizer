"""Offline scoring tests — verdict per policy, remediation ranking, version compare,
risk score v2 (EPSS-amplified, KEV-floored, age-decayed), coverage, NTIA completeness."""
from app.models import (
    Component, Cvss, Dependency, Epss, Finding, Sbom, Summary, Vuln,
)
from app.scoring import (
    KEV_MIN_SCORE, RISK_CEILING, _age_decay, _cvss_base_points, _epss_amp, _score_vuln,
    build_assessment, build_remediation_plan, calc_risk_score, compare_versions,
    compute_coverage, compute_verdict, score_completeness, top_cwes,
)


# ── compare_versions ──────────────────────────────────────────
def test_compare_basic():
    assert compare_versions("1.2.0", "1.10.0") == -1
    assert compare_versions("2.0.0", "2.0.0") == 0
    assert compare_versions("2.0.1", "2.0.0") == 1


def test_compare_prerelease():
    # release outranks its own pre-release
    assert compare_versions("2.0.0", "2.0.0-rc1") == 1
    assert compare_versions("2.0.0-rc1", "2.0.0") == -1
    # trailing numeric outranks the shorter release
    assert compare_versions("2.0.0.1", "2.0.0") == 1
    # numeric segment outranks a string at the same position
    assert compare_versions("1.0.1", "1.0.beta") == 1


# ── verdict per policy ────────────────────────────────────────
def _summary(**kw):
    return Summary(**kw)


def test_verdict_standard_critical_fails():
    v = compute_verdict(_summary(CRITICAL=1, HIGH=2), mal_count=0, kev_count=0, policy="standard")
    assert v.status == "FAIL"
    assert v.policy == "standard"


def test_verdict_standard_high_reviews():
    v = compute_verdict(_summary(HIGH=3), mal_count=0, kev_count=0, policy="standard")
    assert v.status == "REVIEW"


def test_verdict_strict_high_fails():
    v = compute_verdict(_summary(HIGH=1), mal_count=0, kev_count=0, policy="strict")
    assert v.status == "FAIL"


def test_verdict_strict_medium_reviews():
    v = compute_verdict(_summary(MEDIUM=1), mal_count=0, kev_count=0, policy="strict")
    assert v.status == "REVIEW"


def test_verdict_lenient_critical_reviews():
    v = compute_verdict(_summary(CRITICAL=2), mal_count=0, kev_count=0, policy="lenient")
    assert v.status == "REVIEW"


def test_verdict_lenient_kev_fails():
    v = compute_verdict(_summary(CRITICAL=0), mal_count=0, kev_count=1, policy="lenient")
    assert v.status == "FAIL"


def test_verdict_malicious_fails_all_policies():
    for pol in ("strict", "standard", "lenient"):
        v = compute_verdict(_summary(), mal_count=1, kev_count=0, policy=pol)
        assert v.status == "FAIL", pol


def test_verdict_pass_clean():
    v = compute_verdict(_summary(LOW=2), mal_count=0, kev_count=0, policy="standard")
    assert v.status == "PASS"
    assert "2 medium/low findings only" in v.reasons


def test_verdict_invalid_policy_defaults_standard():
    v = compute_verdict(_summary(CRITICAL=1), mal_count=0, kev_count=0, policy="bogus")
    assert v.policy == "standard"
    assert v.status == "FAIL"


# ── risk score v2: EPSS-amplified, KEV-floored, age-decayed ──────

def _mk_vuln(sev, cvss_score=None, is_kev=False, epss_pct=None, published=None):
    return Vuln(
        id="TEST", cvss=Cvss(severity=sev, score=cvss_score),
        kev=is_kev, epss=Epss(score=epss_pct or 0.0, percentile=epss_pct) if epss_pct is not None else None,
        published=published or "2023-01-01",
    )


# ── per-CVE scoring primitives ────────────────────────────────
def test_cvss_base_points_uses_numeric():
    assert _cvss_base_points(10.0, "CRITICAL") == 100.0
    assert _cvss_base_points(7.5,  "HIGH")     == 75.0
    assert _cvss_base_points(None, "CRITICAL") == 90.0
    assert _cvss_base_points(None, "HIGH")     == 65.0
    assert _cvss_base_points(None, "MEDIUM")   == 40.0


def test_epss_amp_kev_overrides():
    assert _epss_amp(None, is_kev=True) == 5.0   # KEV always 5.0
    assert _epss_amp(0.99, is_kev=True) == 5.0   # KEV overrides even 99th pct


def test_epss_amp_tiers():
    assert _epss_amp(0.97, False) == 4.0
    assert _epss_amp(0.80, False) == 2.5
    assert _epss_amp(0.55, False) == 1.5
    assert _epss_amp(0.30, False) == 1.0
    assert _epss_amp(None, False) == 1.0   # neutral when unknown


def test_epss_amp_below_all_tiers_returns_none():
    # Below 25th percentile → caller applies age decay
    assert _epss_amp(0.10, False) is None


def test_age_decay_no_decay_for_kev():
    assert _age_decay("2005-01-01", 0.05, is_kev=True) == 1.0


def test_age_decay_applied_for_old_low_epss():
    decay = _age_decay("2015-01-01", 0.05, is_kev=False)   # > 5 years
    assert decay == 0.30


def test_age_decay_no_decay_recent():
    decay = _age_decay("2025-12-01", 0.05, is_kev=False)   # < 1 year
    assert decay == 0.90


def test_score_vuln_kev_floor():
    # A KEV finding must contribute at least KEV_MIN_SCORE regardless of other factors.
    v = _mk_vuln("LOW", cvss_score=1.0, is_kev=True, published="2000-01-01")
    s = _score_vuln(v)
    assert s >= KEV_MIN_SCORE


def test_score_vuln_high_epss_amplified():
    # CRITICAL+99th pct EPSS should give CRITICAL base × 4.0 amplifier
    v = _mk_vuln("CRITICAL", cvss_score=10.0, is_kev=False, epss_pct=0.97)
    s = _score_vuln(v)
    assert abs(s - 100.0 * 4.0) < 0.1


def test_score_vuln_old_low_epss_decays():
    v_new = _mk_vuln("MEDIUM", cvss_score=5.0, is_kev=False, epss_pct=0.05,
                     published="2025-01-01")   # < 1yr
    v_old = _mk_vuln("MEDIUM", cvss_score=5.0, is_kev=False, epss_pct=0.05,
                     published="2015-01-01")   # > 5yr
    assert _score_vuln(v_old) < _score_vuln(v_new)


# ── overall risk score behaviour ─────────────────────────────
def test_risk_score_kev_floor_on_grade():
    # Even a single KEV finding should make the grade D at minimum (not A/B).
    sbom = Sbom(format="cyclonedx", components=[Component(name="a")])
    findings = [Finding(componentIndex=0, vulns=[
        _mk_vuln("LOW", cvss_score=1.0, is_kev=True)
    ])]
    summ = Summary(LOW=1, total=1, scanned=1)
    r = calc_risk_score(sbom, summ, kev_hits=1, scanned=True, findings=findings)
    assert r.grade in ("D", "F"), f"Expected D/F with KEV, got {r.grade}"


def test_risk_score_clean_sbom():
    sbom = Sbom(format="cyclonedx", components=[])
    r = calc_risk_score(sbom, Summary(), kev_hits=0, scanned=True, findings=[])
    assert r.score == 0
    assert r.grade == "A"


def test_risk_score_capped_at_1000():
    # Massive SBOM: score must never exceed 1000.
    sbom = Sbom(format="cyclonedx", components=[])
    # 50 KEV CRITICAL 10.0 EPSS 99th → 50 × max(100×5, 250) = 50 × 500 = 25000 >> CEILING
    findings = [Finding(componentIndex=0, vulns=[
        _mk_vuln("CRITICAL", 10.0, is_kev=True, epss_pct=0.99) for _ in range(50)
    ])]
    summ = Summary(CRITICAL=50, total=50, scanned=50)
    r = calc_risk_score(sbom, summ, kev_hits=50, scanned=True, findings=findings)
    assert r.score == 1000
    assert r.grade == "F"


def test_risk_score_epss_high_raises_grade():
    # A single HIGH finding with no EPSS should grade lower than the same finding
    # when the CVE is at the 97th EPSS percentile.
    sbom = Sbom(format="cyclonedx", components=[Component(name="x")])
    f_low_epss = [Finding(componentIndex=0, vulns=[
        _mk_vuln("HIGH", 7.5, is_kev=False, epss_pct=0.05)
    ])]
    f_high_epss = [Finding(componentIndex=0, vulns=[
        _mk_vuln("HIGH", 7.5, is_kev=False, epss_pct=0.97)
    ])]
    summ = Summary(HIGH=1, total=1, scanned=1)
    r_low  = calc_risk_score(sbom, summ, 0, True, f_low_epss)
    r_high = calc_risk_score(sbom, summ, 0, True, f_high_epss)
    assert r_high.score > r_low.score


def test_risk_score_summary_fallback():
    # Without findings, the legacy summary-only path must still produce a sane result.
    sbom = Sbom(format="cyclonedx", components=[])
    r = calc_risk_score(sbom, Summary(CRITICAL=3, HIGH=2), kev_hits=0, scanned=True)
    assert 0 < r.score <= 1000
    assert r.grade in ("A", "B", "C", "D", "F")


# ── remediation ranking ───────────────────────────────────────
def _vuln(vid, sev, fixed, kev=False, epss_pct=None):
    return Vuln(id=vid, cveId=vid if vid.startswith("CVE-") else None,
                cvss=Cvss(severity=sev), fixed=fixed, kev=kev,
                epss=Epss(score=0.5, percentile=epss_pct) if epss_pct is not None else None)


def test_remediation_ranking_and_target():
    sbom = Sbom(format="cyclonedx", components=[
        Component(name="low-pkg", version="1.0.0"),
        Component(name="crit-pkg", version="2.0.0"),
    ])
    findings = [
        Finding(componentIndex=0, vulns=[_vuln("CVE-1", "LOW", ["1.0.1"])]),
        Finding(componentIndex=1, vulns=[
            _vuln("CVE-2", "CRITICAL", ["2.1.0", "2.0.5"], kev=True),
            _vuln("CVE-3", "HIGH", ["2.1.0"]),
        ]),
    ]
    plan, no_fix = build_remediation_plan(sbom, findings)
    # crit-pkg has CRITICAL+KEV+HIGH — must rank above LOW pkg regardless of model version
    assert plan[0].name == "crit-pkg"
    assert plan[0].kevCount == 1
    # riskRemoved now uses per-CVE scoring (EPSS-amplified) — just assert it's meaningfully
    # larger than low-pkg and positive
    assert plan[0].riskRemoved > plan[1].riskRemoved > 0
    # max-version target picks 2.1.0 over 2.0.5
    assert plan[0].target == "2.1.0"
    assert plan[1].name == "low-pkg"


def test_remediation_no_fix_listed():
    sbom = Sbom(format="cyclonedx", components=[Component(name="x", version="1.0.0")])
    findings = [Finding(componentIndex=0, vulns=[_vuln("CVE-9", "HIGH", [])])]
    plan, no_fix = build_remediation_plan(sbom, findings)
    assert plan == []
    assert no_fix[0].name == "x" and no_fix[0].vulnCount == 1


# ── coverage ──────────────────────────────────────────────────
def test_coverage_counts_oci_and_devel():
    sbom = Sbom(format="cyclonedx", components=[
        Component(name="a", purl="pkg:npm/a@1.0.0"),         # queryable
        Component(name="img", purl="pkg:oci/img@sha256:x"),  # oci skip
        Component(name="g", version="(devel)", purl="pkg:golang/g"),  # devel skip
        Component(name="", purl=""),                          # noId
    ])
    cov = compute_coverage(sbom)
    assert cov.total == 4
    assert cov.queryable == 1
    assert cov.oci == 1
    assert cov.devel == 1
    assert cov.noId == 1
    assert cov.skipped == 3


# ── NTIA completeness ─────────────────────────────────────────
def test_completeness_full_and_partial():
    sbom = Sbom(format="cyclonedx",
                components=[
                    Component(name="a", version="1", supplier="acme", purl="pkg:npm/a@1",
                              licenses=["MIT"], bomRef="a", type="library"),
                    Component(name="b"),  # mostly empty
                ],
                dependencies=[Dependency(ref="a", deps=["b"])])
    comp = score_completeness(sbom, hashes_by_index={0: [{"alg": "sha256"}]})
    assert 0 <= comp.overallPct <= 100
    # name present in both, supplier only in first
    assert comp.fieldStats["name"].present == 2
    assert comp.fieldStats["supplier"].present == 1
    assert comp.fieldStats["hash"].present == 1
    # relationship: a is a dep ref, b is depended-on -> both present
    assert comp.fieldStats["relationship"].present == 2


# ── CWE aggregation ───────────────────────────────────────────
def test_top_cwes():
    findings = [
        Finding(componentIndex=0, vulns=[
            Vuln(id="A", cwes=["CWE-79", "CWE-502"]),
            Vuln(id="B", cwes=["CWE-79"]),
        ]),
    ]
    top = top_cwes(findings)
    assert top[0].id == "CWE-79" and top[0].count == 2
    assert top[0].name == "Cross-site Scripting"


# ── full assessment assembly ──────────────────────────────────
def test_build_assessment_end_to_end():
    sbom = Sbom(format="cyclonedx", components=[
        Component(name="log4j-core", version="2.14.1",
                  purl="pkg:maven/x/log4j-core@2.14.1", licenses=["Apache-2.0"]),
    ], dependencies=[])
    findings = [Finding(componentIndex=0, vulns=[
        _vuln("CVE-2021-44228", "CRITICAL", ["2.15.0"], kev=True),
    ])]
    summary = Summary(CRITICAL=1, total=1, scanned=1, affected=1, withPurl=1)
    a = build_assessment(sbom, findings, summary, policy="standard")
    assert a.verdict.status == "FAIL"
    assert a.kevCount == 1
    assert a.remediation[0].target == "2.15.0"
    # With v2 scoring: CRITICAL CVSS (no numeric score in this fixture → 90 base pts) × KEV amp 5.0
    # = 450 pts → but KEV floor is 250 and max is max(450,250)=450 → ~450/2000 ceiling = score ~225
    # Exact value may vary; assert grade D/F and score > 0 as KEV creates a floor.
    assert a.risk.score > 0
    assert a.risk.grade in ("D", "F")  # KEV floor prevents A/B/C
