"""Offline CVSS tests — exact base-score math including Log4Shell = 10.0."""
from app.cvss import (
    cvss2_score, cvss3_score, cvss4_score, extract_osv_cvss,
    score_to_severity2, score_to_severity3,
)


def test_log4shell_v31_is_10():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cvss3_score(vec) == 10.0
    assert score_to_severity3(cvss3_score(vec)) == "CRITICAL"


def test_v31_scope_unchanged_medium():
    # CVE-2019-1010083 style — moderate. AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H -> 7.5 HIGH
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert cvss3_score(vec) == 7.5
    assert score_to_severity3(7.5) == "HIGH"


def test_v31_low():
    vec = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    s = cvss3_score(vec)
    assert s == 1.8
    assert score_to_severity3(s) == "LOW"


def test_v30_known_vector():
    # CVSS:3.0 same Log4Shell-shaped vector also rounds to 10.0
    vec = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cvss3_score(vec) == 10.0


def test_v3_round_up_behaviour():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L -> 7.3 (round-up to 1 decimal)
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    assert cvss3_score(vec) == 7.3


def test_v3_none_when_no_impact():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert cvss3_score(vec) == 0.0
    assert score_to_severity3(0.0) == "NONE"


def test_v2_full_compromise():
    # CVSS:2.0 AV:N/AC:L/Au:N/C:C/I:C/A:C -> 10.0
    vec = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    assert cvss2_score(vec) == 10.0
    assert score_to_severity2(10.0) == "HIGH"


def test_v2_medium():
    # AV:N/AC:M/Au:N/C:P/I:P/A:P -> 6.8 MEDIUM
    vec = "AV:N/AC:M/Au:N/C:P/I:P/A:P"
    assert cvss2_score(vec) == 6.8
    assert score_to_severity2(6.8) == "MEDIUM"


def test_v2_low():
    # AV:L/AC:H/Au:N/C:P/I:N/A:N -> 1.2 LOW
    vec = "AV:L/AC:H/Au:N/C:P/I:N/A:N"
    s = cvss2_score(vec)
    assert s == 1.2
    assert score_to_severity2(s) == "LOW"


def test_invalid_vector_returns_none():
    assert cvss3_score("CVSS:3.1/AV:Z/AC:L") is None
    assert cvss3_score("") is None
    assert cvss2_score(None) is None


def test_cvss4_all_high_is_10():
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    assert cvss4_score(vec) == 10.0


def test_cvss4_no_impact_is_zero():
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert cvss4_score(vec) == 0.0


def test_cvss4_invalid_returns_none():
    assert cvss4_score("CVSS:4.0/GARBAGE") is None
    assert cvss4_score("not a vector") is None
    assert cvss4_score("") is None
    assert cvss4_score(None) is None


def test_extract_osv_prefers_v4_over_v31_when_computable():
    # v4 is now locally computable and takes precedence over v3/v2 when present.
    arr = [
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    ]
    out = extract_osv_cvss(arr)
    assert out["score"] == 10.0
    assert out["version"] == "4.0"
    assert out["vector"].startswith("CVSS:4")


def test_extract_osv_v4_only_is_now_scored():
    arr = [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]
    out = extract_osv_cvss(arr)
    assert out["score"] == 9.3
    assert out["version"] == "4.0"
    assert out["vector"].startswith("CVSS:4")


def test_extract_osv_uncomputable_v4_does_not_shadow_v3():
    # A malformed/uncomputable v4 entry must NOT shadow a scorable v3 entry.
    arr = [
        {"type": "CVSS_V4", "score": "CVSS:4.0/GARBAGE"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    ]
    out = extract_osv_cvss(arr)
    assert out["score"] == 10.0
    assert out["version"] == "3.1"


def test_extract_osv_empty():
    out = extract_osv_cvss([])
    assert out == {"score": None, "severity": "UNKNOWN", "version": None, "vector": None}
