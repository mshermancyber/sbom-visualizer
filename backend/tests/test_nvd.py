"""Offline NVD API 2.0 response parsing — CVSS + CWE + references extraction,
and the async token-bucket rate limiter."""
import asyncio
import time

from app.nvd import AsyncRateLimiter, parse_nvd_cve

# Trimmed real-shape NVD API 2.0 response for CVE-2021-44228 (Log4Shell).
SAMPLE_NVD = {
    "resultsPerPage": 1,
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features..."}],
            "metrics": {
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 6.0,
                }],
                "cvssMetricV2": [{
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "baseScore": 9.3,
                    },
                    "baseSeverity": "HIGH",
                }],
            },
            "weaknesses": [{
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [
                    {"lang": "en", "value": "CWE-502"},
                    {"lang": "en", "value": "CWE-917"},
                ],
            }],
            "references": [
                {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                {"url": "https://www.cisa.gov/news"},
            ],
        },
    }],
}


def test_parse_nvd_prefers_v31_score():
    r = parse_nvd_cve(SAMPLE_NVD)
    assert r is not None
    assert r["score"] == 10.0
    assert r["severity"] == "CRITICAL"
    assert r["version"] == "3.1"
    assert r["vector"].startswith("CVSS:3.1")


def test_parse_nvd_extracts_cwes():
    r = parse_nvd_cve(SAMPLE_NVD)
    assert "CWE-502" in r["cwes"]
    assert "CWE-917" in r["cwes"]


def test_parse_nvd_extracts_references():
    r = parse_nvd_cve(SAMPLE_NVD)
    assert "https://logging.apache.org/log4j/2.x/security.html" in r["refs"]
    assert len(r["refs"]) == 2


def test_parse_nvd_v2_only_fallback():
    data = {"vulnerabilities": [{"cve": {
        "id": "CVE-0000-0001",
        "metrics": {"cvssMetricV2": [{
            "type": "Primary",
            "cvssData": {"version": "2.0",
                         "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                         "baseScore": 7.5},
            "baseSeverity": "HIGH",
        }]},
    }}]}
    r = parse_nvd_cve(data)
    assert r["score"] == 7.5
    assert r["version"] == "2.0"
    assert r["severity"] == "HIGH"


def test_parse_nvd_no_metrics():
    data = {"vulnerabilities": [{"cve": {"id": "CVE-0000-0002", "metrics": {},
                                         "weaknesses": [], "references": []}}]}
    r = parse_nvd_cve(data)
    assert r is not None
    assert r["score"] is None
    assert r["cwes"] == []


def test_parse_nvd_empty():
    assert parse_nvd_cve({}) is None
    assert parse_nvd_cve({"vulnerabilities": []}) is None


def test_rate_limiter_spaces_requests():
    # 3 tokens, 1s window -> 4th acquire must wait ~ window/max for the refill.
    limiter = AsyncRateLimiter(max_calls=3, window=1.0)

    async def run():
        start = time.monotonic()
        for _ in range(4):
            await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(run())
    # First 3 are immediate; the 4th waits ~0.33s for one token to refill.
    assert elapsed >= 0.25
