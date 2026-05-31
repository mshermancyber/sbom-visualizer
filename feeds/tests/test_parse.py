"""Offline tests: EPSS CSV parsing, CVEProject cvelistV5 parsing, store wholesale-replace."""
from __future__ import annotations

import gzip
import json

from app.downloader import (
    parse_cve_list_record,
    parse_epss_csv,
    parse_kev,
)
from app.store import Store


# ── EPSS CSV parsing ──────────────────────────────────────────
EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-05-31T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.94400,0.99980\n"
    "CVE-2019-0708,0.90210,0.99500\n"
    "junk,notafloat,0.1\n"
    "NOTACVE,0.1,0.2\n"
    "\n"
)


def test_parse_epss_csv_skips_headers_and_bad_rows():
    rows = parse_epss_csv(EPSS_CSV)
    assert rows == [
        ("CVE-2021-44228", 0.944, 0.9998),
        ("CVE-2019-0708", 0.9021, 0.995),
    ]


def test_parse_epss_csv_handles_gzip_roundtrip():
    gz = gzip.compress(EPSS_CSV.encode())
    text = gzip.decompress(gz).decode()
    assert len(parse_epss_csv(text)) == 2


# ── KEV parsing ───────────────────────────────────────────────
KEV_JSON = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dueDate": "2021-12-24",
         "vulnerabilityName": "Log4Shell"},
        {"cveID": "CVE-2019-0708", "dueDate": "2022-01-01",
         "vulnerabilityName": "BlueKeep"},
        {"cveID": "CVE-2021-44228", "vulnerabilityName": "dup"},  # dedup
        {"cveID": ""},                                             # empty → skip
    ]
}


def test_parse_kev():
    rows = parse_kev(json.dumps(KEV_JSON))
    cves = [r[0] for r in rows]
    assert cves == ["CVE-2021-44228", "CVE-2019-0708"]
    assert rows[0] == ("CVE-2021-44228", "2021-12-24", "Log4Shell")


# ── CVEProject cvelistV5 parsing ──────────────────────────────
# Fixtures use the CVE Record 5.x schema (cveMetadata + containers.cna/adp),
# matching the real format of https://github.com/CVEProject/cvelistV5

CVE_RECORD_LOG4J = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2021-44228",
        "state": "PUBLISHED",
    },
    "containers": {
        "cna": {
            "metrics": [
                {
                    "cvssV3_1": {
                        "cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        }
                    }
                },
                {
                    "cvssV2_0": {
                        "cvssData": {
                            "baseScore": 9.3,
                            "baseSeverity": "HIGH",
                            "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        }
                    }
                },
            ],
            "problemTypes": [
                {"descriptions": [
                    {"cweId": "CWE-502", "lang": "en"},
                    {"cweId": "CWE-917", "lang": "en"},
                ]}
            ],
            "references": [
                {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                {"url": "https://logging.apache.org/log4j/2.x/security.html"},  # dup → deduped
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
            ],
        }
    },
}

CVE_RECORD_NO_METRICS = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2000-0001", "state": "PUBLISHED"},
    "containers": {"cna": {"metrics": [], "references": []}},
}

CVE_RECORD_REJECTED = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2021-0001", "state": "REJECTED"},
    "containers": {},
}

CVE_RECORD_WITH_ADP = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2023-9999", "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "metrics": [],  # CNA has no CVSS
            "references": [{"url": "https://example.com/advisory"}],
        },
        "adp": [{
            "metrics": [{
                "cvssV3_1": {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    }
                }
            }]
        }],
    },
}


def test_parse_cve_list_prefers_v31_over_v2():
    rec = parse_cve_list_record(CVE_RECORD_LOG4J)
    assert rec is not None
    assert rec["cve"] == "CVE-2021-44228"
    assert rec["score"] == 10.0
    assert rec["severity"] == "CRITICAL"
    assert rec["version"] == "3.1"
    assert "CVSS:3.1" in rec["vector"]


def test_parse_cve_list_extracts_cwes():
    rec = parse_cve_list_record(CVE_RECORD_LOG4J)
    assert rec["cwes"] == ["CWE-502", "CWE-917"]


def test_parse_cve_list_deduplicates_refs():
    rec = parse_cve_list_record(CVE_RECORD_LOG4J)
    assert len(rec["refs"]) == 2           # dup removed
    assert "https://logging.apache.org" in rec["refs"][0]


def test_parse_cve_list_no_metrics_returns_none_score():
    rec = parse_cve_list_record(CVE_RECORD_NO_METRICS)
    assert rec is not None
    assert rec["cve"] == "CVE-2000-0001"
    assert rec["score"] is None
    assert rec["severity"] == ""
    assert rec["cwes"] == []


def test_parse_cve_list_rejected_returns_none():
    assert parse_cve_list_record(CVE_RECORD_REJECTED) is None


def test_parse_cve_list_adp_fills_missing_cna_score():
    rec = parse_cve_list_record(CVE_RECORD_WITH_ADP)
    assert rec is not None
    assert rec["score"] == 7.5
    assert rec["severity"] == "HIGH"


def test_parse_cve_list_missing_id_returns_none():
    assert parse_cve_list_record({"cveMetadata": {}, "containers": {}}) is None


# ── store: wholesale replace + lookup ─────────────────────────
def test_store_wholesale_replace_and_lookup(tmp_path):
    store = Store(str(tmp_path / "feeds.db"))
    store.init_db()

    assert store.lookup_kev(["CVE-2021-44228"]) == []
    assert store.lookup_epss(["CVE-2021-44228"]) == {}
    assert store.lookup_nvd(["CVE-2021-44228"]) == {}
    assert store.get_meta("kev")["status"] == "empty"

    # KEV
    n = store.replace_kev(parse_kev(json.dumps(KEV_JSON)))
    assert n == 2
    assert set(store.lookup_kev(["CVE-2021-44228", "CVE-9999-9999"])) == {"CVE-2021-44228"}
    assert store.get_meta("kev")["status"] == "ready"
    assert store.get_meta("kev")["row_count"] == 2

    # EPSS
    store.replace_epss(parse_epss_csv(EPSS_CSV))
    res = store.lookup_epss(["CVE-2021-44228", "CVE-0000-0000"])
    assert res["CVE-2021-44228"]["epss"] == 0.944
    assert res["CVE-2021-44228"]["percentile"] == 0.9998
    assert "CVE-0000-0000" not in res

    # NVD (via cvelistV5 parser — cwes/refs survive JSON round-trip)
    records = [parse_cve_list_record(CVE_RECORD_LOG4J),
               parse_cve_list_record(CVE_RECORD_NO_METRICS)]
    records = [r for r in records if r]
    store.replace_nvd(records)
    nres = store.lookup_nvd(["CVE-2021-44228"])
    assert nres["CVE-2021-44228"]["score"] == 10.0
    assert nres["CVE-2021-44228"]["cwes"] == ["CWE-502", "CWE-917"]
    assert len(nres["CVE-2021-44228"]["refs"]) == 2

    # Wholesale replace truly replaces (old rows gone)
    store.replace_kev([("CVE-2023-1111", None, "only one")])
    assert store.lookup_kev(["CVE-2021-44228"]) == []
    assert set(store.lookup_kev(["CVE-2023-1111"])) == {"CVE-2023-1111"}
    assert store.get_meta("kev")["row_count"] == 1


# ── store: denormalized cve_enriched build + lookup ───────────
def _seed_three_tables(store: Store) -> None:
    """Seed kev/epss/nvd so CVE-2021-44228 is in ALL three, plus single-table CVEs."""
    # KEV: log4shell (shared) + a kev-only CVE.
    store.replace_kev([
        ("CVE-2021-44228", "2021-12-24", "Log4Shell"),
        ("CVE-2020-0001", "2020-06-01", "KevOnly"),
    ])
    # EPSS: log4shell (shared) + an epss-only CVE.
    store.replace_epss([
        ("CVE-2021-44228", 0.944, 0.9998),
        ("CVE-2022-2222", 0.01, 0.42),
    ])
    # NVD: log4shell (shared, score 10.0) + an nvd-only CVE.
    store.replace_nvd([
        parse_cve_list_record(CVE_RECORD_LOG4J),
        {"cve": "CVE-2023-3333", "score": 5.0, "severity": "MEDIUM",
         "version": "3.1", "vector": "CVSS:3.1/x", "cwes": ["CWE-1"], "refs": ["https://r"]},
    ])


def test_build_enriched_joins_correctly(tmp_path):
    store = Store(str(tmp_path / "feeds.db"))
    store.init_db()

    # Empty universe before any source data → empty results, status reflects build.
    assert store.build_enriched() == 0
    assert store.lookup_enriched(["CVE-2021-44228"]) == {}
    assert store.get_meta("enriched")["status"] == "empty"

    _seed_three_tables(store)
    # Universe = UNION of nvd/epss/kev. Shared log4shell counts once → 4 distinct CVEs.
    count = store.build_enriched()
    assert count == 4
    assert store.get_meta("enriched")["status"] == "ready"
    assert store.get_meta("enriched")["row_count"] == 4
    assert "4 CVEs" in store.get_meta("enriched")["detail"]

    res = store.lookup_enriched([
        "CVE-2021-44228", "CVE-2022-2222", "CVE-2020-0001", "CVE-2023-3333", "CVE-9-9"])

    # Shared CVE: kev flag + due date, EPSS, and CVSS all pegged together.
    log4j = res["CVE-2021-44228"]
    assert log4j["kev"] is True
    assert log4j["kevDueDate"] == "2021-12-24"
    assert log4j["epss"] == 0.944
    assert log4j["percentile"] == 0.9998
    assert log4j["score"] == 10.0
    assert log4j["severity"] == "CRITICAL"
    assert log4j["cwes"] == ["CWE-502", "CWE-917"]
    assert len(log4j["refs"]) == 2

    # EPSS-only CVE: kev=0, null cvss, epss present.
    epss_only = res["CVE-2022-2222"]
    assert epss_only["kev"] is False
    assert epss_only["score"] is None
    assert epss_only["severity"] == ""
    assert epss_only["cwes"] == []
    assert epss_only["percentile"] == 0.42

    # KEV-only CVE: kev=1 with due date, null epss + cvss.
    kev_only = res["CVE-2020-0001"]
    assert kev_only["kev"] is True
    assert kev_only["kevDueDate"] == "2020-06-01"
    assert kev_only["epss"] is None
    assert kev_only["score"] is None

    # NVD-only CVE: kev=0, cvss present, null epss.
    nvd_only = res["CVE-2023-3333"]
    assert nvd_only["kev"] is False
    assert nvd_only["score"] == 5.0
    assert nvd_only["epss"] is None

    # Missing CVE absent from results.
    assert "CVE-9-9" not in res

    # Empty lookup → {} (not error).
    assert store.lookup_enriched([]) == {}

    # Rebuild is wholesale: shrink KEV, rebuild, stale rows reflect new join.
    store.replace_kev([("CVE-2021-44228", "2021-12-24", "Log4Shell")])
    store.build_enriched()
    res2 = store.lookup_enriched(["CVE-2020-0001"])
    # CVE-2020-0001 still in universe only if a source has it; KEV dropped it and it was
    # kev-only, so it is gone from the enriched table.
    assert "CVE-2020-0001" not in res2
