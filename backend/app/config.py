"""Environment-driven settings for the SBOM backend.

All upstream URLs, timeouts, concurrency caps, and cache TTLs are configurable
via environment variables so the container can be tuned without code changes.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

VERSION = "1.0.0"


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Upstream endpoints (overridable for testing / mirrors)
    osv_querybatch: str = os.environ.get("OSV_QUERYBATCH", "https://api.osv.dev/v1/querybatch")
    osv_vuln: str = os.environ.get("OSV_VULN", "https://api.osv.dev/v1/vulns/")
    cve_awg_base: str = os.environ.get("CVE_AWG_BASE", "https://cveawg.mitre.org/api/cve/")
    kev_url: str = os.environ.get(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    epss_base: str = os.environ.get("EPSS_BASE", "https://api.first.org/data/v1/epss?cve=")

    # ── Offline OSV mirror (osv-scanner binary) ───────────────
    # When enabled and a populated OSV cache is present, OSV discovery runs the local
    # osv-scanner binary against the mirrored DBs (docs/OFFLINE_OSV.md) instead of the
    # live querybatch+hydrate path, with graceful live fallback.
    use_offline_osv: bool = _bool("USE_OFFLINE_OSV", True)
    osv_cache_dir: str = os.environ.get("OSV_CACHE_DIR", "/osv-cache")
    osv_scanner_bin: str = os.environ.get("OSV_SCANNER_BIN", "osv-scanner")
    # Timeout (seconds) for the offline osv-scanner subprocess.
    osv_scanner_timeout: float = _float("OSV_SCANNER_TIMEOUT", 120.0)
    # Speed router (optional): offline osv-scanner has ~fixed load overhead, so it wins
    # for large SBOMs but is slower than live OSV for tiny ones. Set this to N to route
    # SBOMs with < N queryable components to the live path instead.
    # DEFAULT 0 = ALWAYS use the offline mirror when its cache is present (full air-gap;
    # the operator's chosen behaviour). Set e.g. 50 to favour speed on small SBOMs.
    osv_offline_min_components: int = _int("OSV_OFFLINE_MIN_COMPONENTS", 0)

    # ── Feeds mirror (internal feeds service) ─────────────────
    # When enabled, KEV/EPSS/NVD enrichment is served from a local feeds mirror
    # (docs/FEEDS_CONTRACT.md) instead of live upstreams, with graceful live fallback.
    use_feeds: bool = _bool("USE_FEEDS", True)
    feeds_url: str = os.environ.get("FEEDS_URL", "http://feeds:9000")
    feeds_timeout: float = _float("FEEDS_TIMEOUT", 5.0)
    # How long to cache the feeds /feeds/status response (seconds).
    feeds_status_ttl: float = _float("FEEDS_STATUS_TTL", 60.0)

    # NVD API 2.0 (authoritative CVSS v2/3.x/4.0 + CWE + refs).
    nvd_base: str = os.environ.get("NVD_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = os.environ.get("NVD_API_KEY", "")
    nvd_timeout: float = _float("NVD_TIMEOUT", 8.0)
    # Max CVEs we'll look up in NVD per scan (it's rate-limited).
    nvd_max_lookups: int = _int("NVD_MAX_LOOKUPS", 25)
    # Token-bucket rate limit: max requests per window (seconds).
    # NVD allows 5 req / 30s keyless, 50 req / 30s with a key.
    nvd_rate_window: float = _float("NVD_RATE_WINDOW", 30.0)
    nvd_rate_keyless: int = _int("NVD_RATE_KEYLESS", 5)
    nvd_rate_keyed: int = _int("NVD_RATE_KEYED", 50)

    # Per-source enable toggles (env defaults; per-scan options can further disable).
    enable_nvd: bool = _bool("ENABLE_NVD", True)
    # MITRE/cve.org live enrichment is OFF by default: the local NVD mirror (CVEProject
    # cvelistV5) IS the MITRE CNA data (same CVE Record 5.x source), so the live call is
    # redundant. Set ENABLE_MITRE=true only to use cve.org as an online top-up.
    enable_mitre: bool = _bool("ENABLE_MITRE", False)
    enable_epss: bool = _bool("ENABLE_EPSS", True)
    enable_kev: bool = _bool("ENABLE_KEV", True)

    # Batching / concurrency
    osv_batch_size: int = _int("OSV_BATCH_SIZE", 100)
    detail_concurrency: int = _int("DETAIL_CONCURRENCY", 10)
    cve_awg_concurrency: int = _int("CVE_AWG_CONCURRENCY", 8)
    epss_chunk: int = _int("EPSS_CHUNK", 100)

    # Per-request timeouts (seconds)
    osv_batch_timeout: float = _float("OSV_BATCH_TIMEOUT", 30.0)
    osv_vuln_timeout: float = _float("OSV_VULN_TIMEOUT", 10.0)
    cve_awg_timeout: float = _float("CVE_AWG_TIMEOUT", 8.0)
    kev_timeout: float = _float("KEV_TIMEOUT", 10.0)
    epss_timeout: float = _float("EPSS_TIMEOUT", 10.0)

    # Cache TTL (seconds) — keyed by purl and by cve id. Default 6h.
    cache_ttl: float = _float("CACHE_TTL", 6 * 3600.0)

    # Abort the whole scan after this many querybatch errors.
    max_batch_errors: int = _int("MAX_BATCH_ERRORS", 3)

    # Max querybatch follow-up paging rounds per scan (OSV next_page_token).
    osv_max_pages: int = _int("OSV_MAX_PAGES", 10)

    # Max body size for /api/parse url fetch (bytes)
    max_fetch_bytes: int = _int("MAX_FETCH_BYTES", 25 * 1024 * 1024)

    # ── API hardening ─────────────────────────────────────────
    # Bearer / X-API-Key token. If empty, auth is OFF (localhost dev default) and a
    # startup WARNING is logged. NEVER log the value itself.
    api_token: str = os.environ.get("API_TOKEN", "")
    # Per-client-IP rate limit, "<count>/<minute|second|hour>".
    rate_limit: str = os.environ.get("RATE_LIMIT", "120/minute")
    # Max request body size for any POST (bytes); 413 over this. Default 16 MiB.
    max_body_bytes: int = _int("MAX_BODY_BYTES", 16 * 1024 * 1024)

    # ── NVD per-scan time budget ──────────────────────────────
    # When exhausted, stop issuing NVD lookups and note it in errors. The scan still
    # completes fast on OSV + cve.org scores. The per-scan NVD_MAX_LOOKUPS cap also applies.
    nvd_budget_seconds: float = _float("NVD_BUDGET_SECONDS", 8.0)


settings = Settings()
