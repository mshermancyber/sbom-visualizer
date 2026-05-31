"""Environment-driven settings for the feeds mirror service.

All upstream URLs, the SQLite path, scheduler time, and NVD paging knobs are configurable
via environment variables so the container can be tuned without code changes. Mirrors the
style of the sibling ``backend`` service (config-via-env, frozen dataclass).
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


@dataclass(frozen=True)
class Settings:
    # SQLite database path (named volume in production).
    db_path: str = os.environ.get("FEEDS_DB", "/data/feeds.db")

    # Daily refresh time, "HH:MM" 24h local time.
    daily_at: str = os.environ.get("FEEDS_DAILY_AT", "03:15")

    # A feed older than this many hours is considered stale and refreshed on startup.
    stale_hours: float = _float("FEEDS_STALE_HOURS", 26.0)

    # Upstream endpoints (overridable for testing / mirrors).
    kev_url: str = os.environ.get(
        "KEV_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    epss_url: str = os.environ.get(
        "EPSS_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz"
    )
    nvd_base: str = os.environ.get("NVD_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = os.environ.get("NVD_API_KEY", "")

    # OSV: full daily mirror of the OSV database in the osv-scanner cache layout.
    # Files land at <osv_cache_dir>/osv-scanner/<ECOSYSTEM>/all.zip (the layout the
    # osv-scanner binary reads in offline mode). osv has no SQLite table — meta-only.
    osv_cache_dir: str = os.environ.get("OSV_CACHE_DIR", "/osv-cache")
    osv_bucket_base: str = os.environ.get(
        "OSV_BUCKET_BASE", "https://osv-vulnerabilities.storage.googleapis.com"
    )
    osv_ecosystems_url: str = os.environ.get(
        "OSV_ECOSYSTEMS_URL",
        "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt",
    )

    # NVD paging: 0 = fetch all pages; >0 caps the number of pages (dev/first-run).
    nvd_initial_max_pages: int = _int("NVD_INITIAL_MAX_PAGES", 0)
    nvd_results_per_page: int = _int("NVD_RESULTS_PER_PAGE", 2000)
    # Sleep (seconds) between NVD pages to respect rate limits.
    nvd_page_sleep: float = _float("NVD_PAGE_SLEEP", 6.0)

    # curl timeouts (seconds).
    curl_connect_timeout: float = _float("CURL_CONNECT_TIMEOUT", 15.0)
    curl_max_time: float = _float("CURL_MAX_TIME", 120.0)
    nvd_curl_max_time: float = _float("NVD_CURL_MAX_TIME", 60.0)


settings = Settings()
