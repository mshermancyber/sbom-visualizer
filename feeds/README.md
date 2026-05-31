# feeds — local vulnerability inventory mirror

A small FastAPI service that mirrors the **KEV**, **EPSS**, and **NVD CVE** inventories
into local **SQLite** plus a full daily copy of the **OSV** database to disk (in the
osv-scanner offline cache layout), and serves them over an internal HTTP API consumed by
the `api` (scanner) service. Refreshed **daily** by an in-process scheduler; each refresh
**wholesale-replaces** that feed (no diffing). Internal-only — reached at
`http://feeds:9000`.

Implements `docs/FEEDS_CONTRACT.md` exactly.

## Endpoints

```
GET  /feeds/health   → { "status": "ok" }
GET  /feeds/status   → { "feeds": [ { name, updatedAt, rowCount, status, detail } ],
                         "scheduler": { "dailyAt", "nextRun" } }
POST /feeds/kev      { "cves": [...] } → { "kev": [ ...subset that ARE KEV... ] }
POST /feeds/epss     { "cves": [...] } → { "results": { "CVE-…": { epss, percentile } } }
POST /feeds/nvd      { "cves": [...] } → { "results": { "CVE-…": { score, severity,
                                          version, vector, cwes[], refs[] } } }
POST /feeds/refresh?feed=all|kev|epss|nvd|osv → { "started": true }  (runs in background)
```

- `osv` is a **file mirror**, not a SQLite table: it has no batch-lookup endpoint
  (the `api` runs the `osv-scanner` binary directly against the cached files). It still
  appears in `GET /feeds/status` (`rowCount` = ecosystem zips present, `detail` = total
  size on disk) and is refreshed daily / on startup like the others.

- An empty/unpopulated feed returns **empty results** (never an error); its status is
  `empty`. Missing CVEs are simply absent from `results`.
- Feed `status` is one of `ready | empty | refreshing | error`.

## Storage (SQLite)

Path is `FEEDS_DB` (default `/data/feeds.db`, a named volume in production). Tables:

- `kev(cve PK, due_date, name)`
- `epss(cve PK, epss REAL, percentile REAL)`
- `nvd(cve PK, score REAL, severity, version, vector, cwes /*json*/, refs /*json*/)`
- `meta(feed PK, updated_at, row_count, status, detail)`

Each refresh wholesale-replaces its feed inside a single transaction
(`DELETE` + bulk `INSERT`), then stamps the `meta` row.

## Downloads (curl)

Downloads shell out to **curl** (the container installs it):

- **KEV** — curl the CISA JSON, parse the `vulnerabilities[]` CVE set.
- **EPSS** — curl `epss_scores-current.csv.gz`, gunzip, skip the `#model_version` comment
  line and the `cve,epss,percentile` header, bulk-insert the rows.
- **NVD** — paginate the NVD API 2.0 (`resultsPerPage=2000`, `startIndex` stepping to
  `totalResults`), sending the `apiKey` header when `NVD_API_KEY` is set, sleeping
  `NVD_PAGE_SLEEP` between pages. Each CVE's CVSS (v3.1 → v3.0 → v4.0 → v2),
  CWEs (`weaknesses[].description[].value`), and references are parsed. The whole crawl is
  accumulated and committed atomically. `NVD_INITIAL_MAX_PAGES` bounds first-run/dev.
- **OSV** — curl `OSV_ECOSYSTEMS_URL` (`ecosystems.txt`, ~45 names), then for each
  ecosystem curl `OSV_BUCKET_BASE/<urlencoded-ecosystem>/all.zip` to a temp file and
  `os.replace()` it atomically into `OSV_CACHE_DIR/osv-scanner/<ecosystem>/all.zip` (the
  on-disk directory is the **literal** ecosystem name — spaces/dots and all — the layout
  the offline `osv-scanner` binary reads). Ecosystems with no `all.zip` (HTTP 404) are
  skipped and counted, not fatal. ~1.2 GB total; runs in the background worker thread so it
  never blocks startup/requests.

## Scheduler

- Daily refresh at `FEEDS_DAILY_AT` (default `03:15`, local time) via APScheduler
  `AsyncIOScheduler` (falls back to a simple asyncio loop if APScheduler is unavailable).
- On startup, any feed that is empty or stale (older than `FEEDS_STALE_HOURS`, ~26h) is
  refreshed **in the background** — the API comes up immediately and serves
  `status:"empty"`/`"refreshing"` until populated.
- Refreshes are serialized behind a lock and run in a worker thread, so they never block
  request handling.

## Configuration (env)

| Var | Default | Purpose |
|-----|---------|---------|
| `FEEDS_DB` | `/data/feeds.db` | SQLite path (named volume) |
| `FEEDS_DAILY_AT` | `03:15` | Daily refresh time, `HH:MM` local |
| `FEEDS_STALE_HOURS` | `26` | Age beyond which a feed is refreshed on startup |
| `KEV_URL` | CISA KEV JSON | KEV source |
| `EPSS_URL` | EPSS `csv.gz` | EPSS source |
| `NVD_BASE` | NVD API 2.0 base | NVD source |
| `NVD_API_KEY` | *(empty)* | NVD API key (50 vs 5 req/30s); never logged |
| `NVD_INITIAL_MAX_PAGES` | `0` | Cap NVD pages (0 = all); bounds first-run/dev |
| `NVD_RESULTS_PER_PAGE` | `2000` | NVD page size |
| `NVD_PAGE_SLEEP` | `6.0` | Seconds slept between NVD pages |
| `OSV_CACHE_DIR` | `/osv-cache` | Root of the OSV mirror; zips at `<dir>/osv-scanner/<eco>/all.zip` |
| `OSV_BUCKET_BASE` | `https://osv-vulnerabilities.storage.googleapis.com` | OSV public bucket base |
| `OSV_ECOSYSTEMS_URL` | `<bucket>/ecosystems.txt` | OSV ecosystem list |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `CURL_CONNECT_TIMEOUT` / `CURL_MAX_TIME` / `NVD_CURL_MAX_TIME` | `15` / `120` / `60` | curl timeouts (seconds) |

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 9000
```

### Docker

```bash
docker build -t feeds .
docker run -p 9000:9000 -v feeds-data:/data feeds
```

Image: `python:3.12-slim`, non-root (`appuser`), `curl` installed, `HEALTHCHECK` on
`/feeds/health`, `EXPOSE 9000`, DB on the `/data` volume (writable by the non-root user).

## Tests

```bash
python -m pytest -q
```

Offline tests cover EPSS CSV parsing, KEV/NVD JSON parsing, and the store's
wholesale-replace + lookup behaviour.
