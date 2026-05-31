# Feeds mirror — internal API contract (frozen)

A dedicated **`feeds`** service mirrors the KEV, EPSS, and NVD CVE inventories locally and
serves them over an internal HTTP API consumed by the `api` (scanner) service. Refreshed
**daily** by an in-process scheduler; each refresh **wholesale-replaces** that feed's data
(no diffing). Internal-only — NOT published to the host; reached at `http://feeds:9000`.

## Storage
SQLite on a named volume (`/data/feeds.db`). Tables:
- `kev(cve TEXT PRIMARY KEY)` (+ optional `due_date`, `name`)
- `epss(cve TEXT PRIMARY KEY, epss REAL, percentile REAL)`
- `nvd(cve TEXT PRIMARY KEY, score REAL, severity TEXT, version TEXT, vector TEXT, cwes TEXT /*json*/, refs TEXT /*json*/)`
- `meta(feed TEXT PRIMARY KEY, updated_at TEXT, row_count INTEGER, status TEXT, detail TEXT)`

Wholesale replace = within one transaction `DELETE FROM <t>; INSERT ... ;` (or build a temp
table and swap). Never diff. Lookups are by exact CVE id.

## Downloads (use curl)
- **KEV**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (small).
- **EPSS**: `https://epss.cyentia.com/epss_scores-current.csv.gz` (gz CSV; header rows then `cve,epss,percentile`).
- **NVD**: NVD API 2.0 `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=N`,
  paginated to `totalResults`. Send `apiKey` header if `NVD_API_KEY` set (50 vs 5 req/30s). Rate-limit + sleep between pages. A dev cap (`NVD_INITIAL_MAX_PAGES`, 0=all) bounds first-run.

## Endpoints
```
GET  /feeds/health  → { "status": "ok" }
GET  /feeds/status  → { "feeds": [ { "name":"kev|epss|nvd", "updatedAt": ISO8601|null,
                                     "rowCount": int, "status":"ready|empty|refreshing|error",
                                     "detail": string } ],
                        "scheduler": { "dailyAt": "03:15", "nextRun": ISO8601|null } }
POST /feeds/kev   { "cves": ["CVE-…", …] } → { "kev": ["…subset that ARE KEV…"] }
POST /feeds/epss  { "cves": [...] }        → { "results": { "CVE-…": { "epss": float, "percentile": float } } }
POST /feeds/nvd   { "cves": [...] }        → { "results": { "CVE-…": { "score": float|null, "severity": str,
                                              "version": str, "vector": str, "cwes": [str], "refs": [str] } } }
POST /feeds/refresh?feed=all|kev|epss|nvd  → { "started": true }   (runs in background)
```
- Empty/unpopulated feed ⇒ endpoints return empty results (NOT an error); `status:"empty"`.
- Missing CVEs are simply absent from `results`.

## Scanner integration (api service)
- Env `USE_FEEDS=true`, `FEEDS_URL=http://feeds:9000`.
- KEV/EPSS/NVD enrichment query the feeds service in batch (one POST each per scan) instead of live upstreams.
- **Graceful fallback**: if feeds is unreachable OR a feed's `status` is `empty`, fall back to the existing live path for that source (so the product works on first deploy before the mirror is built). Log which path was used.
- `/api/sources` reflects each source as `mirror (updated <ISO>, N rows)` vs `live` vs `live-fallback`.
