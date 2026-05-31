# SBOM Visualizer — Backend (Python / FastAPI)

Server-side parsing, vulnerability scanning, enrichment, scoring, and assessment for the
SBOM security-assessment webapp. Implements the frozen API contract in
`../docs/API_CONTRACT.md`. The frontend is a pure consumer; all business logic lives here.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl localhost:8000/api/health
# {"status":"ok","version":"1.0.0"}
```

> Python 3.12+ required. The pinned dependency versions ship prebuilt wheels for 3.12–3.14.

## Tests (offline, no network)

```bash
python -m pytest -q
```

Covers the pure functions: CVSS v3.1/v3.0/v2 base scores (incl. Log4Shell = 10.0),
verdict for each gate policy, remediation ranking + semver-aware version compare
(incl. pre-release `2.0.0 > 2.0.0-rc1`), CycloneDX/SPDX/Syft parsing, coverage, and NTIA
completeness. No tests hit the network.

## Docker

```bash
docker build -t sbom-backend .
docker run -p 8000:8000 sbom-backend
```

Runs as a non-root user; includes a `HEALTHCHECK` against `/api/health`.

## Endpoints (base path `/api`)

| Method | Path                      | Purpose |
|--------|---------------------------|---------|
| GET    | `/api/health`             | `{ status, version }` |
| POST   | `/api/parse`              | Parse `{ raw }` or fetch `{ url }` (http/https only, SSRF-guarded) → `{ sbom }` |
| POST   | `/api/scan`               | OSV batch+hydrate → cve.org enrich → KEV → EPSS → `{ findings, summary, errors }` |
| POST   | `/api/assess`             | Pure scoring → `{ assessment }` (verdict / risk / remediation / coverage / CWE / NTIA) |
| POST   | `/api/report`             | Self-contained HTML report (`text/html`) |
| POST   | `/api/export/normalized`  | Normalized SBOM as `application/json` |
| GET    | `/api/sources`            | Connector status `[osv, nvd, mitre, epss, kev]` with `{id,name,enabled,configured,reachable,detail}` (live probe cached ~60s) |
| POST   | `/api/export/sarif`       | `{ sbom, findings }` → **SARIF 2.1.0** (`application/json`) |

### Scanning behaviour

- OSV `querybatch` chunked at 100; detail hydration with bounded concurrency (~10).
- Ecosystem-aware routing (PURL for language ecosystems; name+version+ecosystem for
  rpm/deb/apk; skip `pkg:oci`; RPM epoch stripping; golang pseudo-version skipping).
- cve.org (`cveawg.mitre.org`, "mitre") enrichment (~8 concurrent) only for CVE-aliased
  vulns missing a numeric score.
- **NVD API 2.0** enrichment runs *after* the mitre pass, only for CVEs that still lack a
  numeric score. It is rate-limited (token bucket: 5 req/30s keyless, 50 with
  `NVD_API_KEY`) and capped at `NVD_MAX_LOOKUPS` per scan; on any error it degrades
  gracefully into `errors`.
- Enrichment order for a CVE missing a computable score is **mitre → nvd**; the chosen
  CVSS records its provenance in `Vuln.scoreSource` (`osv`/`ghsa`/`mitre`/`nvd`).
- Per-scan source toggles via `options.sources: { nvd, mitre, epss, kev }` (all default
  true; OSV always on). Env flags `ENABLE_NVD/MITRE/EPSS/KEV` disable a source globally.
- CISA KEV fetched once; EPSS batched (~100/request).
- In-memory TTL cache (default 6h) keyed by PURL/query and by CVE/vuln id.
- Per-request timeouts; a single upstream failure is collected into `errors` and never
  crashes the whole scan.

## Configuration (environment variables)

All upstream URLs, timeouts, concurrency caps, and cache TTL are overridable — see
`app/config.py`. Examples: `OSV_QUERYBATCH`, `CVE_AWG_BASE`, `KEV_URL`, `EPSS_BASE`,
`OSV_BATCH_SIZE`, `DETAIL_CONCURRENCY`, `CACHE_TTL`, `MAX_FETCH_BYTES`.

### Data-source / NVD settings

| Env var | Default | Purpose |
|---------|---------|---------|
| `NVD_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD API 2.0 endpoint |
| `NVD_API_KEY` | *(unset)* | Optional NVD API key (raises rate limit 5→50 / 30s) |
| `NVD_TIMEOUT` | `8.0` | Per-request timeout (s) |
| `NVD_MAX_LOOKUPS` | `25` | Max NVD CVE lookups per scan |
| `NVD_RATE_WINDOW` | `30.0` | Token-bucket window (s) |
| `NVD_RATE_KEYLESS` | `5` | Requests/window without an API key |
| `NVD_RATE_KEYED` | `50` | Requests/window with an API key |
| `ENABLE_NVD` | `true` | Global toggle for the NVD source |
| `ENABLE_MITRE` | `true` | Global toggle for the cve.org (mitre) source |
| `ENABLE_EPSS` | `true` | Global toggle for EPSS |
| `ENABLE_KEV` | `true` | Global toggle for CISA KEV |

### NVD performance / time budget

NVD's keyless rate limit (5 req/30s) dominates multi-SBOM scans. Two mechanisms bound it:

| Env var | Default | Purpose |
|---------|---------|---------|
| `NVD_MAX_LOOKUPS` | `25` | Max *uncached* NVD CVE lookups per scan |
| `NVD_BUDGET_SECONDS` | `8.0` | Per-scan NVD time budget. When exhausted, NVD lookups stop, a `NVD enrichment time-boxed; N CVEs unenriched` note is appended to `errors`, and the scan returns fast on OSV + cve.org scores |

All enrichment caches (OSV query, OSV hydrate, **cve.org**, **NVD**, EPSS, KEV) are
**process-global** and shared across requests and SBOM files. A 2nd SBOM that shares
components/CVEs with the 1st does **zero** repeat upstream work. The cache hit-rate is logged
at the end of every scan (`sbom.cache`).

## Logging (`LOG_LEVEL`)

Structured stdlib logging with a per-request id. Set verbosity via `LOG_LEVEL`
(`DEBUG`/`INFO`/`WARNING`/`ERROR`); the **default is `DEBUG`** (high verbosity) per product
owner request. Loggers: `sbom.api` (each request: method, path, status, duration, request-id),
`sbom.scan` (each phase with timings), `sbom.nvd` (upstream calls), `sbom.cache` (hit/miss +
hit-rate). Secrets are never logged — only whether `NVD_API_KEY`/`API_TOKEN` are *set*.

Run uvicorn with our log format:

```bash
LOG_LEVEL=DEBUG uvicorn app.main:app --host 0.0.0.0 --port 8000
# or with the matching uvicorn log dict written to a file:
python -c "import json; from app.logging_config import uvicorn_log_config as u; json.dump(u(), open('logconf.json','w'))"
uvicorn app.main:app --log-config logconf.json
```

## API hardening (safe beyond localhost)

| Env var | Default | Purpose |
|---------|---------|---------|
| `API_TOKEN` | *(unset)* | When set, all `/api/*` except `/api/health` require `Authorization: Bearer <token>` **or** `X-API-Key: <token>` → else `401 {error}`. Unset ⇒ open (localhost dev) and a startup WARNING is logged |
| `RATE_LIMIT` | `120/minute` | Per-client-IP sliding window (honors first `X-Forwarded-For` hop from nginx). Over-limit ⇒ `429 {error}` with `Retry-After` |
| `MAX_BODY_BYTES` | `16777216` (16 MiB) | Oversize POST/PUT/PATCH bodies ⇒ `413 {error}` (checks `Content-Length` and streamed size) |

## CLI (`sbom-scan`) — CI gate

Installed as the `sbom-scan` console script (and runnable as `python -m app.cli`). It reuses
the exact parse + scan + assess functions the API uses — no HTTP server is started.

```
sbom-scan <SBOM_PATH|-> [--policy strict|standard|lenient]
          [--fail-on kev,critical,high,review] [--license-deny GPL,AGPL]
          [--license-warn LGPL] [--format text|json|sarif] [--output FILE]
          [--no-nvd] [--no-epss] [-v|-vv|-q]
```

* `text` — human summary (verdict, counts, top remediations); `json` — full assessment +
  findings + errors; `sarif` — the SARIF 2.1.0 document.
* **Exit codes:** `0` PASS · `1` gate failed (verdict FAIL, or REVIEW when `--fail-on`
  includes `review`, or any matching `--fail-on` signal / denied license) · `2` runtime error.
* `--fail-on` maps signals (`kev`, `mal`, `critical`, `high`, `medium`, `low`, `review`) → gate.

```bash
sbom-scan sbom.json --policy strict --fail-on kev,critical --license-deny GPL,AGPL
echo "$SBOM_JSON" | sbom-scan - --format json -o result.json
```

## CORS

Intentionally off. In production nginx serves the frontend and reverse-proxies `/api`
same-origin.
