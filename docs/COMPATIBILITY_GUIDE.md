# SBOM Visualizer — Compatibility and Deployment Guide

**Audience:** Operations and platform engineers deploying or integrating the stack.

---

## 1. Architecture Overview

```
                        ┌──────────────────────────────────────┐
                        │           Docker network: sbom-net   │
                        │                                      │
  Browser               │  ┌─────────────────────┐            │
  HTTPS :443 ───────────┼─▶│   web (nginx 1.27)  │            │
  HTTP  :80  ───────────┼─▶│   :80 → redirect    │            │
                        │  │   :443 TLS + SPA     │            │
                        │  └────────┬────────────-┘            │
                        │           │ /api/* proxy              │
                        │           ▼                          │
                        │  ┌─────────────────────┐            │
                        │  │  api (FastAPI)       │            │
                        │  │  :8000 (internal)    │            │
                        │  │  + osv-scanner v2.3.8│◀── osv-db  │
                        │  │  api-data volume     │   (reads)  │
                        │  └────────┬────────────-┘            │
                        │           │ POST /feeds/enriched      │
                        │           ▼                          │
                        │  ┌─────────────────────┐            │
                        │  │  feeds (FastAPI +    │── osv-db   │
                        │  │  APScheduler)        │  (writes)  │
                        │  │  :9000 (internal)    │            │
                        │  │  feeds-data volume   │            │
                        │  └─────────────────────┘            │
                        │           │                          │
                        │    ┌──────┴──────┐                   │
                        │    │ feeds.db    │ (SQLite WAL:      │
                        │    │ named vol   │  kev/epss/nvd/    │
                        │    └─────────────┘  cve_enriched)    │
                        └──────────────────────────────────────┘

External upstreams:
  cveawg.mitre.org (live, non-blocking top-up)
  api.osv.dev · api.first.org · www.cisa.gov · NVD API  (FALLBACK ONLY — used by api when a feed mirror is not ready)

Daily mirror downloads (feeds → local volumes):
  osv-vulnerabilities.storage.googleapis.com  → osv-db volume   (~1.2 GB, all 45 ecosystems)
  github.com/CVEProject/cvelistV5 (main.zip)  → feeds.db (nvd)  (~588 MB, ~354k CVE records)
  FIRST EPSS CSV.gz                            → feeds.db (epss) (~336k CVEs)
  CISA KEV JSON                                → feeds.db (kev)  (~1,607 CVEs)
```

**Named volumes:**

| Volume | Mount | Contents | Writers / readers |
|--------|-------|----------|-------------------|
| `feeds-data` | `/data/feeds.db` (feeds) | SQLite WAL DB: `kev`, `epss`, `nvd`, `cve_enriched` tables + feed metadata | feeds writes; feeds serves to api over HTTP |
| `api-data` | `/data` (api) | SQLite DBs: `vex.db` (suppressions), `scans.db` (persisted scans), `auth.db` (API keys) | api read/write |
| `osv-db` | `/osv-cache` | Offline OSV database in osv-scanner cache layout (`/osv-cache/osv-scanner/<ecosystem>/all.zip`) | feeds writes; api reads via osv-scanner |

**Ports published to the host (defaults):**

| Port | Protocol | Purpose |
|------|----------|---------|
| 80 | HTTP | Redirects to HTTPS |
| 443 | HTTPS | Application (TLS terminated by nginx) |

`api` (port 8000) and `feeds` (port 9000) are internal to `sbom-net` and not published to the host.

---

## 2. Tech Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Frontend | TypeScript | 5.4 |
| Frontend build | Vite | 5.2 |
| Frontend framework | Vanilla TS DOM (no framework) | — |
| Charts | Chart.js | 4.4.1 |
| Graph | D3 | 7.8.5 |
| Icons | Tabler Icons (self-hosted webfont) | 2.47.0 |
| Font | JetBrains Mono (via `@fontsource`, self-hosted) | — |
| Backend language | Python | 3.12+ |
| Backend framework | FastAPI + Uvicorn | — |
| Backend validation | Pydantic v2 | — |
| Backend HTTP client | httpx (async) | — |
| CVSS v4 computation | cvss Python library | 3.6 |
| OSV offline scanner | google/osv-scanner binary (bundled in api image) | v2.3.8 |
| NVD/CVSS/CWE source | CVEProject `cvelistV5` GitHub archive (CVE Record 5.x) | main.zip (~354k records) |
| Feeds service | Python 3.12+, FastAPI, APScheduler | — |
| Feeds / api storage | SQLite (WAL mode) | — |
| Proxy | nginx | 1.27-alpine |
| TLS | TLSv1.2 + TLSv1.3 | — |
| Container orchestration | Docker Compose v2 | — |
| Frontend tests | Vitest | 33 tests |
| Backend tests | pytest | 160 tests |
| Feeds tests | pytest | 16 tests |

---

## 3. SBOM Format Support

| Format | Versions | Detection field(s) | Notes |
|--------|----------|-------------------|-------|
| **CycloneDX** | 1.4, 1.5 | `bomFormat: "CycloneDX"` | JSON only |
| **SPDX** | 2.2, 2.3 | `spdxVersion` + `SPDXID` + `packages` | JSON only. Linux distro inferred from `documentNamespace` and `creationInfo.creators` fields to select the correct OSV ecosystem. |
| **Syft JSON** | schema v16+ | `artifacts` + `source` fields | Anchore Syft native output format. v16 is the minimum schema version supported. |

Detection is automatic. The parser inspects `bomFormat` first (CycloneDX), then `spdxVersion`/`SPDXID`/`packages` (SPDX), then `artifacts`+`source` (Syft). An unrecognized structure returns HTTP 400 with a parse error.

---

## 3a. Data Sources

Four of the five sources are mirrored locally by the feeds service and refreshed daily (wholesale replace, no diffing). MITRE is the one live source. The default scan path makes no live calls.

| Source | Role | Upstream | Size / scale | Mirror store |
|--------|------|----------|--------------|--------------|
| **OSV** | Primary discovery (osv-scanner v2.3.8 `--offline-vulnerabilities`) | `osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip` | ~1.2 GB, all 45 ecosystems | `osv-db` volume (osv-scanner cache layout) |
| **NVD / CVSS / CWE** | Authoritative CVSS v2/3.x/4.0, CWE, refs | CVEProject `cvelistV5` `main.zip` (CVE Record 5.x) | ~588 MB, ~354k CVE records | SQLite `nvd` table |
| **EPSS** | Exploitation probability score + percentile | FIRST daily `CSV.gz` | ~336k CVEs | SQLite `epss` table |
| **CISA KEV** | Confirmed in-the-wild exploitation | CISA KEV JSON | ~1,607 CVEs | SQLite `kev` table |
| **MITRE / cve.org** | Optional, non-blocking CVSS/CWE top-up | `cveawg.mitre.org` | live | none (live only) |

After each daily KEV/EPSS/NVD refresh, the feeds scheduler rebuilds a denormalized **`cve_enriched`** table (~336,837 rows) via one `INSERT…SELECT` join, so every CVE is pre-pegged with KEV + EPSS + NVD data. At scan time the api makes one `POST /feeds/enriched` batch lookup instead of three per-source calls. The scheduler runs daily at `FEEDS_DAILY_AT` (default 03:15 UTC), plus a startup refresh if any feed is empty or stale (> `FEEDS_STALE_HOURS`, default 26 h).

Live fallback: if a mirror is not ready or unreachable, the api falls back to the live upstream for that source (`api.osv.dev`, NVD API, `api.first.org`, CISA). `NVD_API_KEY` is optional and used only on the live NVD-API fallback path.

---

## 4. OSV Ecosystem Routing

The scanner builds an OSV query for each component. Routing depends on the PURL scheme:

| PURL scheme | Query method | Notes |
|-------------|-------------|-------|
| `pkg:npm` | PURL query | |
| `pkg:pypi` | PURL query | |
| `pkg:maven` | PURL query | |
| `pkg:cargo` | PURL query | |
| `pkg:gem` (RubyGems) | PURL query | |
| `pkg:nuget` | PURL query | |
| `pkg:golang` | PURL query | Pseudo-versions (`(devel)`) are skipped |
| `pkg:rpm` (amzn/rhel/fedora/sles/rocky/alma/oracle/centos) | name + version + ecosystem | Epoch prefix stripped from version. Namespace or distro name used to select Amazon Linux, Red Hat, Fedora, openSUSE, Rocky Linux, AlmaLinux, Oracle Linux |
| `pkg:deb` | name + version + ecosystem | Ecosystem is `Ubuntu` or `Debian` based on distro hint from the SBOM |
| `pkg:apk` | name + version + `Alpine` ecosystem | |
| `pkg:alpm` (Arch Linux) | PURL query | No native OSV Arch ecosystem. PURL queries surface upstream CVEs only; distro-specific advisories may be missed. |
| `pkg:oci` | **Skipped** | OCI image components are not queried |

Components with `version = "(devel)"` are always skipped. Components without a name and without a PURL are skipped.

---

## 5. CVSS Version Support

| Version | Computation method | Notes |
|---------|-------------------|-------|
| v3.1 | Local FIRST formula | ISC + exploitability + scope-changed branch. Preferred when vector is present and parseable. |
| v3.0 | Same local formula as v3.1 | |
| v4.0 | `cvss` Python library (v3.6) | Used only when no v3.x score is computable; v4 never shadows a computable v3. |
| v2.0 | Local formula | AV/AC/Au/C/I/A metric mapping. Lowest priority. |

**Resolution order:** v3.1 → v3.0 → v4.0 → v2.0.

The `scoreSource` field on each `Vuln` object records which data source provided the final CVSS vector: `nvd`, `mitre`, `osv`, `ghsa`, or `null`.

---

## 6. Browser Support

Requires a modern browser with ES2020+ support and native ES modules. Tested on:

- Chrome (current)
- Firefox (current)
- Safari (current)
- Edge (current)

Mobile browsers work but the layout is not optimised for narrow viewports. The application is a fully client-rendered SPA with no server-side rendering. All assets (fonts, icons, JS, CSS) are self-hosted; no CDN requests are made, and the CSP enforces `*-src 'self'`.

---

## 7. Deployment Requirements

### Minimum requirements

| Requirement | Value |
|-------------|-------|
| Docker Engine | 24+ |
| Docker Compose | v2 (no `version:` key in compose file) |
| RAM | 2 GB minimum; 4 GB recommended for large SBOMs (5k+ components) |
| Disk | **~2 GB free for offline mode** — the local vulnerability mirrors (OSV ~1.2 GB + cvelistV5 ~588 MB + EPSS/KEV) are **downloaded on first build/run, not shipped** with the release. Without offline mode the footprint is minimal. |
| `curl` | Required in feeds image for OSV / cvelistV5 / EPSS / KEV downloads |
| `openssl` | Required for `make certs` (self-signed cert generation) |

### Not supported

- **Podman:** untested; compatibility not guaranteed.
- **Kubernetes:** no Helm chart or manifests provided.

### Compose v2 note

The `docker-compose.yml` uses the Compose v2 schema and requires `docker compose` (with a space), not the legacy `docker-compose` (hyphenated) CLI plugin. The file does not include a `version:` key.

---

## 8. TLS / Certificates

### Self-signed certificates (development / local)

```bash
make certs
```

Generates `certs/fullchain.pem` and `certs/privkey.pem` using `openssl req -x509`. Certificate properties:

- Validity: 825 days
- Key: RSA 2048
- SANs: `DNS:localhost`, `DNS:*.localhost`, `IP:127.0.0.1`
- Common Name: `localhost`

The script is idempotent: it skips regeneration if a valid, unexpired certificate already exists. Set `FORCE=1` to regenerate unconditionally.

Add extra SANs without editing the script:

```bash
EXTRA_SAN="DNS:sbom.example.com,IP:127.0.0.1" bash certs/generate-certs.sh
```

### Real certificates

The `web` container mounts `./certs` at `/etc/nginx/certs:ro`. To swap in real certificates, replace the two files and restart the `web` service. No image rebuild is required.

```bash
# Let's Encrypt (certbot)
certbot certonly --standalone -d sbom.example.com
cp /etc/letsencrypt/live/sbom.example.com/fullchain.pem certs/fullchain.pem
cp /etc/letsencrypt/live/sbom.example.com/privkey.pem   certs/privkey.pem
docker compose restart web
```

For a commercial CA: concatenate the leaf certificate followed by the CA's intermediate bundle into `fullchain.pem`. Place the unencrypted private key in `privkey.pem`.

---

## 9. Environment Variables

### API service

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging level: `debug`, `info`, `warning`, `error` |
| `API_TOKEN` | _(empty)_ | Master token. Enables auth and acts as the admin key for provisioning per-project API keys (`/api/admin/keys`). If unset, auth is disabled and a startup warning is logged. **Set before deploying beyond localhost.** |
| `RATE_LIMIT` | `120/minute` | Per-client-IP rate limit in `<count>/<unit>` format |
| `MAX_BODY_BYTES` | `16777216` (16 MiB) | Maximum POST body size in bytes; requests over this limit receive HTTP 413 |
| `MAX_FETCH_BYTES` | _(set)_ | Maximum size of a server-side URL fetch (`/api/parse` with `url`) |
| `USE_FEEDS` | `true` | Use the local feeds mirror (KEV/EPSS/NVD + pre-enriched table) |
| `FEEDS_URL` | `http://feeds:9000` | Base URL of the feeds service |
| `FEEDS_TIMEOUT` | _(set)_ | HTTP timeout for calls to the feeds service |
| `FEEDS_STATUS_TTL` | _(set)_ | Cache TTL for the cached feeds `/status` result used by `/api/sources` |
| `USE_OFFLINE_OSV` | `true` | Run the bundled osv-scanner binary against the local OSV mirror. When `false`, OSV discovery always uses live `api.osv.dev`. |
| `OSV_CACHE_DIR` | `/osv-cache` | Path to the offline OSV database (osv-scanner cache layout); shared `osv-db` volume |
| `OSV_SCANNER_BIN` | `osv-scanner` | osv-scanner binary path (absolute or on `PATH`) |
| `OSV_SCANNER_TIMEOUT` | _(set)_ | Timeout (seconds) for the osv-scanner subprocess |
| `OSV_OFFLINE_MIN_COMPONENTS` | `0` | Speed router. `0` = always offline. If `>0`, SBOMs with fewer components than this are routed to live OSV (faster for tiny SBOMs that would otherwise pay the offline load overhead). |
| `OSV_MAX_PAGES` | _(set)_ | Max OSV querybatch pages per CVE (live-path pagination cap) |
| `OSV_BATCH_SIZE` | _(set)_ | OSV querybatch chunk size (live path) |
| `MAX_BATCH_ERRORS` | _(set)_ | Error-count threshold that aborts a scan |
| `ENABLE_NVD` | `true` | Enable NVD enrichment source |
| `ENABLE_MITRE` | `true` | Enable MITRE / cve.org enrichment source |
| `ENABLE_EPSS` | `true` | Enable EPSS exploitation probability overlay |
| `ENABLE_KEV` | `true` | Enable CISA KEV overlay |
| `DETAIL_CONCURRENCY` | `10` | Concurrent OSV detail-hydration requests per scan (live path) |
| `CACHE_TTL` | `21600` (6 h) | In-memory cache TTL in seconds for scan results |
| `NVD_BUDGET_SECONDS` | _(set)_ | Per-scan wall-clock budget for live NVD-API lookups (fallback path only) |
| `NVD_MAX_LOOKUPS` | _(set)_ | Max live NVD-API lookups per scan (fallback path only) |
| `NVD_API_KEY` | _(empty)_ | Optional NVD API key; **fallback path only** (raises the keyless live NVD-API rate limit). Not used by the cvelistV5 mirror. |

SQLite DB paths for VEX suppressions, persisted scans, and auth keys default under `/data` (the `api-data` volume): `vex.db`, `scans.db`, `auth.db`.

### Feeds service

| Variable | Default | Description |
|----------|---------|-------------|
| `FEEDS_DB` | `/data/feeds.db` | Path to the SQLite database file inside the container |
| `FEEDS_DAILY_AT` | `03:15` | Daily refresh time in `HH:MM` UTC format. Wholesale-replaces every feed, then rebuilds the `cve_enriched` table. |
| `FEEDS_STALE_HOURS` | `26` | A feed older than this triggers a startup refresh |
| `OSV_CACHE_DIR` | `/osv-cache` | Destination for the daily full OSV database mirror (`osv-db` volume) |
| `NVD_INITIAL_MAX_PAGES` | `0` | Legacy NVD-API fallback crawl cap only (`0` = full). Not used by the cvelistV5 mirror path, which is the default NVD source. |
| `NVD_API_KEY` | _(empty)_ | Optional NVD API key for the legacy NVD-API fallback crawl |
| `LOG_LEVEL` | `info` | Logging level for the feeds service |

(The feeds image also exposes curl timeout knobs for the upstream downloads.)

### Nginx / web service

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `80` | Host port mapped to nginx port 80 (HTTP redirect) |
| `HTTPS_PORT` | `443` | Host port mapped to nginx port 443 (HTTPS application) |

---

## 10. API Reference

All endpoints are under the `/api` base path. The frontend communicates with the backend exclusively through nginx (`/api` is proxied same-origin). Errors are returned as `{ "error": string }` with an appropriate non-2xx status code.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Liveness check. Returns `{ "status": "ok", "version": string }`. |
| `POST` | `/api/parse` | Parse an SBOM. Body: `{ "raw": <object> }` or `{ "url": string }`. Returns `{ "sbom": Sbom }`. HTTP 400 on unrecognized format, parse failure, or blocked URL. |
| `POST` | `/api/scan` | Synchronous scan of a parsed SBOM. Body: `{ "sbom": Sbom, "options": {...} }`. Returns `{ "findings": Finding[], "summary": Summary, "errors": string[], "scanId": string }`. Used for SBOMs under 200 components. |
| `POST` | `/api/scan/async` | Enqueue an asynchronous scan job (used for SBOMs ≥ 200 components). Returns `{ "jobId": string, "status": string }`. |
| `GET` | `/api/scan/jobs` | List recent scan jobs. |
| `GET` | `/api/scan/jobs/{jobId}` | Poll a scan job. Returns `{ "status": string, "result"?: {...} }`. |
| `GET` | `/api/scans` | List persisted scans (gzip JSON in SQLite). |
| `GET` | `/api/scans/{scanId}` | Retrieve a full stored scan. |
| `DELETE` | `/api/scans/{scanId}` | Delete a stored scan. |
| `POST` | `/api/assess` | Compute verdict, risk score, remediation, coverage, CWE breakdown, NTIA completeness, and license violations from scan results. Pure computation, no network. Body: `{ "sbom": Sbom, "findings": Finding[], "summary": Summary, "policy": "strict"\|"standard"\|"lenient", "licensePolicy"?: { "deny": string[], "warn": string[] }, "suppressions"?: [...] }`. Returns `{ "assessment": Assessment }`. |
| `POST` | `/api/report` | Generate a self-contained HTML report. Returns `text/html`. |
| `POST` | `/api/export/sarif` | Emit findings as SARIF 2.1.0. Returns `application/json`. |
| `POST` | `/api/export/normalized` | Re-emit a normalized SBOM in the internal schema. Returns `application/json`. |
| `GET` | `/api/sources` | Data source connector status. Returns enabled/configured/reachable flags, mirror metadata, and a `servedBy` value (`offline-mirror` / `mirror` / `live`) for the five connectors. |
| `POST`/`GET` | `/api/vex/suppressions` | Create / list VEX suppressions (status, note, optional expiry). |
| `DELETE` | `/api/vex/suppressions/{id}` | Delete a suppression. |
| `POST` | `/api/vex/apply` | Apply suppressions to a finding set (exclude suppressed findings). |
| `POST`/`GET` | `/api/admin/keys` | Create / list per-project API keys. **Requires the master `API_TOKEN`.** |
| `DELETE` | `/api/admin/keys/{label}` | Revoke a per-project API key. Requires the master `API_TOKEN`. |

### Feeds service (internal, port 9000 — not host-published)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/feeds/health` | Liveness check. |
| `GET` | `/feeds/status` | Per-feed row counts, last-update times, readiness. |
| `POST` | `/feeds/enriched` | Batch lookup `{ "cves": [...] }` against the denormalized `cve_enriched` table. The single call the api makes per scan for KEV+EPSS+NVD. |
| `POST` | `/feeds/{kev,epss,nvd,enriched}` | Refresh an individual feed / rebuild the enriched table. |
| `POST` | `/feeds/refresh?feed=all\|kev\|epss\|nvd\|osv\|enriched` | Trigger a refresh of one or all feeds. |

---

## 11. CI Integration

### `sbom-scan` CLI

The `sbom-scan` command is installed as an entry point in the backend Python package. It runs the full parse → scan → assess pipeline in-process (no HTTP server) and returns an exit code suitable for CI gating.

```bash
# Inside the backend container or a virtualenv with the package installed
sbom-scan sbom.cdx.json --policy standard --fail-on kev,critical \
    --format sarif --output results.sarif
```

Exit codes: `0` = PASS, `1` = gate failed, `2` = runtime error.

### Reusable GitHub Action

The composite action at `.github/actions/sbom-scan/action.yml` builds the backend image and runs the CLI gate inside it.

**Inputs:** `sbom` (required path to SBOM file), `policy` (default `standard`), `fail-on` (default `kev,critical`), `license-deny` (optional), `sarif` (default `true`).

**Output:** `sarif-file` (path to `results.sarif` when `sarif=true`).

```yaml
permissions:
  contents: read
  security-events: write        # required for upload-sarif

steps:
  - uses: actions/checkout@v4
  - id: scan
    uses: ./.github/actions/sbom-scan
    with:
      sbom: sbom.cdx.json
      policy: standard
      fail-on: kev,critical
    env:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}   # optional
  - if: always() && steps.scan.outputs.sarif-file != ''
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

A non-zero exit code fails the CI step. SARIF output uploads to GitHub Security → Code Scanning alerts, one alert per (component, vulnerability), severity mapped to SARIF levels (critical/high → error, medium → warning, low/none → note).

See `.github/workflows/sbom-gate.example.yml` for a complete example workflow.

---

## 12. Security Posture

### HTTP security headers (nginx)

All responses from the `web` service include:

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (2 years) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |

`style-src 'unsafe-inline'` is required because Vite injects inline style attributes. All JavaScript, fonts, and icons are bundled by Vite and served from `/assets/` (no CDN).

### Non-root containers

Both `api` and `feeds` are built to run as non-root users inside their containers.

### Internal-only services

`api` and `feeds` are not published to the host network. They are reachable only within `sbom-net`. External traffic reaches `api` only through the nginx reverse proxy at `/api/`.

### API authentication

Set `API_TOKEN` to a strong random string. The middleware enforces Bearer token or `X-API-Key` authentication on all API requests. The master token also authorizes the admin endpoints (`/api/admin/keys`) that provision **per-project API keys**; each project key isolates its own persisted scans and VEX suppressions. Without `API_TOKEN` set, the API is open; this is acceptable for local development but not for any network-exposed deployment.

### Rate limiting

Default: 120 requests per minute per client IP (`RATE_LIMIT`). Configurable via environment variable.

### Request body size cap

Default: 16 MiB (`MAX_BODY_BYTES`). Requests exceeding this receive HTTP 413.

### SSRF guard on URL fetch

`/api/parse` and `/api/export/normalized` accept a `url` parameter. Before fetching, the backend resolves all DNS addresses for the host and blocks any that are loopback, link-local, private, reserved, multicast, or unspecified. Only `http://` and `https://` schemes are allowed.

---

## 13. Known Limitations

| Limitation | Detail |
|------------|--------|
| **`pkg:alpm` (Arch Linux)** | No native OSV Arch Linux ecosystem. PURL queries surface upstream language-ecosystem CVEs only; distro-specific Arch advisories are not covered. |
| **`pkg:oci`** | OCI image layer components are skipped entirely during scanning. They appear in component counts but receive no vulnerability data. |
| **OSV mirror first populate** | The full OSV database mirror is ~1.2 GB (all 45 ecosystems) and takes a few minutes to download on first boot. Until it is ready, OSV discovery falls back to live `api.osv.dev`. |
| **npm-heavy SBOMs (air-gap tax)** | osv-scanner only loads the ecosystem zips present in the SBOM, so most scans are sub-second. An npm-heavy SBOM pays a one-time ~7 s load for the large npm zip (~196 MB). Set `OSV_OFFLINE_MIN_COMPONENTS` > 0 to route small SBOMs to live OSV for speed; the default is always-offline. |
| **NVD cvelistV5 first-boot download** | The cvelistV5 archive is ~588 MB (~354k CVE records) and takes a few minutes to download/import on first start. The scanner falls back to the live NVD API until the mirror is populated. `NVD_INITIAL_MAX_PAGES` affects only the legacy NVD-API fallback crawl, not the cvelistV5 mirror. |
| **MITRE / cve.org is live** | The one remaining non-mirrored source. It is a non-blocking enrichment top-up; KEV/EPSS/NVD already supply CVSS+CWE from the mirror. |
| **SBOM signatures / attestations** | Signatures and attestations are not verified; the SBOM is accepted as-is. |
| **Large SBOMs** | SBOMs with 5,000+ components push memory usage above the 2 GB minimum; 4 GB is recommended. Such scans run asynchronously (≥ 200 components) to survive request timeouts. |
| **cve.org CORS** | In a hypothetical direct-browser context, cve.org would require CORS handling. In this product, all cve.org queries are proxied through the backend API; this is not an issue in production. |
| **Podman / Kubernetes** | Podman is untested. No Kubernetes manifests are provided. |
