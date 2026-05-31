# SBOM Visualizer — Deployment

Productized, dockerized build of the SBOM Visualizer: a FastAPI backend that
parses/scans/scores SBOMs and a TypeScript SPA that renders the results, served
behind an nginx TLS reverse proxy.

This README covers the **deployment infrastructure** (nginx + Docker Compose).
For API and feature details see [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md)
and [`docs/FEATURES.md`](docs/FEATURES.md).

---

## Architecture

```
                         host
                ┌──────────────────────┐
   browser ───► │  :80  ──301──► :443   │   forced HTTPS
   (https)      │                :443   │   (TLS terminated here)
                └────────┬──────────────┘
                         │  container: web  (nginx:1.27-alpine)
            ┌────────────┴─────────────────────────────┐
            │  • serves the built SPA (/usr/share/...)  │
            │  • try_files $uri /index.html  (SPA)      │
            │  • /api/  ──reverse proxy──►              │
            │  • security headers + gzip + HSTS         │
            └────────────┬─────────────────────────────┘
                         │  sbom-net (private bridge network)
                         ▼
                ┌──────────────────────┐
                │  container: api       │   FastAPI / uvicorn
                │  app.main:app  :8000  │   (NOT published to host)
                │  GET /api/health      │
                └────┬───────────┬─────┘
                     │           │  KEV/EPSS/NVD enrichment (batch POST),
                     │           │  live-fallback if mirror empty/unreachable
                     │           ▼
                     │  ┌──────────────────────┐
                     │  │  container: feeds     │   local vuln mirror
                     │  │  :9000 (internal)     │   (NOT published to host)
                     │  │  GET /feeds/health    │
                     │  └────┬───────────┬─────┘
                     │       │           │  named volume
                     │       ▼           │
                     │  [ feeds-data ]   │  /data/feeds.db (SQLite)
                     │                   │
                     │ reads (offline    │ writes daily
                     │ osv-scanner)      ▼ (~1.2GB, 45 ecosystems)
                     └────────►[ osv-db ]  →  /osv-cache/osv-scanner/<eco>/all.zip
```

- **`web`** — built from [`web.Dockerfile`](web.Dockerfile) (multi-stage:
  `node:22-alpine` builds the Vite frontend → `dist/`, copied into
  `nginx:1.27-alpine`). Terminates TLS on 443, redirects 80→443, serves the
  SPA, and reverse-proxies `/api/` to `api:8000`. Publishes host ports 80/443.
- **`api`** — built from `./backend` (owned by the backend team). Internal
  only; reachable as `api:8000` on the private `sbom-net` network. Has a
  `/api/health` healthcheck. Enriches scans from the local `feeds` mirror
  (`USE_FEEDS=true`, `FEEDS_URL=http://feeds:9000`) with live-fallback. Also
  runs the bundled `osv-scanner` binary in offline mode against the shared
  `osv-db` volume for OSV vulnerability discovery (`USE_OFFLINE_OSV=true`).
- **`feeds`** — built from `./feeds` (owned by the feeds team). Internal only;
  reachable as `feeds:9000`. Mirrors KEV/EPSS/NVD into a SQLite DB on the
  `feeds-data` named volume, and downloads the full OSV database (~1.2GB) into
  the shared `osv-db` volume. Has a `/feeds/health` healthcheck. See
  [Local vulnerability mirror](#local-vulnerability-mirror-feeds) below.

---

## Prerequisites

- Docker Engine 24+ with the Compose v2 plugin (`docker compose`).
- `openssl` and `bash` on the host (for self-signed cert generation).
- GNU `make` (optional convenience; raw `docker compose` works too).
- **~2 GB free disk for offline mode.** The KEV/EPSS/NVD and OSV mirrors are **not
  shipped** with this release — the `feeds` service **downloads them on first
  build/run** (OSV ~1.2 GB + cvelistV5 ~588 MB + EPSS/KEV). The first populate takes
  a few minutes; until it finishes the API falls back to live upstreams. Disable
  offline mode (`USE_OFFLINE_OSV=false`) to skip the OSV mirror and its footprint.

---

## Quickstart

```bash
cd product
make certs                          # generate a self-signed cert (idempotent)
docker compose up -d --build        # build images + start the stack
# ...then open:
#   https://localhost
```

The first visit shows a browser warning because the cert is self-signed —
accept it (or import the cert) to proceed. Plain HTTP is auto-redirected:
`http://localhost` → `https://localhost`.

`make up` rolls the first two steps together (it also creates `.env` from the
template if missing):

```bash
make up        # certs + .env + docker compose up -d --build
make logs      # follow logs
make down      # stop
```

---

## How forced HTTPS works

nginx runs two server blocks ([`nginx/default.conf`](nginx/default.conf)):

1. **Port 80** does nothing but redirect:
   `return 301 https://$host$request_uri;` — every plain-HTTP request
   (any path, any query string) is bounced to the HTTPS equivalent.
2. **Port 443** is the real server (TLS, SPA, `/api` proxy). It also sends an
   **HSTS** header (`Strict-Transport-Security: max-age=63072000;
   includeSubDomains`), so after the first visit browsers refuse to talk plain
   HTTP to this host at all.

The TLS certificate/key are **mounted** (`./certs:/etc/nginx/certs:ro`), never
baked into the image — see below to swap in real certs.

## How the `/api` proxy works

`location /api/` in the HTTPS server block proxies to `http://api:8000`
(Docker DNS resolves `api` on the private network). It forwards the original
host and client info:

```
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;     # = https to the backend
```

Because the SPA and the API are served from the **same origin** (`https://
localhost`, path-routed), there is no CORS to configure — exactly as the API
contract assumes. Upstream timeouts are generous (300s read/send) since scans
fan out to OSV.dev / cve.org / KEV / EPSS server-side.

---

## Local vulnerability mirror (feeds)

The internal **`feeds`** service mirrors four vulnerability data sources
locally and serves them to the `api` over the private `sbom-net` network
(`http://feeds:9000`, never published to the host):

- **KEV** — CISA Known Exploited Vulnerabilities catalog.
- **EPSS** — FIRST Exploit Prediction Scoring System (scores + percentiles).
- **NVD** — NIST CVE inventory (CVSS score/severity/vector, CWEs, references).
- **OSV** — the **full OSV database** (~1.2GB, all 45 ecosystems), mirrored from
  the OSV public bucket via [osv-scanner](https://github.com/google/osv-scanner)
  offline mode.

**Offline OSV discovery.** Unlike KEV/EPSS/NVD (which the api fetches from the
feeds HTTP API for enrichment), the OSV database is shared as files on the
**`osv-db`** named volume: `feeds` is the **writer** (it downloads
`/osv-cache/osv-scanner/<ecosystem>/all.zip` daily), and `api` is the
**reader** — it runs `osv-scanner --offline-vulnerabilities` against that cache
to discover vulnerabilities for a scanned SBOM, fully air-gapped. This is
controlled by `USE_OFFLINE_OSV=true`; while the OSV mirror is still populating
(the first download takes several minutes), the api falls back to **live OSV**
(`api.osv.dev`) automatically, so scans work immediately.

**Daily wholesale refresh.** An in-process scheduler refreshes every feed once
a day at `FEEDS_DAILY_AT` (default `03:15`). Each refresh **replaces** that
feed's data wholesale (no diffing). The KEV/EPSS/NVD mirror lives in a SQLite DB
at `/data/feeds.db` on the **`feeds-data`** named volume; the OSV database lives
as per-ecosystem zips on the **`osv-db`** named volume — both persist across
restarts and rebuilds.

**First-boot behavior.** On a fresh deploy the mirror starts empty and begins
crawling in the background. The `api` depends on `feeds` with
`condition: service_started` (not `service_healthy`) and uses **live-fallback**
— querying upstreams directly — for any feed that is still empty or unreachable,
so the product works immediately. `/api/sources` reflects each source as
`mirror (updated <ISO>, N rows)`, `live`, or `live-fallback`.

The keyless **NVD full crawl is slow** (rate-limited to 5 requests / 30s). For
faster first boots:

- Set **`NVD_API_KEY`** in `.env` (50 vs 5 requests / 30s).
- For a demo, set **`NVD_INITIAL_MAX_PAGES`** to a small value (e.g. `2`) to cap
  the first run; `0` (default) mirrors the full inventory.

**Force a refresh** (immediate, runs in the background):

```bash
make feeds-refresh                 # POST /feeds/refresh?feed=all
make osv-refresh                   # POST /feeds/refresh?feed=osv  (~1.2GB OSV only)
make feeds-status                  # per-feed rows / updatedAt / scheduler nextRun
```

Equivalently, without make (exec into the container, pure-Python so no curl
dependency is required):

```bash
docker compose exec feeds python -c \
  "import urllib.request; req=urllib.request.Request('http://localhost:9000/feeds/refresh?feed=all',method='POST'); print(urllib.request.urlopen(req).read().decode())"
docker compose exec feeds python -c \
  "import urllib.request; print(urllib.request.urlopen('http://localhost:9000/feeds/status').read().decode())"
```

`make clean` (i.e. `docker compose down --volumes`) removes both the
`feeds-data` and `osv-db` volumes; the next `up` re-crawls KEV/EPSS/NVD and
re-downloads the ~1.2GB OSV database from scratch.

---

## Replacing the self-signed certificate

The web container only ever reads two files (mounted read-only):

| file                  | contents                                     |
|-----------------------|----------------------------------------------|
| `certs/fullchain.pem` | leaf certificate + intermediate chain (PEM)  |
| `certs/privkey.pem`   | matching unencrypted private key (PEM)        |

To use real certs, replace those two files and restart `web` — **no image
rebuild needed**.

**Let's Encrypt (certbot):**

```bash
certbot certonly --standalone -d sbom.example.com
cp /etc/letsencrypt/live/sbom.example.com/fullchain.pem certs/fullchain.pem
cp /etc/letsencrypt/live/sbom.example.com/privkey.pem   certs/privkey.pem
docker compose restart web
```

**Commercial CA:** concatenate your leaf cert followed by the CA's intermediate
bundle into `certs/fullchain.pem`; put the private key in `certs/privkey.pem`.

To regenerate a self-signed cert for a custom hostname:

```bash
CN=sbom.example.com EXTRA_SAN=DNS:sbom.example.com FORCE=1 \
  bash certs/generate-certs.sh
```

---

## Environment variables

Copy [`.env.example`](.env.example) to `.env` and edit. Highlights:

| var                      | default    | purpose                                        |
|--------------------------|------------|------------------------------------------------|
| `HTTP_PORT`              | `80`       | host port → web :80 (redirect)                 |
| `HTTPS_PORT`             | `443`      | host port → web :443 (app)                     |
| `UPSTREAM_TIMEOUT`       | `20`       | backend external-call timeout (s)              |
| `UPSTREAM_CONNECT_TIMEOUT`| `10`      | backend external-call connect timeout (s)      |
| `SCAN_CONCURRENCY`       | `10`       | max concurrent vuln-detail fetches             |
| `SCAN_ERROR_THRESHOLD`   | `25`       | abort a scan after N upstream errors           |
| `CACHE_TTL`              | `3600`     | server-side PURL/CVE cache TTL (s)             |
| `DEFAULT_POLICY`         | `standard` | default shippability policy                    |
| `LOG_LEVEL`              | `info`     | uvicorn / feeds log level                      |
| `USE_FEEDS`              | `true`     | api uses the local mirror (with live-fallback) |
| `USE_OFFLINE_OSV`        | `true`     | api runs offline osv-scanner vs the osv-db mirror (live-fallback) |
| `OSV_CACHE_DIR`          | `/osv-cache` | shared OSV mirror mount point (osv-db volume) |
| `FEEDS_DAILY_AT`         | `03:15`    | daily mirror refresh time (HH:MM)              |
| `NVD_API_KEY`            | _(unset)_  | optional; raises NVD mirror refresh rate       |
| `NVD_INITIAL_MAX_PAGES`  | `0`        | first-run NVD page cap (`0`=full; `2`=demo)    |

Backend variables are passed through to the `api` service via `env_file`; the
mirror tunables (`FEEDS_DAILY_AT`, `NVD_API_KEY`, `NVD_INITIAL_MAX_PAGES`,
`LOG_LEVEL`) reach the `feeds` service the same way. See
[Local vulnerability mirror](#local-vulnerability-mirror-feeds).

---

## Security notes

- **All third-party calls are proxied server-side.** The browser only ever
  talks to the same origin; OSV/cve.org/KEV/EPSS calls (and any secrets/timeouts)
  live in the backend. The `api` service is **not** published to the host — it
  is reachable only over the private `sbom-net` bridge as `api:8000`.
- **Forced HTTPS + HSTS.** All HTTP is redirected to HTTPS; HSTS pins it for
  two years.
- **Security headers** on every response: HSTS, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a
  locked-down `Content-Security-Policy` (`default-src 'self'`; scripts from
  `'self'` only — Chart.js/D3 are npm-bundled by Vite, no CDN; `connect-src
  'self'` for the `/api` calls; `frame-ancestors 'none'`; `object-src 'none'`).
  `server_tokens` is off so the nginx version isn't leaked.
- **TLS** is restricted to TLSv1.2 + TLSv1.3 with a modern cipher suite.
- **Non-root:** the `nginx:1.27-alpine` image runs its worker processes as the
  unprivileged `nginx` user (master starts as root only to bind 80/443, the
  standard nginx model). The `api` image's user is owned by the backend team.
- Certs are **mounted read-only**, not baked into any image, so rotating them
  never requires a rebuild and keys never land in image layers.

---

## CI / CLI gate

CI lives in the repo root [`.github/`](../.github/) (the product lives under
`product/`, so all workflow paths are `product/...`). The
[`ci.yml`](../.github/workflows/ci.yml) workflow runs on every push/PR with
three jobs: **backend** (`pytest` on Python 3.12), **frontend** (`npm ci` →
`typecheck` → `test --if-present` → `build` on Node 22), and **docker**
(`docker compose -f product/docker-compose.yml config` + `build`, no `up`).

### `sbom-scan` — gate a build on an SBOM assessment

The backend ships a CLI (`sbom-scan`, a.k.a. `python -m app.cli`) that parses,
scans, and assesses an SBOM, then exits with a code you can gate on:

| exit | meaning      |
|------|--------------|
| `0`  | **PASS** — no gate triggers hit |
| `1`  | **gate failed** — a `--fail-on` / license-deny rule matched |
| `2`  | **error** — bad input, parse failure, etc. |

Usage:

```
sbom-scan <sbom> [--policy strict|standard|lenient] \
                 [--fail-on kev,critical,high,review] \
                 [--license-deny GPL,AGPL-3.0] \
                 [--format text|json|sarif] [--output FILE]
```

**Run locally (installed):**

```bash
cd product/backend
pip install -r requirements.txt
python -m app.cli sbom.cdx.json --policy standard --fail-on kev,critical
echo "exit: $?"
```

**Run via Docker** (no local Python needed; mount the workspace at `/work`):

```bash
docker build -t sbom-visualizer-cli ./product/backend
docker run --rm -v "$PWD:/work" -w /work sbom-visualizer-cli \
  python -m app.cli sbom.cdx.json \
    --policy standard --fail-on kev,critical \
    --format sarif --output results.sarif
```

Pass `-e NVD_API_KEY=...` to `docker run` (or set it in the environment) for
higher NVD rate limits.

### GitHub Action (reusable gate)

The composite action at
[`.github/actions/sbom-scan`](../.github/actions/sbom-scan/action.yml) builds
the backend image and runs the CLI gate inside it, emitting `results.sarif` for
upload to code scanning. See
[`sbom-gate.example.yml`](../.github/workflows/sbom-gate.example.yml) for a full
example. Minimal usage:

```yaml
permissions:
  contents: read
  security-events: write        # for upload-sarif

steps:
  - uses: actions/checkout@v4
  - id: scan
    uses: ./.github/actions/sbom-scan
    with:
      sbom: sbom.cdx.json        # committed SBOM to gate on
      policy: standard           # strict | standard | lenient
      fail-on: kev,critical      # add high,review to tighten
      # license-deny: "GPL,AGPL-3.0"
      sarif: "true"
    env:
      NVD_API_KEY: ${{ secrets.NVD_API_KEY }}   # optional
  - if: always() && steps.scan.outputs.sarif-file != ''
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

A non-zero gate exit fails the step (and thus the job). The uploaded
`results.sarif` lands in the repo's **Security → Code scanning alerts** tab,
one alert per (component, vulnerability), with severity mapped to SARIF levels.

**Action inputs:** `sbom` (required), `policy` (default `standard`), `fail-on`
(default `kev,critical`), `license-deny` (optional), `sarif` (default `true`).
**Output:** `sarif-file` (path to `results.sarif` when `sarif=true`).
