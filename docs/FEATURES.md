# SBOM Visualizer — Feature Manifest

Authoritative inventory of capabilities carried into the productized (dockerized) build,
rebaselined from the single-file demo (`1.0-d`). Each item notes where it lives in the new
architecture: **BE** = Python/FastAPI backend, **FE** = TypeScript frontend, **INFRA** = nginx/compose.

---

## 1. Ingest & parsing
| # | Feature | Layer |
|---|---|---|
| 1.1 | Parse **CycloneDX** 1.4 / 1.5 | BE |
| 1.2 | Parse **SPDX** 2.2 / 2.3 (incl. distro inference from namespace/creators) | BE |
| 1.3 | Parse **Syft JSON** (schema v16+) | BE |
| 1.4 | Auto **format detection** | BE |
| 1.5 | Normalize all formats to one internal schema (components, dependencies, metadata) | BE |
| 1.6 | Multi-SBOM load (compare two) | BE/FE |
| 1.7 | Inputs: file upload, **paste JSON**, **fetch-from-URL** | FE→BE |
| 1.8 | Built-in **sample SBOM** for instant demo | FE |

## 2. Vulnerability scanning
| # | Feature | Layer |
|---|---|---|
| 2.1 | **Offline OSV** primary discovery — bundled **osv-scanner v2.3.8** `--offline-vulnerabilities` against the full local OSV mirror (all 45 ecosystems); default `USE_OFFLINE_OSV=true`, `OSV_OFFLINE_MIN_COMPONENTS=0` (always offline) | BE |
| 2.2 | **Live OSV fallback** — automatic when the mirror is not ready; optional speed router (`OSV_OFFLINE_MIN_COMPONENTS`>0) routes tiny SBOMs to live OSV (`/v1/querybatch`, detail hydration concurrency-capped) | BE |
| 2.3 | Ecosystem-aware routing: PURL for lang ecosystems; name+version+ecosystem for rpm/deb/apk; PURL for `pkg:alpm`; skip `pkg:oci` | BE |
| 2.4 | RPM epoch stripping, golang pseudo-version skipping | BE |
| 2.5 | **NVD / CVSS / CWE** from the local **cvelistV5** mirror (~354k CVE Record 5.x records) — CVSS v2/3.x/4.0 + CWE + refs; no API key needed (`NVD_API_KEY` is live-fallback only) | BE |
| 2.6 | **CISA KEV** overlay (known-exploited flagging), local mirror | BE |
| 2.7 | **EPSS** exploitation-probability score + percentile (FIRST.org), local mirror | BE |
| 2.8 | **MITRE / cve.org** enrichment (`cveawg.mitre.org`) — the one live, non-blocking CVSS/CWE top-up | BE |
| 2.9 | **Pre-enriched lookup** — feeds builds a denormalized `cve_enriched` table daily; api does ONE `POST /feeds/enriched` batch lookup per scan instead of three KEV/EPSS/NVD calls (graceful fallback to 3-call, then live) | BE |
| 2.10 | **Score provenance** (`scoreSource`: osv/ghsa/mitre/nvd) + `GET /api/sources` connector status with `servedBy` (offline-mirror/mirror/live); per-source toggles | BE/FE |
| 2.11 | Server-side scan-result **caching** (6 h TTL) | BE |
| 2.12 | Error-threshold abort, per-request timeouts, graceful degradation | BE |
| 2.13 | **Async scan jobs** — SBOMs ≥ 200 components route to `POST /api/scan/async` + polling so big scans survive timeouts; smaller scans run synchronously | BE/FE |
| 2.14 | **Daily feeds mirror** — APScheduler refreshes OSV/NVD/EPSS/KEV at `FEEDS_DAILY_AT` (03:15) + startup refresh if stale (>26 h); wholesale replace | BE |

## 3. CVSS scoring
| # | Feature | Layer |
|---|---|---|
| 3.1 | Local CVSS **v3.1 / v3.0** base score from vector (FIRST formula) | BE |
| 3.2 | Local CVSS **v2.0** base score | BE |
| 3.3 | Multi-layer severity resolution (db_specific → ecosystem_specific → vector → GHSA cvss) | BE |
| 3.4 | Prefer the highest *computable* CVSS version (never let v4 shadow a scorable v3) | BE |
| 3.5 | Severity bucketing (Critical/High/Medium/Low/None) | BE |

## 4. Assessment & prioritization
| # | Feature | Layer |
|---|---|---|
| 4.1 | **Shippability verdict / gate** — PASS / REVIEW / FAIL, policies Strict/Standard/Lenient + license-policy gate | BE |
| 4.2 | **Verdict signal annotations** — verdict reasons prepended with `☠ MALICIOUS PACKAGE`, `⚡ ACTIVE EXPLOITATION (CISA KEV)`, `🔥 HIGH EXPLOIT RISK (≥95th EPSS)` | BE |
| 4.3 | **Remediation plan** — package-level fixes ranked by `riskRemoved` (same v2 per-CVE scoring, normalized to the 0–1000 scale); "fixed-in" target version | BE |
| 4.4 | **Risk score v2** — per-CVE `cvss_base_pts × epss_amplifier × age_decay`, summed + license penalties, normalized to 0–1000 (ceiling 2000); KEV amplifier 5.0× + KEV floor (≥250 pts/finding, grade ≥ D); grade A/B/C/D/F | BE |
| 4.5 | **VEX / finding suppression** — mark findings not_affected/false_positive/in_triage/accepted_risk/resolved with note + optional expiry; persisted (SQLite); suppressed findings excluded from counts/score | BE/FE |
| 4.6 | **Malicious-package alarm** — OSV `MAL-` detection | BE |
| 4.7 | **CWE weakness breakdown** — top weakness types + per-finding chips | BE |
| 4.8 | **Direct-vs-transitive** classification from the dependency graph | BE |
| 4.9 | **Coverage / blind-spot** metric (scannable vs skipped + reasons) | BE |
| 4.10 | **NTIA minimum-elements completeness** + CISA recommended fields | BE |
| 4.11 | **Fixed-in versions** per finding (semver-aware version compare) | BE |
| 4.12 | Per-supplier risk pivot (group by vendor, per-supplier risk) | BE/FE |
| 4.13 | **Transitive vuln paths** (BFS reverse-reachability to roots) | BE |
| 4.14 | **Scan-result persistence** — every scan stored (SQLite, gzip JSON); "Recent Scans" sidebar reloads past scans after a refresh | BE/FE |
| 4.15 | **Multi-user / API keys** — optional per-project keys (admin-provisioned via master `API_TOKEN`); sidebar field stores key in localStorage, sends `Authorization: Bearer`; per-project isolation of scans + suppressions | BE/FE |

## 5. Views (frontend)
Overview · Components · Licenses · Dependencies · Vulnerabilities · **Remediation** · Compare · Completeness · **Dep Graph (D3)** · Suppliers · Vuln Paths — all **FE**.

## 6. UX
| # | Feature | Layer |
|---|---|---|
| 6.1 | Global search (components / CVEs / licenses) | FE |
| 6.2 | Light / dark theme (persisted) | FE |
| 6.3 | Keyboard shortcuts + `?` help overlay | FE |
| 6.4 | Searchable/sortable/paginated component table | FE |
| 6.5 | Chart.js charts; D3 force-directed dependency graph (zoom/drag/highlight, 3 color modes) | FE |
| 6.6 | Toasts, detail panels, severity/depth/KEV/EPSS/CWE/malicious badges | FE |

## 7. Exports
| # | Feature | Layer |
|---|---|---|
| 7.1 | Components CSV (formula-injection-safe) | FE |
| 7.2 | Vulnerabilities CSV (incl. EPSS, Fixed-In, CWE, KEV) | FE |
| 7.3 | Self-contained **HTML report** (verdict, malicious, remediation, CWE, coverage) | FE/BE |
| 7.4 | **Save as PDF** (print-styled report; opens in a new window and prints — requires browser popups) | FE |
| 7.5 | Normalized JSON | BE |
| 7.6 | **Copy assessment summary** to clipboard | FE |

## 8. Security posture (carried from hardening passes)
- Output encoding everywhere (HTML / JS-string / URL contexts); scheme-allowlisted links; `rel=noopener`.
- Prototype-pollution-safe maps on untrusted keys.
- Defensive guards on external API shapes.
- CSV formula-injection neutralization.
- **New in product:** all third-party calls proxied server-side (no secrets in browser, centralized timeouts/caching), nginx security headers (HSTS, X-Frame-Options DENY, nosniff, no-referrer, CSP `*-src 'self'`), forced HTTPS, non-root containers, internal-only api/feeds, SSRF guard on URL fetch, optional master API token + per-project API keys + per-IP rate limit + body-size cap.

---

## 9. Backlog (carried forward)

### Shipped earlier (1.1) ✅
- ✅ **NVD connector** + multi-source enrichment with score provenance + `/api/sources` status.
- ✅ **License-policy gate** — deny/warn lists folded into the verdict (deny→FAIL, warn→REVIEW), violations surfaced in the Licenses view.
- ✅ **SARIF 2.1.0 export** — `/api/export/sarif` + sidebar button (GitHub code-scanning compatible).
- ✅ **Registry deep links** — component → npm/PyPI/Maven/crates/RubyGems/NuGet/Go/Packagist from PURL.
- ✅ **Auto-load via `?sbom=<url>`** — shareable one-click assessment links.
- ✅ **Verdict diff in Compare** — A-vs-B verdict/risk side by side.
- ✅ **Offline mode** — self-hosted assets (icons/fonts bundled, no CDN); CSP `*-src 'self'`.

### Shipped since ✅
- ✅ **Fully offline / air-gapped data plane** — all four mirrorable sources (OSV, NVD/cvelistV5, EPSS, KEV) mirrored locally; default scan makes no live calls. osv-scanner v2.3.8 offline discovery.
- ✅ **Pre-enriched `cve_enriched` table** — one batch lookup per scan replaces three KEV/EPSS/NVD calls.
- ✅ **Scoring model v2** — continuous CVSS base × EPSS amplifier × age decay, KEV floor, 0–1000 normalization.
- ✅ **Verdict signal annotations** — ☠ malicious / ⚡ KEV / 🔥 high-EPSS prepended to verdict reasons.
- ✅ **VEX / finding suppression** — persisted, scoped per project, excluded from counts/score (`/api/vex/*`).
- ✅ **Scan-result persistence + Recent Scans** — every scan stored (SQLite, gzip JSON), reloadable after refresh (`/api/scans`).
- ✅ **Async scan jobs** — SBOMs ≥ 200 components run via `/api/scan/async` + polling.
- ✅ **Multi-user / API keys** — admin-provisioned per-project keys; per-project isolation (`/api/admin/keys`).

### Candidate functional expansions (backlogged — not built)
These change *what the product can do* (vs polish). Reviewed and deferred:
- **Policy-as-code file** — a committed `.sbom-visualizer.yml` (gate thresholds, license deny/allow, CVE/VEX allowlist) read by the CLI/CI instead of flags. Standard for the category (trivy/grype); cheapest high-value CI-adoption add. Small–medium effort.
- **SBOM generation** — point at a container image or source/git directory → generate the SBOM server-side (syft/trivy/osv-scanner) → assess. Removes the "must already have an SBOM" barrier; biggest audience expansion. Medium–large effort.
- **Attestation / signature verification** — verify cosign / in-toto / SLSA provenance on the SBOM before trusting it. Closes the supply-chain-integrity gap; compliance value (EO 14028, SLSA). Medium effort.

### Probably not worth it (recorded for completeness)
- **Function-level reachability** ("is the vulnerable code actually called?") — per-language static analysis; a huge separate project. Only if it becomes the product's thesis.
- **Fleet/portfolio dashboards, trend lines, SLA tracking** — drifts into longitudinal/posture-over-time, which is deliberately out of scope for a point-in-time tool.

### Nice-to-haves (polish, not new capability)
- SPDX 3.0 / CycloneDX 1.6 parsing
- "Explain this score" tooltip (show the EPSS × KEV × age math per finding)
- CycloneDX-VEX *output* export (we consume VEX; could also emit it)
- Cross-SBOM global search
- Slack / webhook notification on a FAIL verdict
- Richer dep-graph (clustering, in-graph search)

### Lower priority / cleanup (still open)
- **OSV querybatch pagination** (`next_page_token`) for packages with 1000+ advisories (live path only; offline osv-scanner path is unaffected).
- **CVSS v4 local base-score** (MacroVector) — currently via the `cvss` Python library.

> Note on scope: VEX suppression and scan persistence were previously listed as out of scope for a point-in-time tool. They are now shipped as **point-in-time, per-project** features (suppressions refine a single assessment; persistence is reload-after-refresh convenience), not as longitudinal posture-over-time / SLA tracking, which remains out of scope.

---

## 10. Productization deltas (demo → 1.0)
- **Backend (Python/FastAPI):** parsing, scanning, enrichment, scoring, and assessment move server-side. Solves browser CORS, centralizes timeouts/caching, enables API consumers (CI).
- **Frontend (TypeScript/Vite):** the 4.5k-line single file is decomposed into typed modules + a thin renderer that consumes the backend API. No business logic duplicated client-side.
- **nginx:** TLS termination, HTTP→HTTPS redirect, security headers, static asset serving, `/api` reverse proxy.
- **feeds service:** Python/FastAPI + APScheduler sidecar that mirrors OSV/NVD/EPSS/KEV to local SQLite + the `osv-db` volume daily and serves the pre-enriched `cve_enriched` lookup to the api — enabling offline / air-gapped operation.
- **Docker Compose:** reproducible 3-service stack (`web` + `api` + `feeds`) over three named volumes (`feeds-data`, `api-data`, `osv-db`); self-signed certs for local, swappable for real certs/Let's Encrypt.
