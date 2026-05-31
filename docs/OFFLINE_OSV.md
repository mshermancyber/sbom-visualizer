# Offline OSV mirror — contract (frozen)

Adds OSV (the primary vulnerability-discovery source) to the local mirror set so scans
can run fully air-gapped. Uses the **official `osv-scanner` v2.3.8 binary** in offline mode
against a locally-mirrored copy of the entire OSV database, refreshed daily by the feeds
scheduler.

## Verified facts (do not re-investigate)
- Binary: `https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_linux_amd64` (~20MB static).
- Offline DB cache layout: **`$XDG_CACHE_HOME/osv-scanner/<ECOSYSTEM>/all.zip`**
  (e.g. `/osv-cache/osv-scanner/npm/all.zip`, `/osv-cache/osv-scanner/Maven/all.zip`).
- OSV public bucket: `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`
  (ecosystem list at `.../ecosystems.txt`, 45 ecosystems, full set ~1.2 GB).
  Per-ecosystem examples: npm 196MB, PyPI 23MB, Maven 8.9MB, Go 8.4MB, Packagist 8.8MB.
- Run: `XDG_CACHE_HOME=/osv-cache osv-scanner scan --offline-vulnerabilities --format json <SBOM.cdx.json>`
  - `--offline-vulnerabilities` = use cached DBs, no network. (Do NOT pass `--download-offline-databases` at scan time; feeds owns downloads.)
  - **Exit code 0 = no vulns, 1 = vulns FOUND (success), anything else = real error.**
  - Accepts a CycloneDX (or SPDX) SBOM file path directly.
- Output JSON shape:
  ```
  results[].packages[].package = {name, version, ecosystem}
  results[].packages[].vulnerabilities[] = standard OSV records
       (id, aliases, affected, severity, database_specific, details, references, published, modified)
  results[].packages[].groups[] = dedup info (ignore; we aggregate ourselves)
  ```
  The vulnerability records are standard OSV JSON → parse with the EXISTING `parse_osv_vuln`.

## Shared volume
Named volume **`osv-db`** mounted at **`/osv-cache`**:
- `feeds` service: read-write (it populates the DB).
- `api` service: read-only (it runs osv-scanner against it).
Files live at `/osv-cache/osv-scanner/<ECOSYSTEM>/all.zip`.

## feeds responsibilities (daily scheduler — "full copy daily")
- New refresh task `osv` (alongside kev/epss/nvd): fetch `ecosystems.txt`, then for EACH ecosystem
  curl `<bucket>/<urlencoded-ecosystem>/all.zip` → write to `/osv-cache/osv-scanner/<ecosystem>/all.zip`.
  Download to a temp file then atomic-rename so a scan never reads a half-written zip.
  Wholesale (overwrite) daily. The on-disk directory name is the literal ecosystem string.
- Report `osv` in `GET /feeds/status` like the others: status ready/refreshing/empty/error,
  rowCount = number of ecosystem zips present, detail = total size + last update.
- Honor `OSV_CACHE_DIR` env (default `/osv-cache`). Runs in the existing daily refresh + startup-if-stale.

## api responsibilities (offline-OSV discovery path)
- Dockerfile installs the osv-scanner v2.3.8 binary at `/usr/local/bin/osv-scanner`.
- New config: `USE_OFFLINE_OSV` (default `true`), `OSV_CACHE_DIR` (default `/osv-cache`), `OSV_SCANNER_BIN` (default `osv-scanner`).
- In `scanner.py`, the OSV discovery phase: when `USE_OFFLINE_OSV` and the cache dir is non-empty,
  write the normalized SBOM to a temp CycloneDX 1.5 file, run osv-scanner offline, parse
  `results[].packages[].vulnerabilities[]` per package, map each package back to our component
  (by purl, else name+version), build the per-component findings using `parse_osv_vuln` on each record.
  This REPLACES the live querybatch+hydrate phases for OSV when offline is active.
- **Fallback to live `api.osv.dev`** (existing querybatch+hydrate path) if: USE_OFFLINE_OSV is off,
  the binary is missing, the cache dir is empty, or osv-scanner exits with a non-{0,1} code.
  Log which path was used (`osv [offline-mirror]` vs `osv [live]`).
- cve.org/NVD/EPSS/KEV enrichment runs unchanged on top of the discovered findings.
- `GET /api/sources`: report osv `servedBy` = `offline-mirror` (with ecosystem count + updatedAt from
  /feeds/status) vs `live`.
