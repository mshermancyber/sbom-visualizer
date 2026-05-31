# SBOM Visualizer — User Guide

**Audience:** Security engineers and developers assessing software bills of materials.

---

## 1. Quick Start

```bash
# Clone the repo, generate certs, and start the stack
make up
```

`make up` runs `certs/generate-certs.sh` (self-signed, idempotent) then `docker compose up -d --build`. The stack starts three services: `api` (FastAPI, port 8000 internal), `feeds` (local KEV/EPSS/NVD mirror, port 9000 internal), and `web` (nginx TLS proxy, ports 80 HTTP and 443 HTTPS by default).

Visit `https://localhost` and accept the self-signed certificate warning. HTTP on port 80 redirects to HTTPS automatically.

Alternatively, without Make:

```bash
docker compose up -d --build
```

---

## 2. Loading an SBOM

Five input methods are supported. All land in the same internal schema before any view is shown.

### File upload
Drag a `.json` file onto the drop zone, or click the file picker. Accepted formats: CycloneDX 1.4/1.5 JSON, SPDX 2.2/2.3 JSON, Syft JSON (schema v16+). Format is detected automatically from the `bomFormat` field (CycloneDX), `spdxVersion`/`SPDXID`/`packages` fields (SPDX), or `artifacts`+`source` structure (Syft). No other file formats are accepted.

### Paste JSON
Click **Paste JSON** in the top bar, paste raw SBOM JSON into the modal, and confirm. Useful when the SBOM is on the clipboard but not saved as a file.

### Fetch from URL
Enter a public HTTPS (or HTTP) URL pointing to a hosted SBOM JSON. The backend fetches it server-side (SSRF-guarded: loopback, link-local, and private IP ranges are blocked). The URL must resolve to a valid SBOM JSON and must not exceed 25 MB.

### Load sample SBOM
Click **Load sample SBOM** to load a built-in demonstration SBOM. Useful for exploring views without your own file.

### `?sbom=<url>` query parameter
Append `?sbom=<encoded-url>` to the application URL. The SBOM at that URL is fetched and parsed automatically on page load. This creates a shareable, one-click assessment link. Example:

```
https://localhost/?sbom=https%3A%2F%2Fexample.com%2Fsbom.json
```

### Multi-SBOM support
The **Compare** view accepts two independently-loaded SBOMs (A and B). Each is loaded separately using any of the above methods. See [Section 9](#9-compare-view).

---

## 3. Running a Scan

After an SBOM is loaded, click **Scan for Vulnerabilities** in the Overview. The scan pipeline runs entirely server-side and, by default, entirely against a **local mirror** of every data source — no live calls are made on the hot path:

1. **OSV** — the primary vulnerability discovery step (PURL + version-range matching). The backend runs the bundled **osv-scanner v2.3.8** binary in `--offline-vulnerabilities` mode against the locally mirrored OSV database (the full database, all 45 ecosystems). osv-scanner only loads the zips for ecosystems actually present in your SBOM, so most scans complete in well under a second. An npm-heavy SBOM pays a one-time ~7 s load for the large npm zip.
2. **NVD / CVSS / CWE** — sourced from the locally mirrored CVEProject **cvelistV5** archive (~354k CVE records, CVE Record 5.x schema). Supplies CVSS v2/v3.x/v4.0 scores, CWE categories, and references. No API key required.
3. **CISA KEV** — the Known Exploited Vulnerabilities catalog (~1,607 CVEs), mirrored locally, overlaid on all findings.
4. **EPSS (FIRST.org)** — exploitation-probability score and percentile (~336k CVEs), mirrored locally, attached to each finding.
5. **MITRE / cve.org** — the one remaining live source: a non-blocking enrichment top-up via `cveawg.mitre.org`. Because KEV, EPSS, and NVD already supply CVSS and CWE from the mirror, this step is optional and never blocks the result.

All four mirrored sources (OSV, NVD, KEV, EPSS) are refreshed daily by the feeds service (see [Section 8](#8-data-sources-panel)). If the mirror is not yet populated or is unreachable, the backend automatically falls back to live upstreams for that source.

Behind the scenes, KEV + EPSS + NVD enrichment is served by a single pre-built lookup table: at scan time the backend makes **one** batch lookup to peg every CVE with its KEV flag/due-date, EPSS score/percentile, and NVD CVSS/CWE data, instead of three separate calls. This is transparent — you only notice that scans are fast.

Progress is shown inline. When the scan finishes, all views update automatically.

**Large SBOMs (async):** SBOMs with **200 or more components** are routed to an asynchronous scan job that survives request timeouts; the UI polls for completion and updates when the result is ready. Smaller SBOMs run synchronously. This is automatic and requires no action.

**Re-scan:** Click **Re-scan** at any time to re-run the full pipeline against the same SBOM (results are cached for 6 hours by default; re-scan bypasses the cache).

**Recent Scans:** Every completed scan is persisted server-side (gzip-compressed JSON in SQLite). The **Recent Scans** section in the sidebar lists past scans and lets you reload one after a page refresh, so you do not lose a result by reloading the tab.

---

## 4. Reading the Verdict

The verdict banner at the top of the Overview shows one of three outcomes:

| Verdict | Meaning |
|---------|---------|
| **PASS** | No findings that trigger the active policy. The SBOM may still have low/medium findings. |
| **REVIEW** | Findings present that warrant human review before shipping. |
| **FAIL** | Findings that the active policy treats as blocking. Do not ship without remediation. |

### Policies

Three gate policies are selectable (default: **Standard**):

| Policy | FAIL on | REVIEW on |
|--------|---------|-----------|
| **Strict** | MAL, KEV, CRITICAL, HIGH | MEDIUM |
| **Standard** | MAL, KEV, CRITICAL | HIGH, MEDIUM |
| **Lenient** | MAL, KEV only | CRITICAL, HIGH |

### Signal annotations

When specific high-priority signals are present, the verdict banner prepends clear annotations so you can act without reading the full findings table:

- `☠ MALICIOUS PACKAGE — N known-malicious finding(s): CVE-IDs` — OSV-detected malicious packages. FAIL under all policies.
- `⚡ ACTIVE EXPLOITATION — N CVE(s) confirmed in-the-wild (CISA KEV): CVE-IDs` — Confirmed active exploitation per CISA. FAIL under all policies.
- `🔥 HIGH EXPLOIT RISK — N CVE(s) at ≥95th EPSS percentile (top: X%): CVE-IDs` — In the top 5% of exploitation probability. This is informational; gate impact depends on the selected policy and severity.

---

## 4a. Suppressing Findings (VEX)

Not every finding is relevant to your build. The VEX (Vulnerability Exploitability eXchange) workflow lets you mark a finding as not applicable and exclude it from the score and counts, with an auditable note.

Each vulnerability card has a **Suppress** button. Suppressing a finding records a VEX status:

| Status | Meaning |
|--------|---------|
| `not_affected` | The vulnerable code path is not reachable in this product. |
| `false_positive` | The finding does not actually apply (e.g. wrong package match). |
| `in_triage` | Under investigation; temporarily set aside. |
| `accepted_risk` | A known risk explicitly accepted for this release. |
| `resolved` | Already mitigated outside the SBOM (patch, config, control). |

A suppression carries a free-text **note** and an optional **expiry** date (after which it lapses). Suppressions are persisted server-side (SQLite) and scoped to your project. **Suppressed findings are excluded from all counts and from the risk score**, so the verdict and grade reflect only the findings you still consider live.

---

## 5. Views

Navigate between views using the sidebar. Keyboard shortcuts 1–9 jump to views in order.

### Overview
High-level dashboard: verdict banner, risk ring with score (0–1000) and letter grade (A–F), a coverage strip showing how many components were scannable, stat cards (total components, affected, KEV count, EPSS-flagged count), a donut chart of component types, and a bar chart of top licenses. Start here for a first read of the SBOM.

### Components
Searchable, sortable, paginated table of all components. Click any row to open a detail panel showing the component's PURL, CPE, licenses, supplier, and its full vulnerability list with severity, CVSS score, EPSS percentile, KEV badge, and Fixed-In version. Use this view to investigate a specific package.

### Licenses
License inventory: all distinct licenses found, how many components carry each, copyleft classification, and any policy violations (denied or warned licenses highlighted). Use this view to audit license compliance before shipping.

### Dependencies
Components grouped by out-degree (number of direct dependents). Click a component to see its full dependency list. Useful for understanding which packages are widely used across the SBOM and should be prioritized for remediation.

### Vulnerabilities
Full finding list. Toggle between **by component** (one row per affected component, expandable) and **by vulnerability** (one row per CVE/OSV ID, showing all affected components). Filter by severity, and sort by EPSS or CVSS score. Badges show severity, KEV status, EPSS percentile tier, CWE category, malicious flag, direct vs. transitive depth, and Fixed-In version. Use the group-by toggle to switch perspectives.

### Remediation
Package-level fix list ranked by risk removed. Each row shows the current version, the recommended upgrade target (highest fixed-in version across all resolvable CVEs), how many CVEs are resolved, KEV count, and maximum EPSS percentile. Prioritize packages at the top of this list first; they contribute the most to the risk score.

### Compare
Side-by-side comparison of two SBOMs (A and B). Shows verdict diff (both verdicts and policy), risk score delta, and three component lists: added (in B only), removed (in A only), and changed (same component, different version). Use this view to assess the security impact of an upgrade or diff between build outputs.

### Completeness
NTIA minimum-elements scoring per component. Shows an overall completeness percentage and per-field coverage for: Component Name, Version, Supplier, Unique Identifier (PURL/CPE/bomRef), License, Hash/Checksum, and Dependency Relationship. Also reports CISA recommended fields: Component Type, Description, Language. Use this view to identify gaps before submitting an SBOM to a customer or regulator.

### Dep Graph
Interactive D3 force-directed graph of component dependencies. Zoom and drag to navigate. Click a node to highlight its direct neighbors. Switch between three color modes: component type, vulnerability severity, and license classification. Use this view to understand the structure of a complex dependency tree or trace paths to vulnerable packages.

### Suppliers
Components grouped by vendor/supplier. Each supplier row shows a per-supplier risk score and a collapsible table of that supplier's components with their vulnerability counts. Use this view to identify which vendors contribute the most risk.

### Vuln Paths
Breadth-first reverse-reachability chains from SBOM root components down to vulnerable packages. Shows the shortest path from a root to each vulnerable component through the dependency graph. Use this view to understand whether a vulnerability is directly reachable or buried deep in a transitive chain.

---

## 6. Exports

All exports are available from the sidebar or the top bar after a scan.

| Export | Content | When to use |
|--------|---------|-------------|
| **Components CSV** | All components: name, version, PURL, licenses, supplier, type, depth. Formula-injection-safe (leading `=`, `+`, `-`, `@` prefixed with a tab). | Spreadsheet analysis or reporting. |
| **Vulnerabilities CSV** | All findings: component, CVE/OSV ID, severity, CVSS score, EPSS score + percentile, KEV flag, CWE categories, Fixed-In version, description. | Ticket filing, security reviews, compliance evidence. |
| **SARIF 2.1.0** | Machine-readable findings in SARIF format. One rule per unique vulnerability (with CWE tags and help URI), one result per (component, vulnerability) with severity mapped to SARIF levels (critical/high → error, medium → warning, low/none → note), and Fixed-In, KEV, and EPSS in the message. | Upload to GitHub Security → Code Scanning via `upload-sarif`. Integrates into PR checks. |
| **HTML Report** | Self-contained HTML file with verdict, remediation plan, top CWEs, coverage strip, and component/vulnerability tables. No external dependencies. | Share with stakeholders who do not have access to the tool. Email or attach to a ticket. |
| **Save as PDF** | Print-styled version of the HTML report triggered via the browser's print dialog. | Archiving, compliance documentation, or any context requiring a fixed-layout document. |
| **Normalized JSON** | The SBOM re-emitted in the internal normalized schema (components, dependencies, metadata). | Programmatic downstream processing; consistent schema regardless of input format. |
| **Copy summary** | Copies a plain-text assessment summary (verdict, risk score, key counts) to the clipboard. | Paste into a Slack message, PR description, or Jira ticket. |

---

## 7. License Policy Gate

The license gate lets you configure which licenses block a release and which trigger a warning.

In the scan options or via the CLI `--license-deny` / `--license-warn` flags, provide comma-separated SPDX identifiers or substrings (case-insensitive). For example, `GPL` matches `GPL-2.0-only`, `GPL-3.0-or-later`, and any other license containing "gpl".

- A component with a **denied** license causes a **FAIL** verdict regardless of vulnerability findings.
- A component with a **warned** license causes at least a **REVIEW** verdict.
- Violations appear in the **Licenses** view with deny/warn badges, and the count is included in the verdict reasons (e.g., `3 denied licenses`).

**Example CLI usage:**

```bash
sbom-scan sbom.json --license-deny "GPL,AGPL-3.0" --license-warn "LGPL"
```

---

## 8. Data Sources Panel

The **Sources** panel (accessible from the top bar) shows the status of all five data connectors. Each row reports how it is being served: `offline-mirror`, `mirror`, or `live`.

- **OSV** — the primary discovery source, served by the local offline OSV mirror (osv-scanner v2.3.8) by default; falls back to live `api.osv.dev` if the mirror is not ready.
- **NVD** — served from the local cvelistV5 mirror (~354k CVE records); shows row count and last update. No API key required (`NVD_API_KEY` is fallback-only).
- **FIRST EPSS** — mirror vs. live status and row count (~336k CVEs).
- **CISA KEV** — mirror vs. live status and row count (~1,607 CVEs).
- **MITRE CVE Services (cve.org)** — always live; a non-blocking enrichment top-up.

The feeds service mirrors all four mirrorable sources (OSV, NVD, KEV, EPSS) daily at **03:15 UTC** by default (`FEEDS_DAILY_AT`), wholesale-replacing each feed (no diffing). A startup refresh also runs if any feed is empty or stale (>26 h). On first boot the OSV mirror (~1.2 GB) and the cvelistV5 archive (~588 MB) take a few minutes to download; until each is ready, its source falls back to live. Use `make feeds-status` to inspect mirror state from the command line.

---

## 8a. API Key (multi-user)

When the deployment is configured with a master `API_TOKEN`, an administrator can provision **per-project API keys**. Enter your key in the sidebar **API Key** field; it is stored in `localStorage` and sent as an `Authorization: Bearer <key>` header on every request. Each project key isolates its own scans and suppressions from other projects. If the deployment has no token configured (local development default), the API is open and the field can be left blank.

---

## 9. Compare View

1. Load your first SBOM (the baseline, or "A") using any input method.
2. Open the **Compare** view from the sidebar.
3. Load a second SBOM ("B") using the file picker or URL input in the Compare panel.
4. Both SBOMs are parsed and assessed independently.

The panel shows:
- **Verdict diff**: verdict and policy for A and B side by side, with a risk delta (B score minus A score).
- **Added components**: present in B, not in A.
- **Removed components**: present in A, not in B.
- **Changed components**: same package name in both, different version.

Use this to evaluate whether a dependency update or a new build output improves or worsens the security posture.

---

## 10. Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` or `Cmd/Ctrl+K` | Focus global search |
| `?` | Toggle shortcut help overlay |
| `g` | Jump to Dep Graph view |
| `v` | Jump to Vulnerabilities view |
| `t` | Toggle light/dark theme |
| `Esc` | Close help overlay, search, or detail panel |
| `1` | Switch to Overview |
| `2` | Switch to Components |
| `3` | Switch to Licenses |
| `4` | Switch to Dependencies |
| `5` | Switch to Vulnerabilities |
| `6` | Switch to Remediation |
| `7` | Switch to Compare |
| `8` | Switch to Completeness |
| `9` | Switch to Dep Graph |

---

## 11. CLI Gate (`sbom-scan`)

`sbom-scan` runs the same parse → scan → assess pipeline as the web UI without starting an HTTP server. Designed for CI pipeline use.

```
sbom-scan <SBOM_PATH|-> [--policy strict|standard|lenient]
          [--fail-on kev,mal,critical,high,medium,low,review]
          [--license-deny GPL,AGPL] [--license-warn LGPL]
          [--format text|json|sarif] [--output FILE]
          [--no-nvd] [--no-epss] [-v|-vv|-q]
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | PASS — gate passed |
| `1` | Gate failed (FAIL verdict, or REVIEW when `--fail-on review` is set, or denied license) |
| `2` | Runtime error (bad input, parse failure, network error) |

**Examples:**

```bash
# Standard gate, text output to stdout
sbom-scan sbom.cdx.json

# Strict gate, emit SARIF for GitHub code scanning
sbom-scan sbom.cdx.json --policy strict --format sarif --output results.sarif

# Fail on KEV and critical; deny GPL licenses; JSON output
sbom-scan sbom.cdx.json --fail-on kev,critical --license-deny GPL --format json

# Read from stdin
cat sbom.spdx.json | sbom-scan -
```

---

## 12. Tips

**Debug logging in the browser**

Append `?debug=debug` to the URL to enable verbose frontend logging to the browser console. All API calls, cache events, and timing information are logged. The level persists in `localStorage`; remove it by navigating to the URL without the param or clearing site data.

**Theme toggle**

Press `t` or use the theme button in the top bar to switch between light and dark modes. The preference is persisted across sessions.

**Shareable assessment links**

Pass any publicly reachable SBOM URL as a query parameter to pre-load it:

```
https://localhost/?sbom=https%3A%2F%2Fraw.githubusercontent.com%2F.../sbom.cdx.json
```

The SBOM is fetched and parsed on page load. Share this URL with a reviewer to give them immediate context.

**Feeds mirror warm-up**

On first deploy, the NVD mirror crawl takes several minutes. KEV and EPSS are available sooner. Until each feed is marked `ready`, the scanner falls back to live upstream queries; no manual intervention is required. Monitor progress with:

```bash
make feeds-status
```

To force an immediate refresh:

```bash
make feeds-refresh
```
