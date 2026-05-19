# SBOM Visualizer

A single-file HTML tool for analyzing Software Bills of Materials. Drop it in a browser, load an SBOM, and get a full vulnerability scan, license audit, dependency graph, and supplier risk breakdown — no server, no install, no data leaves your machine except for external API calls you trigger.

![License](https://img.shields.io/badge/license-GPL--3.0-blue)

---

## What it does

**Parses** CycloneDX 1.4/1.5, SPDX 2.x, and Syft JSON (schema v16+). Load multiple SBOMs at once and compare them side by side.

**Scans** every component against [OSV.dev](https://osv.dev) using ecosystem-aware queries — distro packages (RPM, DEB, APK) get routed to their correct OSV ecosystem, language packages go via PURL. Arch Linux packages (`pkg:alpm`) are queried by PURL since OSV doesn't maintain a native Arch ecosystem index.

**Enriches** CVE records with authoritative CVSS scores from the [MITRE CVE Services API](https://cveawg.mitre.org) (cve.org) where OSV doesn't carry numeric scores. CVSS 2.0, 3.0, 3.1, and 4.0 base scores are computed locally from the vector string using the full FIRST specification formula — no external calculator needed.

**Overlays** the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog on scan results, flagging confirmed in-the-wild exploits with BOD 22-01 remediation context.

---

## Views

| View | What you see |
|---|---|
| **Overview** | Risk score, severity breakdown, top vulnerabilities, license summary |
| **Components** | Searchable, sortable component table with CVSS inline |
| **Licenses** | License distribution, copyleft flags, SPDX identifiers |
| **Dependencies** | Dependency relationships parsed from the SBOM |
| **Vulnerabilities** | Full CVE list with CVSS scores, vectors, KEV badges, descriptions |
| **Compare** | Diff two loaded SBOMs — added, removed, and changed components |
| **Completeness** | NTIA minimum elements score per component |
| **Dep Graph** | D3 force-directed dependency graph with zoom, drag, and node highlight |
| **Suppliers** | Components grouped by vendor/supplier with per-supplier risk scores |
| **Vuln Paths** | Transitive reachability chains — "A → B → vulnerable-lib" |

---

## Supported SBOM formats

| Format | Versions |
|---|---|
| CycloneDX | 1.4, 1.5 |
| SPDX | 2.2, 2.3 |
| Syft JSON | Schema v16+ |

Multi-file loading supported. Drag and drop or file picker.

---

## Vulnerability scanning

Scanning runs in four phases:

1. **Batch query** — all components queried against OSV.dev `/v1/querybatch` in chunks of 100
2. **Hydration** — unique vuln IDs fetched in full from OSV.dev `/v1/vulns/{id}` (10 concurrent)
3. **CVE enrichment** — for any CVE-aliased vuln still missing a numeric score, fetches from `cveawg.mitre.org/api/cve/{id}` (8 concurrent, silent on CORS failure)
4. **KEV overlay** — optional load of the CISA KEV JSON feed; flags matching CVEs with exploit status and BOD 22-01 deadline context

### Ecosystem routing

| PURL scheme | OSV query method |
|---|---|
| `pkg:npm`, `pkg:pypi`, `pkg:maven`, `pkg:cargo`, `pkg:gem`, `pkg:nuget`, `pkg:golang` | PURL |
| `pkg:rpm` (amzn, rhel, fedora, sles, rocky, alma, oracle) | Name + version + ecosystem |
| `pkg:deb` | Name + version + Ubuntu or Debian |
| `pkg:apk` | Name + version + Alpine |
| `pkg:alpm` (Arch Linux) | PURL (OSV has no native Arch ecosystem) |
| `pkg:oci` | Skipped |

### CVSS scoring

Scores are computed locally from the vector string using the FIRST CVSS 3.1 base score formula. Severity buckets follow the official thresholds: Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low >0.0. CVSS 2.0 base scores are also computed. When the cve.org enrichment phase runs, authoritative CNA-supplied scores from `containers.cna.metrics` and the CISA ADP container (`containers.adp`) take precedence.

---

## Exports

- **Components CSV** — name, version, type, license, supplier, PURL, vuln count, top severity
- **Vulnerabilities CSV** — CVE ID, OSV ID, severity, CVSS score, vector, KEV flag, description
- **HTML report** — self-contained shareable report with full findings table
- **Normalized JSON** — parsed SBOM in a consistent internal schema regardless of input format

---

## Other features

- **Multi-SBOM compare** — diff two SBOMs by PURL or name@version key; shows added, removed, and changed components with version delta
- **NTIA completeness scoring** — checks all 7 NTIA minimum elements (name, version, supplier, unique ID, dependency relationships, author, timestamp) per component
- **Supplier/vendor pivot** — groups components by supplier with per-vendor vuln counts and risk scores; click to expand full component table
- **Transitive vuln paths** — BFS reverse-adjacency walk from each vulnerable component back to root nodes; shows reachability chains up to depth 8
- **D3 dependency graph** — force-directed layout with three color modes, zoom, drag, and click-to-highlight
- **Global search** — `⌘K` or `/` to search across all components, vulnerabilities, and licenses
- **Keyboard shortcuts** — `1`–`8` to switch views, `Tab` to cycle, `Escape` to close
- **Session persistence** — loaded files and scan results survive a page refresh via `localStorage`
- **Risk scoring** — composite score per SBOM: CRITICAL×10, HIGH×5, MEDIUM×2, LOW×1, KEV hit×15, copyleft/unlicensed penalties

---

## Sample SBOMs

Need an SBOM to test with? The [anchore/sbom-examples](https://github.com/anchore/sbom-examples?tab=readme-ov-file) repository has a curated collection of CycloneDX and SPDX files across a range of real-world container images and package ecosystems — ready to drop straight into the tool.

## Usage

```
# No install. Just open the file.
open sbom-visualizer.html
```

Or serve it locally if you prefer:

```bash
python3 -m http.server 8080
# then open http://localhost:8080/sbom-visualizer.html
```

Load an SBOM by dragging it onto the drop zone or using the file picker. Click **Scan for Vulnerabilities** to run the OSV query pipeline. Optionally load the CISA KEV feed from the Vulnerabilities view.

---

## Privacy

All SBOM parsing happens locally in your browser. The only outbound calls are:

- `api.osv.dev` — vulnerability queries (package names, versions, PURLs)
- `cveawg.mitre.org` — CVSS score enrichment for CVE-aliased findings
- `www.cisa.gov` — KEV feed download (only when you click "Load KEV Feed")

No telemetry. No analytics. No account required.

---

## Known limitations

- **Arch Linux (`pkg:alpm`)** — OSV does not maintain a native Arch Linux ecosystem index. PURL-based queries will surface upstream CVEs for packages like `curl` and `openssl` but will miss Arch-specific advisories published at [security.archlinux.org](https://security.archlinux.org).
- **cve.org enrichment** — `cveawg.mitre.org` is a public read endpoint but CORS headers from browser context are not guaranteed. Enrichment failures are silent; OSV-computed scores are used as fallback.
- **Large SBOMs** — SBOMs with thousands of components will hit OSV rate limits. The scanner batches queries at 100 per request with a 3-error abort threshold.
- **Dependency graphs** — transitive path tracing requires relationship data in the SBOM (`dependsOn` in CycloneDX, `DEPENDS_ON` in SPDX, `artifactRelationships` in Syft). SBOMs generated without relationship data will show components as direct dependencies only.

---

## Tech stack

Built as a single self-contained HTML file with no build step and no npm.

- [Chart.js 4.4](https://www.chartjs.org) — overview charts
- [D3 7.8](https://d3js.org) — dependency graph
- [Tabler Icons](https://tabler.io/icons) — UI icons
- [OSV.dev API](https://osv.dev/docs/) — vulnerability data
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — exploit status
- [MITRE CVE Services](https://cveawg.mitre.org) — authoritative CVSS scores

---

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
