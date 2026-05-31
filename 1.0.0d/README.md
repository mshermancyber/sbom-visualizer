# SBOM Visualizer — v1.0-d (demo)

A single self-contained HTML file for **quick, one-shot security assessment of a Software Bill of Materials**. Open it in a browser, load an SBOM, and get an instant go/no-go read: vulnerabilities, exploit signals, a prioritized fix list, and a shippability verdict — no install, no server, no build step.

> **Demo build** (`1.0-d`). Everything runs client-side; the only outbound calls are the vulnerability lookups you trigger.

## Run it

```bash
# Just open the file:
open sbom-visualizer-1.0-d.html
# …or serve locally:
python3 -m http.server 8080   # then visit http://localhost:8080/sbom-visualizer-1.0-d.html
```

**Fastest demo:** click **Load sample SBOM** → **Scan via OSV.dev**. The bundled sample surfaces real findings (including Log4Shell, which is in CISA KEV) so every view has something to show — no file needed.

## What it does

- **Parses** CycloneDX 1.4/1.5, SPDX 2.x, and Syft JSON — drag-drop, file picker, **paste JSON**, or **fetch from URL**.
- **Scans** every component against [OSV.dev](https://osv.dev) (no key, no proxy) with ecosystem-aware PURL/distro routing.
- **Scores** CVSS v2/v3.0/v3.1 locally from the vector; enriches missing scores + CWEs from cve.org.
- **Verdict** — a **PASS / REVIEW / FAIL** shippability gate (Strict / Standard / Lenient presets).

## What's new in this build

- **Shippability verdict / gate** — instant go/no-go banner with a configurable policy.
- **Remediation plan** — package-level fix list ranked by risk removed (`log4j-core 2.14.1 → 2.17.1 — resolves 7 CVEs incl. 1 KEV`).
- **EPSS scores** — exploitation-probability percentile (FIRST.org), alongside the CISA **KEV** overlay.
- **Malicious-package alarm** — flags OSV `MAL-` advisories (typosquats / compromised releases) above everything.
- **CWE weakness breakdown** — top weakness types plus per-finding CWE chips.
- **Direct-vs-transitive flag** — shows whether a vulnerable package is yours to fix or buried upstream.
- **Coverage / blind-spot panel** — "N of M components scannable, K skipped" so a PASS is never misread.
- **Fixed-in versions** — the exact version to upgrade to, per finding.
- **Low-friction input** — paste-JSON modal + fetch-from-URL.
- **Copy assessment summary** — one-click text summary for Slack / a PR / a ticket.
- **Enriched report / PDF** — exported HTML report and Save-as-PDF now include the verdict, malicious alarm, remediation table, CWE breakdown, fixed-in + direct/transitive columns, and coverage line.
- **Light/dark theme**, `?` keyboard-shortcut overlay, and full keyboard navigation.

## Views

Overview · Components · Licenses · Dependencies · Vulnerabilities · **Remediation** · Compare · Completeness (NTIA) · Dep Graph · Suppliers · Vuln Paths

## Exports

Components CSV · Vulnerabilities CSV (with EPSS, Fixed-In, CWE) · Self-contained HTML report · Save as PDF · Normalized JSON · Copy summary

## Privacy

All parsing is local. Outbound calls only when you trigger them: `api.osv.dev` (vuln queries), `cveawg.mitre.org` (CVSS/CWE enrichment), `api.first.org` (EPSS), `www.cisa.gov` (KEV feed). No telemetry, no account.

## License

GPL-3.0 — see [LICENSE](LICENSE).
