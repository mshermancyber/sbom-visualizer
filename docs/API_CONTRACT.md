# API Contract — v1 (frozen)

Backend base path: `/api`. All requests/responses are JSON. The frontend is a pure
consumer; the backend owns parsing, scanning, enrichment, scoring, and assessment.

## Types (shared shapes)

```ts
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";
type Format   = "cyclonedx" | "spdx" | "syft";
type Depth    = "direct" | "transitive" | "unknown";

interface Component {
  name: string; version: string; type: string;
  purl: string; cpe: string; description: string;
  licenses: string[]; supplier: string; language: string;
  bomRef: string;            // resolved id used for dependency edges
  depth: Depth;              // direct/transitive (computed)
}
interface Dependency { ref: string; deps: string[]; }

interface Cvss { score: number | null; severity: Severity; version: string | null; vector: string | null; }
interface Vuln {
  id: string; cveId: string | null; aliases: string[];
  description: string; cvss: Cvss;
  cwes: string[];            // e.g. ["CWE-502"]
  fixed: string[];           // fixed-in versions
  malicious: boolean; kev: boolean;
  epss: { score: number; percentile: number } | null;
  references: string[]; published: string; modified: string;
}
interface Finding { componentIndex: number; vulns: Vuln[]; }

interface Sbom {
  id: string;                // server-assigned handle for this parsed SBOM
  format: Format; formatVersion: string;
  name: string; version: string; timestamp: string;
  tools: string[]; serialNumber: string;
  distro?: string; distroVersion?: string;
  components: Component[]; dependencies: Dependency[];
}

interface Summary { CRITICAL:number; HIGH:number; MEDIUM:number; LOW:number; NONE:number; UNKNOWN:number;
                    total:number; scanned:number; affected:number; withPurl:number; }
interface Coverage { total:number; queryable:number; skipped:number; oci:number; devel:number; noId:number; other:number; }
interface Verdict { status:"PASS"|"REVIEW"|"FAIL"; reasons:string[]; policy:"strict"|"standard"|"lenient"; }
interface RemediationItem { componentIndex:number; name:string; currentVersion:string; target:string;
                            cvesResolved:number; kevCount:number; maxEpssPercentile:number|null;
                            riskRemoved:number; sevCounts:Record<Severity,number>; cveIds:string[]; }
interface Completeness { overallPct:number; fieldStats:Record<string,{present:number;total:number;pct:number}>; }
interface RiskScore { score:number; grade:"A"|"B"|"C"|"D"|"F"; pct:number; copyleft:number; noLic:number; }
interface Assessment {
  verdict: Verdict; risk: RiskScore; summary: Summary; coverage: Coverage;
  remediation: RemediationItem[]; noFix: { componentIndex:number; name:string; vulnCount:number }[];
  topCwes: { id:string; name:string; count:number }[];
  kevCount:number; maliciousCount:number; completeness: Completeness;
}
```

## Endpoints

### `GET /api/health` → `{ status:"ok", version:string }`

### `POST /api/parse`
Body: `{ raw: <object|string> }` (raw SBOM JSON) **or** `{ url: string }` (server fetches it; http/https only).
→ `200 { sbom: Sbom }` · `400 { error }` on unrecognized format / parse failure / bad URL.

### `POST /api/scan`
Body: `{ sbom: Sbom, options?: { kev?:boolean=true, epss?:boolean=true, testMode?:boolean=false } }`
Runs OSV batch+hydrate → cve.org enrichment → KEV → EPSS (server-side, cached).
→ `200 { findings: Finding[], summary: Summary, errors: string[] }`

### `POST /api/assess`
Body: `{ sbom: Sbom, findings: Finding[], summary: Summary, policy?: "strict"|"standard"|"lenient" }`
→ `200 { assessment: Assessment }`  (pure, no network — verdict/risk/remediation/coverage/CWE/completeness)

### `POST /api/report`
Body: `{ sbom, findings, summary, assessment, format: "html" }`
→ `200` `text/html` self-contained report (used by FE "download HTML" / "Save as PDF").

### `POST /api/export/normalized` → `application/json` (normalized SBOM)

## Conventions
- Errors: non-2xx with `{ "error": string }`.
- Concurrency caps & timeouts live in the backend; the client just awaits.
- CORS: same-origin via nginx (`/api` proxied), so no cross-origin config needed in prod.
- Frontend keeps all rendering/UX/exports-formatting; CSV/PDF generated client-side from these payloads.

---

# v1.1 additions (data sources + backlog)

## Data-source connectors
Five upstreams, each individually toggleable/configurable via env:
- **osv** — OSV.dev (primary vuln discovery; always on)
- **nvd** — NVD API 2.0 `services.nvd.nist.gov/rest/json/cves/2.0` (authoritative CVSS v2/3.x/4.0 + CWE + refs). Optional `NVD_API_KEY` (raises rate limit 5→50 per 30s). Rate-limited + capped per scan; degrades gracefully if unconfigured/unreachable.
- **mitre** — MITRE CVE Services / cve.org `cveawg.mitre.org/api/cve/{id}` (CNA CVSS + CWE). (This is the "cve.org" source.)
- **epss** — FIRST EPSS `api.first.org`
- **kev** — CISA KEV feed

`Vuln` gains: `scoreSource?: "nvd" | "mitre" | "osv" | "ghsa" | null` — provenance of the chosen CVSS score.

### `GET /api/sources`
→ `{ sources: { id:string; name:string; enabled:boolean; configured:boolean; reachable:boolean|null; detail:string }[] }`
(reachable may be null if not probed; a lightweight live probe is acceptable with short timeout.)

### `POST /api/scan` — options extended
`options.sources?: { nvd?:boolean; mitre?:boolean; epss?:boolean; kev?:boolean }` (all default true; osv always on). CVSS enrichment order for a CVE missing a computable score: **mitre (cve.org) → nvd**; `scoreSource` records which filled it. CWEs/refs merged from whichever source supplies them.

## License-policy gate (backlog)
### `POST /api/assess` — body extended
`licensePolicy?: { deny: string[]; warn: string[] }` — case-insensitive matches against each component's license ids (SPDX id or substring, e.g. "GPL", "AGPL-3.0").
`Assessment` gains:
- `licenseViolations: { componentIndex:number; name:string; license:string; rule:"deny"|"warn" }[]`
Verdict integration: any `deny` violation ⇒ **FAIL**; any `warn` ⇒ at least **REVIEW**; reasons include `"N denied license(s)"`.

## SARIF export (backlog)
### `POST /api/export/sarif`
Body: `{ sbom: Sbom, findings: Finding[] }` → `200 application/json` — **SARIF 2.1.0**. One `run` (tool driver "SBOM Visualizer / OSV"), one `rule` per unique vuln id (with CWE tags + help URI to osv.dev), one `result` per (component,vuln) with `level` mapped from severity (critical/high→error, medium→warning, low/none→note) and a message naming the component, version, fixed-in, KEV/EPSS.

## Backlog handled in frontend (no contract change)
- **Registry deep links** — component name → npm/PyPI/Maven Central/crates.io/RubyGems/NuGet/Go/Packagist URL derived from PURL.
- **`?sbom=<url>` auto-load** and **verdict diff in Compare** — verify present; complete if missing.
