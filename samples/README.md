# Sample SBOMs

Ready-to-use SBOMs for exercising the scanner across all supported formats. Each
parses cleanly and every component is queryable, so a scan returns real findings
(except the `clean` sample, which is intentionally vulnerability-free).

| File | Format | Components | What it demonstrates |
|------|--------|-----------|----------------------|
| `cyclonedx-1.5-vulnerable.json` | CycloneDX 1.5 | 5 | Known-vulnerable libs (Log4Shell `log4j-core` 2.14.1, `lodash` 4.17.15, `jackson-databind` 2.9.8, old `requests`) → FAIL/REVIEW verdict |
| `cyclonedx-1.5-clean.json` | CycloneDX 1.5 | 2 | Up-to-date libraries → expected grade A / PASS |
| `spdx-2.3-example.json` | SPDX 2.3 | 3 | `purl` + `cpe23Type` external refs, `DEPENDS_ON` relationships |
| `syft-example.json` | Syft JSON (schema 16) | 3 | Container image SBOM with distro (Debian 11), CPEs, `artifactRelationships` |

## How to use

**Web UI** — open the app, click *Upload*, and select any file above. Then press
*Scan* and *Assess*.

**API** — POST the raw JSON to the parse/scan/assess endpoints:

```bash
# Parse → scan → (returns findings + summary)
curl -sk https://localhost/api/parse \
  -H 'Content-Type: application/json' \
  -d "{\"raw\": $(cat samples/cyclonedx-1.5-vulnerable.json)}"
```

> The vulnerable sample pins deliberately old versions so it produces findings even
> as the vulnerability feeds update. Exact scores/grades depend on current
> KEV/EPSS/NVD data, which the stack downloads at build time (see the main README).

These samples contain **no real or proprietary data** — they reference only
well-known public open-source package coordinates.
