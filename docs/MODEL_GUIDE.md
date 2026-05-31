# SBOM Visualizer — Scoring Model Guide

**Audience:** Security engineers who want to understand how risk scores, grades, and verdicts are computed.

---

## 1. Design Philosophy

The v1 model was a flat weighted sum of severity buckets (CRITICAL×10, HIGH×5, MEDIUM×2, LOW×1). It had three structural problems:

1. **Coarse buckets.** CVSS 9.9 and CVSS 7.1 both counted identically as "HIGH×5". A 40% difference in raw severity was invisible.
2. **No exploitation signal.** A CVE being mass-exploited in the wild scored identically to a theoretical finding with EPSS 0.01% that nobody had ever attempted.
3. **No decay.** A 2005 CVE with near-zero exploitation probability carried the same weight forever.

The v2 model replaces this with a per-CVE formula that is:

- **Continuous on CVSS.** The actual numeric score (0–10) drives base points on a 0–100 scale, not a bucket.
- **Exploitation-amplified.** EPSS percentile and KEV status each apply a multiplier derived from observed real-world exploitation data. This aligns with the SSVC and CVSS-EPSS prioritization frameworks: exploitation evidence should dominate severity.
- **Age-decayed for dormant findings.** Old CVEs with no exploitation signal are de-weighted. Active or recently-published CVEs are not.
- **KEV-floored.** Any confirmed in-the-wild exploitation produces a hard minimum score and prevents a grade better than D, regardless of CVSS value.

---

## 2. Data Sources and Their Roles

Each data source has a distinct role in the pipeline. **Four of the five sources are mirrored locally** by the feeds service and refreshed daily; only MITRE remains live. The default scan path makes no live calls.

| Source | Role | Served by (default) |
|--------|------|---------------------|
| **OSV** | Primary vulnerability discovery (PURL + version-range matching). The backend runs the bundled **osv-scanner v2.3.8** binary `--offline-vulnerabilities` against the full local OSV database mirror (all 45 ecosystems, in the osv-scanner cache layout). | Offline OSV mirror (`osv-db` volume); live `api.osv.dev` only as fallback when the mirror is not ready. |
| **NVD (cvelistV5 mirror)** | CVSS/CWE enrichment. Mirror of the CVEProject **cvelistV5** GitHub archive (~354k CVE records, CVE Record 5.x schema) supplying CVSS v2/v3.x/v4.0, CWE categories, and references. No API key required; `NVD_API_KEY` is fallback-only (legacy NVD-API path). | Local SQLite mirror (`nvd` table); live NVD API only as fallback. |
| **CISA KEV** | Confirmed exploitation. The Known Exploited Vulnerabilities catalog (~1,607 CVEs) of CVEs CISA confirms are being actively exploited in the wild. | Local SQLite mirror (`kev` table); live CISA JSON only as fallback. |
| **EPSS (FIRST.org)** | Exploitation probability. A score and percentile (0–1) per CVE (~336k CVEs) representing relative likelihood of exploitation. | Local SQLite mirror (`epss` table); live `api.first.org` only as fallback. |
| **MITRE / cve.org** | Optional, non-blocking CVSS/CWE top-up via `cveawg.mitre.org`. KEV/EPSS/NVD already supply CVSS+CWE from the mirror, so this never blocks a result. | Live (`cveawg.mitre.org`) — the one remaining non-mirrored source. |

OSV discovers vulnerabilities. NVD (and the MITRE top-up) enrich them with authoritative scoring data. EPSS and KEV modulate the risk weight of each finding.

### Pre-enrichment (one batch lookup per scan)

After each daily KEV/EPSS/NVD refresh, the feeds scheduler builds a single denormalized **`cve_enriched`** SQLite table (one `INSERT…SELECT` join over the union of all CVE ids — currently ~336,837 rows). Every CVE is pre-pegged with its KEV flag + due date, EPSS score + percentile, and NVD CVSS score/severity/version/vector/CWEs.

At scan time the backend makes **one** `POST /feeds/enriched {cves}` batch lookup instead of three separate KEV/EPSS/NVD calls — so per-source application is effectively 0 ms. If the enriched table is not yet built, it falls back gracefully to the three-call path, then to live. The join is done once per day, never per scan.

---

## 3. Per-CVE Score Formula

```
per_cve_score = cvss_base_points(cvss_score, severity)
              × epss_amplifier(epss_percentile, is_kev)
              × age_decay_factor(published, epss_percentile, is_kev)
```

When a KEV finding's raw score would fall below 250, it is raised to 250 (see [Section 6](#6-kev-floor)).

### `cvss_base_points`

Maps the CVSS numeric score (0–10) to a base point value on a 0–100 scale:

```
base_points = cvss_score × 10
```

When no numeric CVSS score is available (vector not parseable, source did not supply one), a severity-bucket fallback is used:

| Severity | Fallback base points |
|----------|---------------------|
| CRITICAL | 90 |
| HIGH | 65 |
| MEDIUM | 40 |
| LOW | 10 |
| UNKNOWN | 25 |
| NONE | 0 |

### Worked example: Log4Shell (CVE-2021-44228)

- CVSS 3.1 score: 10.0 → base points = 10.0 × 10 = **100 pts**
- In CISA KEV: yes → amplifier = **5.0×**
- Age decay: not applied (KEV overrides)
- Per-CVE score: 100 × 5.0 = **500 pts**
- KEV floor (250 pts minimum): 500 ≥ 250 — floor does not activate

A single Log4Shell finding contributes 500 raw points toward the normalised score.

---

## 4. EPSS Amplifier Table

The EPSS amplifier is selected based on the CVE's EPSS percentile at scan time. KEV overrides all EPSS tiers with no further decay:

| Condition | Amplifier | Notes |
|-----------|-----------|-------|
| Is KEV | **5.0×** | Overrides all tiers; no age decay ever |
| EPSS ≥ 95th percentile | **4.0×** | Weaponized / mass-exploited |
| EPSS ≥ 75th percentile | **2.5×** | Active exploitation attempts observed |
| EPSS ≥ 50th percentile | **1.5×** | Above-average exploitation probability |
| EPSS ≥ 25th percentile | **1.0×** | Baseline |
| EPSS < 25th percentile | (age decay applied instead) | See Section 5 |
| No EPSS data | **1.0×** (neutral) | No decay without evidence |

KEV takes precedence over all EPSS tiers; even a CVE with EPSS below the 25th percentile receives the full 5.0× amplifier if it is in the KEV catalog.

---

## 5. Age Decay Table

Age decay is applied **only** when both conditions are true:
1. EPSS percentile is below the 25th percentile (or EPSS data is unavailable), **AND**
2. The CVE is NOT in CISA KEV.

In all other cases the age decay factor is 1.0 (no decay).

| Published age | Decay factor |
|---------------|-------------|
| Less than 1 year | 0.90 |
| 1 to 2 years | 0.75 |
| 2 to 3 years | 0.60 |
| 3 to 5 years | 0.45 |
| More than 5 years | 0.30 |

Rationale: an old CVE with no exploitation evidence is less operationally urgent than a recent one. However, if it has any meaningful EPSS signal (≥25th percentile) or is KEV, it is not decayed regardless of age.

---

## 6. KEV Floor

Any KEV finding contributes **at least 250 raw points** regardless of its CVSS score, EPSS tier, or age. This floor ensures a low-CVSS CVE confirmed in the wild cannot be invisible in the score.

```python
if is_kev:
    per_cve = max(per_cve, 250.0)
```

Additionally, the KEV floor applies to the grade: if any KEV finding is present, the SBOM cannot receive a grade better than **D**. Internally this is implemented by forcing `effective_pct ≥ 50` before the grade thresholds are evaluated.

---

## 7. Normalisation

Raw per-CVE scores are summed across all findings, then license penalties are added (see [Section 12](#12-license-risk)), and the total is normalised:

```
pct        = min(raw_sum / 2000, 1.0) × 100
grade_pct  = max(pct, 50) if kev_count > 0 else pct  (KEV floor on grade)
score      = min(raw_sum / 2000, 1.0) × 1000          (reported 0–1000)
```

The ceiling of 2000 raw points is calibrated to a badly-vulnerable SBOM containing approximately five CRITICAL findings all in KEV at the 90th+ EPSS tier.

### Grade thresholds

| `grade_pct` | Grade |
|-------------|-------|
| < 15% | **A** |
| 15% to < 30% | **B** |
| 30% to < 50% | **C** |
| 50% to < 70% | **D** |
| ≥ 70% | **F** |

**KEV floor on grade:** if any KEV finding is present, `grade_pct` is forced to at least 50%, making D the best achievable grade.

---

## 8. Verdict Gate

The verdict gate evaluates signal counts against a policy and emits PASS, REVIEW, or FAIL. The gate is independent of the risk score; a high score does not automatically produce FAIL.

### Policies

| Policy | FAIL on | REVIEW on |
|--------|---------|-----------|
| **Strict** | MAL, KEV, CRITICAL, HIGH | MEDIUM |
| **Standard** (default) | MAL, KEV, CRITICAL | HIGH, MEDIUM |
| **Lenient** | MAL, KEV | CRITICAL, HIGH |

**MAL** = malicious-package findings (OSV IDs prefixed `MAL-`). MAL triggers FAIL under all three policies.

### Signal annotations

After the gate policy is evaluated, the following annotations are prepended to the verdict reasons when the relevant signals are present. They do not change the verdict status; the gate policies already handle that.

- `☠ MALICIOUS PACKAGE — N known-malicious finding(s): CVE-IDs`
- `⚡ ACTIVE EXPLOITATION — N CVE(s) confirmed in-the-wild (CISA KEV): CVE-IDs` (up to 5 IDs shown)
- `🔥 HIGH EXPLOIT RISK — N CVE(s) at ≥95th EPSS percentile (top: X%): CVE-IDs` (KEV findings excluded from this annotation; they are already captured by ⚡)

---

## 9. Remediation Ranking

The Remediation view lists only components that have at least one fixable CVE (a CVE with a known fixed-in version). Each entry shows the recommended upgrade target (highest fixed-in version across all fixable CVEs for that component) and the `riskRemoved` value.

`riskRemoved` is the sum of per-CVE scores for all fixable CVEs on that component — the same formula used for the overall risk score. This means EPSS, KEV, and age decay are all factored into the remediation priority, not just severity.

Sort order:
1. `riskRemoved` descending (primary)
2. `kevCount` descending (tiebreaker)
3. `maxEpssPercentile` descending (secondary tiebreaker)

Fix the top-ranked component first; it removes the most risk from the score.

---

## 10. CVSS Computation

CVSS scores are computed locally from vectors wherever possible. The resolution order prefers the highest computable version; v4 never shadows a computable v3 score.

| Version | Computation method |
|---------|-------------------|
| v3.1 | Local FIRST formula (ISC + exploitability, scope-changed branch). Verified: Log4Shell vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → 10.0. |
| v3.0 | Same local formula as v3.1. |
| v4.0 | Computed via the `cvss` Python library (cvss==3.6). |
| v2.0 | Local formula (AV/AC/Au/C/I/A metric mapping). |

**Resolution order:** v3.1 → v3.0 → v4.0 → v2.0. If a v3.x vector is present and parseable, v4 and v2 are not used. v4 is used only when no v3.x score is computable.

The `scoreSource` field on each finding records which source provided the CVSS score: `nvd`, `mitre`, `osv`, `ghsa`, or `null`.

---

## 11. NTIA Completeness Scoring

The Completeness view scores each component against the NTIA minimum-elements requirements. The max score per component is 11 points.

### Required fields (NTIA minimum elements)

| Field | Weight | How checked |
|-------|--------|-------------|
| Component Name | 2 | `name` field present |
| Version | 2 | `version` field present |
| Supplier | 1 | `supplier` field present |
| Unique Identifier | 2 | `purl` OR `cpe` OR `bomRef` present |
| License | 2 | At least one entry in `licenses` |
| Hash / Checksum | 1 | At least one hash in the component's hash list |
| Dependency Relationship | 1 | Component appears in the SBOM's dependency graph |

The per-component score is `(sum of weights for present fields) / 11 × 100%`. The overall SBOM completeness is the mean of all per-component percentages.

### CISA recommended fields (informational, no weight)

Component Type, Description, Language. These are reported in the field stats but do not affect the numeric score.

---

## 12. License Risk

License classification is based on substring matching of the SPDX identifier (case-insensitive):

| Class | Matched substrings |
|-------|--------------------|
| **Copyleft** | `gpl`, `lgpl`, `agpl`, `copyleft`, `mpl`, `eupl`, `cc-by-sa` |
| **Permissive** | `mit`, `apache`, `bsd`, `isc`, `unlicense`, `0bsd`, `boost`, `public domain`, `cc0` |
| **Unknown** | Anything that does not match either list, or absent |

### License penalties in the risk score

These are additive to the per-CVE raw score sum before normalisation:

- Each copyleft component: **+2 raw points**
- Each unlicensed component: **+1 raw point**

These penalties are informational — they modestly influence the risk score but do not by themselves drive the score into FAIL territory on typical SBOMs.

### Policy gate integration

License policy violations (`--license-deny` / `--license-warn`) fold into the verdict independently of vulnerability findings:

- Any **deny** match → verdict is escalated to **FAIL**; reason: `N denied license(s)`
- Any **warn** match → verdict is escalated to at least **REVIEW**; reason: `N flagged license(s)`

Matching is case-insensitive substring/SPDX: a pattern `GPL` matches `GPL-2.0-only`, `GPL-3.0-or-later`, etc. `deny` takes precedence over `warn` for the same (component, license) pair.

---

## 13. Limitations

The model explicitly does **not** account for:

- **Network exposure.** A component running in an air-gapped or network-isolated context may have effectively zero exploitability regardless of EPSS or KEV status. The model has no visibility into deployment context.
- **Patch availability timing.** A CVE may have been fixed upstream but not yet backported in a distribution package. The model uses fixed-in versions from OSV and does not verify deployment state.
- **Asset criticality.** A vulnerability in a low-privilege background process and an identical vulnerability in an authentication service carry the same per-CVE score. The model has no knowledge of what the affected component does in production.
- **Compensating controls.** WAF rules, network segmentation, or runtime protections that reduce exploitability are not reflected.
- **Transitive reach.** The Vuln Paths view can show whether a vulnerable component is reachable from a root, but the model does not reduce the score for deeply transitive dependencies.

When any of these factors apply, use the score and grade as a starting signal, not a final decision. The KEV and high-EPSS annotations are the most reliable operational indicators in the model; treat them as unconditional flags that require human review.
