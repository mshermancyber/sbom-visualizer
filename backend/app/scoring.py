"""Pure assessment math — risk, verdict, remediation, coverage, depth, NTIA, CWE.

Risk model v2: EPSS-amplified, KEV-floored, age-decayed per-CVE scoring.

## Design rationale

The v1 model was a flat weighted sum of severity buckets (CRIT×10, HIGH×5 …). It had three
problems:
  1. Coarse buckets: CVSS 9.9 and 7.1 both counted as "HIGH×5".
  2. No exploitation signal: a CVE being mass-exploited scored identically to a theoretical
     finding no one had ever attempted.
  3. No decay: a 2005 CVE with EPSS 0.01% and no KEV carried the same weight forever.

## New model (per-CVE)

    per_cve_score = cvss_base_points(cvss_score, severity)
                    × epss_amplifier(epss_percentile, is_kev)
                    × age_decay_factor(published_age_days, epss_percentile, is_kev)

    kev_floor: any KEV finding contributes at least KEV_MIN_SCORE points regardless of age/EPSS;
               this ensures a SBOM with even 1 KEV can never grade as A or B.

### cvss_base_points
Uses the actual CVSS numeric score (0-10) when available, mapped to a 0-100 scale.
Severity-bucket fallback when no numeric score: CRITICAL=90, HIGH=65, MEDIUM=40, LOW=10.

### epss_amplifier  (KEV overrides everything)
  KEV:                  5.0  — confirmed real-world exploitation, no decay ever
  EPSS ≥ 95th pct:      4.0  — weaponized / mass-exploited
  EPSS ≥ 75th pct:      2.5  — active exploitation attempts observed
  EPSS ≥ 50th pct:      1.5  — above-average exploitation probability
  EPSS ≥ 25th pct:      1.0  — baseline
  EPSS < 25th pct:      [age_decay applies]
  No EPSS data:         1.0  — neutral; no decay without evidence

### age_decay_factor  (only when EPSS < 25th percentile AND NOT KEV)
  < 1 year:             0.90  — recent, still pay attention
  1–2 years:            0.75
  2–3 years:            0.60
  3–5 years:            0.45
  > 5 years:            0.30  — old theoretical finding with no exploitation evidence

### Normalisation
Raw scores are summed and compared against a calibrated ceiling (RISK_CEILING = 1200 raw
points, representing a badly-vulnerable SBOM with ~5 critical findings in KEV). The
capped percentage drives the grade; the reported score is capped at 1000.

### KEV floor on grade
After computing the grade from pct, apply: if kev_count > 0 → grade ≥ D (pct forced to
at least 50 if it would give A or B/C below 50). This ensures any KEV finding makes the
SBOM ungradable as "good".

### License penalties  (unchanged from v1)
Copyleft components: +2 pts each. Unlicensed: +1 pt each.
"""
from __future__ import annotations

import re
from functools import cmp_to_key

from .models import (
    Assessment, Completeness, Component, Coverage, Dependency, FieldStat,
    Finding, LicensePolicy, LicenseViolation, NoFixItem, RemediationItem, RiskScore,
    Sbom, Summary, TopCwe, Verdict,
)
from .parsers import _extract_purl_spdx  # noqa: F401 (kept for parity / potential reuse)

# ── Legacy flat weights (used only in remediation plan ranking, not risk score) ──
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
KEV_WEIGHT = 15

# ── Risk model v2 constants ───────────────────────────────────
# CVSS base scale: actual score (0-10) → points (0-100).
_CVSS_SCALE = 10.0   # multiply cvss_score by this

# Severity-bucket fallback (when no numeric CVSS score is available).
_SEV_BASE = {"CRITICAL": 90.0, "HIGH": 65.0, "MEDIUM": 40.0, "LOW": 10.0,
             "NONE": 0.0, "UNKNOWN": 25.0}

# KEV minimum score per finding (floor — guarantees KEV can't grade as A/B).
KEV_MIN_SCORE = 250.0

# EPSS amplifiers (keyed by inclusive lower percentile bound, highest wins).
# Order matters: evaluate from highest threshold down.
_EPSS_TIERS: list[tuple[float, float]] = [
    (0.95, 4.0),   # weaponized / mass-exploited
    (0.75, 2.5),   # active exploitation observed
    (0.50, 1.5),   # above-average exploitation probability
    (0.25, 1.0),   # baseline
]
_EPSS_KEV_AMP     = 5.0   # KEV overrides all EPSS tiers
_EPSS_NEUTRAL     = 1.0   # no EPSS data → neutral

# Age-decay thresholds (days) applied ONLY when EPSS < 25th pct AND NOT KEV.
_AGE_DECAY: list[tuple[int, float]] = [
    (0,    0.90),   # < 1 year
    (365,  0.75),   # 1–2 years
    (730,  0.60),   # 2–3 years
    (1095, 0.45),   # 3–5 years
    (1825, 0.30),   # > 5 years
]

# Calibration ceiling: a badly-vulnerable SBOM with ~5 CRITICAL+KEV findings in the
# 90th+ EPSS tier ≈ 5 × (9.5×10) × 5.0 = 2375 raw pts; we set the ceiling to 2000 to
# give a 1000-pt reported score headroom without everything immediately pegging at F.
RISK_CEILING = 2000.0

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")


# ── License classification (port of licClass) ─────────────────
_COPYLEFT = ("gpl", "lgpl", "agpl", "copyleft", "mpl", "eupl", "cc-by-sa")
_PERMISSIVE = ("mit", "apache", "bsd", "isc", "unlicense", "0bsd", "boost",
               "public domain", "cc0")


def lic_class(lic: str) -> str:
    if not lic or lic == "(none)":
        return "license-unknown"
    l = lic.lower()
    if any(k in l for k in _COPYLEFT):
        return "license-copyleft"
    if any(k in l for k in _PERMISSIVE):
        return "license-permissive"
    return ""


def _is_copyleft(comp: Component) -> bool:
    return any("copyleft" in lic_class(l) for l in comp.licenses)


# ── OSV query buildability (needed by coverage) ───────────────
def _ecosystem_from_purl(purl: str) -> str:
    m = re.match(r"^pkg:([^/]+)/", purl)
    if not m:
        return ""
    scheme = m.group(1).lower()
    mapping = {
        "npm": "npm", "pypi": "PyPI", "gem": "RubyGems", "maven": "Maven",
        "cargo": "crates.io", "nuget": "NuGet", "golang": "Go", "composer": "Packagist",
        "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "cocoapods": "CocoaPods",
        "deb": "Debian", "rpm": "Rocky Linux", "apk": "Alpine",
    }
    return mapping.get(scheme, "")


def _distro_ecosystem(purl: str, distro_name: str) -> str | None:
    if not purl:
        return None
    d = (distro_name or "").lower()
    if purl.startswith("pkg:rpm"):
        ns = purl.split("/")[1] if len(purl.split("/")) > 1 else ""
        if ns == "amzn" or "amazon" in d:
            return "Amazon Linux"
        if ns in ("rhel", "redhat") or "red hat" in d:
            return "Red Hat"
        if ns == "fedora" or "fedora" in d:
            return "Fedora"
        if ns in ("sles", "opensuse") or "suse" in d:
            return "openSUSE"
        if ns == "rocky" or "rocky" in d:
            return "Rocky Linux"
        if ns == "alma" or "alma" in d:
            return "AlmaLinux"
        if ns == "oracle" or "oracle" in d:
            return "Oracle Linux"
        if "centos" in d:
            return "Rocky Linux"
    if purl.startswith("pkg:deb"):
        return "Ubuntu" if "ubuntu" in d else "Debian"
    if purl.startswith("pkg:apk"):
        return "Alpine"
    return None


def build_osv_query(comp: Component, distro: str = "") -> dict | None:
    """Port of buildOsvQuery — returns an OSV query dict, or None if unqueryable."""
    purl = comp.purl or ""
    ver = comp.version or ""

    if not purl and not comp.name:
        return None
    if ver == "(devel)":
        return None
    if purl.startswith("pkg:oci"):
        return None

    eco = _distro_ecosystem(purl, distro)
    if eco and comp.name:
        clean_ver = re.sub(r"^\d+:", "", ver)
        if not clean_ver:
            return None
        return {"version": clean_ver, "package": {"name": comp.name, "ecosystem": eco}}

    if purl.startswith("pkg:golang"):
        clean = purl.split("?")[0].split("#")[0]
        if "@(" in clean or "@" not in clean:
            return None
        return {"package": {"purl": clean}}

    by_purl = _purl_to_osv(purl)
    if by_purl:
        return by_purl

    return _name_version_to_osv(comp)


def _purl_to_osv(purl: str) -> dict | None:
    if not purl:
        return None
    clean = purl.split("?")[0].split("#")[0].strip()
    if not clean.startswith("pkg:"):
        return None
    return {"package": {"purl": clean}}


def _name_version_to_osv(comp: Component) -> dict | None:
    if not comp.name:
        return None
    eco = _ecosystem_from_purl(comp.purl or "")
    q: dict = {"package": {"name": comp.name}}
    if eco:
        q["package"]["ecosystem"] = eco
    if comp.version:
        q["version"] = re.sub(r"^\d+:", "", comp.version)
    return q


# ── Coverage (port of computeCoverage) ────────────────────────
def compute_coverage(sbom: Sbom) -> Coverage:
    distro = sbom.distro or ""
    queryable = oci = devel = no_id = other = 0
    for c in sbom.components:
        if build_osv_query(c, distro):
            queryable += 1
            continue
        purl = c.purl or ""
        if purl.startswith("pkg:oci"):
            oci += 1
        elif (c.version or "") == "(devel)":
            devel += 1
        elif not purl and not c.name:
            no_id += 1
        else:
            other += 1
    total = len(sbom.components)
    return Coverage(total=total, queryable=queryable, skipped=total - queryable,
                    oci=oci, devel=devel, noId=no_id, other=other)


# ── Dependency depth (port of classifyDependencyDepth) ────────
def _build_dep_maps(sbom: Sbom):
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for d in sbom.dependencies:
        forward.setdefault(d.ref, set())
        for dep in d.deps or []:
            forward[d.ref].add(dep)
            reverse.setdefault(dep, set()).add(d.ref)
    return forward, reverse


def _component_refs(c: Component) -> list[str]:
    return [r for r in (c.bomRef, c.name, c.purl, f"{c.name}@{c.version}") if r]


def classify_dependency_depth(sbom: Sbom) -> dict[int, str]:
    out: dict[int, str] = {}
    if not sbom.dependencies:
        return out
    forward, reverse = _build_dep_maps(sbom)
    all_refs = set(forward.keys()) | set(reverse.keys())
    roots = [r for r in all_refs if r not in reverse or len(reverse[r]) == 0]
    direct_refs: set[str] = set()
    for root in roots:
        for d in forward.get(root, set()):
            direct_refs.add(d)
    for i, c in enumerate(sbom.components):
        refs = _component_refs(c)
        if any(r in direct_refs for r in refs):
            out[i] = "direct"
        elif any(r in all_refs for r in refs):
            out[i] = "transitive"
    return out


# ── Version compare (port of compareVersions) ─────────────────
_SEG_SPLIT = re.compile(r"[.\-+_~]")


def _tokenize(s: str) -> list:
    toks = []
    for t in _SEG_SPLIT.split(str(s)):
        if re.fullmatch(r"\d+", t):
            toks.append(("n", int(t)))
        else:
            toks.append(("s", t))
    return toks


def compare_versions(a: str, b: str) -> int:
    pa, pb = _tokenize(a), _tokenize(b)
    n = max(len(pa), len(pb))
    for i in range(n):
        x = pa[i] if i < len(pa) else None
        y = pb[i] if i < len(pb) else None
        if x is None:
            return 1 if y[0] == "s" else -1
        if y is None:
            return -1 if x[0] == "s" else 1
        xn, yn = x[0] == "n", y[0] == "n"
        if xn and yn:
            if x[1] != y[1]:
                return -1 if x[1] < y[1] else 1
        elif xn != yn:
            return 1 if xn else -1
        else:
            if x[1] != y[1]:
                return -1 if x[1] < y[1] else 1
    return 0


def _max_version(arr: list[str]) -> str | None:
    best = None
    for v in arr:
        if best is None or compare_versions(v, best) > 0:
            best = v
    return best


# ── Risk score v2: EPSS-amplified, KEV-floored, age-decayed ──
def _cvss_base_points(cvss_score: float | None, severity: str) -> float:
    """Map a CVSS numeric score (0-10) to base points (0-100). Falls back to severity bucket."""
    if cvss_score is not None:
        return max(0.0, min(float(cvss_score), 10.0)) * _CVSS_SCALE
    return _SEV_BASE.get((severity or "UNKNOWN").upper(), 25.0)


def _epss_amp(epss_percentile: float | None, is_kev: bool) -> float:
    """EPSS amplifier. KEV overrides all tiers. No EPSS data → neutral 1.0."""
    if is_kev:
        return _EPSS_KEV_AMP
    if epss_percentile is None:
        return _EPSS_NEUTRAL
    for threshold, amp in _EPSS_TIERS:
        if epss_percentile >= threshold:
            return amp
    return None  # caller applies age decay when below all tiers


def _age_decay(published: str | None, epss_percentile: float | None, is_kev: bool) -> float:
    """Age-decay factor. Only applied when EPSS < 25th percentile AND NOT KEV."""
    if is_kev:
        return 1.0
    if epss_percentile is not None and epss_percentile >= 0.25:
        return 1.0
    if not published:
        return 1.0  # unknown age → no penalty
    try:
        from datetime import date
        pub_date = date.fromisoformat(published[:10])
        age_days = (date.today() - pub_date).days
    except (ValueError, TypeError):
        return 1.0
    for threshold_days, factor in reversed(_AGE_DECAY):
        if age_days >= threshold_days:
            return factor
    return 1.0


def _score_vuln(v) -> float:  # v: Vuln model
    """Compute the risk contribution of a single vulnerability finding."""
    is_kev = bool(v.kev)
    cvss_score = v.cvss.score if v.cvss else None
    severity = (v.cvss.severity or "UNKNOWN") if v.cvss else "UNKNOWN"
    epss_pct = v.epss.percentile if v.epss else None
    published = v.published or None

    base = _cvss_base_points(cvss_score, severity)
    amp = _epss_amp(epss_pct, is_kev)

    if amp is None:
        # Below all EPSS tiers (< 25th pct) and not KEV: apply age decay instead
        decay = _age_decay(published, epss_pct, is_kev)
        amp = decay

    per_cve = base * amp

    # KEV floor: any KEV finding is worth at least KEV_MIN_SCORE points.
    if is_kev:
        per_cve = max(per_cve, KEV_MIN_SCORE)

    return per_cve


def calc_risk_score(
    sbom: Sbom,
    summary: Summary,
    kev_hits: int,
    scanned: bool,
    findings: list | None = None,   # list[Finding] — drives per-CVE scoring when available
) -> RiskScore:
    """Compute a risk score using EPSS-amplified, KEV-floored, age-decayed per-CVE scoring.

    When ``findings`` are supplied (the full per-component vuln list) the score is computed
    per-CVE so EPSS and age can modulate each finding. When not supplied (legacy call with
    only summary counts) we fall back to the v1 severity-bucket model so existing callers
    do not break.
    """
    raw = 0.0
    kev_count = 0

    if scanned:
        if findings:
            # ── Per-CVE path (preferred) ───────────────────────────────────
            for f in findings:
                for v in f.vulns:
                    raw += _score_vuln(v)
                    if v.kev:
                        kev_count += 1
        else:
            # ── Legacy summary-only fallback ───────────────────────────────
            raw += (summary.CRITICAL or 0) * _CVSS_SCALE * 9.0   # approx CVSS 9 mid-critical
            raw += (summary.HIGH or 0)     * _CVSS_SCALE * 7.0
            raw += (summary.MEDIUM or 0)   * _CVSS_SCALE * 5.0
            raw += (summary.LOW or 0)      * _CVSS_SCALE * 2.0
            raw += kev_hits * KEV_MIN_SCORE
            kev_count = kev_hits

    # License penalties (small; informational not security-critical).
    copyleft = sum(1 for c in sbom.components if _is_copyleft(c))
    no_lic   = sum(1 for c in sbom.components if not c.licenses)
    raw += copyleft * 2.0
    raw += no_lic   * 1.0

    # Normalise against the calibrated ceiling → percentage → grade.
    pct = round(min(raw / RISK_CEILING, 1.0) * 100)
    reported = round(min(raw / RISK_CEILING, 1.0) * 1000)  # 0-1000 reported score

    # KEV floor on grade: any KEV finding prevents A/B.
    effective_pct = pct
    if kev_count > 0 and effective_pct < 50:
        effective_pct = 50  # floor at D when KEV present

    if effective_pct >= 70:
        grade = "F"
    elif effective_pct >= 50:
        grade = "D"
    elif effective_pct >= 30:
        grade = "C"
    elif effective_pct >= 15:
        grade = "B"
    else:
        grade = "A"

    return RiskScore(score=reported, grade=grade, pct=pct, copyleft=copyleft, noLic=no_lic)


# ── Verdict / gate policies (port of GATE_POLICIES) ───────────
GATE_POLICIES = {
    "strict":   {"label": "Strict",   "fail": ["MAL", "KEV", "CRITICAL", "HIGH"], "review": ["MEDIUM"]},
    "standard": {"label": "Standard", "fail": ["MAL", "KEV", "CRITICAL"],         "review": ["HIGH", "MEDIUM"]},
    "lenient":  {"label": "Lenient",  "fail": ["MAL", "KEV"],                     "review": ["CRITICAL", "HIGH"]},
}

_SIGNAL_NAMES = {
    "MAL": "known-malicious package", "KEV": "actively-exploited (KEV)",
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
}


def compute_verdict(summary: Summary, mal_count: int, kev_count: int, policy: str) -> Verdict:
    pol = GATE_POLICIES.get(policy) or GATE_POLICIES["standard"]
    if policy not in GATE_POLICIES:
        policy = "standard"
    signals = {
        "MAL": mal_count, "KEV": kev_count,
        "CRITICAL": summary.CRITICAL, "HIGH": summary.HIGH,
        "MEDIUM": summary.MEDIUM, "LOW": summary.LOW,
    }
    reasons: list[str] = []
    status = "PASS"
    for k in pol["fail"]:
        if signals.get(k, 0) > 0:
            status = "FAIL"
            reasons.append(f"{signals[k]} {_SIGNAL_NAMES[k]}")
    if status != "FAIL":
        for k in pol["review"]:
            if signals.get(k, 0) > 0:
                status = "REVIEW"
                reasons.append(f"{signals[k]} {_SIGNAL_NAMES[k]}")
    if status == "PASS":
        lows = signals["MEDIUM"] + signals["LOW"]
        if lows:
            reasons.append(f"{lows} medium/low finding{'s' if lows != 1 else ''} only")
        else:
            reasons.append("no findings")
    return Verdict(status=status, reasons=reasons, policy=policy)  # type: ignore[arg-type]


def annotate_verdict_signals(
    verdict: Verdict,
    findings: list,           # list[Finding]
) -> Verdict:
    """Prepend clear, explicit signal annotations to the verdict reasons so operators
    can read the danger at a glance without digging into findings tables.

    Annotations added (front of reasons list, only when present):
      ⚡ ACTIVE EXPLOITATION: N CVE(s) confirmed exploited in the wild (CISA KEV)
      🔥 HIGH EXPLOIT RISK: N CVE(s) in top 5% exploitation probability (EPSS ≥ 95th pct)
      ☠  MALICIOUS PACKAGE: N known-malicious package finding(s)

    These are purely informational labels prepended to the existing reasons — they do not
    change the verdict status (the gate policies already handle that).
    """
    kev_vulns: list = []
    high_epss_vulns: list = []
    mal_vulns: list = []

    for f in findings:
        for v in f.vulns:
            if getattr(v, "kev", False):
                kev_vulns.append(v)
            if getattr(v, "malicious", False):
                mal_vulns.append(v)
            epss = getattr(v, "epss", None)
            if epss and getattr(epss, "percentile", None) is not None:
                if epss.percentile >= 0.95 and not getattr(v, "kev", False):
                    high_epss_vulns.append(v)

    annotations: list[str] = []

    if mal_vulns:
        ids = sorted({getattr(v, "id", "?") for v in mal_vulns})[:3]
        suffix = (", ".join(ids)) + (" …" if len(mal_vulns) > 3 else "")
        annotations.append(
            f"☠ MALICIOUS PACKAGE — {len(mal_vulns)} known-malicious finding(s): {suffix}"
        )

    if kev_vulns:
        # Show the CVE IDs so operators can act immediately.
        cve_ids = sorted({getattr(v, "cveId", None) or getattr(v, "id", "?")
                          for v in kev_vulns})[:5]
        suffix = (", ".join(cve_ids)) + (" …" if len(kev_vulns) > 5 else "")
        annotations.append(
            f"⚡ ACTIVE EXPLOITATION — {len(kev_vulns)} CVE(s) confirmed in-the-wild (CISA KEV): {suffix}"
        )

    if high_epss_vulns:
        top = sorted(high_epss_vulns,
                     key=lambda v: (getattr(v.epss, "percentile", 0) if v.epss else 0),
                     reverse=True)[:5]
        cve_ids = [getattr(v, "cveId", None) or getattr(v, "id", "?") for v in top]
        best_pct = round((top[0].epss.percentile if top[0].epss else 0) * 100)
        annotations.append(
            f"🔥 HIGH EXPLOIT RISK — {len(high_epss_vulns)} CVE(s) at ≥95th EPSS percentile "
            f"(top: {best_pct}%): {', '.join(cve_ids)}"
        )

    if not annotations:
        return verdict

    return Verdict(
        status=verdict.status,
        reasons=annotations + list(verdict.reasons),
        policy=verdict.policy,
    )


# ── License-policy gate ───────────────────────────────────────
def compute_license_violations(sbom: Sbom,
                               policy: LicensePolicy | None) -> list[LicenseViolation]:
    """Case-insensitive substring/SPDX match of each component's licenses against the
    policy. A component license matches a pattern when the (lowercased) pattern is a
    substring of the (lowercased) license id, or vice-versa. ``deny`` takes precedence
    over ``warn`` for a given (component, license) pair."""
    if not policy:
        return []
    deny = [p.strip().lower() for p in (policy.deny or []) if p and p.strip()]
    warn = [p.strip().lower() for p in (policy.warn or []) if p and p.strip()]
    if not deny and not warn:
        return []

    out: list[LicenseViolation] = []
    for idx, comp in enumerate(sbom.components):
        for lic in comp.licenses:
            ll = (lic or "").lower()
            if not ll:
                continue
            rule = None
            if any(p in ll or ll in p for p in deny):
                rule = "deny"
            elif any(p in ll or ll in p for p in warn):
                rule = "warn"
            if rule:
                out.append(LicenseViolation(componentIndex=idx, name=comp.name,
                                            license=lic, rule=rule))  # type: ignore[arg-type]
    return out


def _fold_license_into_verdict(verdict: Verdict,
                               violations: list[LicenseViolation]) -> Verdict:
    """Fold license violations into an existing verdict: any deny ⇒ FAIL, any warn ⇒ at
    least REVIEW. Reasons gain ``N denied/flagged license(s)``."""
    if not violations:
        return verdict
    deny_n = sum(1 for v in violations if v.rule == "deny")
    warn_n = sum(1 for v in violations if v.rule == "warn")
    status = verdict.status
    reasons = list(verdict.reasons)
    # Drop the "no findings"/"...only" filler if we're escalating off PASS.
    if status == "PASS" and (deny_n or warn_n):
        reasons = [r for r in reasons
                   if r not in ("no findings",) and not r.endswith(" only")]
    if deny_n:
        status = "FAIL"
        reasons.append(f"{deny_n} denied license{'s' if deny_n != 1 else ''}")
    if warn_n and status != "FAIL":
        status = "REVIEW"
    if warn_n:
        reasons.append(f"{warn_n} flagged license{'s' if warn_n != 1 else ''}")
    return Verdict(status=status, reasons=reasons, policy=verdict.policy)


# ── Remediation (port of buildRemediationPlan) ────────────────
def build_remediation_plan(sbom: Sbom, findings: list[Finding]):
    plan: list[RemediationItem] = []
    no_fix: list[NoFixItem] = []
    for f in findings:
        idx = f.componentIndex
        if idx < 0 or idx >= len(sbom.components):
            continue
        comp = sbom.components[idx]
        fixable = [v for v in f.vulns if v.fixed]
        unfixable = [v for v in f.vulns if not v.fixed]
        if unfixable:
            no_fix.append(NoFixItem(componentIndex=idx, name=comp.name, vulnCount=len(unfixable)))
        if not fixable:
            continue

        target = _max_version([fv for v in fixable for fv in v.fixed]) or ""
        # Use the same per-CVE scoring model as calc_risk_score so riskRemoved is
        # directly comparable to the overall risk score and remediation priorities
        # reflect EPSS+KEV+age, not just severity buckets.
        risk_removed = 0.0
        kev_count = 0
        max_epss = None
        sev_counts = {s: 0 for s in SEV_ORDER}
        cve_ids: list[str] = []
        for v in fixable:
            risk_removed += _score_vuln(v)
            if v.kev:
                kev_count += 1
            if v.cvss and v.cvss.severity in sev_counts:
                sev_counts[v.cvss.severity] += 1
            if v.epss and v.epss.percentile is not None:
                max_epss = max(max_epss or 0, v.epss.percentile)
            cid = v.cveId or v.id
            if cid:
                cve_ids.append(cid)
        # Normalise riskRemoved to the same 0-1000 scale as the overall risk score
        # so the numbers are directly comparable in the UI (e.g. "upgrades removes
        # 250 pts" vs "current score 867/1000" — both on the same axis).
        risk_removed_normalised = round(min(risk_removed / RISK_CEILING, 1.0) * 1000)
        plan.append(RemediationItem(
            componentIndex=idx, name=comp.name, currentVersion=comp.version,
            target=target, cvesResolved=len(fixable), kevCount=kev_count,
            maxEpssPercentile=max_epss, riskRemoved=risk_removed_normalised,
            sevCounts=sev_counts, cveIds=cve_ids,
        ))

    def _cmp(a: RemediationItem, b: RemediationItem) -> int:
        if b.riskRemoved != a.riskRemoved:
            return b.riskRemoved - a.riskRemoved
        if b.kevCount != a.kevCount:
            return b.kevCount - a.kevCount
        ae = a.maxEpssPercentile or 0
        be = b.maxEpssPercentile or 0
        return -1 if be < ae else (1 if be > ae else 0)

    plan.sort(key=cmp_to_key(_cmp))
    return plan, no_fix


# ── CWE aggregation (port of topCwes) ─────────────────────────
CWE_NAMES = {
    "CWE-79": "Cross-site Scripting", "CWE-89": "SQL Injection", "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal", "CWE-352": "CSRF", "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization", "CWE-787": "Out-of-bounds Write", "CWE-125": "Out-of-bounds Read",
    "CWE-416": "Use After Free", "CWE-190": "Integer Overflow", "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-770": "Resource Allocation w/o Limits", "CWE-918": "SSRF", "CWE-94": "Code Injection",
    "CWE-1321": "Prototype Pollution", "CWE-200": "Information Exposure", "CWE-20": "Improper Input Validation",
    "CWE-287": "Improper Authentication", "CWE-863": "Incorrect Authorization", "CWE-732": "Incorrect Permissions",
    "CWE-611": "XXE", "CWE-77": "Command Injection", "CWE-401": "Memory Leak", "CWE-476": "NULL Pointer Deref",
    "CWE-295": "Improper Cert Validation", "CWE-327": "Broken Crypto", "CWE-798": "Hard-coded Credentials",
    "CWE-915": "Mass Assignment", "CWE-1333": "Inefficient Regex (ReDoS)", "CWE-601": "Open Redirect",
}


def cwe_name(cid: str) -> str:
    return CWE_NAMES.get(cid, cid)


def top_cwes(findings: list[Finding], limit: int = 8) -> list[TopCwe]:
    counts: dict[str, int] = {}
    for f in findings:
        for v in f.vulns:
            for cid in v.cwes or []:
                counts[cid] = counts.get(cid, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [TopCwe(id=cid, name=cwe_name(cid), count=n) for cid, n in ordered]


# ── NTIA completeness (port of scoreCompleteness) ─────────────
# fn returns truthiness for the field's presence. relationship checks the dep graph.
NTIA_FIELDS = [
    {"key": "name", "label": "Component Name", "weight": 2, "fn": lambda c, s: bool(c.name)},
    {"key": "version", "label": "Version", "weight": 2, "fn": lambda c, s: bool(c.version)},
    {"key": "supplier", "label": "Supplier", "weight": 1, "fn": lambda c, s: bool(c.supplier)},
    {"key": "purl", "label": "Unique Identifier", "weight": 2,
     "fn": lambda c, s: bool(c.purl or c.cpe or c.bomRef)},
    {"key": "licenses", "label": "License", "weight": 2, "fn": lambda c, s: len(c.licenses) > 0},
    {"key": "hash", "label": "Hash / Checksum", "weight": 1, "fn": None},  # filled from hashes_by_index
    {"key": "relationship", "label": "Dependency Relationship", "weight": 1,
     "fn": lambda c, s: _has_relationship(c, s)},
]

CISA_FIELDS = [
    {"key": "type", "label": "Component Type", "fn": lambda c, s: bool(c.type and c.type != "other")},
    {"key": "description", "label": "Description", "fn": lambda c, s: bool(c.description)},
    {"key": "language", "label": "Language", "fn": lambda c, s: bool(c.language)},
]


def _has_relationship(c: Component, sbom: Sbom) -> bool:
    ref = c.bomRef or c.name
    for d in sbom.dependencies:
        if d.ref == ref or ref in (d.deps or []):
            return True
    return False


def score_completeness(sbom: Sbom, hashes_by_index: dict[int, list] | None = None) -> Completeness:
    hashes_by_index = hashes_by_index or {}
    total = len(sbom.components)
    max_score = sum(f["weight"] for f in NTIA_FIELDS)

    field_present: dict[str, int] = {f["key"]: 0 for f in NTIA_FIELDS}
    for f in CISA_FIELDS:
        field_present[f["key"]] = 0

    per_comp_pcts: list[int] = []
    for i, comp in enumerate(sbom.components):
        has_hash = len(hashes_by_index.get(i, []) or []) > 0
        got = 0
        for f in NTIA_FIELDS:
            if f["key"] == "hash":
                present = has_hash
            else:
                present = bool(f["fn"](comp, sbom))
            if present:
                got += f["weight"]
                field_present[f["key"]] += 1
        for f in CISA_FIELDS:
            if bool(f["fn"](comp, sbom)):
                field_present[f["key"]] += 1
        per_comp_pcts.append(round(got / max_score * 100) if max_score else 0)

    field_stats = {
        key: FieldStat(present=present, total=total,
                       pct=round(present / total * 100) if total else 0)
        for key, present in field_present.items()
    }
    overall = round(sum(per_comp_pcts) / total) if total else 0
    return Completeness(overallPct=overall, fieldStats=field_stats)


# ── Top-level assembly ────────────────────────────────────────
def build_assessment(sbom: Sbom, findings: list[Finding], summary: Summary,
                     policy: str = "standard",
                     hashes_by_index: dict[int, list] | None = None,
                     license_policy: LicensePolicy | None = None) -> Assessment:
    mal_count = sum(1 for f in findings for v in f.vulns if v.malicious)
    kev_count = sum(1 for f in findings for v in f.vulns if v.kev)

    verdict = compute_verdict(summary, mal_count, kev_count, policy)
    license_violations = compute_license_violations(sbom, license_policy)
    verdict = _fold_license_into_verdict(verdict, license_violations)
    # Prepend clear KEV/high-exploit/malicious annotations to the verdict reasons.
    verdict = annotate_verdict_signals(verdict, findings)
    # Pass findings for per-CVE EPSS-amplified, KEV-floored, age-decayed scoring.
    risk = calc_risk_score(sbom, summary, kev_count, scanned=True, findings=findings)
    coverage = compute_coverage(sbom)
    plan, no_fix = build_remediation_plan(sbom, findings)
    cwes = top_cwes(findings)
    completeness = score_completeness(sbom, hashes_by_index)

    return Assessment(
        verdict=verdict, risk=risk, summary=summary, coverage=coverage,
        remediation=plan, noFix=no_fix, topCwes=cwes,
        kevCount=kev_count, maliciousCount=mal_count, completeness=completeness,
        licenseViolations=license_violations,
    )
