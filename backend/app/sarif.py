"""SARIF 2.1.0 export — one run (driver "SBOM Visualizer / OSV"), one rule per unique
vuln id, one result per (component, vuln).

Severity → SARIF level: critical/high → ``error``, medium → ``warning``, low/none/unknown
→ ``note``. Each rule carries CWE tags and a help URI to osv.dev; each result's message
names the component@version, fixed-in versions, and KEV/EPSS signals.
"""
from __future__ import annotations

from .models import Finding, Sbom

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note", "NONE": "note", "UNKNOWN": "note",
}


def _level_for(severity: str) -> str:
    return _LEVEL.get((severity or "UNKNOWN").upper(), "note")


def _result_message(comp_name: str, comp_version: str, vuln) -> str:
    parts = [f"{vuln.id} affects {comp_name}@{comp_version or '?'}"]
    if vuln.cveId and vuln.cveId != vuln.id:
        parts.append(f"({vuln.cveId})")
    sev = vuln.cvss.severity or "UNKNOWN"
    score = vuln.cvss.score
    parts.append(f"— severity {sev}" + (f" ({score})" if score is not None else ""))
    if vuln.fixed:
        parts.append(f"; fixed in {', '.join(vuln.fixed)}")
    else:
        parts.append("; no fixed version")
    if vuln.malicious:
        parts.append("; MALICIOUS")
    if vuln.kev:
        parts.append("; CISA KEV (actively exploited)")
    if vuln.epss and vuln.epss.percentile is not None:
        parts.append(f"; EPSS pct {round(vuln.epss.percentile * 100)}%")
    return " ".join(parts)


def build_sarif(sbom: Sbom, findings: list[Finding]) -> dict:
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for f in findings:
        if not (0 <= f.componentIndex < len(sbom.components)):
            continue
        comp = sbom.components[f.componentIndex]
        for v in f.vulns:
            # One rule per unique vuln id.
            if v.id not in rule_index:
                rule_index[v.id] = len(rules)
                tags = ["security", "vulnerability"]
                tags.extend(c for c in (v.cwes or []))
                relationships = [
                    {"target": {"id": cwe, "toolComponent": {"name": "CWE"}},
                     "kinds": ["relevant"]}
                    for cwe in (v.cwes or [])
                ]
                rule: dict = {
                    "id": v.id,
                    "name": v.id,
                    "shortDescription": {"text": (v.description[:120] or v.id)},
                    "helpUri": f"https://osv.dev/vulnerability/{v.id}",
                    "properties": {"tags": tags},
                }
                if v.description:
                    rule["fullDescription"] = {"text": v.description[:1000]}
                if v.cvss.severity:
                    rule["properties"]["security-severity"] = (
                        str(v.cvss.score) if v.cvss.score is not None
                        else _severity_band(v.cvss.severity)
                    )
                if relationships:
                    rule["relationships"] = relationships
                rules.append(rule)

            ridx = rule_index[v.id]
            results.append({
                "ruleId": v.id,
                "ruleIndex": ridx,
                "level": _level_for(v.cvss.severity),
                "message": {"text": _result_message(comp.name, comp.version, v)},
                "locations": [{
                    "logicalLocations": [{
                        "name": f"{comp.name}@{comp.version}" if comp.version else comp.name,
                        "kind": "package",
                        "fullyQualifiedName": comp.purl or comp.bomRef
                                              or f"{comp.name}@{comp.version}",
                    }],
                }],
                "properties": {
                    "componentIndex": f.componentIndex,
                    "package": comp.name,
                    "version": comp.version,
                    "cveId": v.cveId,
                    "kev": v.kev,
                    "epssPercentile": v.epss.percentile if v.epss else None,
                    "fixedIn": v.fixed,
                },
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SBOM Visualizer",
                    "fullName": "SBOM Visualizer / OSV",
                    "informationUri": "https://osv.dev",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def _severity_band(severity: str) -> str:
    # Fallback numeric security-severity midpoints when no base score is available.
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0",
            "LOW": "2.0", "NONE": "0.0"}.get((severity or "").upper(), "0.0")
