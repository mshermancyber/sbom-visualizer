"""Pydantic v2 models matching the FROZEN API contract (docs/API_CONTRACT.md)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
Format = Literal["cyclonedx", "spdx", "syft"]
Depth = Literal["direct", "transitive", "unknown"]
Policy = Literal["strict", "standard", "lenient"]


# ── Core SBOM shapes ──────────────────────────────────────────
class Component(BaseModel):
    name: str = ""
    version: str = ""
    type: str = "library"
    purl: str = ""
    cpe: str = ""
    description: str = ""
    licenses: list[str] = Field(default_factory=list)
    supplier: str = ""
    language: str = ""
    bomRef: str = ""           # resolved id used for dependency edges
    depth: Depth = "unknown"   # direct / transitive (computed)


class Dependency(BaseModel):
    ref: str
    deps: list[str] = Field(default_factory=list)


class Sbom(BaseModel):
    id: str = ""
    format: Format
    formatVersion: str = ""
    name: str = ""
    version: str = ""
    timestamp: str = ""
    tools: list[str] = Field(default_factory=list)
    serialNumber: str = ""
    distro: Optional[str] = None
    distroVersion: Optional[str] = None
    components: list[Component] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)


# ── Vulnerability shapes ──────────────────────────────────────
class Cvss(BaseModel):
    score: Optional[float] = None
    severity: Severity = "UNKNOWN"
    version: Optional[str] = None
    vector: Optional[str] = None


class Epss(BaseModel):
    score: float
    percentile: float


class Vuln(BaseModel):
    id: str
    cveId: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    cvss: Cvss = Field(default_factory=Cvss)
    cwes: list[str] = Field(default_factory=list)
    fixed: list[str] = Field(default_factory=list)
    malicious: bool = False
    kev: bool = False
    epss: Optional[Epss] = None
    references: list[str] = Field(default_factory=list)
    published: str = ""
    modified: str = ""
    scoreSource: Optional[Literal["nvd", "mitre", "osv", "ghsa"]] = None
    suppressed: bool = False
    suppressionStatus: Optional[str] = None


class Finding(BaseModel):
    componentIndex: int
    vulns: list[Vuln] = Field(default_factory=list)


# ── Assessment shapes ─────────────────────────────────────────
class Summary(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    NONE: int = 0
    UNKNOWN: int = 0
    total: int = 0
    scanned: int = 0
    affected: int = 0
    withPurl: int = 0
    suppressedCount: int = 0


class Coverage(BaseModel):
    total: int = 0
    queryable: int = 0
    skipped: int = 0
    oci: int = 0
    devel: int = 0
    noId: int = 0
    other: int = 0


class Verdict(BaseModel):
    status: Literal["PASS", "REVIEW", "FAIL"]
    reasons: list[str] = Field(default_factory=list)
    policy: Policy


class RemediationItem(BaseModel):
    componentIndex: int
    name: str
    currentVersion: str
    target: str
    cvesResolved: int
    kevCount: int
    maxEpssPercentile: Optional[float] = None
    riskRemoved: float
    sevCounts: dict[str, int]
    cveIds: list[str] = Field(default_factory=list)


class NoFixItem(BaseModel):
    componentIndex: int
    name: str
    vulnCount: int


class FieldStat(BaseModel):
    present: int
    total: int
    pct: int


class Completeness(BaseModel):
    overallPct: int
    fieldStats: dict[str, FieldStat]


class RiskScore(BaseModel):
    score: int
    grade: Literal["A", "B", "C", "D", "F"]
    pct: int
    copyleft: int
    noLic: int


class TopCwe(BaseModel):
    id: str
    name: str
    count: int


class LicenseViolation(BaseModel):
    componentIndex: int
    name: str
    license: str
    rule: Literal["deny", "warn"]


class Assessment(BaseModel):
    verdict: Verdict
    risk: RiskScore
    summary: Summary
    coverage: Coverage
    remediation: list[RemediationItem] = Field(default_factory=list)
    noFix: list[NoFixItem] = Field(default_factory=list)
    topCwes: list[TopCwe] = Field(default_factory=list)
    kevCount: int = 0
    maliciousCount: int = 0
    completeness: Completeness
    licenseViolations: list[LicenseViolation] = Field(default_factory=list)


# ── Request bodies ────────────────────────────────────────────
class ParseRequest(BaseModel):
    raw: object | None = None
    url: Optional[str] = None


class ScanSources(BaseModel):
    nvd: bool = True
    mitre: bool = True
    epss: bool = True
    kev: bool = True


class ScanOptions(BaseModel):
    kev: bool = True
    epss: bool = True
    testMode: bool = False
    sources: ScanSources = Field(default_factory=ScanSources)


class ScanRequest(BaseModel):
    sbom: Sbom
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanResponse(BaseModel):
    findings: list[Finding]
    summary: Summary
    errors: list[str] = Field(default_factory=list)
    scanId: Optional[str] = None


class LicensePolicy(BaseModel):
    deny: list[str] = Field(default_factory=list)
    warn: list[str] = Field(default_factory=list)


class VexSuppression(BaseModel):
    """Inlined suppression record for use in assess / apply requests."""
    id: Optional[str] = None
    cveId: str
    componentPurl: Optional[str] = None
    componentName: Optional[str] = None
    status: Literal[
        "not_affected", "false_positive", "in_triage", "resolved", "accepted_risk"
    ]
    justification: Optional[str] = None
    note: Optional[str] = None
    author: Optional[str] = None
    expiresAt: Optional[str] = None
    project: Optional[str] = None


class AssessRequest(BaseModel):
    sbom: Sbom
    findings: list[Finding] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)
    policy: Policy = "standard"
    licensePolicy: Optional[LicensePolicy] = None
    suppressions: Optional[list[VexSuppression]] = None


class VexApplyRequest(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    suppressions: Optional[list[VexSuppression]] = None


class SarifRequest(BaseModel):
    sbom: Sbom
    findings: list[Finding] = Field(default_factory=list)


class ReportRequest(BaseModel):
    sbom: Sbom
    findings: list[Finding] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)
    assessment: Optional[Assessment] = None   # None = report without scan results
    format: Literal["html"] = "html"
