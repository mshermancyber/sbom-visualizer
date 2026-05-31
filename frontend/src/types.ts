// Types mirrored from product/docs/API_CONTRACT.md (frozen v1).

export type Severity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "NONE"
  | "UNKNOWN";
export type Format = "cyclonedx" | "spdx" | "syft";
export type Depth = "direct" | "transitive" | "unknown";

export interface Component {
  name: string;
  version: string;
  type: string;
  purl: string;
  cpe: string;
  description: string;
  licenses: string[];
  supplier: string;
  language: string;
  bomRef: string; // resolved id used for dependency edges
  depth: Depth; // direct/transitive (computed)
}

export interface Dependency {
  ref: string;
  deps: string[];
}

export interface Cvss {
  score: number | null;
  severity: Severity;
  version: string | null;
  vector: string | null;
}

export interface Vuln {
  id: string;
  cveId: string | null;
  aliases: string[];
  description: string;
  cvss: Cvss;
  cwes: string[]; // e.g. ["CWE-502"]
  fixed: string[]; // fixed-in versions
  malicious: boolean;
  kev: boolean;
  epss: { score: number; percentile: number } | null;
  references: string[];
  published: string;
  modified: string;
  scoreSource?: "nvd" | "mitre" | "osv" | "ghsa" | null;
  // VEX suppression fields
  suppressed?: boolean;
  suppressionStatus?: string;
}

// ── Data-source connector status (v1.1) ──
export interface Source {
  id: string;
  name: string;
  enabled: boolean;
  configured: boolean;
  reachable: boolean | null;
  detail: string;
}

// ── License policy gate (v1.1) ──
export interface LicensePolicy {
  deny: string[];
  warn: string[];
}

export interface LicenseViolation {
  componentIndex: number;
  name: string;
  license: string;
  rule: "deny" | "warn";
}

export interface Finding {
  componentIndex: number;
  vulns: Vuln[];
}

export interface Sbom {
  id: string; // server-assigned handle for this parsed SBOM
  format: Format;
  formatVersion: string;
  name: string;
  version: string;
  timestamp: string;
  tools: string[];
  serialNumber: string;
  distro?: string;
  distroVersion?: string;
  components: Component[];
  dependencies: Dependency[];
}

export interface Summary {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  NONE: number;
  UNKNOWN: number;
  total: number;
  scanned: number;
  affected: number;
  withPurl: number;
}

export interface Coverage {
  total: number;
  queryable: number;
  skipped: number;
  oci: number;
  devel: number;
  noId: number;
  other: number;
}

export interface Verdict {
  status: "PASS" | "REVIEW" | "FAIL";
  reasons: string[];
  policy: "strict" | "standard" | "lenient";
}

export interface RemediationItem {
  componentIndex: number;
  name: string;
  currentVersion: string;
  target: string;
  cvesResolved: number;
  kevCount: number;
  maxEpssPercentile: number | null;
  riskRemoved: number;
  sevCounts: Record<Severity, number>;
  cveIds: string[];
}

export interface Completeness {
  overallPct: number;
  fieldStats: Record<string, { present: number; total: number; pct: number }>;
}

export interface RiskScore {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  pct: number;
  copyleft: number;
  noLic: number;
}

export interface Assessment {
  verdict: Verdict;
  risk: RiskScore;
  summary: Summary;
  coverage: Coverage;
  remediation: RemediationItem[];
  noFix: { componentIndex: number; name: string; vulnCount: number }[];
  topCwes: { id: string; name: string; count: number }[];
  kevCount: number;
  maliciousCount: number;
  completeness: Completeness;
  licenseViolations: LicenseViolation[];
}

// ── Scan response ──
export interface ScanResult {
  findings: Finding[];
  summary: Summary;
  errors: string[];
}

export type Policy = "strict" | "standard" | "lenient";

// ── Async scan job ──
export interface AsyncJobRef {
  jobId: string;
  status: string;
}

export interface AsyncJob {
  jobId: string;
  status: "running" | "done" | "error";
  result?: ScanResult;
}

// ── Scan persistence ──
export interface ScanListItem {
  id: string;
  sbomName: string;
  sbomFormat: string;
  componentCount: number;
  createdAt: string;
  summary: Summary;
}

export interface ScanListResponse {
  scans: ScanListItem[];
}

export interface SavedScan {
  id: string;
  sbomName: string;
  sbomFormat: string;
  componentCount: number;
  createdAt: string;
  summary: Summary;
  findings: Finding[];
}

// ── VEX / Suppression ──
export type SuppressionStatus =
  | "not_affected"
  | "false_positive"
  | "in_triage"
  | "accepted_risk";

export interface Suppression {
  id: string;
  cveId: string;
  componentPurl: string;
  status: SuppressionStatus;
  note?: string;
  expiresAt?: string;
  createdAt: string;
}

export interface SuppressionParams {
  cveId: string;
  componentPurl: string;
  status: SuppressionStatus;
  note?: string;
  expiresAt?: string;
}

export interface SuppressionsResponse {
  suppressions: Suppression[];
}

export interface AppliedFindingsResponse {
  findings: Finding[];
}

// ── Aggregate state for one loaded SBOM ──
export interface LoadedSbom {
  sbom: Sbom;
  filename: string;
  filesize: number;
  scan: ScanResult | null;
  assessment: Assessment | null;
  // Convenience: componentIndex -> vulns
  findingsByComp: Map<number, Vuln[]>;
}
