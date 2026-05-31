import type {
  Sbom,
  ScanResult,
  Assessment,
  Finding,
  Summary,
  Policy,
  Source,
  LicensePolicy,
  AsyncJobRef,
  AsyncJob,
  ScanListResponse,
  SavedScan,
  SuppressionParams,
  SuppressionsResponse,
  AppliedFindingsResponse,
} from "./types";
import { debug } from "./debug";

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const done = debug.time("api", `POST ${path}`, "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e) {
    done("network-error");
    throw new ApiError(
      `Network error contacting ${path}: ${(e as Error).message}`,
      0,
    );
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data && typeof data.error === "string") msg = data.error;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(msg, resp.status);
  }
  return (await resp.json()) as T;
}

async function getJson<T>(path: string): Promise<T> {
  const done = debug.time("api", `GET ${path}`, "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + path);
  } catch (e) {
    done("network-error");
    throw new ApiError(
      `Network error contacting ${path}: ${(e as Error).message}`,
      0,
    );
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data && typeof data.error === "string") msg = data.error;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(msg, resp.status);
  }
  return (await resp.json()) as T;
}

async function deleteJson<T>(path: string): Promise<T> {
  const done = debug.time("api", `DELETE ${path}`, "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + path, {
      method: "DELETE",
    });
  } catch (e) {
    done("network-error");
    throw new ApiError(
      `Network error contacting ${path}: ${(e as Error).message}`,
      0,
    );
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data && typeof data.error === "string") msg = data.error;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(msg, resp.status);
  }
  return (await resp.json()) as T;
}

/** POST /api/parse with a raw SBOM object/string. */
export async function parse(raw: unknown): Promise<Sbom> {
  const res = await postJson<{ sbom: Sbom }>("/parse", { raw });
  return res.sbom;
}

/** POST /api/parse with a URL (server-side fetch). */
export async function parseUrl(url: string): Promise<Sbom> {
  const res = await postJson<{ sbom: Sbom }>("/parse", { url });
  return res.sbom;
}

/** POST /api/scan (synchronous). */
export async function scan(
  sbom: Sbom,
  options?: {
    kev?: boolean;
    epss?: boolean;
    testMode?: boolean;
    sources?: { nvd?: boolean; mitre?: boolean; epss?: boolean; kev?: boolean };
  },
): Promise<ScanResult> {
  return postJson<ScanResult>("/scan", { sbom, options });
}

/** POST /api/scan/async — returns immediately with jobId. */
export async function scanAsync(
  sbom: Sbom,
  options?: {
    kev?: boolean;
    epss?: boolean;
    testMode?: boolean;
    sources?: { nvd?: boolean; mitre?: boolean; epss?: boolean; kev?: boolean };
  },
): Promise<AsyncJobRef> {
  return postJson<AsyncJobRef>("/scan/async", { sbom, options });
}

/** GET /api/scan/jobs/{jobId} — poll for job status/result. */
export async function pollJob(jobId: string): Promise<AsyncJob> {
  return getJson<AsyncJob>(`/scan/jobs/${encodeURIComponent(jobId)}`);
}

/** GET /api/scan/jobs — list all jobs. */
export async function listJobs(): Promise<AsyncJob[]> {
  return getJson<AsyncJob[]>("/scan/jobs");
}

/** POST /api/assess. */
export async function assess(
  sbom: Sbom,
  findings: Finding[],
  summary: Summary,
  policy: Policy = "standard",
  licensePolicy?: LicensePolicy,
): Promise<Assessment> {
  const res = await postJson<{ assessment: Assessment }>("/assess", {
    sbom,
    findings,
    summary,
    policy,
    licensePolicy,
  });
  return res.assessment;
}

/** GET /api/sources → data-source connector status. */
export async function getSources(): Promise<{ sources: Source[] }> {
  return getJson<{ sources: Source[] }>("/sources");
}

/** POST /api/export/sarif → SARIF 2.1.0 JSON (as text for download). */
export async function exportSarif(
  sbom: Sbom,
  findings: Finding[],
): Promise<string> {
  const done = debug.time("api", "POST /export/sarif", "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + "/export/sarif", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbom, findings }),
    });
  } catch (e) {
    done("network-error");
    throw new ApiError(`Network error: ${(e as Error).message}`, 0);
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data?.error) msg = data.error;
    } catch {
      /* ignore */
    }
    throw new ApiError(msg, resp.status);
  }
  return resp.text();
}

/** POST /api/report → self-contained HTML string. */
export async function report(
  sbom: Sbom,
  findings: Finding[],
  summary: Summary,
  assessment: Assessment | null,
): Promise<string> {
  const done = debug.time("api", "POST /report", "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + "/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbom, findings, summary, assessment, format: "html" }),
    });
  } catch (e) {
    done("network-error");
    throw new ApiError(`Network error: ${(e as Error).message}`, 0);
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data?.error) msg = data.error;
    } catch {
      /* ignore */
    }
    throw new ApiError(msg, resp.status);
  }
  return resp.text();
}

/** POST /api/export/normalized → normalized SBOM JSON (as text for download). */
export async function exportNormalized(sbom: Sbom): Promise<string> {
  const done = debug.time("api", "POST /export/normalized", "info");
  let resp: Response;
  try {
    resp = await fetch(BASE + "/export/normalized", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sbom }),
    });
  } catch (e) {
    done("network-error");
    throw new ApiError(`Network error: ${(e as Error).message}`, 0);
  }
  done(`status=${resp.status}`);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const data = (await resp.json()) as { error?: string };
      if (data?.error) msg = data.error;
    } catch {
      /* ignore */
    }
    throw new ApiError(msg, resp.status);
  }
  return resp.text();
}

/** GET /api/health. */
export async function health(): Promise<{ status: string; version: string }> {
  return getJson<{ status: string; version: string }>("/health");
}

// ── Scan persistence ─────────────────────────────────────────────────────────

/** GET /api/scans → list of recent scan summaries. */
export async function listScans(): Promise<ScanListResponse> {
  return getJson<ScanListResponse>("/scans");
}

/** GET /api/scans/{id} → full scan with findings. */
export async function getScan(id: string): Promise<SavedScan> {
  return getJson<SavedScan>(`/scans/${encodeURIComponent(id)}`);
}

// ── VEX / Suppression ────────────────────────────────────────────────────────

/** POST /api/vex/suppressions → create a suppression. */
export async function createSuppression(
  params: SuppressionParams,
): Promise<{ suppression: import("./types").Suppression }> {
  return postJson<{ suppression: import("./types").Suppression }>(
    "/vex/suppressions",
    params,
  );
}

/** GET /api/vex/suppressions?cveId=&componentPurl= → list suppressions. */
export async function listSuppressions(
  filters?: { cveId?: string; componentPurl?: string },
): Promise<SuppressionsResponse> {
  const params = new URLSearchParams();
  if (filters?.cveId) params.set("cveId", filters.cveId);
  if (filters?.componentPurl) params.set("componentPurl", filters.componentPurl);
  const qs = params.toString();
  return getJson<SuppressionsResponse>(`/vex/suppressions${qs ? "?" + qs : ""}`);
}

/** DELETE /api/vex/suppressions/{id} → delete a suppression. */
export async function deleteSuppression(id: string): Promise<void> {
  await deleteJson<unknown>(`/vex/suppressions/${encodeURIComponent(id)}`);
}

/** POST /api/vex/apply → apply suppressions to findings. */
export async function applySuppressions(
  findings: Finding[],
  suppressions?: import("./types").Suppression[],
): Promise<AppliedFindingsResponse> {
  return postJson<AppliedFindingsResponse>("/vex/apply", {
    findings,
    suppressions,
  });
}
