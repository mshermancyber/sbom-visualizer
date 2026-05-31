import type { LoadedSbom, Policy, Vuln } from "./types";

export type ViewName =
  | "overview"
  | "components"
  | "licenses"
  | "dependencies"
  | "vulnerabilities"
  | "remediation"
  | "compare"
  | "completeness"
  | "graph"
  | "suppliers"
  | "transitive";

export interface AppState {
  files: LoadedSbom[];
  active: number;
  // Compare view: two independent picks (indices into `files`), or null when unset.
  compareA: number | null;
  compareB: number | null;
  view: ViewName;
  policy: Policy;
  theme: "dark" | "light";
}

export const state: AppState = {
  files: [],
  active: -1,
  compareA: null,
  compareB: null,
  view: "overview",
  policy: "standard",
  theme: "dark",
};

export function activeFile(): LoadedSbom | null {
  return state.active >= 0 ? state.files[state.active] ?? null : null;
}

/** Build a componentIndex -> vulns map from a scan result. */
export function buildFindingsMap(
  findings: { componentIndex: number; vulns: Vuln[] }[],
): Map<number, Vuln[]> {
  const m = new Map<number, Vuln[]>();
  for (const f of findings) m.set(f.componentIndex, f.vulns);
  return m;
}
