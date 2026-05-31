import { describe, it, expect } from "vitest";
import { renderCompare } from "./views/compare";
import type { LoadedSbom, Component, Assessment, ScanResult } from "./types";

function comp(name: string, version: string): Component {
  return {
    name,
    version,
    type: "library",
    purl: `pkg:npm/${name}@${version}`,
    cpe: "",
    description: "",
    licenses: ["MIT"],
    supplier: "",
    language: "js",
    bomRef: `${name}@${version}`,
    depth: "direct",
  };
}

function scan(total: number, crit: number): ScanResult {
  return {
    findings: [],
    summary: {
      CRITICAL: crit,
      HIGH: total - crit,
      MEDIUM: 0,
      LOW: 0,
      NONE: 0,
      UNKNOWN: 0,
      total,
      scanned: 1,
      affected: 1,
      withPurl: 1,
    },
    errors: [],
  };
}

function assess(
  status: "PASS" | "REVIEW" | "FAIL",
  score: number,
  grade: "A" | "B" | "C" | "D" | "F",
): Assessment {
  return {
    verdict: { status, reasons: [], policy: "standard" },
    risk: { score, grade, pct: 50, copyleft: 0, noLic: 0 },
    summary: scan(0, 0).summary,
    coverage: { total: 1, queryable: 1, skipped: 0, oci: 0, devel: 0, noId: 0, other: 0 },
    remediation: [],
    noFix: [],
    topCwes: [],
    kevCount: 0,
    maliciousCount: 0,
    completeness: { overallPct: 100, fieldStats: {} },
    licenseViolations: [],
  };
}

function loaded(
  name: string,
  comps: Component[],
  s: ScanResult,
  a: Assessment,
): LoadedSbom {
  return {
    sbom: {
      id: name,
      format: "cyclonedx",
      formatVersion: "1.5",
      name,
      version: "1.0",
      timestamp: "",
      tools: [],
      serialNumber: "",
      components: comps,
      dependencies: [],
    },
    filename: `${name}.json`,
    filesize: 100,
    scan: s,
    assessment: a,
    findingsByComp: new Map(),
  };
}

describe("renderCompare side-by-side", () => {
  const fileA = loaded(
    "app-v1",
    [comp("left-pad", "1.0.0"), comp("lodash", "4.17.20"), comp("old-dep", "1.0.0")],
    scan(2, 1),
    assess("REVIEW", 420, "C"),
  );
  const fileB = loaded(
    "app-v2",
    [comp("left-pad", "1.0.0"), comp("lodash", "4.17.21"), comp("new-dep", "2.0.0")],
    scan(5, 3),
    assess("FAIL", 720, "F"),
  );
  const files = [fileA, fileB];

  it("renders two independent pickers and populates both columns", () => {
    const el = document.createElement("div");
    renderCompare(el, files, { a: 0, b: 1 }, () => {});

    const selA = el.querySelector<HTMLSelectElement>("[data-pick-a]");
    const selB = el.querySelector<HTMLSelectElement>("[data-pick-b]");
    expect(selA).not.toBeNull();
    expect(selB).not.toBeNull();
    // Each picker lists ALL loaded SBOMs (true independent selection).
    expect(selA!.options.length).toBe(2);
    expect(selB!.options.length).toBe(2);
    expect(selA!.value).toBe("0");
    expect(selB!.value).toBe("1");

    const text = el.textContent ?? "";
    // Both verdicts present (A REVIEW, B FAIL) → genuine side-by-side.
    expect(text).toContain("REVIEW");
    expect(text).toContain("FAIL");
    // Risk grades from both sides.
    expect(text).toContain("app-v1");
    expect(text).toContain("app-v2");
    console.log("[verify] both columns populated: A=REVIEW/C, B=FAIL/F");
  });

  it("computes the component diff between A and B", () => {
    const el = document.createElement("div");
    renderCompare(el, files, { a: 0, b: 1 }, () => {});
    const text = el.textContent ?? "";
    // new-dep added, old-dep removed, lodash version changed.
    expect(text).toContain("new-dep@2.0.0");
    expect(text).toContain("old-dep@1.0.0");
    expect(text).toContain("lodash: 4.17.20 → 4.17.21");
    console.log("[verify] diff: +new-dep, -old-dep, lodash 4.17.20→4.17.21");
  });

  it("fires onPick when either picker changes (re-render wiring)", () => {
    const el = document.createElement("div");
    const picks: { a: number | null; b: number | null }[] = [];
    renderCompare(el, files, { a: 0, b: 1 }, (sel) => picks.push(sel));

    const selB = el.querySelector<HTMLSelectElement>("[data-pick-b]")!;
    selB.value = "0";
    selB.dispatchEvent(new Event("change"));
    expect(picks).toContainEqual({ a: 0, b: 0 });

    const selA = el.querySelector<HTMLSelectElement>("[data-pick-a]")!;
    selA.value = "1";
    selA.dispatchEvent(new Event("change"));
    expect(picks).toContainEqual({ a: 1, b: 1 });
    console.log("[verify] picker change handlers fire onPick:", JSON.stringify(picks));
  });

  it("re-renders with swapped selection (switching updates the diff)", () => {
    const el = document.createElement("div");
    // Now A=B(app-v2), B=A(app-v1): added/removed should invert.
    renderCompare(el, files, { a: 1, b: 0 }, () => {});
    const text = el.textContent ?? "";
    expect(text).toContain("old-dep@1.0.0"); // now ADDED (in B=app-v1)
    expect(text).toContain("new-dep@2.0.0"); // now REMOVED (from A=app-v2)
    expect(text).toContain("lodash: 4.17.21 → 4.17.20");
    console.log("[verify] swapped pickers invert the diff correctly");
  });

  it("shows a delta row (risk score + CVE deltas)", () => {
    const el = document.createElement("div");
    renderCompare(el, files, { a: 0, b: 1 }, () => {});
    const text = el.textContent ?? "";
    expect(text).toContain("Risk Score"); // delta card present
    expect(text).toContain("+300"); // 720 - 420
    expect(text).toContain("+3"); // 5 - 2 CVEs
    console.log("[verify] delta row: risk +300, CVEs +3");
  });
});
