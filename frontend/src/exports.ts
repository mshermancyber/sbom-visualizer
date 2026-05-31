import type { LoadedSbom } from "./types";
import { csvRow, downloadText } from "./util";
import * as api from "./api";
import { toast } from "./ui";

export function exportComponentsCsv(file: LoadedSbom): void {
  const { sbom } = file;
  const header = [
    "name",
    "version",
    "type",
    "depth",
    "purl",
    "cpe",
    "licenses",
    "supplier",
    "language",
    "vulnCount",
  ];
  const lines = [csvRow(header)];
  sbom.components.forEach((c, i) => {
    const vc = file.findingsByComp.get(i)?.length ?? 0;
    lines.push(
      csvRow([
        c.name,
        c.version,
        c.type,
        c.depth,
        c.purl,
        c.cpe,
        c.licenses.join("; "),
        c.supplier,
        c.language,
        vc,
      ]),
    );
  });
  downloadText(
    `${safeName(sbom.name)}-components.csv`,
    lines.join("\r\n"),
    "text/csv",
  );
  toast("Components CSV downloaded", "success");
}

export function exportVulnsCsv(file: LoadedSbom): void {
  const { sbom } = file;
  const header = [
    "component",
    "version",
    "depth",
    "vulnId",
    "cveId",
    "severity",
    "cvssScore",
    "cvssVersion",
    "kev",
    "malicious",
    "epssScore",
    "epssPercentile",
    "cwes",
    "fixedIn",
  ];
  const lines = [csvRow(header)];
  for (const [idx, vulns] of file.findingsByComp) {
    const c = sbom.components[idx];
    if (!c) continue;
    for (const v of vulns) {
      lines.push(
        csvRow([
          c.name,
          c.version,
          c.depth,
          v.id,
          v.cveId ?? "",
          v.cvss.severity,
          v.cvss.score ?? "",
          v.cvss.version ?? "",
          v.kev ? "yes" : "",
          v.malicious ? "yes" : "",
          v.epss ? v.epss.score : "",
          v.epss ? v.epss.percentile : "",
          v.cwes.join("; "),
          v.fixed.join("; "),
        ]),
      );
    }
  }
  if (lines.length === 1) {
    toast("No vulnerabilities to export", "info");
    return;
  }
  downloadText(
    `${safeName(sbom.name)}-vulnerabilities.csv`,
    lines.join("\r\n"),
    "text/csv",
  );
  toast("Vulnerabilities CSV downloaded", "success");
}

export async function exportSarif(file: LoadedSbom): Promise<void> {
  if (!file.scan) {
    toast("Scan first to export SARIF findings", "info");
    return;
  }
  try {
    const findings = [...file.findingsByComp.entries()].map(
      ([componentIndex, vulns]) => ({ componentIndex, vulns }),
    );
    const json = await api.exportSarif(file.sbom, findings);
    downloadText(
      `${safeName(file.sbom.name)}.sarif.json`,
      json,
      "application/json",
    );
    toast("SARIF report downloaded", "success");
  } catch (e) {
    toast(`SARIF export failed: ${(e as Error).message}`, "error");
  }
}

export async function exportNormalizedJson(file: LoadedSbom): Promise<void> {
  try {
    const json = await api.exportNormalized(file.sbom);
    downloadText(
      `${safeName(file.sbom.name)}-normalized.json`,
      json,
      "application/json",
    );
    toast("Normalized JSON downloaded", "success");
  } catch (e) {
    toast(`Export failed: ${(e as Error).message}`, "error");
  }
}

export async function exportHtmlReport(file: LoadedSbom): Promise<void> {
  if (!file.scan || !file.assessment) {
    toast("Scan and assess first to build a report", "info");
    return;
  }
  try {
    const findings = [...file.findingsByComp.entries()].map(
      ([componentIndex, vulns]) => ({ componentIndex, vulns }),
    );
    const html = await api.report(
      file.sbom,
      findings,
      file.scan.summary,
      file.assessment,
    );
    downloadText(`${safeName(file.sbom.name)}-report.html`, html, "text/html");
    toast("HTML report downloaded", "success");
  } catch (e) {
    toast(`Report failed: ${(e as Error).message}`, "error");
  }
}

export async function printReport(file: LoadedSbom): Promise<void> {
  if (!file.scan) {
    toast("Scan and assess first to build a report", "info");
    return;
  }
  try {
    const findings = [...file.findingsByComp.entries()].map(
      ([componentIndex, vulns]) => ({ componentIndex, vulns }),
    );
    const html = await api.report(
      file.sbom,
      findings,
      file.scan.summary,
      file.assessment,
    );
    const win = window.open("", "_blank", "noopener,noreferrer");
    if (!win) {
      // Pop-up blocked — fall back to downloading the HTML as a file
      downloadText(`${safeName(file.sbom.name)}-report.html`, html, "text/html");
      toast("Pop-up blocked — downloaded HTML report instead", "info");
      return;
    }
    win.document.open();
    win.document.write(html);
    win.document.close();
    toast("Opening print dialog — choose Save as PDF", "success");
    // Use setTimeout only — the load event on a document.write-populated window
    // fires immediately or never and is unreliable. 800ms gives large reports
    // time to lay out before the print dialog opens.
    setTimeout(() => {
      try {
        win.print();
      } catch {
        // In sandboxed environments win.print() may throw; fall back to download
        downloadText(
          `${safeName(file.sbom.name)}-report.html`,
          html,
          "text/html",
        );
        toast("Print unavailable — downloaded HTML report instead", "info");
      }
    }, 800);
  } catch (e) {
    toast(`Report failed: ${(e as Error).message}`, "error");
  }
}

export async function copySummary(file: LoadedSbom): Promise<void> {
  const { sbom, scan, assessment } = file;
  const lines: string[] = [];
  lines.push(`SBOM: ${sbom.name || "Unnamed"} ${sbom.version || ""}`.trim());
  lines.push(`Format: ${sbom.format} ${sbom.formatVersion}`);
  lines.push(`Components: ${sbom.components.length}`);
  if (assessment) {
    lines.push(
      `Verdict: ${assessment.verdict.status} (${assessment.verdict.policy} policy)`,
    );
    if (assessment.verdict.reasons.length)
      lines.push(`  Reasons: ${assessment.verdict.reasons.join("; ")}`);
    lines.push(
      `Risk: ${assessment.risk.score}/1000 (grade ${assessment.risk.grade})`,
    );
  }
  if (scan) {
    const s = scan.summary;
    lines.push(
      `Vulnerabilities: ${s.total} total — ${s.CRITICAL} critical, ${s.HIGH} high, ${s.MEDIUM} medium, ${s.LOW} low`,
    );
    lines.push(`Affected components: ${s.affected}`);
  }
  if (assessment) {
    lines.push(`KEV: ${assessment.kevCount} · Malicious: ${assessment.maliciousCount}`);
    lines.push(`NTIA completeness: ${assessment.completeness.overallPct}%`);
  }
  const text = lines.join("\n");
  try {
    await navigator.clipboard.writeText(text);
    toast("Summary copied to clipboard", "success");
  } catch {
    // fallback
    downloadText(`${safeName(sbom.name)}-summary.txt`, text, "text/plain");
    toast("Clipboard unavailable — downloaded summary instead", "info");
  }
}

function safeName(name: string): string {
  return (name || "sbom").replace(/[^a-z0-9._-]+/gi, "_").slice(0, 60);
}
