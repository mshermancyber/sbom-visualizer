import type { LoadedSbom } from "../types";
import { escapeHtml } from "../util";

export function renderDependencies(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const { sbom } = file;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-git-branch"></i> Dependencies</div>`;
  el.appendChild(header);

  if (!sbom.dependencies.length) {
    el.innerHTML += `<div class="loading">No dependency relationships in this SBOM.</div>`;
    return;
  }

  // ref -> component label
  const refLabel = new Map<string, string>();
  for (const c of sbom.components) {
    if (c.bomRef) refLabel.set(c.bomRef, `${c.name} ${c.version}`);
    refLabel.set(c.name, `${c.name} ${c.version}`);
  }
  const label = (ref: string) =>
    refLabel.get(ref) || ref.split("/").pop()?.split("#").pop() || ref;

  const direct = sbom.components.filter((c) => c.depth === "direct").length;
  const transitive = sbom.components.filter(
    (c) => c.depth === "transitive",
  ).length;

  const stats = document.createElement("div");
  stats.className = "stats-row";
  stats.innerHTML = `
    <div class="stat-card accent"><div class="stat-label">Relationships</div><div class="stat-value">${sbom.dependencies.length}</div></div>
    <div class="stat-card green"><div class="stat-label">Direct</div><div class="stat-value">${direct}</div></div>
    <div class="stat-card"><div class="stat-label">Transitive</div><div class="stat-value">${transitive}</div></div>`;
  el.appendChild(stats);

  const grid = document.createElement("div");
  grid.className = "deps-grid";
  grid.innerHTML = sbom.dependencies
    .filter((d) => d.deps.length)
    .map(
      (d) => `<div class="dep-card">
      <div class="dep-name">${escapeHtml(label(d.ref))}</div>
      <div class="dep-count">${d.deps.length} direct dep${d.deps.length === 1 ? "" : "s"}</div>
      <div class="dep-ver" style="white-space:normal">${d.deps
        .slice(0, 6)
        .map((dep) => escapeHtml(label(dep)))
        .join(", ")}${d.deps.length > 6 ? ` +${d.deps.length - 6}` : ""}</div>
    </div>`,
    )
    .join("");
  el.appendChild(grid);
}
