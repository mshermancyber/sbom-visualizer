import type { LoadedSbom } from "../types";
import { escapeHtml } from "../util";

export function renderCompleteness(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const a = file.assessment;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-clipboard-check"></i> SBOM Completeness</div>`;
  el.appendChild(header);

  if (!a) {
    el.innerHTML += `<div class="loading">No assessment available.</div>`;
    return;
  }

  const comp = a.completeness;
  const barColor =
    comp.overallPct >= 80
      ? "var(--green)"
      : comp.overallPct >= 50
        ? "var(--amber)"
        : "var(--red)";

  const overall = document.createElement("div");
  overall.className = "ntia-card";
  overall.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between">
      <div style="font-size:13px;font-weight:600;color:var(--text)">NTIA minimum-elements coverage</div>
      <div style="font-family:var(--font);font-size:20px;font-weight:700;color:${barColor}">${comp.overallPct}%</div>
    </div>
    <div class="completeness-bar-wrap"><div class="completeness-bar-fill" style="width:${comp.overallPct}%;background:${barColor}"></div></div>`;
  el.appendChild(overall);

  const grid = document.createElement("div");
  grid.className = "ntia-grid";
  grid.innerHTML = Object.entries(comp.fieldStats)
    .map(([field, st]) => {
      const ok = st.pct >= 95;
      const partial = st.pct >= 50;
      const icon = ok
        ? `<span class="ntia-check" style="color:var(--green)">✓</span>`
        : partial
          ? `<span class="ntia-check" style="color:var(--amber)">◐</span>`
          : `<span class="ntia-check" style="color:var(--red)">✗</span>`;
      return `<div class="ntia-card">
        <div class="ntia-field-row">
          ${icon}
          <span class="ntia-fname">${escapeHtml(field)}</span>
          <span class="ntia-fval">${st.present}/${st.total} (${st.pct}%)</span>
        </div>
        <div class="completeness-bar-wrap"><div class="completeness-bar-fill" style="width:${st.pct}%;background:${ok ? "var(--green)" : partial ? "var(--amber)" : "var(--red)"}"></div></div>
      </div>`;
    })
    .join("");
  el.appendChild(grid);
}
