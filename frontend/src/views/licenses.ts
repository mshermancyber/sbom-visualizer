import type { LoadedSbom, LicenseViolation } from "../types";
import { escapeHtml, licClass } from "../util";
import { openLicensePolicyModal } from "../settings";

export function renderLicenses(
  el: HTMLElement,
  file: LoadedSbom,
  onPolicyChange?: () => void,
): void {
  el.innerHTML = "";
  const { sbom } = file;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-license"></i> Licenses</div>
    <button class="export-btn" id="editLicPolicy"><i class="ti ti-gavel"></i> License policy</button>`;
  el.appendChild(header);
  header.querySelector("#editLicPolicy")?.addEventListener("click", () =>
    openLicensePolicyModal(() => onPolicyChange?.()),
  );

  // License-policy violations (from assessment)
  const violations: LicenseViolation[] = file.assessment?.licenseViolations ?? [];
  if (violations.length) {
    const denyCount = violations.filter((v) => v.rule === "deny").length;
    const warnCount = violations.filter((v) => v.rule === "warn").length;
    const vbox = document.createElement("div");
    vbox.style.cssText =
      "border:1px solid var(--border2);border-radius:var(--r2);overflow:hidden";
    vbox.innerHTML = `
      <div style="padding:10px 14px;background:var(--bg3);font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px">
        <i class="ti ti-gavel" style="color:var(--amber)"></i> License policy violations
        ${denyCount ? `<span class="sev-badge sev-badge-CRITICAL">${denyCount} deny</span>` : ""}
        ${warnCount ? `<span class="sev-badge sev-badge-MEDIUM">${warnCount} warn</span>` : ""}
      </div>
      <div style="display:flex;flex-direction:column">
        ${violations
          .map(
            (v) => `<div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-top:1px solid var(--border)">
              <span class="sev-badge ${v.rule === "deny" ? "sev-badge-CRITICAL" : "sev-badge-MEDIUM"}">${escapeHtml(v.rule)}</span>
              <span class="comp-name" style="flex:1">${escapeHtml(v.name)}</span>
              <span class="license-tag ${licClass(v.license)}">${escapeHtml(v.license)}</span>
            </div>`,
          )
          .join("")}
      </div>`;
    el.appendChild(vbox);
  }

  // Set of component indices that violate, for flagging in the grid below.
  const offendingLicenses = new Set(
    violations.map((v) => v.license.toLowerCase()),
  );

  const counts = new Map<string, number>();
  for (const c of sbom.components) {
    const lics = c.licenses.length ? c.licenses : ["(none)"];
    for (const l of lics) counts.set(l, (counts.get(l) || 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const copyleft = sorted.filter(([l]) => licClass(l) === "license-copyleft");
  const noLic = counts.get("(none)") || 0;

  const stats = document.createElement("div");
  stats.className = "stats-row";
  stats.innerHTML = `
    <div class="stat-card accent"><div class="stat-label">Unique Licenses</div><div class="stat-value">${sorted.filter(([l]) => l !== "(none)").length}</div></div>
    <div class="stat-card ${copyleft.length ? "amber" : "green"}"><div class="stat-label">Copyleft</div><div class="stat-value">${copyleft.reduce((s, [, n]) => s + n, 0)}</div><div class="stat-sub">${copyleft.length} distinct</div></div>
    <div class="stat-card ${noLic ? "red" : "green"}"><div class="stat-label">Unlicensed</div><div class="stat-value">${noLic}</div><div class="stat-sub">components</div></div>`;
  el.appendChild(stats);

  const grid = document.createElement("div");
  grid.className = "deps-grid";
  grid.innerHTML = sorted
    .map(([l, n]) => {
      const flagged = offendingLicenses.has(l.toLowerCase());
      return `<div class="dep-card"${flagged ? ' style="border-color:var(--red)"' : ""}>
      <div><span class="license-tag ${licClass(l)}">${escapeHtml(l)}</span>${flagged ? ' <i class="ti ti-gavel" title="Violates license policy" style="color:var(--red);font-size:13px"></i>' : ""}</div>
      <div class="dep-count">${n} component${n === 1 ? "" : "s"}</div>
    </div>`;
    })
    .join("");
  el.appendChild(grid);
}
