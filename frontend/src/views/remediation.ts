import type { LoadedSbom, Severity } from "../types";
import { escapeHtml, SEV_ORDER } from "../util";

export function renderRemediation(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const a = file.assessment;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-tool"></i> Remediation Plan</div>`;
  el.appendChild(header);

  if (!a) {
    el.innerHTML += `<div class="loading">No assessment available. Scan an SBOM first.</div>`;
    return;
  }

  const plan = a.remediation;
  const totalCves = plan.reduce((s, p) => s + p.cvesResolved, 0);
  const totalRisk = plan.reduce((s, p) => s + p.riskRemoved, 0);

  const summary = document.createElement("div");
  summary.className = "stats-row";
  summary.innerHTML = `
    <div class="stat-card accent"><div class="stat-label">Fixable Packages</div><div class="stat-value">${plan.length}</div><div class="stat-sub">have a fixed-in target</div></div>
    <div class="stat-card green"><div class="stat-label">CVEs Resolved</div><div class="stat-value">${totalCves}</div><div class="stat-sub">if plan applied</div></div>
    <div class="stat-card amber"><div class="stat-label">Risk Removed</div><div class="stat-value">${totalRisk}</div><div class="stat-sub">weighted points</div></div>
    <div class="stat-card red"><div class="stat-label">No Fix Available</div><div class="stat-value">${a.noFix.length}</div><div class="stat-sub">packages</div></div>`;
  el.appendChild(summary);

  if (!plan.length) {
    el.innerHTML += `<div class="loading">No remediable vulnerabilities — nothing to upgrade.</div>`;
  } else {
    const sevChips = (counts: Record<Severity, number>) =>
      SEV_ORDER.filter((s) => counts[s] > 0)
        .map(
          (s) =>
            `<span class="sev-badge sev-badge-${s}">${counts[s]} ${s}</span>`,
        )
        .join("");

    const cards = document.createElement("div");
    cards.style.cssText = "display:flex;flex-direction:column;gap:12px";
    cards.innerHTML = plan
      .map(
        (p, i) => `<div class="diff-card">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <span style="font-family:var(--font);font-size:11px;color:var(--text3)">#${i + 1}</span>
          <div style="font-family:var(--font);font-size:14px;font-weight:600;color:var(--text);flex:1">${escapeHtml(p.name)}</div>
          <div style="display:flex;align-items:center;gap:6px;font-family:var(--font);font-size:12px">
            <span class="diff-removed">${escapeHtml(p.currentVersion || "—")}</span>
            <i class="ti ti-arrow-right" style="color:var(--text3)"></i>
            <span class="diff-added">${escapeHtml(p.target || "—")}</span>
          </div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
          ${sevChips(p.sevCounts)}
          ${p.kevCount ? `<span class="kev-badge"><i class="ti ti-bolt"></i> ${p.kevCount} KEV</span>` : ""}
          ${p.maxEpssPercentile != null ? `<span class="not-scanned-badge" style="color:var(--amber)"><i class="ti ti-chart-line"></i> EPSS ${Math.round(p.maxEpssPercentile * 100)}%</span>` : ""}
          <span class="count-badge">resolves ${p.cvesResolved} CVE${p.cvesResolved === 1 ? "" : "s"} · risk −${p.riskRemoved}</span>
        </div>
        ${p.cveIds.length ? `<div class="vuln-affected-chips">${p.cveIds.slice(0, 12).map((id) => `<span class="affected-chip">${escapeHtml(id)}</span>`).join("")}${p.cveIds.length > 12 ? `<span class="affected-chip">+${p.cveIds.length - 12} more</span>` : ""}</div>` : ""}
      </div>`,
      )
      .join("");
    el.appendChild(cards);
  }

  if (a.noFix.length) {
    const noFixHeader = document.createElement("div");
    noFixHeader.className = "section-header";
    noFixHeader.style.marginTop = "8px";
    noFixHeader.innerHTML = `<div class="section-title"><i class="ti ti-alert-octagon"></i> No Fix Available</div>`;
    el.appendChild(noFixHeader);

    const noFix = document.createElement("div");
    noFix.className = "deps-grid";
    noFix.innerHTML = a.noFix
      .map(
        (n) => `<div class="dep-card">
        <div class="dep-name">${escapeHtml(n.name)}</div>
        <div class="dep-count">${n.vulnCount} unfixable vuln${n.vulnCount === 1 ? "" : "s"}</div>
      </div>`,
      )
      .join("");
    el.appendChild(noFix);
  }
}
