import { Chart } from "chart.js/auto";
import type { LoadedSbom, Verdict, RiskScore } from "../types";
import { escapeHtml, cssVar, fmtSize } from "../util";
import type { Policy } from "../types";

let typeChart: Chart | null = null;
let licChart: Chart | null = null;

const FMT_META: Record<string, { color: string; border: string; bg: string }> =
  {
    cyclonedx: { color: "var(--green)", border: "#25703a", bg: "var(--green-bg)" },
    spdx: { color: "var(--accent)", border: "#1f6feb", bg: "#0c1d37" },
    syft: { color: "var(--purple)", border: "#6e40c9", bg: "var(--purple-bg)" },
  };

function verdictBanner(
  verdict: Verdict | null,
  policy: Policy,
  onPolicy: (p: Policy) => void,
): HTMLElement {
  const wrap = document.createElement("div");
  const policies: Policy[] = ["strict", "standard", "lenient"];
  const selector = `<select class="filter-select" data-policy style="font-size:11px;padding:4px 8px;flex-shrink:0" title="Gate policy">
    ${policies
      .map(
        (p) =>
          `<option value="${p}"${p === policy ? " selected" : ""}>${p[0].toUpperCase() + p.slice(1)} gate</option>`,
      )
      .join("")}
  </select>`;

  if (!verdict) {
    wrap.innerHTML = `<div style="display:flex;align-items:center;gap:14px;background:var(--bg2);border:1px dashed var(--border2);border-radius:var(--r2);padding:14px 20px">
      <i class="ti ti-gavel" style="font-size:28px;color:var(--text3);opacity:0.5"></i>
      <div style="flex:1"><div style="font-size:15px;font-weight:700;color:var(--text2)">Shippability — not assessed</div>
      <div style="font-size:12px;color:var(--text3)">Awaiting assessment.</div></div>
      ${selector}</div>`;
  } else {
    const cfg = {
      FAIL: { color: "#cf222e", bg: "var(--red-bg)", icon: "ti-ban", label: "FAIL — do not ship" },
      REVIEW: { color: "var(--amber)", bg: "var(--amber-bg)", icon: "ti-alert-triangle", label: "REVIEW needed" },
      PASS: { color: "var(--green)", bg: "var(--green-bg)", icon: "ti-circle-check", label: "PASS" },
    }[verdict.status];
    wrap.innerHTML = `<div style="display:flex;align-items:center;gap:16px;background:${cfg.bg};border:2px solid ${cfg.color}66;border-radius:var(--r2);padding:16px 20px">
      <i class="ti ${cfg.icon}" style="font-size:34px;color:${cfg.color}"></i>
      <div style="flex:1;min-width:0">
        <div style="font-size:18px;font-weight:800;color:${cfg.color};letter-spacing:0.3px">${cfg.label}</div>
        <div style="font-size:12px;color:var(--text2);margin-top:2px">${escapeHtml((verdict.reasons || []).join(" · ") || "No blocking issues.")}</div>
      </div>
      ${selector}</div>`;
  }
  wrap
    .querySelector<HTMLSelectElement>("[data-policy]")
    ?.addEventListener("change", (e) =>
      onPolicy((e.target as HTMLSelectElement).value as Policy),
    );
  return wrap;
}

function riskCard(risk: RiskScore | null, kevCount: number): HTMLElement {
  const wrap = document.createElement("div");
  if (!risk) {
    wrap.innerHTML = `<div class="risk-score-card" style="border-color:var(--border2)">
      <i class="ti ti-shield-half" style="font-size:36px;color:var(--text3);opacity:0.4"></i>
      <div><div class="risk-score-label">SBOM Risk Score</div>
      <div style="font-size:14px;color:var(--text3);margin-top:4px">Not assessed.</div></div></div>`;
    return wrap;
  }
  const color =
    risk.grade === "A"
      ? "var(--green)"
      : risk.grade === "B"
        ? "#7fb800"
        : risk.grade === "C"
          ? "var(--amber)"
          : risk.grade === "D"
            ? "#f0883e"
            : "var(--red)";
  const circumference = 2 * Math.PI * 30;
  const filled = circumference * (1 - risk.pct / 100);
  wrap.innerHTML = `<div class="risk-score-card" style="border-color:${color}40">
    <svg class="risk-score-ring" viewBox="0 0 80 80">
      <circle cx="40" cy="40" r="30" fill="none" stroke="var(--bg4)" stroke-width="8"/>
      <circle cx="40" cy="40" r="30" fill="none" stroke="${color}" stroke-width="8"
        stroke-dasharray="${circumference}" stroke-dashoffset="${filled}"
        stroke-linecap="round" transform="rotate(-90 40 40)" style="transition:stroke-dashoffset 0.8s"/>
      <text x="40" y="36" text-anchor="middle" font-size="18" font-weight="700" fill="${color}" font-family="monospace">${risk.grade}</text>
      <text x="40" y="50" text-anchor="middle" font-size="8" fill="#6e7681" font-family="monospace">${risk.pct}%</text>
    </svg>
    <div style="flex:1">
      <div class="risk-score-label">SBOM Risk Score</div>
      <div style="display:flex;align-items:baseline;gap:10px;margin:4px 0">
        <span class="risk-score-num" style="color:${color}">${risk.score}</span>
        <span style="font-size:12px;color:var(--text3)">/ 1000</span>
      </div>
      <div class="risk-detail-grid">
        <div class="risk-detail-item"><div class="risk-detail-k">Copyleft</div><div class="risk-detail-v" style="color:var(--amber)">${risk.copyleft}</div></div>
        <div class="risk-detail-item"><div class="risk-detail-k">No License</div><div class="risk-detail-v" style="color:var(--amber)">${risk.noLic}</div></div>
        ${kevCount ? `<div class="risk-detail-item"><div class="risk-detail-k">KEV Hits</div><div class="risk-detail-v" style="color:#ff4444">⚡ ${kevCount}</div></div>` : ""}
      </div>
    </div>
  </div>`;
  return wrap;
}

export function renderOverview(
  el: HTMLElement,
  file: LoadedSbom,
  policy: Policy,
  onPolicy: (p: Policy) => void,
  goVuln: () => void,
): void {
  if (typeChart) {
    typeChart.destroy();
    typeChart = null;
  }
  if (licChart) {
    licChart.destroy();
    licChart = null;
  }
  el.innerHTML = "";
  const { sbom, scan, assessment } = file;

  el.appendChild(
    verdictBanner(assessment?.verdict ?? null, policy, onPolicy),
  );

  // Meta card
  const meta = FMT_META[sbom.format] ?? FMT_META.cyclonedx;
  const metaEl = document.createElement("div");
  metaEl.className = "sbom-meta";
  metaEl.innerHTML = `
    <div class="sbom-meta-header">
      <div style="flex:1">
        <div class="sbom-title">${escapeHtml(sbom.name || "Unnamed SBOM")}</div>
        ${sbom.version ? `<div class="sbom-subtitle">v${escapeHtml(sbom.version)}</div>` : ""}
      </div>
      <span class="sbom-type-badge" style="color:${meta.color};border-color:${meta.border};background:${meta.bg}">
        <i class="ti ti-shield-check"></i> ${escapeHtml((sbom.format + " " + (sbom.formatVersion || "")).toUpperCase())}
      </span>
    </div>
    <div class="meta-grid">
      ${sbom.timestamp ? `<div class="meta-item"><div class="meta-key">Generated</div><div class="meta-val">${escapeHtml(sbom.timestamp)}</div></div>` : ""}
      ${sbom.tools.length ? `<div class="meta-item"><div class="meta-key">Tools</div><div class="meta-val">${escapeHtml(sbom.tools.join(", "))}</div></div>` : ""}
      ${sbom.serialNumber ? `<div class="meta-item" style="grid-column:1/-1"><div class="meta-key">${sbom.format === "spdx" ? "Namespace" : "Serial"}</div><div class="meta-val">${escapeHtml(sbom.serialNumber)}</div></div>` : ""}
      ${sbom.distro ? `<div class="meta-item"><div class="meta-key">Distribution</div><div class="meta-val">${escapeHtml(sbom.distro)} ${escapeHtml(sbom.distroVersion || "")}</div></div>` : ""}
      ${file.filename ? `<div class="meta-item"><div class="meta-key">File</div><div class="meta-val">${escapeHtml(file.filename)} (${fmtSize(file.filesize)})</div></div>` : ""}
    </div>`;
  el.appendChild(metaEl);

  // Stats
  const licenseSet = new Set(sbom.components.flatMap((c) => c.licenses));
  const types = new Set(sbom.components.map((c) => c.type || "other"));
  const noLicense = sbom.components.filter((c) => !c.licenses.length).length;
  const covPct = sbom.components.length
    ? Math.round(((sbom.components.length - noLicense) / sbom.components.length) * 100)
    : 0;
  const sum = scan?.summary;
  const statsEl = document.createElement("div");
  statsEl.className = "stats-row";
  const vulnStat = sum
    ? `<div class="stat-card red" style="cursor:pointer" data-go-vuln title="View vulnerabilities">
        <div class="stat-label">CVEs Found</div>
        <div class="stat-value" style="color:${sum.CRITICAL ? "#ff4444" : sum.HIGH ? "var(--red)" : sum.MEDIUM ? "#f0883e" : "var(--green)"}">${sum.total}</div>
        <div class="stat-sub">${sum.CRITICAL} critical · ${sum.HIGH} high</div>
      </div>`
    : `<div class="stat-card" style="cursor:pointer;border-color:var(--border2)" data-go-vuln>
        <div class="stat-label">Vulnerabilities</div>
        <div class="stat-value" style="color:var(--text3);font-size:16px;padding-top:4px">Not scanned</div>
        <div class="stat-sub">click to view</div>
      </div>`;
  statsEl.innerHTML = `
    <div class="stat-card accent"><div class="stat-label">Components</div><div class="stat-value">${sbom.components.length}</div><div class="stat-sub">${types.size} types</div></div>
    <div class="stat-card green"><div class="stat-label">Unique Licenses</div><div class="stat-value">${licenseSet.size}</div><div class="stat-sub">${noLicense} unlicensed</div></div>
    <div class="stat-card"><div class="stat-label">Dependencies</div><div class="stat-value">${sbom.dependencies.length}</div><div class="stat-sub">relationships mapped</div></div>
    <div class="stat-card ${noLicense > 0 ? "amber" : "green"}"><div class="stat-label">License Coverage</div><div class="stat-value">${covPct}%</div><div class="stat-sub">of components</div></div>
    ${vulnStat}`;
  statsEl
    .querySelectorAll("[data-go-vuln]")
    .forEach((n) => n.addEventListener("click", goVuln));
  el.appendChild(statsEl);

  // Coverage / blind-spot
  const cov = assessment?.coverage;
  if (cov) {
    const covColor = cov.skipped === 0 ? "var(--green)" : "var(--amber)";
    const reasons: string[] = [];
    if (cov.oci) reasons.push(`${cov.oci} OCI`);
    if (cov.devel) reasons.push(`${cov.devel} devel`);
    if (cov.noId) reasons.push(`${cov.noId} no-id`);
    if (cov.other) reasons.push(`${cov.other} other`);
    const covEl = document.createElement("div");
    covEl.style.cssText = `font-size:12px;color:var(--text2);background:var(--bg2);border:1px solid var(--border);border-left:3px solid ${covColor};border-radius:var(--r);padding:8px 14px;display:flex;align-items:center;gap:8px`;
    covEl.innerHTML = `<i class="ti ti-radar-2" style="color:${covColor};font-size:16px"></i> <span><strong style="color:var(--text)">${cov.queryable} of ${cov.total}</strong> components are scannable via OSV${cov.skipped ? ` · <span style="color:var(--amber)">${cov.skipped} skipped (${escapeHtml(reasons.join(", "))})</span>` : " · full coverage"}</span>`;
    el.appendChild(covEl);
  }

  el.appendChild(riskCard(assessment?.risk ?? null, assessment?.kevCount ?? 0));

  // Charts
  const typeCount: Record<string, number> = {};
  for (const c of sbom.components) {
    const t = c.type || "other";
    typeCount[t] = (typeCount[t] || 0) + 1;
  }
  const licCount: Record<string, number> = {};
  for (const c of sbom.components) {
    const lics = c.licenses.length ? c.licenses : ["(none)"];
    for (const l of lics) licCount[l] = (licCount[l] || 0) + 1;
  }
  const topLicenses = Object.entries(licCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const chartsEl = document.createElement("div");
  chartsEl.className = "charts-grid";
  chartsEl.innerHTML = `
    <div class="chart-card">
      <div class="chart-title"><i class="ti ti-chart-donut-2"></i> Component Types</div>
      <div class="chart-wrap"><canvas id="typeChart" role="img" aria-label="Component types"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title"><i class="ti ti-certificate"></i> Top Licenses</div>
      <div class="chart-wrap" style="height:${Math.max(220, topLicenses.length * 32 + 60)}px"><canvas id="licChart" role="img" aria-label="Top licenses"></canvas></div>
    </div>`;
  el.appendChild(chartsEl);

  requestAnimationFrame(() => {
    const cText2 = cssVar("--text2") || "#8b949e";
    const cText3 = cssVar("--text3") || "#6e7681";
    const cGrid = cssVar("--bg4") || "#21262d";
    const cCard = cssVar("--bg2") || "#161b22";
    const cBar = cssVar("--accent2") || "#1f6feb";
    const typeColorMap: Record<string, string> = {
      library: "#378ADD",
      framework: "#7F77DD",
      application: "#1D9E75",
      container: "#BA7517",
      file: "#D85A30",
      os: "#639922",
      other: "#6e7681",
    };
    const typeLabels = Object.keys(typeCount);
    const typeCtx = document.getElementById("typeChart") as HTMLCanvasElement | null;
    if (typeCtx && typeLabels.length) {
      typeChart = new Chart(typeCtx, {
        type: "doughnut",
        data: {
          labels: typeLabels,
          datasets: [
            {
              data: typeLabels.map((t) => typeCount[t]),
              backgroundColor: typeLabels.map((t) => typeColorMap[t] || "#6e7681"),
              borderWidth: 2,
              borderColor: cCard,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "right",
              labels: { color: cText2, font: { size: 11 }, boxWidth: 12 },
            },
          },
        },
      });
    }
    const licCtx = document.getElementById("licChart") as HTMLCanvasElement | null;
    if (licCtx && topLicenses.length) {
      licChart = new Chart(licCtx, {
        type: "bar",
        data: {
          labels: topLicenses.map(([l]) => l),
          datasets: [
            {
              data: topLicenses.map(([, n]) => n),
              backgroundColor: cBar,
              borderRadius: 4,
            },
          ],
        },
        options: {
          indexAxis: "y",
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: cGrid }, ticks: { color: cText3, font: { size: 11 } } },
            y: { grid: { display: false }, ticks: { color: cText2, font: { size: 11 } } },
          },
        },
      });
    }
  });
}
