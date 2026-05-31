import type { LoadedSbom, Severity } from "../types";
import { escapeHtml, SEV_ORDER } from "../util";

interface CompareSelection {
  a: number | null;
  b: number | null;
}

/**
 * Side-by-side SBOM comparison with two independent pickers:
 * Baseline (A) and Comparison (B). Either picker can select any loaded SBOM.
 * Changing either re-renders via `onPick`.
 */
export function renderCompare(
  el: HTMLElement,
  files: LoadedSbom[],
  selection: CompareSelection,
  onPick: (sel: CompareSelection) => void,
): void {
  el.innerHTML = "";

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-git-diff"></i> Compare SBOMs</div>`;
  el.appendChild(header);

  if (files.length < 2) {
    const note = document.createElement("div");
    note.className = "loading";
    note.textContent =
      "Load a second SBOM (via file / paste / URL) to compare two side by side.";
    el.appendChild(note);
    return;
  }

  // Resolve A and B, defaulting to two distinct files.
  let aIdx = clamp(selection.a, files.length);
  let bIdx = clamp(selection.b, files.length);
  if (aIdx == null) aIdx = 0;
  if (bIdx == null) bIdx = aIdx === 0 ? 1 : 0;

  const fileLabel = (f: LoadedSbom, i: number) =>
    f.sbom.name || f.filename || `SBOM ${i + 1}`;

  const optionsFor = (selected: number) =>
    files
      .map(
        (f, i) =>
          `<option value="${i}"${i === selected ? " selected" : ""}>${escapeHtml(fileLabel(f, i))}</option>`,
      )
      .join("");

  // ── Pickers ──
  const pickers = document.createElement("div");
  pickers.className = "table-controls";
  pickers.style.cssText = "display:flex;gap:16px;flex-wrap:wrap;align-items:center";
  pickers.innerHTML = `
    <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2)">
      <span class="count-badge" style="background:var(--accent-bg,#0c1d37);color:var(--accent)">Baseline (A)</span>
      <select class="filter-select" data-pick-a>${optionsFor(aIdx)}</select>
    </label>
    <i class="ti ti-arrow-right" style="color:var(--text3)"></i>
    <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2)">
      <span class="count-badge" style="background:var(--purple-bg);color:var(--purple)">Comparison (B)</span>
      <select class="filter-select" data-pick-b>${optionsFor(bIdx)}</select>
    </label>`;
  el.appendChild(pickers);

  pickers
    .querySelector<HTMLSelectElement>("[data-pick-a]")!
    .addEventListener("change", (e) =>
      onPick({ a: Number((e.target as HTMLSelectElement).value), b: bIdx }),
    );
  pickers
    .querySelector<HTMLSelectElement>("[data-pick-b]")!
    .addEventListener("change", (e) =>
      onPick({ a: aIdx, b: Number((e.target as HTMLSelectElement).value) }),
    );

  const a = files[aIdx];
  const b = files[bIdx];

  if (aIdx === bIdx) {
    const note = document.createElement("div");
    note.className = "loading";
    note.textContent =
      "Baseline and Comparison are the same SBOM — pick a different file on one side to see a diff.";
    el.appendChild(note);
  }

  // ── Side-by-side summary columns ──
  const cols = document.createElement("div");
  cols.className = "charts-grid";
  cols.innerHTML =
    summaryColumn("A · Baseline", a, aIdx, "var(--accent)") +
    summaryColumn("B · Comparison", b, bIdx, "var(--purple)");
  el.appendChild(cols);

  // ── Verdict / risk delta ──
  if (a.assessment && b.assessment) {
    el.appendChild(deltaRow(a, b));
  }

  // ── Component diff ──
  const key = (n: string, v: string) => `${n}@${v}`;
  const setA = new Map(a.sbom.components.map((c) => [key(c.name, c.version), c]));
  const setB = new Map(b.sbom.components.map((c) => [key(c.name, c.version), c]));
  const added = [...setB.keys()].filter((k) => !setA.has(k));
  const removed = [...setA.keys()].filter((k) => !setB.has(k));
  const common = [...setA.keys()].filter((k) => setB.has(k));

  // version-changed: same name in both, different version
  const nameVerA = new Map<string, string>();
  for (const c of a.sbom.components) nameVerA.set(c.name, c.version);
  const changed: { name: string; from: string; to: string }[] = [];
  for (const c of b.sbom.components) {
    const prev = nameVerA.get(c.name);
    if (prev != null && prev !== c.version)
      changed.push({ name: c.name, from: prev, to: c.version });
  }

  const stats = document.createElement("div");
  stats.className = "stats-row";
  stats.innerHTML = `
    <div class="stat-card green"><div class="stat-label">Added (in B)</div><div class="stat-value diff-added">${added.length}</div></div>
    <div class="stat-card red"><div class="stat-label">Removed (from A)</div><div class="stat-value diff-removed" style="text-decoration:none">${removed.length}</div></div>
    <div class="stat-card amber"><div class="stat-label">Version Changed</div><div class="stat-value diff-changed">${changed.length}</div></div>
    <div class="stat-card"><div class="stat-label">Unchanged</div><div class="stat-value">${common.length - changed.length}</div></div>`;
  el.appendChild(stats);

  const lists = document.createElement("div");
  lists.className = "charts-grid";
  const listCard = (title: string, items: string[], cls: string) =>
    `<div class="chart-card"><div class="chart-title">${escapeHtml(title)} (${items.length})</div>
      <div style="display:flex;flex-direction:column;gap:4px;max-height:300px;overflow:auto">
        ${
          items.length
            ? items
                .map(
                  (k) =>
                    `<div class="${cls}" style="font-family:var(--font);font-size:12px">${escapeHtml(k)}</div>`,
                )
                .join("")
            : '<div style="color:var(--text3);font-size:12px">none</div>'
        }
      </div></div>`;
  lists.innerHTML =
    listCard("Added", added, "diff-added") +
    listCard("Removed", removed, "diff-removed") +
    listCard(
      "Version changed",
      changed.map((c) => `${c.name}: ${c.from} → ${c.to}`),
      "diff-changed",
    );
  el.appendChild(lists);
}

function clamp(idx: number | null, len: number): number | null {
  if (idx == null) return null;
  if (idx < 0 || idx >= len) return null;
  return idx;
}

/** One column of the side-by-side: verdict + risk grade/score + severity summary. */
function summaryColumn(
  label: string,
  f: LoadedSbom,
  idx: number,
  accent: string,
): string {
  const name = f.sbom.name || f.filename || `SBOM ${idx + 1}`;
  const verdict = f.assessment?.verdict.status ?? null;
  const risk = f.assessment?.risk ?? null;
  const sum = f.scan?.summary ?? null;

  const verdictHtml = verdict
    ? `<span style="font-size:16px;font-weight:800;color:${verdictColor(verdict)}">${escapeHtml(verdict)}</span>`
    : `<span style="font-size:13px;color:var(--text3)">not assessed</span>`;

  const riskHtml = risk
    ? `<span style="font-family:var(--font);font-size:13px;color:var(--text2)">Grade <strong style="color:${gradeColor(risk.grade)}">${escapeHtml(risk.grade)}</strong> · ${risk.score}/1000</span>`
    : `<span style="font-size:12px;color:var(--text3)">no risk score</span>`;

  const sevRows = SEV_ORDER.filter((s) => s !== "NONE")
    .map((s) => {
      const n = sum ? (sum[s] ?? 0) : 0;
      return `<div style="display:flex;justify-content:space-between;font-size:12px;font-family:var(--font)">
        <span style="color:var(--text3)">${sevDot(s)} ${escapeHtml(s)}</span>
        <span style="color:var(--text);font-weight:600">${n}</span>
      </div>`;
    })
    .join("");

  return `<div class="chart-card" style="border-top:3px solid ${accent}">
    <div class="chart-title" style="display:flex;justify-content:space-between;gap:8px">
      <span>${escapeHtml(label)}</span>
    </div>
    <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:8px;word-break:break-word">${escapeHtml(name)}</div>
    <div style="display:flex;flex-direction:column;gap:6px">
      <div style="display:flex;align-items:baseline;gap:10px">
        <span style="font-size:11px;color:var(--text3)">Verdict</span> ${verdictHtml}
      </div>
      <div>${riskHtml}</div>
      <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text3)">
        <span>${f.sbom.components.length} components</span>
        <span>${sum ? sum.total + " CVEs" : "not scanned"}</span>
      </div>
      <div style="border-top:1px solid var(--border);margin-top:4px;padding-top:6px;display:flex;flex-direction:column;gap:3px">
        ${sevRows}
      </div>
    </div>
  </div>`;
}

/** Verdict + risk delta between A and B. */
function deltaRow(a: LoadedSbom, b: LoadedSbom): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "stats-row";
  const ra = a.assessment!.risk;
  const rb = b.assessment!.risk;
  const va = a.assessment!.verdict.status;
  const vb = b.assessment!.verdict.status;
  const totalA = a.scan?.summary.total ?? 0;
  const totalB = b.scan?.summary.total ?? 0;

  const scoreDelta = rb.score - ra.score;
  const cveDelta = totalB - totalA;

  // For risk score & CVE counts, lower is better → an increase is "bad" (red).
  const scoreColor =
    scoreDelta === 0
      ? "var(--text2)"
      : scoreDelta > 0
        ? "var(--red)"
        : "var(--green)";
  const cveColor =
    cveDelta === 0
      ? "var(--text2)"
      : cveDelta > 0
        ? "var(--red)"
        : "var(--green)";

  const verdictDelta =
    va === vb
      ? `<span style="color:var(--text2)">unchanged (${escapeHtml(va)})</span>`
      : `<span style="color:${verdictColor(va)}">${escapeHtml(va)}</span> <span style="color:var(--text3)">→</span> <span style="color:${verdictColor(vb)}">${escapeHtml(vb)}</span>`;

  wrap.innerHTML = `
    <div class="stat-card"><div class="stat-label">Verdict A → B</div><div class="stat-value" style="font-size:15px;padding-top:6px">${verdictDelta}</div></div>
    <div class="stat-card"><div class="stat-label">Risk Score Δ</div><div class="stat-value" style="color:${scoreColor}">${fmtDelta(scoreDelta)}</div><div class="stat-sub">${ra.score} → ${rb.score}</div></div>
    <div class="stat-card"><div class="stat-label">Grade A → B</div><div class="stat-value" style="font-size:18px"><span style="color:${gradeColor(ra.grade)}">${escapeHtml(ra.grade)}</span> <span style="color:var(--text3);font-size:13px">→</span> <span style="color:${gradeColor(rb.grade)}">${escapeHtml(rb.grade)}</span></div></div>
    <div class="stat-card"><div class="stat-label">CVE Count Δ</div><div class="stat-value" style="color:${cveColor}">${fmtDelta(cveDelta)}</div><div class="stat-sub">${totalA} → ${totalB}</div></div>`;
  return wrap;
}

function fmtDelta(n: number): string {
  if (n === 0) return "±0";
  return n > 0 ? `+${n}` : String(n);
}

function verdictColor(status: string): string {
  return status === "PASS"
    ? "var(--green)"
    : status === "FAIL"
      ? "var(--red)"
      : "var(--amber)";
}

function gradeColor(grade: string): string {
  switch (grade) {
    case "A":
      return "var(--green)";
    case "B":
      return "#7fb800";
    case "C":
      return "var(--amber)";
    case "D":
      return "#f0883e";
    default:
      return "var(--red)";
  }
}

function sevDot(s: Severity): string {
  const color =
    s === "CRITICAL"
      ? "#ff4444"
      : s === "HIGH"
        ? "var(--red)"
        : s === "MEDIUM"
          ? "#f0883e"
          : s === "LOW"
            ? "var(--amber)"
            : "var(--text3)";
  return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${color}"></span>`;
}
