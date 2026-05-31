import "@tabler/icons-webfont/tabler-icons.min.css"; // self-hosted icons (bundled, CSP-safe)
import "@fontsource/jetbrains-mono/index.css";       // self-hosted mono font (bundled)
import "./styles.css";
import * as api from "./api";
import type {
  LoadedSbom,
  Policy,
  Sbom,
  Summary,
  ScanResult,
  AsyncJobRef,
  AsyncJob,
  SavedScan,
  Severity,
  Format,
  Depth,
} from "./types";
import { state, activeFile, buildFindingsMap, type ViewName } from "./store";
import { toast, openModal, toggleShortcutHelp } from "./ui";
import { escapeHtml, safeUrl } from "./util";
import { debug } from "./debug";
import { SAMPLE_SBOM } from "./sample";
import {
  exportComponentsCsv,
  exportVulnsCsv,
  exportNormalizedJson,
  exportHtmlReport,
  printReport,
  copySummary,
  exportSarif,
} from "./exports";
import {
  getLicensePolicy,
  openLicensePolicyModal,
  openSourcesModal,
} from "./settings";

import { renderOverview } from "./views/overview";
import { renderComponents } from "./views/components";
import { renderVulnerabilities } from "./views/vulnerabilities";
import { renderRemediation } from "./views/remediation";
import { renderLicenses } from "./views/licenses";
import { renderDependencies } from "./views/dependencies";
import { renderCompleteness } from "./views/completeness";
import { renderSuppliers } from "./views/suppliers";
import { renderTransitive } from "./views/transitive";
import { renderCompare } from "./views/compare";
import { renderGraph } from "./views/graph";

// ── Layout (mirrors the demo body markup) ──
const APP_HTML = `
<header class="site-header">
  <div class="site-logo"><img class="logo-img" src="/logo.jpg" alt="logo" /> SBOM Visualizer</div>
  <div style="flex:1;max-width:340px;position:relative;margin:0 8px">
    <i class="ti ti-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:15px;pointer-events:none"></i>
    <input id="globalSearch" type="text" placeholder="Search components, CVEs, licenses… (/ or Cmd+K)" autocomplete="off"
      style="width:100%;padding:7px 12px 7px 32px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;font-family:var(--font-ui);outline:none">
    <div id="globalSearchResults" style="display:none;position:absolute;top:calc(100% + 6px);left:0;right:0;background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r2);max-height:360px;overflow-y:auto;z-index:200;box-shadow:0 8px 24px #00000060"></div>
  </div>
  <div class="header-pills">
    <span class="format-pill pill-cyclonedx">CycloneDX</span>
    <span class="format-pill pill-spdx">SPDX</span>
    <span class="format-pill pill-syft">Syft JSON</span>
    <button id="sourcesToggle" title="Data sources status" class="header-icon-btn"><i class="ti ti-plug-connected"></i></button>
    <button id="policyToggle" title="License policy gate" class="header-icon-btn"><i class="ti ti-gavel"></i></button>
    <button id="themeToggle" title="Toggle light / dark theme" class="header-icon-btn"><i class="ti ti-sun"></i></button>
    <button id="helpToggle" title="Keyboard shortcuts (press ?)" class="header-icon-btn"><i class="ti ti-keyboard"></i></button>
  </div>
</header>
<div class="app-layout">
  <aside class="sidebar">
    <div class="drop-zone" id="dropZone">
      <input type="file" id="fileInput" accept=".json" multiple>
      <div class="drop-icon"><i class="ti ti-cloud-upload"></i></div>
      <div class="drop-title">Drop SBOM files here</div>
      <div class="drop-sub">Supports CycloneDX, SPDX, and Syft JSON formats. Multiple files OK.</div>
    </div>
    <button class="export-btn" style="justify-content:center" id="btnSample"><i class="ti ti-sparkles"></i> Load sample SBOM</button>
    <div style="display:flex;gap:6px">
      <button class="export-btn" style="flex:1;justify-content:center" id="btnPaste"><i class="ti ti-clipboard"></i> Paste</button>
      <button class="export-btn" style="flex:1;justify-content:center" id="btnUrl"><i class="ti ti-link"></i> From URL</button>
    </div>
    <div class="sidebar-section">
      <div class="sidebar-label">Loaded Files</div>
      <div id="fileList" style="display:flex;flex-direction:column;gap:6px;">
        <div style="font-size:12px;color:var(--text3);padding:8px 4px;">No files loaded yet</div>
      </div>
    </div>
    <div class="sidebar-section" id="scanSection" style="display:none;">
      <div class="sidebar-label">Vulnerability Scan</div>
      <button class="nvd-scan-btn" id="btnScan"><i class="ti ti-shield-search"></i> Scan for Vulnerabilities</button>
      <div id="scanStatus" style="font-size:11px;color:var(--text3);text-align:center;font-family:var(--font);display:none;margin-top:6px"></div>
    </div>
    <div class="sidebar-section" id="navSection" style="display:none;">
      <div class="sidebar-label">Views</div>
      <div class="sidebar-nav" id="sidebarNav"></div>
    </div>
    <div class="sidebar-section" id="exportSection" style="display:none;">
      <div class="sidebar-label">Export</div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        <button class="export-btn" id="exCsv"><i class="ti ti-file-spreadsheet"></i> Components CSV</button>
        <button class="export-btn" id="exVulnCsv"><i class="ti ti-file-alert"></i> Vulns CSV</button>
        <button class="export-btn" id="exSarif"><i class="ti ti-shield-code"></i> SARIF</button>
        <button class="export-btn" id="exHtml"><i class="ti ti-report"></i> HTML Report</button>
        <button class="export-btn" id="exPdf"><i class="ti ti-printer"></i> Save as PDF</button>
        <button class="export-btn" id="exJson"><i class="ti ti-file-code"></i> Normalized JSON</button>
        <button class="export-btn" id="exCopy"><i class="ti ti-clipboard-check"></i> Copy summary</button>
      </div>
    </div>
    <div class="sidebar-section" id="recentScansSection">
      <div class="sidebar-label" style="cursor:pointer;display:flex;align-items:center;gap:6px;user-select:none" id="recentScansToggle">
        <i class="ti ti-history"></i> Recent Scans
        <i class="ti ti-chevron-down" id="recentScansChevron" style="margin-left:auto;font-size:12px;transition:transform 0.2s"></i>
      </div>
      <div id="recentScansList" style="display:none;margin-top:6px;display:flex;flex-direction:column;gap:4px"></div>
    </div>
    <div class="sidebar-footer">
      <img class="logo-img" src="/logo.jpg" alt="" style="width:18px;height:18px" />
      <span><a href="https://github.com/mshermancyber/sbom-visualizer" target="_blank" rel="noopener noreferrer">SBOM Visualizer</a> · <a href="https://www.gnu.org/licenses/gpl-3.0.html" target="_blank" rel="noopener noreferrer">GPL-3.0</a></span>
    </div>
  </aside>
  <main class="main" id="mainContent">
    <div class="empty-state" id="emptyState">
      <i class="ti ti-file-code"></i>
      <div class="empty-title">No SBOM loaded</div>
      <div class="empty-sub">Upload a JSON SBOM file to inspect its components, licenses, and dependency graph. Supports all three major formats.</div>
      <div class="sample-formats">
        <span class="format-pill pill-cyclonedx">CycloneDX</span>
        <span class="format-pill pill-spdx">SPDX 2.x</span>
        <span class="format-pill pill-syft">Syft JSON</span>
      </div>
    </div>
    <div id="viewRoot" style="display:none;flex-direction:column;gap:20px;"></div>
  </main>
</div>
<div class="toast" id="toast"></div>`;

const NAV: { id: ViewName; icon: string; label: string }[] = [
  { id: "overview", icon: "ti-layout-dashboard", label: "Overview" },
  { id: "components", icon: "ti-package", label: "Components" },
  { id: "licenses", icon: "ti-license", label: "Licenses" },
  { id: "dependencies", icon: "ti-git-branch", label: "Dependencies" },
  { id: "vulnerabilities", icon: "ti-shield-exclamation", label: "Vulnerabilities" },
  { id: "remediation", icon: "ti-tool", label: "Remediation" },
  { id: "compare", icon: "ti-git-diff", label: "Compare" },
  { id: "completeness", icon: "ti-clipboard-check", label: "Completeness" },
  { id: "graph", icon: "ti-hierarchy-2", label: "Dep Graph" },
  { id: "suppliers", icon: "ti-building-factory-2", label: "Suppliers" },
  { id: "transitive", icon: "ti-binary-tree-2", label: "Vuln Paths" },
];

function boot(): void {
  const app = document.getElementById("app")!;
  app.innerHTML = APP_HTML;

  // theme
  const savedTheme = localStorage.getItem("sbom-theme");
  state.theme = savedTheme === "light" ? "light" : "dark";
  applyTheme();

  buildNav();
  wireSidebar();
  wireSearch();
  wireKeyboard();
  wireRecentScans();

  document.getElementById("themeToggle")?.addEventListener("click", toggleTheme);
  document
    .getElementById("helpToggle")
    ?.addEventListener("click", toggleShortcutHelp);
  document
    .getElementById("sourcesToggle")
    ?.addEventListener("click", openSourcesModal);
  document
    .getElementById("policyToggle")
    ?.addEventListener("click", () =>
      openLicensePolicyModal(() => void reassessActive()),
    );

  // ?sbom=<url> auto-load (backlog feature)
  const params = new URLSearchParams(location.search);
  const sbomUrl = params.get("sbom");
  if (sbomUrl) {
    const safe = safeUrl(sbomUrl);
    if (safe) ingest(() => api.parseUrl(safe), shortUrl(safe));
  }
}

function applyTheme(): void {
  document.body.classList.toggle("theme-light", state.theme === "light");
  const icon = document.querySelector("#themeToggle i");
  if (icon)
    icon.className = state.theme === "light" ? "ti ti-moon" : "ti ti-sun";
}
function toggleTheme(): void {
  state.theme = state.theme === "light" ? "dark" : "light";
  localStorage.setItem("sbom-theme", state.theme);
  applyTheme();
  renderActiveView();
}

function buildNav(): void {
  const nav = document.getElementById("sidebarNav")!;
  nav.innerHTML = NAV.map(
    (n) =>
      `<button class="nav-btn${n.id === state.view ? " active" : ""}" data-view="${n.id}">
        <i class="ti ${n.icon}"></i> ${escapeHtml(n.label)}
        ${n.id === "vulnerabilities" ? `<span id="vulnNavBadge" style="display:none;margin-left:auto;font-size:10px;background:var(--red-bg);color:var(--red);border:1px solid #f8514960;border-radius:20px;padding:1px 7px;font-family:var(--font)"></span>` : ""}
      </button>`,
  ).join("");
  nav.querySelectorAll<HTMLElement>("[data-view]").forEach((b) =>
    b.addEventListener("click", () => switchView(b.dataset.view as ViewName)),
  );
}

function wireSidebar(): void {
  const fileInput = document.getElementById("fileInput") as HTMLInputElement;
  const dropZone = document.getElementById("dropZone")!;
  fileInput.addEventListener("change", () => {
    if (fileInput.files) handleFiles([...fileInput.files]);
    fileInput.value = "";
  });
  ["dragover", "dragenter"].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    }),
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
    }),
  );
  dropZone.addEventListener("drop", (e) => {
    const dt = (e as DragEvent).dataTransfer;
    if (dt?.files?.length) handleFiles([...dt.files]);
  });

  document
    .getElementById("btnSample")
    ?.addEventListener("click", () =>
      ingest(() => api.parse(SAMPLE_SBOM), "sample-sbom.json"),
    );
  document.getElementById("btnPaste")?.addEventListener("click", openPasteModal);
  document.getElementById("btnUrl")?.addEventListener("click", openUrlModal);

  document.getElementById("exCsv")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) exportComponentsCsv(f);
  });
  document.getElementById("exVulnCsv")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) exportVulnsCsv(f);
  });
  document.getElementById("exSarif")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) void exportSarif(f);
  });
  document.getElementById("exHtml")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) void exportHtmlReport(f);
  });
  document.getElementById("exPdf")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) void printReport(f);
  });
  document.getElementById("exJson")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) void exportNormalizedJson(f);
  });
  document.getElementById("exCopy")?.addEventListener("click", () => {
    const f = activeFile();
    if (f) void copySummary(f);
  });
  document.getElementById("btnScan")?.addEventListener("click", () => void scanActive());
}

async function handleFiles(files: File[]): Promise<void> {
  // Single-file path is unchanged: parse → scan → assess, identical UX.
  if (files.length === 1) {
    const file = files[0];
    try {
      const raw = await readFileRaw(file);
      await ingest(() => api.parse(raw), file.name, file.size);
    } catch (e) {
      toast(`Failed to read ${file.name}: ${(e as Error).message}`, "error");
    }
    return;
  }

  // Multi-file path: parse all (sequential, cheap + server-handled), then scan
  // all concurrently so N scans don't serialize on the client.
  const t0 = debug.time("ingest", `parse ${files.length} files`, "info");
  const parsed: LoadedSbom[] = [];
  for (const file of files) {
    try {
      const raw = await readFileRaw(file);
      const sbom = await api.parse(raw);
      parsed.push({
        sbom,
        filename: file.name,
        filesize: file.size,
        scan: null,
        assessment: null,
        findingsByComp: new Map(),
      });
    } catch (e) {
      toast(`Failed to parse ${file.name}: ${(e as Error).message}`, "error");
    }
  }
  t0();
  if (!parsed.length) return;

  // Append all parsed files; activate the first newly-added one and show UI.
  const firstNewIdx = state.files.length;
  state.files.push(...parsed);
  state.active = firstNewIdx;
  renderFileList();
  showApp();
  switchView("overview");
  toast(`Parsed ${parsed.length} SBOMs. Scanning concurrently…`, "info");

  // Scan + assess every newly-parsed file concurrently. Each updates the UI as
  // it lands; we only mutate `f` (its own object) — never reorder state.files —
  // so there's no race on state.active or the file list.
  const scanAll = debug.time("scan", `scan ${parsed.length} files (parallel)`, "info");
  await Promise.all(
    parsed.map((f) =>
      scanFile(f).then(() => {
        renderFileList();
        // Only refresh the main view + badge if this file is the active one.
        if (activeFile() === f) {
          updateVulnBadge();
          renderActiveView();
        }
      }),
    ),
  );
  scanAll();
  const fails = parsed.filter(
    (f) => f.assessment?.verdict.status === "FAIL",
  ).length;
  toast(
    `Scanned ${parsed.length} SBOMs${fails ? ` — ${fails} FAIL` : ""}.`,
    fails ? "error" : "success",
  );
}

async function readFileRaw(file: File): Promise<unknown> {
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch {
    return text; // let the backend attempt to parse the raw string
  }
}

/**
 * Scan + assess a single LoadedSbom in place. Does NOT touch state.active or
 * any shared DOM button — safe to run concurrently for many files.
 */
async function scanFile(f: LoadedSbom): Promise<void> {
  const tScan = debug.time("scan", `scan ${f.filename}`, "debug");
  try {
    f.scan = await api.scan(f.sbom);
    f.findingsByComp = buildFindingsMap(f.scan.findings);
  } catch (e) {
    toast(`Scan failed for ${f.filename}: ${(e as Error).message}`, "error");
  }
  tScan(`${f.scan?.summary.total ?? 0} CVEs`);
  if (!f.scan) return;
  await applyAndAssess(f);
}

/**
 * Fetch suppressions, apply them to the current scan findings, then call
 * /api/assess. Shared by both sync and async scan paths.
 */
async function applyAndAssess(f: LoadedSbom): Promise<void> {
  if (!f.scan) return;
  const tAssess = debug.time("assess", `assess ${f.filename}`, "debug");
  // Fetch and apply VEX suppressions before assessing
  let findings = f.scan.findings;
  try {
    const { suppressions } = await api.listSuppressions();
    if (suppressions.length > 0) {
      const applied = await api.applySuppressions(findings, suppressions);
      findings = applied.findings;
      // Rebuild the findingsByComp map with suppression data applied
      f.findingsByComp = buildFindingsMap(findings);
    }
  } catch {
    // Suppression fetch/apply is best-effort; don't block assessment
  }
  try {
    f.assessment = await api.assess(
      f.sbom,
      findings,
      f.scan.summary,
      state.policy,
      getLicensePolicy(),
    );
  } catch (e) {
    toast(`Assessment failed for ${f.filename}: ${(e as Error).message}`, "error");
  }
  tAssess(f.assessment?.verdict.status ?? "n/a");
}

function openPasteModal(): void {
  openModal(
    "Paste SBOM JSON",
    `<textarea id="pasteArea" class="nvd-input" style="width:100%;min-height:240px;font-family:var(--font);resize:vertical" placeholder='{ "bomFormat": "CycloneDX", ... }'></textarea>
     <button class="nvd-scan-btn" id="pasteSubmit" style="margin-top:12px"><i class="ti ti-check"></i> Parse JSON</button>`,
    (root, close) => {
      const area = root.querySelector("#pasteArea") as HTMLTextAreaElement;
      root.querySelector("#pasteSubmit")?.addEventListener("click", () => {
        const txt = area.value.trim();
        if (!txt) {
          toast("Nothing pasted", "error");
          return;
        }
        let raw: unknown;
        try {
          raw = JSON.parse(txt);
        } catch {
          raw = txt;
        }
        close();
        void ingest(() => api.parse(raw), "pasted.json", txt.length);
      });
      area.focus();
    },
  );
}

function openUrlModal(): void {
  openModal(
    "Fetch SBOM from URL",
    `<label class="sidebar-label" style="padding:0">SBOM URL (http / https)</label>
     <input id="urlInput" class="nvd-input" style="width:100%;margin-top:8px" placeholder="https://example.com/sbom.json">
     <button class="nvd-scan-btn" id="urlSubmit" style="margin-top:12px"><i class="ti ti-download"></i> Fetch & parse</button>`,
    (root, close) => {
      const input = root.querySelector("#urlInput") as HTMLInputElement;
      const submit = () => {
        const url = safeUrl(input.value.trim());
        if (!url) {
          toast("Enter a valid http/https URL", "error");
          return;
        }
        close();
        void ingest(() => api.parseUrl(url), shortUrl(url));
      };
      root.querySelector("#urlSubmit")?.addEventListener("click", submit);
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") submit();
      });
      input.focus();
    },
  );
}

/** Run parse → scan → assess for one input, append to state, render. */
async function ingest(
  parseFn: () => Promise<Sbom>,
  filename: string,
  filesize = 0,
): Promise<void> {
  toast("Parsing SBOM…", "info");
  let sbom: Sbom;
  try {
    sbom = await parseFn();
  } catch (e) {
    toast(`Parse failed: ${(e as Error).message}`, "error");
    return;
  }
  const loaded: LoadedSbom = {
    sbom,
    filename,
    filesize,
    scan: null,
    assessment: null,
    findingsByComp: new Map(),
  };
  state.files.push(loaded);
  state.active = state.files.length - 1;
  renderFileList();
  showApp();
  switchView("overview");
  toast(
    `Parsed ${sbom.format.toUpperCase()} — ${sbom.components.length} components. Scanning…`,
    "success",
  );

  // Auto-run the first scan; the sidebar "Re-scan" button can re-run it on demand.
  await scanActive();
}

/** Run (or re-run) the OSV/NVD/MITRE/EPSS/KEV scan + assessment for the active file.
 *  Uses async polling for SBOMs with >= 200 components. */
async function scanActive(): Promise<void> {
  const f = activeFile();
  if (!f) return;
  const btn = document.getElementById("btnScan") as HTMLButtonElement | null;
  const status = document.getElementById("scanStatus");
  if (btn) {
    btn.disabled = true;
    btn.classList.add("scanning");
    btn.innerHTML = '<i class="ti ti-loader-2"></i> Scanning…';
  }
  if (status) {
    status.style.display = "";
    status.textContent = "Querying OSV / NVD / MITRE / EPSS / KEV…";
  }
  const tTotal = debug.time("scan", `scanActive ${f.filename}`, "info");

  const compCount = f.sbom.components.length;
  if (compCount >= 200) {
    // Use async scan with polling for large SBOMs
    await scanActiveAsync(f, compCount, status);
  } else {
    await scanFile(f);
  }

  tTotal(f.assessment?.verdict.status ?? "n/a");
  if (f.assessment) {
    toast(
      `Assessment complete — verdict ${f.assessment.verdict.status}`,
      f.assessment.verdict.status === "FAIL" ? "error" : "success",
    );
  }
  if (btn) {
    btn.disabled = false;
    btn.classList.remove("scanning");
    btn.innerHTML = '<i class="ti ti-refresh"></i> Re-scan';
  }
  if (status) status.style.display = "none";
  renderFileList();
  updateVulnBadge();
  renderActiveView();
}

/** Async scan path: POST /api/scan/async then poll every 2s. */
async function scanActiveAsync(
  f: LoadedSbom,
  compCount: number,
  status: HTMLElement | null,
): Promise<void> {
  let jobRef: AsyncJobRef;
  try {
    jobRef = await api.scanAsync(f.sbom);
  } catch (e) {
    toast(`Async scan failed: ${(e as Error).message}`, "error");
    return;
  }
  if (status) {
    status.textContent = `Scanning… ${compCount} components via OSV/NVD/KEV/EPSS`;
  }
  // Poll every 2 seconds until done or error
  let elapsed = 0;
  while (true) {
    await new Promise<void>((resolve) => setTimeout(resolve, 2000));
    elapsed += 2;
    let job: AsyncJob;
    try {
      job = await api.pollJob(jobRef.jobId);
    } catch (e) {
      toast(`Scan poll error: ${(e as Error).message}`, "error");
      return;
    }
    if (status) {
      status.textContent = `Scanning… ${compCount} components via OSV/NVD/KEV/EPSS (${elapsed}s)`;
    }
    if (job.status === "done" && job.result) {
      f.scan = job.result;
      f.findingsByComp = buildFindingsMap(f.scan.findings);
      // Apply suppressions before assess
      await applyAndAssess(f);
      return;
    }
    if (job.status === "error") {
      toast(`Async scan job failed`, "error");
      return;
    }
    // still running — continue polling
  }
}

/** Keep the scan button label in sync with whether the active file has been scanned. */
function updateScanButton(): void {
  const btn = document.getElementById("btnScan") as HTMLButtonElement | null;
  if (!btn || btn.classList.contains("scanning")) return;
  const f = activeFile();
  btn.innerHTML = f && f.scan
    ? '<i class="ti ti-refresh"></i> Re-scan'
    : '<i class="ti ti-shield-search"></i> Scan for Vulnerabilities';
}

async function reassess(policy: Policy): Promise<void> {
  state.policy = policy;
  await reassessActive();
}

/** Re-run /api/assess for the active file using the current policy + license policy.
 *  Fetches and applies VEX suppressions before calling assess. */
async function reassessActive(): Promise<void> {
  const f = activeFile();
  if (!f || !f.scan) return;
  try {
    // Apply suppressions before re-assessing
    let findings = f.scan.findings;
    try {
      const { suppressions } = await api.listSuppressions();
      if (suppressions.length > 0) {
        const applied = await api.applySuppressions(findings, suppressions);
        findings = applied.findings;
        f.findingsByComp = buildFindingsMap(findings);
      }
    } catch {
      // best-effort
    }
    f.assessment = await api.assess(
      f.sbom,
      findings,
      f.scan.summary,
      state.policy,
      getLicensePolicy(),
    );
    renderActiveView();
  } catch (e) {
    toast(`Re-assess failed: ${(e as Error).message}`, "error");
  }
}

function renderFileList(): void {
  const list = document.getElementById("fileList")!;
  if (!state.files.length) {
    list.innerHTML = `<div style="font-size:12px;color:var(--text3);padding:8px 4px;">No files loaded yet</div>`;
    return;
  }
  list.innerHTML = state.files
    .map((f, i) => {
      const fmt = f.sbom.format;
      const badge = `badge-${fmt}`;
      const icon =
        f.assessment?.verdict.status === "FAIL"
          ? "ti-alert-triangle"
          : "ti-file-code";
      return `<div class="loaded-file${i === state.active ? " active" : ""}" data-file="${i}">
        <i class="ti ${icon} file-icon"></i>
        <div class="file-info">
          <div class="file-name">${escapeHtml(f.sbom.name || f.filename)}</div>
          <div class="file-meta">${f.sbom.components.length} comp${f.scan ? " · " + f.scan.summary.total + " CVE" : ""}</div>
        </div>
        <span class="file-badge ${badge}">${escapeHtml(fmt)}</span>
        <button class="remove-btn" data-remove="${i}" title="Remove">&times;</button>
      </div>`;
    })
    .join("");
  list.querySelectorAll<HTMLElement>("[data-file]").forEach((node) =>
    node.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("[data-remove]")) return;
      state.active = Number(node.dataset.file);
      renderFileList();
      updateVulnBadge();
      renderActiveView();
    }),
  );
  list.querySelectorAll<HTMLElement>("[data-remove]").forEach((btn) =>
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = Number(btn.dataset.remove);
      state.files.splice(idx, 1);
      // Reconcile compare picks against the removed index.
      state.compareA = reconcileIdx(state.compareA, idx);
      state.compareB = reconcileIdx(state.compareB, idx);
      if (state.active >= state.files.length)
        state.active = state.files.length - 1;
      if (!state.files.length) {
        hideApp();
      } else {
        renderFileList();
        updateVulnBadge();
        renderActiveView();
      }
    }),
  );
}

function showApp(): void {
  document.getElementById("emptyState")!.style.display = "none";
  document.getElementById("viewRoot")!.style.display = "flex";
  document.getElementById("navSection")!.style.display = "flex";
  document.getElementById("scanSection")!.style.display = "flex";
  document.getElementById("exportSection")!.style.display = "flex";
  updateScanButton();
}
function hideApp(): void {
  state.active = -1;
  renderFileList();
  document.getElementById("emptyState")!.style.display = "flex";
  document.getElementById("viewRoot")!.style.display = "none";
  document.getElementById("navSection")!.style.display = "none";
  document.getElementById("scanSection")!.style.display = "none";
  document.getElementById("exportSection")!.style.display = "none";
}

function updateVulnBadge(): void {
  const badge = document.getElementById("vulnNavBadge");
  if (!badge) return;
  const f = activeFile();
  const total = f?.scan?.summary.total ?? 0;
  if (total > 0) {
    badge.style.display = "inline-block";
    badge.textContent = String(total);
  } else {
    badge.style.display = "none";
  }
}

function switchView(view: ViewName): void {
  state.view = view;
  document.querySelectorAll<HTMLElement>(".nav-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === view),
  );
  renderActiveView();
}

function renderActiveView(): void {
  const root = document.getElementById("viewRoot");
  const f = activeFile();
  if (!root || !f) return;
  debug.debug("view", `render ${state.view}`, f.filename);
  updateScanButton();
  root.innerHTML = "";
  switch (state.view) {
    case "overview":
      renderOverview(root, f, state.policy, reassess, () =>
        switchView("vulnerabilities"),
      );
      break;
    case "components":
      renderComponents(root, f);
      break;
    case "licenses":
      renderLicenses(root, f, () => void reassessActive());
      break;
    case "dependencies":
      renderDependencies(root, f);
      break;
    case "vulnerabilities":
      renderVulnerabilities(root, f);
      break;
    case "remediation":
      renderRemediation(root, f);
      break;
    case "compare": {
      // Default A = active file, B = the other file if present.
      const defA = state.compareA ?? (state.active >= 0 ? state.active : 0);
      const defB =
        state.compareB ??
        (state.files.length > 1 ? (defA === 0 ? 1 : 0) : null);
      renderCompare(
        root,
        state.files,
        { a: defA, b: defB },
        (sel) => {
          state.compareA = sel.a;
          state.compareB = sel.b;
          renderActiveView();
        },
      );
      break;
    }
    case "completeness":
      renderCompleteness(root, f);
      break;
    case "graph":
      renderGraph(root, f);
      break;
    case "suppliers":
      renderSuppliers(root, f);
      break;
    case "transitive":
      renderTransitive(root, f);
      break;
  }
}

// ── Global search ──
function wireSearch(): void {
  const input = document.getElementById("globalSearch") as HTMLInputElement;
  const results = document.getElementById("globalSearchResults")!;
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    const f = activeFile();
    if (!q || !f) {
      results.style.display = "none";
      return;
    }
    const out: string[] = [];
    const comps = f.sbom.components
      .map((c, i) => ({ c, i }))
      .filter(({ c }) =>
        `${c.name} ${c.version} ${c.purl}`.toLowerCase().includes(q),
      )
      .slice(0, 6);
    if (comps.length) {
      out.push(`<div class="gsearch-cat">Components</div>`);
      for (const { c, i } of comps)
        out.push(
          `<div class="gsearch-item" data-go="components" data-idx="${i}"><i class="ti ti-package" style="color:var(--accent)"></i><span class="gsearch-name">${escapeHtml(c.name)}</span><span class="gsearch-meta">${escapeHtml(c.version)}</span></div>`,
        );
    }
    const cves: { id: string; sev: string }[] = [];
    for (const [, vulns] of f.findingsByComp)
      for (const v of vulns)
        if (`${v.id} ${v.cveId ?? ""}`.toLowerCase().includes(q))
          cves.push({ id: v.cveId ?? v.id, sev: v.cvss.severity });
    if (cves.length) {
      out.push(`<div class="gsearch-cat">CVEs</div>`);
      for (const c of cves.slice(0, 6))
        out.push(
          `<div class="gsearch-item" data-go="vulnerabilities"><i class="ti ti-shield-exclamation" style="color:var(--red)"></i><span class="gsearch-name">${escapeHtml(c.id)}</span><span class="gsearch-meta">${escapeHtml(c.sev)}</span></div>`,
        );
    }
    const lics = new Set<string>();
    for (const c of f.sbom.components)
      for (const l of c.licenses)
        if (l.toLowerCase().includes(q)) lics.add(l);
    if (lics.size) {
      out.push(`<div class="gsearch-cat">Licenses</div>`);
      for (const l of [...lics].slice(0, 6))
        out.push(
          `<div class="gsearch-item" data-go="licenses"><i class="ti ti-license" style="color:var(--purple)"></i><span class="gsearch-name">${escapeHtml(l)}</span></div>`,
        );
    }
    if (!out.length) {
      results.innerHTML = `<div class="gsearch-item"><span class="gsearch-meta">No matches</span></div>`;
    } else {
      results.innerHTML = out.join("");
      results.querySelectorAll<HTMLElement>("[data-go]").forEach((node) =>
        node.addEventListener("click", () => {
          switchView(node.dataset.go as ViewName);
          results.style.display = "none";
          input.value = "";
        }),
      );
    }
    results.style.display = "block";
  });
  input.addEventListener("blur", () =>
    setTimeout(() => (results.style.display = "none"), 150),
  );
}

function wireKeyboard(): void {
  document.addEventListener("keydown", (e) => {
    const tag = (e.target as HTMLElement)?.tagName;
    const typing =
      tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    if ((e.key === "/" || (e.key === "k" && (e.metaKey || e.ctrlKey)))) {
      if (!typing || e.metaKey || e.ctrlKey) {
        e.preventDefault();
        (document.getElementById("globalSearch") as HTMLInputElement)?.focus();
      }
      return;
    }
    if (typing) return;
    if (e.key === "?") {
      toggleShortcutHelp();
      return;
    }
    if (!activeFile()) return;
    const numMap: Record<string, ViewName> = {
      "1": "overview",
      "2": "components",
      "3": "licenses",
      "4": "dependencies",
      "5": "vulnerabilities",
      "6": "remediation",
      "7": "compare",
      "8": "completeness",
      "9": "graph",
      "0": "suppliers",
    };
    if (numMap[e.key]) {
      switchView(numMap[e.key]);
      return;
    }
    if (e.key === "g") switchView("graph");
    else if (e.key === "v") switchView("vulnerabilities");
    else if (e.key === "t") toggleTheme();
  });
}

/** Adjust a stored file index after the file at `removed` was spliced out. */
function reconcileIdx(idx: number | null, removed: number): number | null {
  if (idx == null) return null;
  if (idx === removed) return null;
  return idx > removed ? idx - 1 : idx;
}

function shortUrl(u: string): string {
  try {
    return new URL(u).pathname.split("/").pop() || u;
  } catch {
    return u;
  }
}

// ── Recent scans sidebar section ─────────────────────────────────────────────

function wireRecentScans(): void {
  let expanded = false;

  const toggle = document.getElementById("recentScansToggle");
  const chevron = document.getElementById("recentScansChevron");
  const list = document.getElementById("recentScansList");
  if (!toggle || !list) return;

  toggle.addEventListener("click", () => {
    expanded = !expanded;
    list.style.display = expanded ? "flex" : "none";
    if (chevron) chevron.style.transform = expanded ? "rotate(180deg)" : "";
    if (expanded) void loadRecentScans(list);
  });
}

async function loadRecentScans(list: HTMLElement): Promise<void> {
  list.innerHTML = `<div style="font-size:12px;color:var(--text3);padding:4px 0">Loading…</div>`;
  try {
    const { scans } = await api.listScans();
    if (!scans.length) {
      list.innerHTML = `<div style="font-size:12px;color:var(--text3);padding:4px 0">No saved scans yet.</div>`;
      return;
    }
    list.innerHTML = scans
      .slice(0, 15)
      .map((s) => {
        const worst = worstSeverityFromSummary(s.summary);
        const date = new Date(s.createdAt).toLocaleDateString();
        return `<div class="loaded-file" data-scan-id="${escapeHtml(s.id)}" style="cursor:pointer">
          <div class="file-info" style="flex:1;min-width:0">
            <div class="file-name">${escapeHtml(s.sbomName)}</div>
            <div class="file-meta">${s.componentCount} comp · ${s.summary.total} CVE · ${date}</div>
          </div>
          <span class="sev-badge sev-badge-${worst}" style="font-size:9px">${worst}</span>
        </div>`;
      })
      .join("");
    list.querySelectorAll<HTMLElement>("[data-scan-id]").forEach((row) =>
      row.addEventListener("click", () => {
        const id = row.dataset.scanId ?? "";
        if (id) void loadSavedScan(id);
      }),
    );
  } catch (e) {
    list.innerHTML = `<div style="font-size:12px;color:var(--red);padding:4px 0">Failed: ${escapeHtml((e as Error).message)}</div>`;
  }
}

function worstSeverityFromSummary(summary: Summary): Severity {
  if (summary.CRITICAL > 0) return "CRITICAL";
  if (summary.HIGH > 0) return "HIGH";
  if (summary.MEDIUM > 0) return "MEDIUM";
  if (summary.LOW > 0) return "LOW";
  if (summary.total > 0) return "NONE";
  return "UNKNOWN";
}

async function loadSavedScan(id: string): Promise<void> {
  toast("Loading saved scan…", "info");
  let saved: SavedScan;
  try {
    saved = await api.getScan(id);
  } catch (e) {
    toast(`Failed to load scan: ${(e as Error).message}`, "error");
    return;
  }
  // Build a minimal Sbom stub from the saved scan metadata so we can render
  const stubSbom: Sbom = {
    id: saved.id,
    format: saved.sbomFormat as Format,
    formatVersion: "",
    name: saved.sbomName,
    version: "",
    timestamp: saved.createdAt,
    tools: [],
    serialNumber: "",
    components: Array.from({ length: saved.componentCount }, (_, i) => ({
      name: `Component ${i + 1}`,
      version: "",
      type: "library",
      purl: "",
      cpe: "",
      description: "",
      licenses: [],
      supplier: "",
      language: "",
      bomRef: `stub-${i}`,
      depth: "unknown" as Depth,
    })),
    dependencies: [],
  };
  const scanResult: ScanResult = {
    findings: saved.findings,
    summary: saved.summary,
    errors: [],
  };
  const loaded: LoadedSbom = {
    sbom: stubSbom,
    filename: saved.sbomName,
    filesize: 0,
    scan: scanResult,
    assessment: null,
    findingsByComp: buildFindingsMap(saved.findings),
  };
  state.files.push(loaded);
  state.active = state.files.length - 1;
  renderFileList();
  showApp();
  switchView("vulnerabilities");
  toast(`Loaded saved scan: ${saved.sbomName}`, "success");
  // Run assess so we get a verdict
  await applyAndAssess(loaded);
  updateVulnBadge();
  renderActiveView();
}

boot();
