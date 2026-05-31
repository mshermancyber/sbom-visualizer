import type { LoadedSbom, Severity, Vuln, SuppressionStatus } from "../types";
import { escapeHtml, SEV_ORDER, sevRank, worstSeverity } from "../util";
import { vulnCard } from "../badges";
import * as api from "../api";
import { toast, openModal } from "../ui";
import { buildFindingsMap } from "../store";

interface VState {
  search: string;
  sevFilter: Severity | "ALL";
  groupBy: "component" | "severity" | "none";
  onlyKev: boolean;
  onlyDirect: boolean;
}

const vstate: VState = {
  search: "",
  sevFilter: "ALL",
  groupBy: "component",
  onlyKev: false,
  onlyDirect: false,
};

interface FlatVuln {
  v: Vuln;
  compIdx: number;
  compLabel: string;
  compPurl: string;
  direct: boolean;
}

export function renderVulnerabilities(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const { sbom, scan } = file;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-shield-exclamation"></i> Vulnerabilities</div>`;
  el.appendChild(header);

  if (!scan) {
    el.innerHTML +=
      '<div class="loading">No scan results yet. Load and scan an SBOM.</div>';
    return;
  }

  const sum = scan.summary;
  const summaryGrid = document.createElement("div");
  summaryGrid.className = "vuln-summary-grid";
  summaryGrid.innerHTML = `
    <div class="vuln-summary-card sum-critical"><div class="vuln-sum-label">Critical</div><div class="vuln-sum-count">${sum.CRITICAL}</div></div>
    <div class="vuln-summary-card sum-high"><div class="vuln-sum-label">High</div><div class="vuln-sum-count">${sum.HIGH}</div></div>
    <div class="vuln-summary-card sum-medium"><div class="vuln-sum-label">Medium</div><div class="vuln-sum-count">${sum.MEDIUM}</div></div>
    <div class="vuln-summary-card sum-low"><div class="vuln-sum-label">Low</div><div class="vuln-sum-count">${sum.LOW}</div></div>
    <div class="vuln-summary-card sum-clean"><div class="vuln-sum-label">Affected</div><div class="vuln-sum-count">${sum.affected}</div></div>`;
  el.appendChild(summaryGrid);

  if (scan.errors && scan.errors.length) {
    const errEl = document.createElement("div");
    errEl.style.cssText =
      "font-size:12px;color:var(--amber);background:var(--amber-bg);border:1px solid #d2992240;border-radius:var(--r);padding:8px 14px";
    errEl.textContent = `Scan warnings: ${scan.errors.slice(0, 3).join("; ")}`;
    el.appendChild(errEl);
  }

  // Flatten findings
  const flat: FlatVuln[] = [];
  for (const [idx, vulns] of file.findingsByComp) {
    const c = sbom.components[idx];
    if (!c) continue;
    const label = `${c.name} ${c.version}`;
    const direct = c.depth === "direct";
    for (const v of vulns) flat.push({ v, compIdx: idx, compLabel: label, compPurl: c.purl, direct });
  }

  // Controls
  const controls = document.createElement("div");
  controls.style.cssText = "display:flex;flex-direction:column;gap:10px";
  controls.innerHTML = `
    <div class="table-controls">
      <div class="search-wrap"><i class="ti ti-search"></i>
        <input class="search-input" data-search placeholder="Filter CVE id, description, CWE, component…" value="${escapeHtml(vstate.search)}"></div>
      <select class="filter-select" data-group>
        <option value="component"${vstate.groupBy === "component" ? " selected" : ""}>Group by component</option>
        <option value="severity"${vstate.groupBy === "severity" ? " selected" : ""}>Group by severity</option>
        <option value="none"${vstate.groupBy === "none" ? " selected" : ""}>No grouping</option>
      </select>
      <span class="count-badge" data-count></span>
    </div>
    <div class="vuln-filter-bar">
      ${(["ALL", ...SEV_ORDER] as (Severity | "ALL")[])
        .map(
          (s) =>
            `<button class="sev-filter-btn ${vstate.sevFilter === s ? "active active-" + s : ""}" data-sev="${s}">${s}</button>`,
        )
        .join("")}
      <button class="sev-filter-btn ${vstate.onlyKev ? "active" : ""}" data-kev><i class="ti ti-bolt"></i> KEV only</button>
      <button class="sev-filter-btn ${vstate.onlyDirect ? "active" : ""}" data-direct>Direct only</button>
    </div>`;
  el.appendChild(controls);

  const list = document.createElement("div");
  list.style.cssText = "display:flex;flex-direction:column;gap:12px";
  el.appendChild(list);

  const searchInput = controls.querySelector<HTMLInputElement>("[data-search]")!;
  searchInput.addEventListener("input", () => {
    vstate.search = searchInput.value;
    draw();
  });
  controls
    .querySelector<HTMLSelectElement>("[data-group]")!
    .addEventListener("change", (e) => {
      vstate.groupBy = (e.target as HTMLSelectElement).value as VState["groupBy"];
      draw();
    });
  controls.querySelectorAll<HTMLElement>("[data-sev]").forEach((b) =>
    b.addEventListener("click", () => {
      vstate.sevFilter = b.dataset.sev as Severity | "ALL";
      renderVulnerabilities(el, file);
    }),
  );
  controls.querySelector("[data-kev]")?.addEventListener("click", () => {
    vstate.onlyKev = !vstate.onlyKev;
    renderVulnerabilities(el, file);
  });
  controls.querySelector("[data-direct]")?.addEventListener("click", () => {
    vstate.onlyDirect = !vstate.onlyDirect;
    renderVulnerabilities(el, file);
  });

  function matches(fv: FlatVuln): boolean {
    if (vstate.sevFilter !== "ALL" && fv.v.cvss.severity !== vstate.sevFilter)
      return false;
    if (vstate.onlyKev && !fv.v.kev) return false;
    if (vstate.onlyDirect && !fv.direct) return false;
    const q = vstate.search.trim().toLowerCase();
    if (q) {
      const hay = [
        fv.v.id,
        fv.v.cveId,
        fv.v.description,
        fv.compLabel,
        ...(fv.v.cwes || []),
        ...(fv.v.aliases || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  /** Wire suppress buttons inside a rendered container. */
  function wireSuppressButtons(container: HTMLElement): void {
    container.querySelectorAll<HTMLElement>("[data-suppress-vuln]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const cveId = btn.dataset.suppressVuln ?? "";
        const compPurl = btn.dataset.suppressPurl ?? "";
        openSuppressModal(cveId, compPurl, file, () => {
          renderVulnerabilities(el, file);
        });
      });
    });
  }

  function draw(): void {
    const rows = flat.filter(matches);
    rows.sort(
      (a, b) =>
        sevRank(a.v.cvss.severity) - sevRank(b.v.cvss.severity) ||
        (b.v.cvss.score ?? 0) - (a.v.cvss.score ?? 0),
    );
    (controls.querySelector("[data-count]") as HTMLElement).textContent =
      `${rows.length} finding${rows.length === 1 ? "" : "s"}`;
    list.innerHTML = "";

    if (!rows.length) {
      list.innerHTML = `<div class="loading">No vulnerabilities match the current filters.</div>`;
      return;
    }

    if (vstate.groupBy === "none") {
      list.innerHTML = rows
        .map((fv) => vulnCard(fv.v, fv.compLabel, fv.compPurl))
        .join("");
      wireSuppressButtons(list);
      return;
    }

    const groups = new Map<string, FlatVuln[]>();
    for (const fv of rows) {
      const key =
        vstate.groupBy === "component" ? fv.compLabel : fv.v.cvss.severity;
      const arr = groups.get(key) ?? [];
      arr.push(fv);
      groups.set(key, arr);
    }
    const entries = [...groups.entries()];
    if (vstate.groupBy === "severity") {
      entries.sort(
        (a, b) =>
          sevRank(a[0] as Severity) - sevRank(b[0] as Severity),
      );
    } else {
      entries.sort(
        (a, b) =>
          sevRank(worstSeverity(a[1].map((f) => f.v.cvss.severity))) -
          sevRank(worstSeverity(b[1].map((f) => f.v.cvss.severity))),
      );
    }

    list.innerHTML = entries
      .map(([key, fvs]) => {
        const worst = worstSeverity(fvs.map((f) => f.v.cvss.severity));
        return `<div class="vuln-group-card">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="font-family:var(--font);font-size:13px;font-weight:600;color:var(--text);flex:1">${escapeHtml(key)}</div>
            <span class="sev-badge sev-badge-${worst}">worst: ${worst}</span>
            <span class="count-badge">${fvs.length}</span>
          </div>
          <div style="display:flex;flex-direction:column;gap:10px;margin-top:6px">
            ${fvs.map((fv) => vulnCard(fv.v, vstate.groupBy === "component" ? undefined : fv.compLabel, fv.compPurl)).join("")}
          </div>
        </div>`;
      })
      .join("");
    wireSuppressButtons(list);
  }

  draw();
}

/** Open the suppression creation modal for a CVE + component purl. */
function openSuppressModal(
  cveId: string,
  compPurl: string,
  file: LoadedSbom,
  onDone: () => void,
): void {
  const STATUSES: SuppressionStatus[] = [
    "not_affected",
    "false_positive",
    "in_triage",
    "accepted_risk",
  ];
  openModal(
    `Suppress ${cveId}`,
    `<div style="font-size:12px;color:var(--text2);margin-bottom:12px">
       Component: <code style="font-family:var(--font);color:var(--text3)">${escapeHtml(compPurl || "(no purl)")}</code>
     </div>
     <label class="sidebar-label" style="padding:0">Status</label>
     <select id="supStatus" class="filter-select" style="width:100%;margin:6px 0 12px">
       ${STATUSES.map((s) => `<option value="${s}">${s.replace(/_/g, " ")}</option>`).join("")}
     </select>
     <label class="sidebar-label" style="padding:0">Note (optional)</label>
     <input id="supNote" class="nvd-input" style="width:100%;margin:6px 0 12px" placeholder="Reason for suppression…">
     <label class="sidebar-label" style="padding:0">Expires at (optional)</label>
     <input id="supExpiry" class="nvd-input" type="date" style="width:100%;margin:6px 0 16px">
     <button class="nvd-scan-btn" id="supSubmit"><i class="ti ti-ban"></i> Create suppression</button>`,
    (root, close) => {
      const statusSel = root.querySelector("#supStatus") as HTMLSelectElement;
      const noteInput = root.querySelector("#supNote") as HTMLInputElement;
      const expiryInput = root.querySelector("#supExpiry") as HTMLInputElement;
      root.querySelector("#supSubmit")?.addEventListener("click", () => {
        const params = {
          cveId,
          componentPurl: compPurl,
          status: statusSel.value as SuppressionStatus,
          note: noteInput.value.trim() || undefined,
          expiresAt: expiryInput.value || undefined,
        };
        void (async () => {
          try {
            await api.createSuppression(params);
            toast(`Suppressed ${cveId}`, "success");
            close();
            // Rebuild findingsByComp with suppression applied
            if (file.scan) {
              try {
                const { suppressions } = await api.listSuppressions();
                const applied = await api.applySuppressions(
                  file.scan.findings,
                  suppressions,
                );
                file.findingsByComp = buildFindingsMap(applied.findings);
              } catch {
                // best-effort
              }
            }
            onDone();
          } catch (e) {
            toast(`Failed to create suppression: ${(e as Error).message}`, "error");
          }
        })();
      });
      statusSel.focus();
    },
  );
}
