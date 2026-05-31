import type { LoadedSbom } from "../types";
import { escapeHtml, worstSeverity } from "../util";
import type { Severity } from "../types";

export function renderSuppliers(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const { sbom } = file;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-building-factory-2"></i> Suppliers</div>`;
  el.appendChild(header);

  interface Group {
    comps: number;
    vulns: number;
    worst: Severity;
    names: string[];
  }
  const groups = new Map<string, Group>();
  sbom.components.forEach((c, i) => {
    const key = c.supplier || "(unknown)";
    const g = groups.get(key) ?? {
      comps: 0,
      vulns: 0,
      worst: "UNKNOWN",
      names: [],
    };
    g.comps++;
    g.names.push(`${c.name} ${c.version}`);
    const vulns = file.findingsByComp.get(i) ?? [];
    g.vulns += vulns.length;
    if (vulns.length)
      g.worst = worstSeverity([g.worst, ...vulns.map((v) => v.cvss.severity)]);
    groups.set(key, g);
  });

  const sorted = [...groups.entries()].sort(
    (a, b) => b[1].vulns - a[1].vulns || b[1].comps - a[1].comps,
  );

  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:10px";
  wrap.innerHTML = sorted
    .map(
      ([name, g]) => `<div class="supplier-card">
      <div class="supplier-header" data-toggle>
        <i class="ti ti-chevron-right"></i>
        <div class="supplier-name">${escapeHtml(name)}</div>
        <div class="supplier-stats">
          <div class="supplier-stat"><strong>${g.comps}</strong>components</div>
          <div class="supplier-stat"><strong style="color:${g.vulns ? "var(--red)" : "var(--green)"}">${g.vulns}</strong>vulns</div>
          ${g.vulns ? `<span class="sev-badge sev-badge-${g.worst}">${g.worst}</span>` : ""}
        </div>
      </div>
      <div class="supplier-body">
        <div class="deps-grid" style="padding:12px">
          ${g.names
            .map((n) => `<div class="dep-card"><div class="dep-name">${escapeHtml(n)}</div></div>`)
            .join("")}
        </div>
      </div>
    </div>`,
    )
    .join("");
  el.appendChild(wrap);

  wrap.querySelectorAll<HTMLElement>("[data-toggle]").forEach((h) =>
    h.addEventListener("click", () => {
      const body = h.nextElementSibling as HTMLElement;
      body.classList.toggle("open");
      const chevron = h.querySelector("i");
      if (chevron)
        chevron.className = body.classList.contains("open")
          ? "ti ti-chevron-down"
          : "ti ti-chevron-right";
    }),
  );
}
