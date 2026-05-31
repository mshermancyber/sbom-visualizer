import type { LoadedSbom, Component } from "../types";
import {
  escapeHtml,
  typeClass,
  licClass,
  externalLink,
  purlToRegistryUrl,
} from "../util";

/** Component name, linked to its registry page when derivable from the purl. */
function compNameHtml(c: Component): string {
  const reg = purlToRegistryUrl(c.purl);
  if (reg)
    return `<div class="comp-name">${externalLink(reg, c.name)}</div>`;
  return `<div class="comp-name">${escapeHtml(c.name)}</div>`;
}

interface CompState {
  search: string;
  sortKey: "name" | "version" | "type" | "licenses" | "vulns";
  sortDir: 1 | -1;
  page: number;
  pageSize: number;
  selected: number | null;
}

const cstate: CompState = {
  search: "",
  sortKey: "name",
  sortDir: 1,
  page: 0,
  pageSize: 25,
  selected: null,
};

function vulnCountFor(file: LoadedSbom, idx: number): number {
  return file.findingsByComp.get(idx)?.length ?? 0;
}

export function renderComponents(el: HTMLElement, file: LoadedSbom): void {
  const { sbom } = file;
  el.innerHTML = "";

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-package"></i> Components</div>`;
  el.appendChild(header);

  const controls = document.createElement("div");
  controls.className = "table-controls";
  controls.innerHTML = `
    <div class="search-wrap"><i class="ti ti-search"></i>
      <input class="search-input" data-search placeholder="Filter by name, version, purl, license…" value="${escapeHtml(cstate.search)}">
    </div>
    <span class="count-badge" data-count></span>`;
  el.appendChild(controls);

  const tableWrap = document.createElement("div");
  tableWrap.className = "table-wrap";
  el.appendChild(tableWrap);

  const paginator = document.createElement("div");
  paginator.className = "paginator";
  el.appendChild(paginator);

  const detail = document.createElement("div");
  detail.className = "detail-panel";
  detail.id = "compDetail";
  el.appendChild(detail);

  const searchInput = controls.querySelector<HTMLInputElement>("[data-search]")!;
  searchInput.addEventListener("input", () => {
    cstate.search = searchInput.value;
    cstate.page = 0;
    draw();
  });

  function indexed(): { c: Component; i: number }[] {
    return sbom.components.map((c, i) => ({ c, i }));
  }

  function filtered(): { c: Component; i: number }[] {
    const q = cstate.search.trim().toLowerCase();
    let rows = indexed();
    if (q) {
      rows = rows.filter(({ c }) =>
        [c.name, c.version, c.purl, c.type, ...c.licenses, c.supplier]
          .join(" ")
          .toLowerCase()
          .includes(q),
      );
    }
    rows.sort((a, b) => {
      let av: string | number;
      let bv: string | number;
      switch (cstate.sortKey) {
        case "vulns":
          av = vulnCountFor(file, a.i);
          bv = vulnCountFor(file, b.i);
          break;
        case "licenses":
          av = a.c.licenses.join(",");
          bv = b.c.licenses.join(",");
          break;
        default:
          av = (a.c[cstate.sortKey] as string) || "";
          bv = (b.c[cstate.sortKey] as string) || "";
      }
      if (av < bv) return -1 * cstate.sortDir;
      if (av > bv) return 1 * cstate.sortDir;
      return 0;
    });
    return rows;
  }

  function sortIcon(key: CompState["sortKey"]): string {
    if (cstate.sortKey !== key)
      return `<i class="ti ti-arrows-sort sort-icon"></i>`;
    return `<i class="ti ti-arrow-${cstate.sortDir === 1 ? "up" : "down"} sort-icon"></i>`;
  }

  function draw(): void {
    const rows = filtered();
    const totalPages = Math.max(1, Math.ceil(rows.length / cstate.pageSize));
    if (cstate.page >= totalPages) cstate.page = totalPages - 1;
    const start = cstate.page * cstate.pageSize;
    const pageRows = rows.slice(start, start + cstate.pageSize);

    (controls.querySelector("[data-count]") as HTMLElement).textContent =
      `${rows.length} of ${sbom.components.length} components`;

    const cols: [CompState["sortKey"], string][] = [
      ["name", "Component"],
      ["type", "Type"],
      ["licenses", "Licenses"],
      ["vulns", "Vulns"],
    ];
    tableWrap.innerHTML = `<table><thead><tr>
      ${cols
        .map(
          ([k, label]) =>
            `<th data-sort="${k}" class="${cstate.sortKey === k ? "sorted" : ""}">${escapeHtml(label)} ${sortIcon(k)}</th>`,
        )
        .join("")}
    </tr></thead><tbody>
      ${pageRows
        .map(({ c, i }) => {
          const vc = vulnCountFor(file, i);
          return `<tr class="clickable-row" data-row="${i}">
            <td>${compNameHtml(c)}
              <div class="comp-version">${escapeHtml(c.version || "—")} · ${escapeHtml(c.depth)}</div>
              ${c.purl ? `<div class="comp-purl">${escapeHtml(c.purl)}</div>` : ""}</td>
            <td><span class="type-tag ${typeClass(c.type)}">${escapeHtml(c.type || "other")}</span></td>
            <td>${c.licenses.length ? c.licenses.map((l) => `<span class="license-tag ${licClass(l)}">${escapeHtml(l)}</span>`).join("") : '<span class="license-tag license-unknown">none</span>'}</td>
            <td>${vc ? `<span class="sev-badge sev-badge-HIGH">${vc}</span>` : '<span class="vuln-dot vuln-low"></span>'}</td>
          </tr>`;
        })
        .join("")}
    </tbody></table>`;

    tableWrap.querySelectorAll<HTMLElement>("th[data-sort]").forEach((th) =>
      th.addEventListener("click", () => {
        const k = th.dataset.sort as CompState["sortKey"];
        if (cstate.sortKey === k) cstate.sortDir = cstate.sortDir === 1 ? -1 : 1;
        else {
          cstate.sortKey = k;
          cstate.sortDir = 1;
        }
        draw();
      }),
    );
    tableWrap.querySelectorAll<HTMLElement>("tr[data-row]").forEach((tr) =>
      tr.addEventListener("click", () => {
        cstate.selected = Number(tr.dataset.row);
        drawDetail();
      }),
    );

    paginator.innerHTML = `
      <button class="page-btn" data-prev ${cstate.page === 0 ? "disabled" : ""}>‹ Prev</button>
      <span class="page-info">Page ${cstate.page + 1} / ${totalPages}</span>
      <button class="page-btn" data-next ${cstate.page >= totalPages - 1 ? "disabled" : ""}>Next ›</button>`;
    paginator.querySelector("[data-prev]")?.addEventListener("click", () => {
      if (cstate.page > 0) {
        cstate.page--;
        draw();
      }
    });
    paginator.querySelector("[data-next]")?.addEventListener("click", () => {
      if (cstate.page < totalPages - 1) {
        cstate.page++;
        draw();
      }
    });
  }

  function drawDetail(): void {
    if (cstate.selected == null) {
      detail.classList.remove("open");
      return;
    }
    const c = sbom.components[cstate.selected];
    const vulns = file.findingsByComp.get(cstate.selected) ?? [];
    const field = (k: string, v: string, full = false) =>
      `<div class="detail-field${full ? " full" : ""}"><div class="detail-key">${escapeHtml(k)}</div><div class="detail-val${v ? "" : " empty"}">${v ? escapeHtml(v) : "—"}</div></div>`;
    detail.classList.add("open");
    detail.innerHTML = `
      <div class="detail-header">
        <span class="type-tag ${typeClass(c.type)}">${escapeHtml(c.type || "other")}</span>
        <div class="comp-name">${purlToRegistryUrl(c.purl) ? externalLink(purlToRegistryUrl(c.purl), c.name) : escapeHtml(c.name)} <span class="comp-version">${escapeHtml(c.version)}</span></div>
        <button class="detail-close" data-detail-close>&times;</button>
      </div>
      <div class="detail-body">
        ${field("PURL", c.purl)}
        ${field("CPE", c.cpe)}
        ${field("Supplier", c.supplier)}
        ${field("Language", c.language)}
        ${field("Depth", c.depth)}
        ${field("BOM Ref", c.bomRef)}
        <div class="detail-field full"><div class="detail-key">Licenses</div><div>${c.licenses.length ? c.licenses.map((l) => `<span class="license-tag ${licClass(l)}">${escapeHtml(l)}</span>`).join("") : '<span class="detail-val empty">—</span>'}</div></div>
        ${c.description ? field("Description", c.description, true) : ""}
        ${
          vulns.length
            ? `<div class="detail-field full"><div class="detail-key">Vulnerabilities (${vulns.length})</div><div style="display:flex;flex-wrap:wrap;gap:6px">${vulns
                .map(
                  (v) =>
                    `<span class="sev-badge sev-badge-${v.cvss.severity}">${externalLink(v.cveId ? `https://nvd.nist.gov/vuln/detail/${v.cveId}` : "", v.cveId || v.id)}</span>`,
                )
                .join("")}</div></div>`
            : ""
        }
      </div>`;
    detail
      .querySelector("[data-detail-close]")
      ?.addEventListener("click", () => {
        cstate.selected = null;
        detail.classList.remove("open");
      });
    detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  draw();
  drawDetail();
}
