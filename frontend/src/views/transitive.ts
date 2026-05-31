import type { LoadedSbom } from "../types";
import { escapeHtml, worstSeverity } from "../util";

export function renderTransitive(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const { sbom } = file;

  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<div class="section-title"><i class="ti ti-binary-tree-2"></i> Vulnerability Paths</div>`;
  el.appendChild(header);

  if (!file.scan) {
    el.innerHTML += `<div class="path-no-data">Scan an SBOM to trace vulnerability paths.</div>`;
    return;
  }
  if (!sbom.dependencies.length) {
    el.innerHTML += `<div class="path-no-data">No dependency graph available to trace paths.</div>`;
    return;
  }

  // Build ref -> compIdx and parent map (who depends on me).
  const refToIdx = new Map<string, number>();
  sbom.components.forEach((c, i) => {
    if (c.bomRef) refToIdx.set(c.bomRef, i);
    refToIdx.set(c.name, i);
  });
  const idxToRef = new Map<number, string>();
  sbom.components.forEach((c, i) => idxToRef.set(i, c.bomRef || c.name));

  // parents: child ref -> set of parent refs
  const parents = new Map<string, Set<string>>();
  const childRefs = new Set<string>();
  for (const d of sbom.dependencies) {
    for (const child of d.deps) {
      childRefs.add(child);
      const set = parents.get(child) ?? new Set<string>();
      set.add(d.ref);
      parents.set(child, set);
    }
  }
  const allRefs = new Set<string>();
  for (const d of sbom.dependencies) {
    allRefs.add(d.ref);
    for (const c of d.deps) allRefs.add(c);
  }
  const roots = new Set([...allRefs].filter((r) => !childRefs.has(r)));

  const labelOf = (ref: string): string => {
    const i = refToIdx.get(ref);
    if (i != null) return `${sbom.components[i].name} ${sbom.components[i].version}`;
    return ref.split("/").pop()?.split("#").pop() || ref;
  };

  // For each vulnerable component, BFS upward to a root, recording one shortest path.
  function pathToRoot(startRef: string): string[] {
    if (roots.has(startRef)) return [startRef];
    const queue: string[][] = [[startRef]];
    const seen = new Set<string>([startRef]);
    while (queue.length) {
      const path = queue.shift()!;
      const cur = path[path.length - 1];
      if (roots.has(cur)) return path;
      for (const p of parents.get(cur) ?? []) {
        if (seen.has(p)) continue;
        seen.add(p);
        queue.push([...path, p]);
      }
    }
    return [startRef];
  }

  const cards: { html: string; rank: number }[] = [];
  for (const [idx, vulns] of file.findingsByComp) {
    if (!vulns.length) continue;
    const ref = idxToRef.get(idx);
    if (!ref) continue;
    const worst = worstSeverity(vulns.map((v) => v.cvss.severity));
    const path = pathToRoot(ref).reverse(); // root → … → vulnerable
    const chain = path
      .map((r, i) => {
        const isRoot = i === 0 && roots.has(r);
        const isVuln = i === path.length - 1;
        const cls = isVuln ? "vuln-node" : isRoot ? "root-node" : "";
        return `<span class="path-node ${cls}">${escapeHtml(labelOf(r))}</span>`;
      })
      .join(`<i class="ti ti-arrow-right path-arrow"></i>`);
    cards.push({
      rank: vulns.length,
      html: `<div class="path-card">
        <div style="display:flex;align-items:center;gap:10px">
          <span class="sev-badge sev-badge-${worst}">${worst}</span>
          <div style="font-family:var(--font);font-size:13px;color:var(--text);flex:1">${escapeHtml(labelOf(ref))}</div>
          <span class="count-badge">${vulns.length} vuln${vulns.length === 1 ? "" : "s"} · depth ${path.length - 1}</span>
        </div>
        <div class="path-chain">${chain}</div>
      </div>`,
    });
  }
  cards.sort((a, b) => b.rank - a.rank);

  if (!cards.length) {
    el.innerHTML += `<div class="path-no-data">No vulnerable components to trace.</div>`;
    return;
  }
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;flex-direction:column;gap:10px";
  wrap.innerHTML = cards.map((c) => c.html).join("");
  el.appendChild(wrap);
}
