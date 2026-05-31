import * as d3 from "d3";
import type { LoadedSbom, Component } from "../types";
import { escapeHtml, licClass, worstSeverity } from "../util";

interface GNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  compIdx: number;
  comp: Component | null;
}
interface GLink extends d3.SimulationLinkDatum<GNode> {
  source: string | GNode;
  target: string | GNode;
}

type ColorMode = "type" | "vuln" | "license";

const TYPE_COLORS: Record<string, string> = {
  library: "#378ADD",
  framework: "#7F77DD",
  application: "#1D9E75",
  container: "#BA7517",
  file: "#D85A30",
  os: "#639922",
  other: "#888780",
};

export function renderGraph(el: HTMLElement, file: LoadedSbom): void {
  el.innerHTML = "";
  const { sbom } = file;

  if (!sbom.dependencies.length) {
    el.innerHTML = `<div class="path-no-data">No dependency relationships found in this SBOM.</div>`;
    return;
  }

  const controls = document.createElement("div");
  controls.className = "graph-controls";
  controls.innerHTML = `
    <div class="section-title"><i class="ti ti-hierarchy-2"></i> Dependency Graph</div>
    <div style="margin-left:auto;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <label style="font-size:12px;color:var(--text3);display:flex;align-items:center;gap:6px">Max nodes:
        <select id="graphMaxNodes" class="filter-select" style="width:80px">
          <option value="60">60</option><option value="120" selected>120</option><option value="250">250</option>
        </select></label>
      <label style="font-size:12px;color:var(--text3);display:flex;align-items:center;gap:6px">Color by:
        <select id="graphColorBy" class="filter-select" style="width:100px">
          <option value="type">Type</option><option value="vuln">Vulnerabilities</option><option value="license">License</option>
        </select></label>
      <button class="page-btn" data-reset title="Reset layout"><i class="ti ti-refresh"></i></button>
    </div>`;
  el.appendChild(controls);

  const info = document.createElement("div");
  info.style.cssText = "font-size:11px;color:var(--text3)";
  info.textContent =
    "Drag nodes to reposition. Scroll to zoom. Click a node to highlight its connections.";
  el.appendChild(info);

  const svgWrap = document.createElement("div");
  svgWrap.style.cssText = "width:100%;height:600px;position:relative";
  el.appendChild(svgWrap);

  const draw = () => drawD3(file, svgWrap);
  draw();
  controls
    .querySelector("#graphMaxNodes")
    ?.addEventListener("change", draw);
  controls.querySelector("#graphColorBy")?.addEventListener("change", draw);
  controls.querySelector("[data-reset]")?.addEventListener("click", draw);
}

function drawD3(file: LoadedSbom, container: HTMLElement): void {
  container.innerHTML = "";
  const { sbom } = file;
  const maxNodes = Number(
    (document.getElementById("graphMaxNodes") as HTMLSelectElement)?.value || 120,
  );
  const colorBy =
    ((document.getElementById("graphColorBy") as HTMLSelectElement)
      ?.value as ColorMode) || "type";

  const refToComp = new Map<string, number>();
  sbom.components.forEach((c, i) => {
    if (c.bomRef) refToComp.set(c.bomRef, i);
    refToComp.set(c.name, i);
    refToComp.set(`${c.name}@${c.version}`, i);
  });

  const nodeSet = new Map<string, GNode>();
  let edges: GLink[] = [];
  const getOrCreate = (ref: string): GNode => {
    const existing = nodeSet.get(ref);
    if (existing) return existing;
    const compIdx = refToComp.get(ref) ?? -1;
    const comp = compIdx >= 0 ? sbom.components[compIdx] : null;
    const label = comp
      ? comp.name
      : (ref.split("/").pop()?.split("#").pop() || ref).substring(0, 20);
    const node: GNode = { id: ref, label, compIdx, comp };
    nodeSet.set(ref, node);
    return node;
  };
  for (const d of sbom.dependencies) {
    if (!d.deps.length) continue;
    const src = getOrCreate(d.ref);
    for (const dep of d.deps) {
      const tgt = getOrCreate(dep);
      edges.push({ source: src.id, target: tgt.id });
    }
  }

  let nodes = [...nodeSet.values()];
  if (nodes.length > maxNodes) {
    const degree = new Map<string, number>();
    for (const e of edges) {
      degree.set(e.source as string, (degree.get(e.source as string) || 0) + 1);
      degree.set(e.target as string, (degree.get(e.target as string) || 0) + 1);
    }
    nodes.sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0));
    nodes = nodes.slice(0, maxNodes);
    const ids = new Set(nodes.map((n) => n.id));
    edges = edges.filter(
      (e) => ids.has(e.source as string) && ids.has(e.target as string),
    );
  }

  const getColor = (n: GNode): string => {
    if (colorBy === "vuln") {
      if (n.compIdx < 0) return "#444c56";
      const vulns = file.findingsByComp.get(n.compIdx) || [];
      if (!vulns.length) return "#3fb950";
      const top = worstSeverity(vulns.map((v) => v.cvss.severity));
      return (
        {
          CRITICAL: "#ff4444",
          HIGH: "#f85149",
          MEDIUM: "#f0883e",
          LOW: "#d29922",
          NONE: "#3fb950",
          UNKNOWN: "#6e7681",
        }[top] || "#6e7681"
      );
    }
    if (colorBy === "license" && n.comp) {
      const lics = n.comp.licenses;
      if (!lics.length) return "#d29922";
      const cls = licClass(lics[0]);
      if (cls.includes("copyleft")) return "#f97583";
      if (cls.includes("permissive")) return "#3fb950";
      return "#378ADD";
    }
    return TYPE_COLORS[n.comp?.type || "other"] || "#888780";
  };

  const W = container.offsetWidth || 800;
  const H = 580;

  const svg = d3
    .select(container)
    .append("svg")
    .attr("id", "depGraphSvg")
    .attr("width", W)
    .attr("height", H)
    .attr("viewBox", `0 0 ${W} ${H}`);

  const g = svg.append("g");
  svg.call(
    d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (e) => g.attr("transform", e.transform.toString())),
  );

  const defs = svg.append("defs");
  const pat = defs
    .append("pattern")
    .attr("id", "grid")
    .attr("width", 40)
    .attr("height", 40)
    .attr("patternUnits", "userSpaceOnUse");
  pat
    .append("path")
    .attr("d", "M 40 0 L 0 0 0 40")
    .attr("fill", "none")
    .attr("stroke", "#21262d")
    .attr("stroke-width", "0.5");
  g.append("rect").attr("width", W).attr("height", H).attr("fill", "url(#grid)");

  defs
    .append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -4 8 8")
    .attr("refX", 14)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-4L8,0L0,4")
    .attr("fill", "#444c56");

  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.source as string, (degree.get(e.source as string) || 0) + 1);
    degree.set(e.target as string, (degree.get(e.target as string) || 0) + 1);
  }
  const rScale = d3
    .scaleSqrt()
    .domain([0, d3.max([...degree.values()]) || 1])
    .range([5, 18]);

  const sim = d3
    .forceSimulation<GNode>(nodes)
    .force(
      "link",
      d3
        .forceLink<GNode, GLink>(edges)
        .id((d) => d.id)
        .distance(60)
        .strength(0.4),
    )
    .force("charge", d3.forceManyBody().strength(-120))
    .force("center", d3.forceCenter(W / 2, H / 2))
    .force(
      "collision",
      d3.forceCollide<GNode>().radius((d) => rScale(degree.get(d.id) || 0) + 4),
    );

  const link = g
    .append("g")
    .selectAll<SVGLineElement, GLink>("line")
    .data(edges)
    .join("line")
    .attr("class", "graph-link")
    .attr("marker-end", "url(#arrow)");

  const node = g
    .append("g")
    .selectAll<SVGGElement, GNode>("g")
    .data(nodes)
    .join("g")
    .attr("class", "graph-node")
    .call(
      d3
        .drag<SVGGElement, GNode>()
        .on("start", (e, d) => {
          if (!e.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (e, d) => {
          d.fx = e.x;
          d.fy = e.y;
        })
        .on("end", (e, d) => {
          if (!e.active) sim.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }),
    )
    .on("click", (_e, d) => highlight(d));

  node
    .append("circle")
    .attr("r", (d) => rScale(degree.get(d.id) || 0))
    .attr("fill", (d) => getColor(d) + "cc")
    .attr("stroke", (d) => getColor(d));
  node
    .append("text")
    .attr("x", 0)
    .attr("y", (d) => rScale(degree.get(d.id) || 0) + 11)
    .attr("text-anchor", "middle")
    .text((d) => d.label.substring(0, 18));

  const tip = d3
    .select(container)
    .append("div")
    .style("position", "absolute")
    .style("display", "none")
    .style("background", "var(--bg2)")
    .style("border", "1px solid var(--border2)")
    .style("border-radius", "6px")
    .style("padding", "8px 12px")
    .style("font-size", "12px")
    .style("color", "var(--text)")
    .style("pointer-events", "none")
    .style("max-width", "220px")
    .style("z-index", "50");

  node
    .on("mouseover", (e: MouseEvent, d) => {
      const vulns = file.findingsByComp.get(d.compIdx) || [];
      tip
        .html(
          `<strong>${escapeHtml(d.label)}</strong>${d.comp?.version ? "<br>v" + escapeHtml(d.comp.version) : ""}${vulns.length ? `<br><span style="color:var(--red)">${vulns.length} vuln${vulns.length > 1 ? "s" : ""}</span>` : ""}`,
        )
        .style("display", "block")
        .style("left", e.offsetX + 12 + "px")
        .style("top", e.offsetY - 20 + "px");
    })
    .on("mousemove", (e: MouseEvent) => {
      tip
        .style("left", e.offsetX + 12 + "px")
        .style("top", e.offsetY - 20 + "px");
    })
    .on("mouseout", () => tip.style("display", "none"));

  // highlight connections
  const adjacency = new Map<string, Set<string>>();
  for (const e of edges) {
    const s = e.source as string;
    const t = e.target as string;
    (adjacency.get(s) ?? adjacency.set(s, new Set()).get(s)!).add(t);
    (adjacency.get(t) ?? adjacency.set(t, new Set()).get(t)!).add(s);
  }
  let highlighted: string | null = null;
  function highlight(d: GNode): void {
    if (highlighted === d.id) {
      highlighted = null;
      node.style("opacity", 1);
      link.style("opacity", 0.6).attr("stroke", "var(--border2)");
      return;
    }
    highlighted = d.id;
    const neigh = adjacency.get(d.id) ?? new Set<string>();
    node.style("opacity", (n) =>
      n.id === d.id || neigh.has(n.id) ? 1 : 0.15,
    );
    link
      .style("opacity", (l) => {
        const s = (l.source as GNode).id ?? (l.source as string);
        const t = (l.target as GNode).id ?? (l.target as string);
        return s === d.id || t === d.id ? 1 : 0.05;
      })
      .attr("stroke", (l) => {
        const s = (l.source as GNode).id ?? (l.source as string);
        const t = (l.target as GNode).id ?? (l.target as string);
        return s === d.id || t === d.id ? "var(--accent)" : "var(--border2)";
      });
  }

  sim.on("tick", () => {
    link
      .attr("x1", (d) => (d.source as GNode).x ?? 0)
      .attr("y1", (d) => (d.source as GNode).y ?? 0)
      .attr("x2", (d) => (d.target as GNode).x ?? 0)
      .attr("y2", (d) => (d.target as GNode).y ?? 0);
    node.attr("transform", (d) => `translate(${d.x ?? 0},${d.y ?? 0})`);
  });

  // legend
  const legendItems: [string, string][] =
    colorBy === "type"
      ? Object.entries(TYPE_COLORS).slice(0, 5)
      : colorBy === "vuln"
        ? [
            ["Clean", "#3fb950"],
            ["Low", "#d29922"],
            ["Medium", "#f0883e"],
            ["High", "#f85149"],
            ["Critical", "#ff4444"],
          ]
        : [
            ["Permissive", "#3fb950"],
            ["Copyleft", "#f97583"],
            ["Other", "#378ADD"],
            ["Unknown", "#d29922"],
          ];
  const legend = svg
    .append("g")
    .attr("transform", `translate(14,${H - 14 - legendItems.length * 18})`);
  legendItems.forEach(([label, color], i) => {
    legend
      .append("circle")
      .attr("cx", 6)
      .attr("cy", i * 18)
      .attr("r", 5)
      .attr("fill", color + "cc")
      .attr("stroke", color);
    legend
      .append("text")
      .attr("x", 16)
      .attr("y", i * 18 + 4)
      .attr("font-size", 10)
      .attr("fill", "#8b949e")
      .text(label);
  });
}
