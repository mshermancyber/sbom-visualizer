import type { Vuln, Severity, Depth } from "./types";
import { escapeHtml, externalLink } from "./util";

export function suppressedBadge(status?: string): string {
  const label = status ? escapeHtml(status.replace(/_/g, " ")) : "suppressed";
  return `<span class="not-scanned-badge" style="color:var(--text3)" title="VEX suppressed: ${label}"><i class="ti ti-ban"></i> ${label}</span>`;
}

export function sevBadge(sev: Severity): string {
  return `<span class="sev-badge sev-badge-${sev}">${escapeHtml(sev)}</span>`;
}

export function kevBadge(): string {
  return `<span class="kev-badge"><i class="ti ti-bolt"></i> KEV</span>`;
}

export function maliciousBadge(): string {
  return `<span class="sev-badge sev-badge-CRITICAL"><i class="ti ti-skull"></i> MALICIOUS</span>`;
}

export function depthBadge(depth: Depth): string {
  if (depth === "direct")
    return `<span class="type-tag type-application">direct</span>`;
  if (depth === "transitive")
    return `<span class="type-tag type-other">transitive</span>`;
  return `<span class="type-tag type-other">unknown</span>`;
}

export function epssBadge(v: Vuln): string {
  if (!v.epss) return "";
  const pct = Math.round((v.epss.percentile ?? 0) * 100);
  const score = (v.epss.score ?? 0).toFixed(3);
  const color =
    pct >= 90 ? "var(--red)" : pct >= 50 ? "var(--amber)" : "var(--text3)";
  return `<span class="not-scanned-badge" style="color:${color}" title="EPSS exploit-probability score ${score}"><i class="ti ti-chart-line"></i> EPSS ${pct}%</span>`;
}

export function fixedBadge(v: Vuln): string {
  if (!v.fixed || !v.fixed.length) return "";
  return `<span class="not-scanned-badge" style="color:var(--green)" title="Fixed in ${escapeHtml(v.fixed.join(", "))}"><i class="ti ti-circle-check"></i> fixed-in ${escapeHtml(v.fixed[0])}</span>`;
}

export function scoreSourceLabel(v: Vuln): string {
  if (!v.scoreSource) return "";
  const name = v.scoreSource.toUpperCase();
  return `<span class="not-scanned-badge" style="color:var(--text3)" title="CVSS score provenance"><i class="ti ti-database"></i> via ${escapeHtml(name)}</span>`;
}

export function cweTags(v: Vuln): string {
  if (!v.cwes || !v.cwes.length) return "";
  return `<div class="vuln-cwes">${v.cwes
    .map((c) => `<span class="cwe-tag">${escapeHtml(c)}</span>`)
    .join("")}</div>`;
}

/** Full vuln card matching the demo markup.
 *  Pass compPurl to enable the Suppress button (sets data-suppress-vuln / data-suppress-purl). */
export function vulnCard(v: Vuln, compLabel?: string, compPurl?: string): string {
  const idLink = v.cveId
    ? externalLink(`https://nvd.nist.gov/vuln/detail/${v.cveId}`, v.cveId)
    : escapeHtml(v.id);
  const score = v.cvss.score != null ? v.cvss.score.toFixed(1) : "—";
  const refs = (v.references || [])
    .slice(0, 3)
    .map((r) => externalLink(r, shortenUrl(r)))
    .join(" · ");
  const suppressed = v.suppressed === true;
  const suppressBtn = compPurl
    ? `<button class="sev-filter-btn" style="font-size:10px;padding:2px 8px;opacity:${suppressed ? "0.5" : "1"}"
         data-suppress-vuln="${escapeHtml(v.cveId ?? v.id)}"
         data-suppress-purl="${escapeHtml(compPurl)}"
         title="${suppressed ? "Manage suppression" : "Suppress this finding"}">
         <i class="ti ti-ban"></i>${suppressed ? " Suppressed" : " Suppress"}
       </button>`
    : "";
  return `<div class="vuln-card${suppressed ? '" style="opacity:0.55' : ""}">
    <div class="vuln-card-header">
      <div style="flex:1;min-width:0">
        <div class="vuln-cve-id">${idLink}</div>
        ${compLabel ? `<div class="comp-version">${escapeHtml(compLabel)}</div>` : ""}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;align-items:center">
        ${suppressed ? suppressedBadge(v.suppressionStatus) : ""}
        ${!suppressed ? sevBadge(v.cvss.severity) : ""}
        ${v.malicious && !suppressed ? maliciousBadge() : ""}
        ${v.kev && !suppressed ? kevBadge() : ""}
        ${suppressBtn}
      </div>
    </div>
    ${v.description ? `<div class="vuln-desc">${escapeHtml(truncate(v.description, 400))}</div>` : ""}
    <div class="vuln-meta-row">
      <span class="vuln-score">CVSS ${escapeHtml(score)}${v.cvss.version ? " v" + escapeHtml(v.cvss.version) : ""}</span>
      ${scoreSourceLabel(v)}
      ${epssBadge(v)}
      ${fixedBadge(v)}
    </div>
    ${cweTags(v)}
    ${refs ? `<div class="vuln-refs">${refs}</div>` : ""}
  </div>`;
}

function shortenUrl(u: string): string {
  try {
    const url = new URL(u);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return u.slice(0, 30);
  }
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
