import type { Severity } from "./types";

/** Escape a string for safe interpolation into an HTML context. */
export function escapeHtml(value: unknown): string {
  const s = value == null ? "" : String(value);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SAFE_SCHEMES = ["http:", "https:", "mailto:"];

/** Return the URL only if its scheme is allowlisted, else "". */
export function safeUrl(raw: unknown): string {
  const s = raw == null ? "" : String(raw).trim();
  if (!s) return "";
  try {
    const u = new URL(s, window.location.origin);
    if (SAFE_SCHEMES.includes(u.protocol)) return s;
  } catch {
    /* invalid URL */
  }
  return "";
}

/** Build a safe external anchor (escaped href + text, rel/target hardened). */
export function externalLink(href: string, text: string): string {
  const safe = safeUrl(href);
  if (!safe) return escapeHtml(text);
  return `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
}

/** Create a DOM element with optional class/html. */
export function el(
  tag: string,
  className?: string,
  html?: string,
): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (html !== undefined) node.innerHTML = html;
  return node;
}

/** Read a CSS variable from :root (resolves theme). */
export function cssVar(name: string): string {
  return getComputedStyle(document.body).getPropertyValue(name).trim();
}

export function fmtSize(bytes: number): string {
  if (!bytes) return "0 B";
  const k = 1024;
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export const SEV_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "NONE",
  "UNKNOWN",
];

const SEV_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  NONE: 4,
  UNKNOWN: 5,
};

export function sevRank(s: Severity): number {
  return SEV_RANK[s] ?? 5;
}

/** Highest (worst) severity among a list. */
export function worstSeverity(sevs: Severity[]): Severity {
  return sevs.reduce<Severity>(
    (best, s) => (sevRank(s) < sevRank(best) ? s : best),
    "UNKNOWN",
  );
}

/** Neutralize spreadsheet formula injection, then CSV-quote a value. */
export function csvCell(value: unknown): string {
  let s = value == null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

export function csvRow(cells: unknown[]): string {
  return cells.map(csvCell).join(",");
}

/** Trigger a client-side download of text content. */
export function downloadText(
  filename: string,
  content: string,
  mime = "text/plain",
): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** License classification used for color coding (mirrors the demo heuristic). */
export function licClass(license: string): string {
  const l = (license || "").toUpperCase();
  if (!l || l === "(NONE)" || l === "NONE" || l === "NOASSERTION")
    return "license-unknown";
  const copyleft = [
    "GPL",
    "LGPL",
    "AGPL",
    "MPL",
    "EPL",
    "CDDL",
    "EUPL",
    "OSL",
    "CC-BY-SA",
  ];
  if (copyleft.some((c) => l.includes(c))) return "license-copyleft";
  const permissive = [
    "MIT",
    "APACHE",
    "BSD",
    "ISC",
    "ZLIB",
    "UNLICENSE",
    "WTFPL",
    "0BSD",
    "PYTHON",
  ];
  if (permissive.some((p) => l.includes(p))) return "license-permissive";
  return "license-tag";
}

/**
 * Map a Package URL (purl) to its public registry page, when derivable.
 * Returns "" if the type is unknown or the purl can't be parsed.
 * Result is always scheme-allowlisted via safeUrl().
 */
export function purlToRegistryUrl(purl: unknown): string {
  const raw = purl == null ? "" : String(purl).trim();
  if (!raw.startsWith("pkg:")) return "";
  // pkg:type/namespace/name@version?qualifiers#subpath
  let body = raw.slice(4);
  // strip qualifiers / subpath
  const hash = body.indexOf("#");
  if (hash >= 0) body = body.slice(0, hash);
  const qmark = body.indexOf("?");
  if (qmark >= 0) body = body.slice(0, qmark);
  const slash = body.indexOf("/");
  if (slash < 0) return "";
  const type = body.slice(0, slash).toLowerCase();
  let rest = body.slice(slash + 1);
  // drop version
  const at = rest.lastIndexOf("@");
  if (at > 0) rest = rest.slice(0, at);
  const segments = rest.split("/").filter(Boolean).map(decodePurlSegment);
  if (!segments.length) return "";
  const namespace = segments.slice(0, -1).join("/");
  const name = segments[segments.length - 1];

  let url = "";
  switch (type) {
    case "npm":
      url = `https://www.npmjs.com/package/${namespace ? namespace + "/" + name : name}`;
      break;
    case "pypi":
      url = `https://pypi.org/project/${name}/`;
      break;
    case "maven":
      if (!namespace) return "";
      url = `https://central.sonatype.com/artifact/${namespace}/${name}`;
      break;
    case "cargo":
      url = `https://crates.io/crates/${name}`;
      break;
    case "gem":
      url = `https://rubygems.org/gems/${name}`;
      break;
    case "nuget":
      url = `https://www.nuget.org/packages/${name}`;
      break;
    case "golang":
      url = `https://pkg.go.dev/${namespace ? namespace + "/" + name : name}`;
      break;
    case "composer":
      if (!namespace) return "";
      url = `https://packagist.org/packages/${namespace}/${name}`;
      break;
    default:
      return "";
  }
  return safeUrl(url);
}

function decodePurlSegment(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function typeClass(type: string): string {
  const t = (type || "other").toLowerCase();
  const known = [
    "library",
    "framework",
    "application",
    "container",
    "file",
    "os",
  ];
  return known.includes(t) ? `type-${t}` : "type-other";
}
