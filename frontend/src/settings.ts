import type { LicensePolicy, Source } from "./types";
import * as api from "./api";
import { openModal, toast } from "./ui";
import { escapeHtml } from "./util";

const LS_LICENSE = "sbom-license-policy";

const DEFAULT_POLICY: LicensePolicy = { deny: [], warn: [] };

/** Read the persisted license policy (empty deny/warn by default). */
export function getLicensePolicy(): LicensePolicy {
  try {
    const raw = localStorage.getItem(LS_LICENSE);
    if (!raw) return { ...DEFAULT_POLICY };
    const parsed = JSON.parse(raw) as Partial<LicensePolicy>;
    return {
      deny: Array.isArray(parsed.deny) ? parsed.deny.map(String) : [],
      warn: Array.isArray(parsed.warn) ? parsed.warn.map(String) : [],
    };
  } catch {
    return { ...DEFAULT_POLICY };
  }
}

/** Persist the license policy. Empty lists are kept so the user can clear rules. */
export function setLicensePolicy(policy: LicensePolicy): void {
  localStorage.setItem(LS_LICENSE, JSON.stringify(policy));
}

/** True if any deny/warn rule is configured. */
export function hasLicensePolicy(): boolean {
  const p = getLicensePolicy();
  return p.deny.length > 0 || p.warn.length > 0;
}

function parseList(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Modal to edit deny/warn license lists; calls onSave when applied. */
export function openLicensePolicyModal(onSave: () => void): void {
  const current = getLicensePolicy();
  openModal(
    "License policy gate",
    `<div style="font-size:12px;color:var(--text2);margin-bottom:14px">
       Comma-separated SPDX ids or substrings (case-insensitive). Any <strong>deny</strong> match forces a <strong>FAIL</strong> verdict; any <strong>warn</strong> match forces at least <strong>REVIEW</strong>.
     </div>
     <label class="sidebar-label" style="padding:0">Deny (block)</label>
     <input id="denyInput" class="nvd-input" style="width:100%;margin:6px 0 14px" placeholder="AGPL, GPL-3.0" value="${escapeHtml(current.deny.join(", "))}">
     <label class="sidebar-label" style="padding:0">Warn (review)</label>
     <input id="warnInput" class="nvd-input" style="width:100%;margin:6px 0 14px" placeholder="LGPL, MPL-2.0" value="${escapeHtml(current.warn.join(", "))}">
     <button class="nvd-scan-btn" id="policySave" style="margin-top:4px"><i class="ti ti-check"></i> Save & re-assess</button>`,
    (root, close) => {
      const deny = root.querySelector("#denyInput") as HTMLInputElement;
      const warn = root.querySelector("#warnInput") as HTMLInputElement;
      root.querySelector("#policySave")?.addEventListener("click", () => {
        setLicensePolicy({
          deny: parseList(deny.value),
          warn: parseList(warn.value),
        });
        close();
        toast("License policy saved", "success");
        onSave();
      });
      deny.focus();
    },
  );
}

function dot(reachable: boolean | null, enabled: boolean): string {
  let color = "var(--text3)";
  let title = "disabled";
  if (enabled) {
    if (reachable === true) {
      color = "var(--green)";
      title = "reachable";
    } else if (reachable === false) {
      color = "var(--red)";
      title = "unreachable";
    } else {
      color = "var(--amber)";
      title = "not probed";
    }
  }
  return `<span title="${escapeHtml(title)}" style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${color};flex-shrink:0"></span>`;
}

function sourcesHtml(sources: Source[]): string {
  if (!sources.length)
    return `<div style="font-size:12px;color:var(--text3)">No connectors reported.</div>`;
  return sources
    .map(
      (s) => `<div style="display:flex;align-items:flex-start;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)">
        ${dot(s.reachable, s.enabled)}
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:600;color:var(--text)">${escapeHtml(s.name)}${s.configured ? "" : ` <span style="font-weight:400;color:var(--text3);font-size:11px">(not configured)</span>`}</div>
          <div style="font-size:12px;color:var(--text3);margin-top:2px;word-break:break-word">${escapeHtml(s.detail)}</div>
        </div>
        <span style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px">${s.enabled ? "on" : "off"}</span>
      </div>`,
    )
    .join("");
}

/** Modal listing the 5 data-source connectors, fetched live. */
export function openSourcesModal(): void {
  openModal(
    "Data sources",
    `<div id="sourcesBody"><div class="loading">Loading connector status…</div></div>`,
    (root) => {
      const body = root.querySelector("#sourcesBody") as HTMLElement;
      api
        .getSources()
        .then(({ sources }) => {
          body.innerHTML = sourcesHtml(sources);
        })
        .catch((e: Error) => {
          body.innerHTML = `<div style="font-size:12px;color:var(--red)">Failed to load sources: ${escapeHtml(e.message)}</div>`;
        });
    },
  );
}
