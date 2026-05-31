import { escapeHtml } from "./util";

let toastTimer: number | undefined;

export function toast(
  message: string,
  kind: "info" | "success" | "error" = "info",
): void {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.className = `toast ${kind === "info" ? "" : kind}`;
  const icon =
    kind === "error"
      ? "ti-alert-circle"
      : kind === "success"
        ? "ti-circle-check"
        : "ti-info-circle";
  t.innerHTML = `<i class="ti ${icon}"></i> <span></span>`;
  (t.querySelector("span") as HTMLElement).textContent = message;
  // force reflow then show
  void t.offsetWidth;
  t.classList.add("show");
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => t?.classList.remove("show"), 3500);
}

/** Generic modal overlay. Returns a close fn. Content is built by caller (already escaped). */
export function openModal(
  title: string,
  bodyHtml: string,
  onMount?: (root: HTMLElement, close: () => void) => void,
  onClose?: () => void,
): () => void {
  const overlay = document.createElement("div");
  overlay.style.cssText =
    "position:fixed;inset:0;background:#00000099;z-index:500;display:flex;align-items:center;justify-content:center;padding:24px";
  const box = document.createElement("div");
  box.style.cssText =
    "background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r2);max-width:640px;width:100%;max-height:80vh;display:flex;flex-direction:column;overflow:hidden";
  box.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;padding:16px 20px;border-bottom:1px solid var(--border);background:var(--bg3)">
      <div style="font-size:15px;font-weight:600;color:var(--text);flex:1">${escapeHtml(title)}</div>
      <button class="detail-close" data-close>&times;</button>
    </div>
    <div style="padding:20px;overflow:auto" data-body>${bodyHtml}</div>`;
  overlay.appendChild(box);
  document.body.appendChild(overlay);

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    overlay.remove();
    if (onClose) onClose();
  };
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });
  box.querySelector("[data-close]")?.addEventListener("click", close);
  const escHandler = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      close();
      document.removeEventListener("keydown", escHandler);
    }
  };
  document.addEventListener("keydown", escHandler);

  if (onMount) onMount(box.querySelector("[data-body]") as HTMLElement, close);
  return close;
}

const SHORTCUTS: [string, string][] = [
  ["/ or Cmd/Ctrl+K", "Focus global search"],
  ["1 – 9, 0", "Jump to view (Overview…Transitive)"],
  ["g", "Open dependency graph"],
  ["v", "Open vulnerabilities"],
  ["t", "Toggle light / dark theme"],
  ["?", "Show / hide this help"],
  ["Esc", "Close panels / modals"],
];

let closeShortcuts: (() => void) | null = null;
export function toggleShortcutHelp(): void {
  if (closeShortcuts) {
    closeShortcuts();
    closeShortcuts = null;
    return;
  }
  const rows = SHORTCUTS.map(
    ([k, d]) =>
      `<div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border)">
        <kbd style="font-family:var(--font);font-size:11px;background:var(--bg4);border:1px solid var(--border2);border-radius:4px;padding:2px 8px;color:var(--text);min-width:140px;text-align:center">${escapeHtml(k)}</kbd>
        <span style="font-size:13px;color:var(--text2)">${escapeHtml(d)}</span>
      </div>`,
  ).join("");
  const close = openModal("Keyboard shortcuts", rows, undefined, () => {
    closeShortcuts = null;
  });
  closeShortcuts = close;
}
