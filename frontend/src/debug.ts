// Tiny leveled debug logger.
//
// Level is resolved (in priority order) from:
//   1. a `?debug=<level>` query param (also persisted to localStorage)
//   2. localStorage "sbom-debug"
//   3. default "warn"
//
// Usage:
//   import { debug } from "./debug";
//   debug.info("scan", "took", ms, "ms");
//   const end = debug.time("api", "POST /scan");  ...  end();
//
// No secrets should ever be passed to these functions.

export type DebugLevel = "error" | "warn" | "info" | "debug";

const LEVELS: DebugLevel[] = ["error", "warn", "info", "debug"];
const RANK: Record<DebugLevel, number> = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

const DEFAULT_LEVEL: DebugLevel = "warn";
const STORAGE_KEY = "sbom-debug";

function isLevel(v: unknown): v is DebugLevel {
  return typeof v === "string" && (LEVELS as string[]).includes(v);
}

function readQueryLevel(): DebugLevel | null {
  try {
    const params = new URLSearchParams(location.search);
    const q = params.get("debug");
    if (q == null) return null;
    // `?debug` with no value is treated as "debug"
    if (q === "") return "debug";
    return isLevel(q) ? q : null;
  } catch {
    return null;
  }
}

function readStorageLevel(): DebugLevel | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return isLevel(v) ? v : null;
  } catch {
    return null;
  }
}

function resolveLevel(): DebugLevel {
  // Query param wins and is persisted so it survives navigation within the app.
  const q = readQueryLevel();
  if (q) {
    try {
      localStorage.setItem(STORAGE_KEY, q);
    } catch {
      /* ignore */
    }
    return q;
  }
  return readStorageLevel() ?? DEFAULT_LEVEL;
}

let currentLevel: DebugLevel = resolveLevel();

/** Explicitly set the active debug level (also persisted to localStorage). */
export function setDebugLevel(level: DebugLevel): void {
  if (!isLevel(level)) return;
  currentLevel = level;
  try {
    localStorage.setItem(STORAGE_KEY, level);
  } catch {
    /* ignore */
  }
}

/** Current active level. */
export function getDebugLevel(): DebugLevel {
  return currentLevel;
}

function enabled(level: DebugLevel): boolean {
  return RANK[level] <= RANK[currentLevel];
}

function emit(
  level: DebugLevel,
  scope: string,
  args: unknown[],
): void {
  if (!enabled(level)) return;
  const prefix = `[sbom:${scope}]`;
  const sink =
    level === "error"
      ? console.error
      : level === "warn"
        ? console.warn
        : level === "info"
          ? console.info
          : console.debug;
  sink(prefix, ...args);
}

export const debug = {
  error: (scope: string, ...args: unknown[]) => emit("error", scope, args),
  warn: (scope: string, ...args: unknown[]) => emit("warn", scope, args),
  info: (scope: string, ...args: unknown[]) => emit("info", scope, args),
  debug: (scope: string, ...args: unknown[]) => emit("debug", scope, args),
  /**
   * Start a timer; returns a function that, when called, logs the elapsed
   * milliseconds at the given level (default "debug").
   */
  time(scope: string, label: string, level: DebugLevel = "debug") {
    const t0 =
      typeof performance !== "undefined" ? performance.now() : Date.now();
    return (...extra: unknown[]): number => {
      const t1 =
        typeof performance !== "undefined" ? performance.now() : Date.now();
      const ms = Math.round((t1 - t0) * 10) / 10;
      emit(level, scope, [label, `${ms}ms`, ...extra]);
      return ms;
    };
  },
};

// Make the setter reachable from the devtools console without bundler help.
try {
  (globalThis as unknown as Record<string, unknown>).setDebugLevel =
    setDebugLevel;
} catch {
  /* ignore */
}
