"""Downloaders + parsers for the KEV, EPSS, and NVD (CVEProject cvelistV5) feeds.

Downloads use **curl** via subprocess (per the contract). Parsing is split into pure
functions (``parse_kev``, ``parse_epss_csv``, ``parse_cve_list_record``) so they can be
unit-tested offline from fixtures. The ``refresh_*`` functions tie download + parse +
wholesale store-replace together and update the ``meta`` status as they go.

## NVD / CVE source
We use the **CVEProject cvelistV5** GitHub archive instead of the NVD API 2.0:
  https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip
This is a ZIP of every published CVE as a JSON file (same format as cve.org / MITRE CVE
Services API), ~350k entries, no rate limit, no API key. One download replaces the entire
inventory daily. The format is the MITRE CVE Record 5.x schema (cveMetadata + containers),
which we already parse in the backend for cve.org enrichment.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from .config import settings
from .logging_config import get_logger
from .store import Store

log = get_logger("feeds.download")

_SEV_OK = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CVE_ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"


# ── curl helpers ──────────────────────────────────────────────
def curl_bytes(url: str, *, max_time: float | None = None,
               headers: dict[str, str] | None = None) -> bytes:
    """Fetch ``url`` with curl, returning the raw response body as bytes.

    Raises ``RuntimeError`` on a non-zero curl exit or an HTTP error status. ``--fail``
    makes curl exit non-zero on HTTP >= 400. Secrets in headers are never logged.
    """
    cmd = [
        "curl", "-sSL", "--fail",
        "--connect-timeout", str(int(settings.curl_connect_timeout)),
        "--max-time", str(int(max_time if max_time is not None else settings.curl_max_time)),
    ]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    log.debug("curl GET %s", url)
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"curl failed ({proc.returncode}) for {url}: {err}")
    return proc.stdout


def curl_to_file(url: str, dest: Path, *, max_time: float | None = None) -> int:
    """Download ``url`` with curl straight to ``dest``, returning bytes written.

    Raises ``RuntimeError`` on a non-zero curl exit / HTTP error (``--fail``). The caller
    is responsible for any atomic-rename dance; this just writes to the given path.
    """
    cmd = [
        "curl", "-sSL", "--fail",
        "--connect-timeout", str(int(settings.curl_connect_timeout)),
        "--max-time", str(int(max_time if max_time is not None else settings.curl_max_time)),
        "-o", str(dest),
        url,
    ]
    log.debug("curl GET %s -> %s", url, dest)
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"curl failed ({proc.returncode}) for {url}: {err}")
    return dest.stat().st_size if dest.exists() else 0


# ── KEV ───────────────────────────────────────────────────────
def parse_kev(raw: bytes | str | dict) -> list[tuple[str, str | None, str | None]]:
    """Parse the CISA KEV JSON into ``(cve, due_date, name)`` rows."""
    data = raw if isinstance(raw, dict) else json.loads(raw)
    rows: list[tuple[str, str | None, str | None]] = []
    seen: set[str] = set()
    for v in data.get("vulnerabilities") or []:
        cve = (v.get("cveID") or "").strip()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        rows.append((cve, v.get("dueDate") or None, v.get("vulnerabilityName") or None))
    return rows


def refresh_kev(store: Store) -> int:
    store.set_status("kev", "refreshing", "downloading KEV")
    try:
        raw = curl_bytes(settings.kev_url)
        rows = parse_kev(raw)
        count = store.replace_kev(rows)
        log.info("KEV refreshed: %d CVEs", count)
        return count
    except Exception as e:  # noqa: BLE001 — record + re-raise to caller
        log.error("KEV refresh failed: %s", e)
        store.set_status("kev", "error", str(e)[:300])
        raise


# ── EPSS ──────────────────────────────────────────────────────
def parse_epss_csv(text: str) -> list[tuple[str, float, float]]:
    """Parse the EPSS CSV body into ``(cve, epss, percentile)`` rows.

    The file starts with a ``#model_version...`` comment line, then the
    ``cve,epss,percentile`` header, then data rows. We skip any leading ``#`` comment
    line(s) and the column header, and tolerate malformed rows by skipping them.
    """
    rows: list[tuple[str, float, float]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("cve,"):
            continue  # column header
        parts = line.split(",")
        if len(parts) < 3:
            continue
        cve = parts[0].strip()
        if not cve.upper().startswith("CVE-"):
            continue
        try:
            epss = float(parts[1])
            pct = float(parts[2])
        except ValueError:
            continue
        rows.append((cve, epss, pct))
    return rows


def refresh_epss(store: Store) -> int:
    store.set_status("epss", "refreshing", "downloading EPSS")
    try:
        gz = curl_bytes(settings.epss_url)
        text = gzip.decompress(gz).decode("utf-8", "replace")
        rows = parse_epss_csv(text)
        count = store.replace_epss(rows)
        log.info("EPSS refreshed: %d CVEs", count)
        return count
    except Exception as e:  # noqa: BLE001
        log.error("EPSS refresh failed: %s", e)
        store.set_status("epss", "error", str(e)[:300])
        raise


# ── CVEProject cvelistV5  (https://github.com/CVEProject/cvelistV5/tree/main/cves) ──
# The authoritative CVE catalog maintained by the CVE Program. Downloaded as a ZIP
# archive (main.zip) which contains every published CVE as an individual JSON file
# under cves/<YEAR>/<RANGE>/CVE-YEAR-NNNNN.json using the CVE Record 5.x schema
# (same format as the cve.org / MITRE CVE Services API).
# No rate limit, no API key. ~350k CVEs. One download replaces the entire inventory.

_CVE_LIST_ZIP = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"


def parse_cve_list_record(data: dict) -> dict | None:
    """Parse one cvelistV5 JSON record (CVE Record 5.x) into a normalised row.

    Returns None for REJECTED records or entries without a CVE id.
    CVSS preference: v3.1 → v3.0 → v4.0 → v2.0 (highest-quality first, matching backend).
    """
    meta = data.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or "").strip()
    if not cve_id:
        return None
    if (meta.get("state") or "").upper() == "REJECTED":
        return None

    containers = data.get("containers") or {}
    # CNA is authoritative; ADP containers (e.g. CISA vulnrichment) supplement.
    sources: list[dict] = [s for s in
                           [containers.get("cna")] + list(containers.get("adp") or [])
                           if s]

    score: float | None = None
    severity: str | None = None
    version: str | None = None
    vector: str | None = None

    _order = [("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV4_0", "4.0"), ("cvssV2_0", "2.0")]
    for src in sources:
        for metrics_entry in (src.get("metrics") or []):
            for key, ver in _order:
                m = metrics_entry.get(key)
                if not m:
                    continue
                cdata = m.get("cvssData") or m
                sc = cdata.get("baseScore")
                if sc is None:
                    continue
                score = round(float(sc) * 10) / 10
                sev = (cdata.get("baseSeverity") or "").upper()
                severity = sev if sev in _SEV_OK else None
                vector = cdata.get("vectorString") or None
                version = ver
                break
            if score is not None:
                break
        if score is not None:
            break

    cwes: list[str] = []
    seen_c: set[str] = set()
    for src in sources:
        for pt in (src.get("problemTypes") or []):
            for d in (pt.get("descriptions") or []):
                raw_id = str(d.get("cweId") or d.get("value") or "")
                m = _CWE_RE.search(raw_id)
                if m:
                    cid = m.group(0).upper()
                    if cid not in seen_c:
                        seen_c.add(cid)
                        cwes.append(cid)

    refs: list[str] = []
    seen_r: set[str] = set()
    cna = containers.get("cna") or {}
    for r in list(cna.get("references") or [])[:10]:
        url = r.get("url") or ""
        if url and url not in seen_r:
            seen_r.add(url)
            refs.append(url)

    return {
        "cve": cve_id, "score": score, "severity": severity or "",
        "version": version or "", "vector": vector or "",
        "cwes": cwes, "refs": refs,
    }


def refresh_nvd(store: Store) -> int:
    """Download the CVEProject cvelistV5 ZIP, parse all CVE records, wholesale-replace.

    Downloads https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip via curl
    to a temp file, then streams through the ZIP reading CVE JSON files one at a time (no
    full disk extraction). Commits the entire record set in one atomic transaction.
    """
    store.set_status("nvd", "refreshing", "downloading CVEProject cvelistV5 zip…")
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        log.info("Downloading CVEProject cvelistV5 archive from GitHub…")
        cmd = [
            "curl", "-sSL", "--fail",
            "--connect-timeout", str(int(settings.curl_connect_timeout)),
            "--max-time", "600",        # full zip ~100-200 MB; allow 10 min
            "-o", str(tmp_path),
            _CVE_LIST_ZIP,
        ]
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(f"curl download failed ({proc.returncode}): {err}")

        zip_mb = tmp_path.stat().st_size / 1_048_576
        log.info("Downloaded %.1f MB; streaming CVE JSON files…", zip_mb)
        store.set_status("nvd", "refreshing", f"parsing {zip_mb:.0f} MB archive…")

        records: list[dict] = []
        skipped = 0
        with zipfile.ZipFile(tmp_path, "r") as zf:
            # Only process files under cves/ (skip delta.json, deltaLog.json, etc.)
            cve_names = [
                n for n in zf.namelist()
                if "/cves/" in n and n.endswith(".json")
                and not n.split("/")[-1].startswith("delta")
            ]
            total_files = len(cve_names)
            log.info("%d CVE JSON files in archive", total_files)

            for i, name in enumerate(cve_names):
                try:
                    rec = parse_cve_list_record(json.loads(zf.read(name)))
                    if rec:
                        records.append(rec)
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    skipped += 1
                if i % 50_000 == 0 and i > 0:
                    pct = round(i / total_files * 100)
                    log.info("Parsed %d/%d (%d%%) — %d records", i, total_files, pct, len(records))
                    store.set_status("nvd", "refreshing",
                                     f"{i}/{total_files} ({pct}%) — {len(records)} records")

        log.info("Parsed %d records, %d skipped/rejected; committing…", len(records), skipped)
        store.set_status("nvd", "refreshing", f"committing {len(records):,} records…")
        count = store.replace_nvd(records)
        log.info("CVEProject cvelistV5 mirror: %d CVEs stored", count)
        return count

    except Exception as e:  # noqa: BLE001
        log.error("NVD/cvelistV5 refresh failed: %s", e)
        store.set_status("nvd", "error", str(e)[:300])
        raise
    finally:
        if tmp_path:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass


# ── OSV  (https://osv-vulnerabilities.storage.googleapis.com) ──
# A full daily copy of the OSV database in the **osv-scanner offline cache layout**:
#   <OSV_CACHE_DIR>/osv-scanner/<ECOSYSTEM>/all.zip
# The on-disk directory name is the LITERAL ecosystem string (spaces and dots and all);
# only the URL is percent-encoded. Unlike kev/epss/nvd this feed has no SQLite table — it
# is files on disk — so we track it in the ``meta`` row only. ~1.2 GB across 45 ecosystems.

# Per-file curl timeout: the largest ecosystem (npm) is ~200 MB, so allow plenty.
_OSV_MAX_TIME = 600.0


# An ecosystem name is used VERBATIM as a single filesystem path segment
# (``<cache>/osv-scanner/<eco>/all.zip``). Real OSV names look like "npm", "PyPI",
# "crates.io", "Red Hat", "Debian:11", "Ubuntu:22.04" — letters/digits plus a small
# set of punctuation, always starting with an alphanumeric. This allowlist rejects
# anything that could traverse the path (``/``, ``\``, ``..``, leading ``.``/``-``/``:``,
# control chars, or an absolute path) before it ever reaches ``root / eco``.
_ECO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]*$")


def _is_safe_ecosystem(name: str) -> bool:
    """True iff ``name`` is a safe single path segment (no traversal)."""
    return bool(_ECO_RE.fullmatch(name)) and ".." not in name


def parse_ecosystems(text: str) -> list[str]:
    """Parse ``ecosystems.txt`` (one ecosystem name per line) into a list.

    Names may contain spaces ("Red Hat") and dots ("crates.io"). Blank lines are
    dropped; surrounding whitespace is stripped; order/duplicates are preserved-but-deduped.
    Names that are not a safe single path segment (path separators, ``..``, absolute
    paths, control chars) are rejected — they are used verbatim as directory names, so
    an unsanitized one would let a tampered/MITM'd ``ecosystems.txt`` write outside the
    cache root (path traversal).
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        name = line.strip()
        if not name or name in seen:
            continue
        if not _is_safe_ecosystem(name):
            log.warning("OSV: rejecting unsafe ecosystem name %r (path-traversal guard)", name)
            continue
        seen.add(name)
        out.append(name)
    return out


def refresh_osv(store: Store) -> int:
    """Mirror the entire OSV database into the osv-scanner offline cache layout.

    Fetches ``ecosystems.txt``, then for each ecosystem downloads
    ``<bucket>/<urlencoded-ecosystem>/all.zip`` to a temp file in the target directory and
    atomically ``os.replace()``-s it into ``<cache>/osv-scanner/<ecosystem>/all.zip`` so a
    concurrent scan never reads a half-written zip. Ecosystems with no ``all.zip`` (HTTP
    404) are skipped and counted, not fatal. Wholesale overwrite every run.

    Returns the number of ecosystem zips successfully written (also the ``osv`` rowCount).
    """
    store.set_status("osv", "refreshing", "downloading ecosystems.txt…")
    try:
        text = curl_bytes(settings.osv_ecosystems_url).decode("utf-8", "replace")
        ecosystems = parse_ecosystems(text)
        log.info("OSV: %d ecosystems to mirror", len(ecosystems))

        root = Path(settings.osv_cache_dir) / "osv-scanner"
        root_resolved = root.resolve()
        written = 0
        skipped = 0
        total_bytes = 0

        for i, eco in enumerate(ecosystems, 1):
            # Local path uses the LITERAL ecosystem name; only the URL is encoded.
            eco_dir = root / eco
            # Defense-in-depth: even though parse_ecosystems() allowlists names, verify the
            # resolved target stays under the cache root before creating/writing anything.
            try:
                eco_dir.resolve().relative_to(root_resolved)
            except ValueError:
                skipped += 1
                log.warning("OSV %d/%d: skip %s (escapes cache root)", i, len(ecosystems), eco)
                continue
            eco_dir.mkdir(parents=True, exist_ok=True)
            dest = eco_dir / "all.zip"
            url = f"{settings.osv_bucket_base}/{quote(eco, safe='')}/all.zip"

            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".zip.tmp", dir=str(eco_dir))
            os.close(tmp_fd)
            tmp_path = Path(tmp_name)
            try:
                size = curl_to_file(url, tmp_path, max_time=_OSV_MAX_TIME)
                os.replace(tmp_path, dest)  # atomic within the same dir
                written += 1
                total_bytes += size
                log.debug("OSV %d/%d: %s (%d bytes)", i, len(ecosystems), eco, size)
            except RuntimeError as e:  # noqa: PERF203 — 404 / no all.zip → skip
                skipped += 1
                log.info("OSV %d/%d: skip %s (%s)", i, len(ecosystems), eco, e)
                tmp_path.unlink(missing_ok=True)
            if i % 10 == 0:
                store.set_status("osv", "refreshing",
                                 f"{i}/{len(ecosystems)} ecosystems…")

        mb = total_bytes / 1_048_576
        detail = f"{mb:.0f} MB across {written} ecosystems ({skipped} skipped)"
        store.stamp_meta("osv", written, "ready" if written else "empty", detail)
        log.info("OSV mirror: %d zips written, %d skipped, %.0f MB",
                 written, skipped, mb)
        return written
    except Exception as e:  # noqa: BLE001
        log.error("OSV refresh failed: %s", e)
        store.set_status("osv", "error", str(e)[:300])
        raise


# ── enriched  (denormalized KEV+EPSS+NVD join, built from the local tables) ──
def refresh_enriched(store: Store) -> int:
    """Rebuild the denormalized ``cve_enriched`` table from the local kev/epss/nvd tables.

    No download — this is a pure in-DB join run as the FINAL step of every refresh so it
    pegs every CVE against the freshly-updated KEV/EPSS/NVD data. ``build_enriched`` stamps
    ``meta['enriched']`` itself; we just mark it refreshing first for status visibility.
    """
    store.set_status("enriched", "refreshing", "rebuilding enriched join…")
    try:
        count = store.build_enriched()
        log.info("enriched rebuilt: %d CVEs", count)
        return count
    except Exception as e:  # noqa: BLE001
        log.error("enriched rebuild failed: %s", e)
        store.set_status("enriched", "error", str(e)[:300])
        raise


REFRESHERS = {
    "kev": refresh_kev,
    "epss": refresh_epss,
    "nvd": refresh_nvd,
    "osv": refresh_osv,
    "enriched": refresh_enriched,
}
