"""Offline tests for the OSV file mirror: ecosystems.txt parsing, the on-disk
osv-scanner cache layout, URL encoding, 404-skip handling, and meta status.

All downloads are mocked (the curl helpers are monkeypatched to write a tiny fake zip),
so these run offline and fast — the real 1.2 GB download is never touched here.
"""
from __future__ import annotations

import dataclasses
import io
import zipfile
from pathlib import Path

import app.downloader as downloader
from app.downloader import parse_ecosystems, refresh_osv
from app.store import Store


def _patch_settings(monkeypatch, **overrides):
    """Swap downloader.settings for a copy with overridden fields (it's a frozen dataclass)."""
    patched = dataclasses.replace(downloader.settings, **overrides)
    monkeypatch.setattr(downloader, "settings", patched)
    return patched


def _tiny_zip(name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{name}.json", '{"id": "FAKE-0001"}')
    return buf.getvalue()


# ── ecosystems.txt parsing ────────────────────────────────────
ECOSYSTEMS_TXT = (
    "npm\n"
    "PyPI\n"
    "Maven\n"
    "crates.io\n"        # dot
    "Red Hat\n"          # space
    "Alpine:v3.20\n"     # colon
    "\n"                 # blank → dropped
    "  npm  \n"          # whitespace + duplicate → dropped
)


def test_parse_ecosystems_handles_spaces_dots_and_blanks():
    names = parse_ecosystems(ECOSYSTEMS_TXT)
    assert names == ["npm", "PyPI", "Maven", "crates.io", "Red Hat", "Alpine:v3.20"]


# ── refresh_osv: layout, encoding, meta ───────────────────────
def test_refresh_osv_writes_correct_layout(tmp_path, monkeypatch):
    cache = tmp_path / "osv-cache"
    _patch_settings(monkeypatch, osv_cache_dir=str(cache),
                    osv_bucket_base="https://bucket.example")

    ecosystems = ["npm", "crates.io", "Red Hat"]
    monkeypatch.setattr(
        downloader, "curl_bytes",
        lambda url, **kw: ("\n".join(ecosystems)).encode(),
    )

    seen_urls: list[str] = []

    def fake_curl_to_file(url, dest, **kw):
        seen_urls.append(url)
        data = _tiny_zip("rec")
        Path(dest).write_bytes(data)
        return len(data)

    monkeypatch.setattr(downloader, "curl_to_file", fake_curl_to_file)

    store = Store(str(tmp_path / "feeds.db"))
    store.init_db()

    written = refresh_osv(store)
    assert written == 3

    # On-disk layout uses the LITERAL ecosystem name (spaces and dots intact).
    for eco in ecosystems:
        zpath = cache / "osv-scanner" / eco / "all.zip"
        assert zpath.exists(), f"missing {zpath}"
        assert zipfile.is_zipfile(zpath)
        # no leftover temp files
        leftovers = list(zpath.parent.glob("*.tmp"))
        assert leftovers == []

    # URLs are percent-encoded (space → %20, dot kept literal as it is unreserved).
    assert "https://bucket.example/npm/all.zip" in seen_urls
    assert "https://bucket.example/crates.io/all.zip" in seen_urls
    assert "https://bucket.example/Red%20Hat/all.zip" in seen_urls

    meta = store.get_meta("osv")
    assert meta["status"] == "ready"
    assert meta["row_count"] == 3
    assert meta["updated_at"] is not None
    assert "ecosystems" in meta["detail"]


def test_refresh_osv_skips_404_ecosystems(tmp_path, monkeypatch):
    cache = tmp_path / "osv-cache"
    _patch_settings(monkeypatch, osv_cache_dir=str(cache),
                    osv_bucket_base="https://bucket.example")

    monkeypatch.setattr(
        downloader, "curl_bytes",
        lambda url, **kw: b"npm\nGHC\nMaven\n",
    )

    def fake_curl_to_file(url, dest, **kw):
        if "GHC" in url:  # simulate a 404 — no all.zip for this ecosystem
            raise RuntimeError("curl failed (22) for ...: HTTP 404")
        data = _tiny_zip("rec")
        Path(dest).write_bytes(data)
        return len(data)

    monkeypatch.setattr(downloader, "curl_to_file", fake_curl_to_file)

    store = Store(str(tmp_path / "feeds.db"))
    store.init_db()

    written = refresh_osv(store)
    assert written == 2  # npm + Maven; GHC skipped
    assert (cache / "osv-scanner" / "npm" / "all.zip").exists()
    assert (cache / "osv-scanner" / "Maven" / "all.zip").exists()
    assert not (cache / "osv-scanner" / "GHC" / "all.zip").exists()
    # the failed download leaves no temp file behind
    assert list((cache / "osv-scanner" / "GHC").glob("*.tmp")) == []

    meta = store.get_meta("osv")
    assert meta["status"] == "ready"
    assert meta["row_count"] == 2


def test_osv_in_feeds_and_status_seeded(tmp_path):
    store = Store(str(tmp_path / "feeds.db"))
    store.init_db()
    # osv is seeded empty until first refresh, and present in all_meta().
    assert "osv" in store.all_meta()
    assert store.get_meta("osv")["status"] == "empty"
    assert store.get_meta("osv")["row_count"] == 0
