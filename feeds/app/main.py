"""FastAPI app — feeds mirror internal API (per docs/FEEDS_CONTRACT.md).

Internal-only service reached at ``http://feeds:9000``. Serves batch CVE lookups against
the locally mirrored KEV / EPSS / NVD inventories, plus health/status and refresh triggers.
The API comes up immediately; an empty/stale feed returns empty results (never an error)
and is refreshed in the background by the scheduler.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

from .config import VERSION, settings
from .logging_config import get_logger, setup_logging
from .scheduler import FeedScheduler
from .store import FEEDS, Store

setup_logging()
log = get_logger("feeds.api")

store = Store(settings.db_path)
scheduler = FeedScheduler(store)


class CvesRequest(BaseModel):
    cves: list[str] = Field(default_factory=list)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    store.init_db()
    log.info("feeds service starting; db=%s; NVD key %s; daily refresh %s",
             settings.db_path, "set" if settings.nvd_api_key else "unset (keyless)",
             settings.daily_at)
    scheduler.start()
    scheduler.startup_refresh()
    yield
    scheduler.stop()


app = FastAPI(title="Feeds Mirror", version=VERSION, lifespan=_lifespan)


@app.get("/feeds/health")
async def health():
    return {"status": "ok"}


@app.get("/feeds/status")
async def status():
    metas = store.all_meta()
    feeds = []
    for name in FEEDS:
        m = metas[name]
        feeds.append({
            "name": name,
            "updatedAt": m.get("updated_at"),
            "rowCount": m.get("row_count", 0),
            "status": m.get("status", "empty"),
            "detail": m.get("detail", ""),
        })
    next_run = scheduler.next_run()
    return {
        "feeds": feeds,
        "scheduler": {
            "dailyAt": settings.daily_at,
            "nextRun": next_run.astimezone().isoformat() if next_run else None,
        },
    }


@app.post("/feeds/kev")
async def kev_lookup(req: CvesRequest):
    return {"kev": store.lookup_kev(req.cves)}


@app.post("/feeds/epss")
async def epss_lookup(req: CvesRequest):
    return {"results": store.lookup_epss(req.cves)}


@app.post("/feeds/nvd")
async def nvd_lookup(req: CvesRequest):
    return {"results": store.lookup_nvd(req.cves)}


@app.post("/feeds/enriched")
async def enriched_lookup(req: CvesRequest):
    """One denormalized lookup pegging each CVE with KEV + EPSS + NVD(CVSS/CWE).

    Missing CVEs are absent from results; an empty table yields empty results, not an error.
    """
    return {"results": store.lookup_enriched(req.cves)}


@app.post("/feeds/refresh")
async def refresh(feed: str = Query("all")):
    feed = (feed or "all").lower()
    feeds = list(FEEDS) if feed == "all" else [feed]
    feeds = [f for f in feeds if f in FEEDS]
    if feeds:
        scheduler.trigger_background(feeds)
    return {"started": True}
