"""Refresh scheduler for the feeds service.

A daily refresh runs at ``FEEDS_DAILY_AT`` (local time). On startup, any feed that is
empty or stale (older than ~``FEEDS_STALE_HOURS``) is refreshed in the background so the
API comes up immediately and serves ``status:"empty"``/``"refreshing"`` until populated.

Refreshes are **serialized** behind an asyncio lock and run in a worker thread (the
downloaders are blocking curl/sqlite), so they never block request handling. Uses
APScheduler's AsyncIOScheduler when available, falling back to a simple asyncio loop.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from .config import settings
from .downloader import REFRESHERS
from .logging_config import get_logger
from .store import Store

log = get_logger("feeds.sched")


def _parse_hhmm(value: str) -> tuple[int, int]:
    try:
        h, m = value.split(":")
        return max(0, min(23, int(h))), max(0, min(59, int(m)))
    except (ValueError, AttributeError):
        return 3, 15


class FeedScheduler:
    def __init__(self, store: Store):
        self.store = store
        self._lock = asyncio.Lock()
        self._loop_task: asyncio.Task | None = None
        self._aps = None
        self.hour, self.minute = _parse_hhmm(settings.daily_at)

    # ── refresh execution ─────────────────────────────────────
    async def refresh(self, feeds: list[str]) -> None:
        """Refresh the given feeds sequentially. Serialized by a lock so concurrent
        triggers queue instead of overlapping. Each runs in a worker thread.

        The denormalized ``enriched`` join is always rebuilt LAST when any of kev/epss/nvd
        were refreshed (so it joins the freshly-updated data), and is de-duplicated if it
        was also requested explicitly. ``/feeds/refresh?feed=enriched`` still works alone.
        """
        async with self._lock:
            # Run kev/epss/nvd/osv first; defer the enriched rebuild to the very end so it
            # joins the just-updated tables. An explicit "enriched" request still runs it.
            ordered = [f for f in feeds if f != "enriched"]
            wants_enriched = "enriched" in feeds
            for feed in ordered:
                fn = REFRESHERS.get(feed)
                if fn is None:
                    continue
                log.info("refresh start: %s", feed)
                try:
                    count = await asyncio.to_thread(fn, self.store)
                    log.info("refresh done: %s (%d rows)", feed, count)
                except Exception as e:  # noqa: BLE001 — already recorded in meta
                    log.error("refresh error: %s: %s", feed, e)

            # Rebuild enriched LAST if any source table changed, or it was asked for directly.
            if wants_enriched or any(f in ("kev", "epss", "nvd") for f in ordered):
                fn = REFRESHERS.get("enriched")
                if fn is not None:
                    log.info("refresh start: enriched (final build step)")
                    try:
                        count = await asyncio.to_thread(fn, self.store)
                        log.info("refresh done: enriched (%d rows)", count)
                    except Exception as e:  # noqa: BLE001 — already recorded in meta
                        log.error("refresh error: enriched: %s", e)

    def trigger_background(self, feeds: list[str]) -> None:
        """Fire-and-forget a refresh without blocking the caller (request/startup)."""
        asyncio.create_task(self.refresh(feeds))

    # ── staleness check ───────────────────────────────────────
    def _is_stale(self, meta: dict) -> bool:
        if meta.get("row_count", 0) == 0 or not meta.get("updated_at"):
            return True
        try:
            ts = datetime.strptime(meta["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except (ValueError, TypeError):
            return True
        age = datetime.now(timezone.utc) - ts
        return age > timedelta(hours=settings.stale_hours)

    def startup_refresh(self) -> None:
        """Trigger a background refresh for any empty/stale feed (non-blocking)."""
        stale = [f for f, m in self.store.all_meta().items() if self._is_stale(m)]
        if stale:
            log.info("startup: refreshing stale/empty feeds %s", stale)
            self.trigger_background(stale)
        else:
            log.info("startup: all feeds fresh, no refresh needed")

    # ── daily schedule ────────────────────────────────────────
    def next_run(self) -> datetime:
        now = datetime.now().astimezone()
        target = now.replace(hour=self.hour, minute=self.minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target

    def start(self) -> None:
        """Start the daily scheduler. Prefer APScheduler, else an asyncio loop."""
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
            from apscheduler.triggers.cron import CronTrigger  # type: ignore

            self._aps = AsyncIOScheduler()
            self._aps.add_job(
                lambda: self.trigger_background(["kev", "epss", "nvd", "osv", "enriched"]),
                CronTrigger(hour=self.hour, minute=self.minute),
                id="daily-refresh",
            )
            self._aps.start()
            log.info("APScheduler daily refresh at %02d:%02d", self.hour, self.minute)
        except Exception as e:  # noqa: BLE001 — fall back to asyncio loop
            log.info("APScheduler unavailable (%s); using asyncio loop", e)
            self._loop_task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        log.info("asyncio daily loop at %02d:%02d", self.hour, self.minute)
        while True:
            wait = (self.next_run() - datetime.now().astimezone()).total_seconds()
            try:
                await asyncio.sleep(max(1.0, wait))
            except asyncio.CancelledError:
                return
            self.trigger_background(["kev", "epss", "nvd", "osv", "enriched"])

    def stop(self) -> None:
        if self._aps is not None:
            try:
                self._aps.shutdown(wait=False)
            except Exception:  # noqa: BLE001
                pass
        if self._loop_task is not None:
            self._loop_task.cancel()
