"""Process-GLOBAL TTL cache shared across requests and SBOM files.

Instances are created at module import time (in scanner.py / nvd.py), so a 2nd SBOM with
overlapping components or CVEs reuses the 1st scan's upstream results and does zero repeat
work. Each cache tracks hit/miss counters and logs hit/miss at DEBUG on ``sbom.cache``.
"""
from __future__ import annotations

import time

from .logging_config import get_logger

cache_log = get_logger("sbom.cache")


class TTLCache:
    def __init__(self, ttl: float, name: str = ""):
        self.ttl = ttl
        self.name = name
        self._store: dict[str, tuple[float, object]] = {}
        self.hits = 0
        self.misses = 0

    def get(self, key: str):
        item = self._store.get(key)
        if not item:
            self.misses += 1
            cache_log.debug("MISS %s key=%s", self.name, key)
            return None
        ts, val = item
        if time.monotonic() - ts > self.ttl:
            self._store.pop(key, None)
            self.misses += 1
            cache_log.debug("MISS(expired) %s key=%s", self.name, key)
            return None
        self.hits += 1
        cache_log.debug("HIT %s key=%s", self.name, key)
        return val

    def set(self, key: str, val: object):
        self._store[key] = (time.monotonic(), val)

    def reset_stats(self) -> None:
        self.hits = 0
        self.misses = 0
