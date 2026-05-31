"""Structured stdlib logging for the feeds service.

Verbosity is driven by ``LOG_LEVEL`` (DEBUG/INFO/WARNING/ERROR), default INFO. Lines are
single-line and readable. Secrets (e.g. ``NVD_API_KEY``) are NEVER logged — only presence.
Matches the sibling ``backend`` service's logging conventions.
"""
from __future__ import annotations

import logging
import os
import sys

_CONFIGURED = False

_FORMAT = "%(asctime)s %(levelname)-7s %(name)-12s %(message)s"


def log_level() -> int:
    raw = (os.environ.get("LOG_LEVEL") or "INFO").strip().upper()
    return getattr(logging, raw, logging.INFO)


def setup_logging(force: bool = False) -> None:
    """Configure root + uvicorn loggers once. Idempotent unless ``force``."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    level = log_level()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(level)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
