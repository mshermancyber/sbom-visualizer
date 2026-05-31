"""Structured stdlib logging for the SBOM backend.

Verbosity is driven by the ``LOG_LEVEL`` env var (DEBUG/INFO/WARNING/ERROR). The product
owner asked for high verbosity by default, so the default is ``DEBUG``.

Lines are single-line and readable:

    2026-05-31 12:00:00,123 DEBUG   sbom.scan [req=ab12cd34] OSV querybatch: 3 queries 142ms

A per-request id is carried on a :class:`contextvars.ContextVar` so any logger (api, scan,
nvd, cache) automatically stamps the current request id without threading it through every
call. Secrets (e.g. ``NVD_API_KEY`` values) are NEVER logged — only their presence as a bool.
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from contextvars import ContextVar

# Per-request correlation id. Defaults to "-" outside any request (CLI, startup).
_request_id: ContextVar[str] = ContextVar("request_id", default="-")

_CONFIGURED = False


def new_request_id() -> str:
    """Generate a short request id."""
    return uuid.uuid4().hex[:8]


def set_request_id(rid: str | None) -> str:
    """Bind a request id to the current context; returns the value set."""
    rid = rid or new_request_id()
    _request_id.set(rid)
    return rid


def get_request_id() -> str:
    return _request_id.get()


class _RequestIdFilter(logging.Filter):
    """Inject the contextvar request id onto every record as ``request_id``."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get()
        return True


_FORMAT = "%(asctime)s %(levelname)-7s %(name)-9s [req=%(request_id)s] %(message)s"


def log_level() -> int:
    raw = (os.environ.get("LOG_LEVEL") or "DEBUG").strip().upper()
    return getattr(logging, raw, logging.DEBUG)


def setup_logging(force: bool = False) -> None:
    """Configure root + uvicorn loggers once. Idempotent unless ``force``."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    level = log_level()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    # Replace any pre-existing handlers so we own the format.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)

    # Make uvicorn's own loggers flow through our handler/format.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(level)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)


# uvicorn --log-config compatible dict (used when launched via `uvicorn ... --log-config`).
def uvicorn_log_config() -> dict:
    level = logging.getLevelName(log_level())
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"request_id": {"()": "app.logging_config._RequestIdFilter"}},
        "formatters": {"default": {"format": _FORMAT}},
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "default",
                "filters": ["request_id"],
            }
        },
        "root": {"level": level, "handlers": ["default"]},
        "loggers": {
            "uvicorn": {"level": level, "handlers": ["default"], "propagate": False},
            "uvicorn.error": {"level": level, "handlers": ["default"], "propagate": False},
            "uvicorn.access": {"level": level, "handlers": ["default"], "propagate": False},
        },
    }
