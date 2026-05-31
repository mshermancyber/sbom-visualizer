"""API hardening + request logging middleware.

Three concerns, all env-driven and safe to deploy beyond localhost:

* **Auth** (``API_TOKEN``): when set, every ``/api/*`` route except ``/api/health`` requires
  ``Authorization: Bearer <token>`` or ``X-API-Key: <token>``; otherwise 401 ``{error}``.
  When unset, auth is open (dev default) and a startup WARNING is emitted.
* **Rate limit** (``RATE_LIMIT``, e.g. ``120/minute``): per-client-IP sliding window. The
  client IP is the first hop of ``X-Forwarded-For`` (nginx) when present, else the socket
  peer. Over-limit ⇒ 429 ``{error}`` with a ``Retry-After`` header.
* **Body cap** (``MAX_BODY_BYTES``): rejects oversize POST bodies (declared
  ``Content-Length`` or streamed bytes) with 413 ``{error}``.

A single request-logging middleware also stamps a per-request id and logs method/path/status/
duration on ``sbom.api``. No secrets are ever logged.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import settings
from .logging_config import get_logger, new_request_id, set_request_id

log = get_logger("sbom.api")

_OPEN_PATHS = {"/api/health"}


def _json_error(status: int, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message}, headers=headers)


def client_ip(request: Request) -> str:
    """First X-Forwarded-For hop (trusting the nginx reverse proxy) or the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _provided_token(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    xkey = request.headers.get("x-api-key")
    if xkey:
        return xkey.strip()
    return None


# ── Sliding-window rate limiter ───────────────────────────────
def parse_rate(spec: str) -> tuple[int, float]:
    """Parse ``"<count>/<unit>"`` → (count, window_seconds). Falls back to 120/min."""
    try:
        count_s, _, unit = spec.partition("/")
        count = int(count_s.strip())
        unit = unit.strip().lower()
        window = {"second": 1.0, "sec": 1.0, "s": 1.0,
                  "minute": 60.0, "min": 60.0, "m": 60.0,
                  "hour": 3600.0, "h": 3600.0}.get(unit, 60.0)
        return max(1, count), window
    except (ValueError, AttributeError):
        return 120, 60.0


class SlidingWindowLimiter:
    """In-memory per-key sliding-window counter (no external deps)."""

    def __init__(self, count: int, window: float):
        self.count = count
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        dq = self._hits[key]
        cutoff = now - self.window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= self.count:
            retry = max(0.0, dq[0] + self.window - now)
            return False, retry
        dq.append(now)
        return True, 0.0


class HardeningMiddleware(BaseHTTPMiddleware):
    """Per-request id + logging, auth, rate limit, and body-size cap for ``/api/*``."""

    def __init__(self, app):
        super().__init__(app)
        count, window = parse_rate(settings.rate_limit)
        self._limiter = SlidingWindowLimiter(count, window)
        self._rate_window = window
        self._max_body = settings.max_body_bytes

    async def dispatch(self, request: Request, call_next):
        rid = set_request_id(request.headers.get("x-request-id") or new_request_id())
        start = time.monotonic()
        path = request.url.path
        method = request.method

        try:
            resp = await self._guard(request, call_next, path, method)
        except Exception:  # noqa: BLE001
            dur = (time.monotonic() - start) * 1000
            log.exception("%s %s -> 500 %.1fms", method, path, dur)
            raise
        dur = (time.monotonic() - start) * 1000
        log.info("%s %s -> %d %.1fms", method, path, resp.status_code, dur)
        resp.headers["X-Request-Id"] = rid
        return resp

    async def _guard(self, request: Request, call_next, path: str, method: str) -> Response:
        is_api = path.startswith("/api/")
        protected = is_api and path not in _OPEN_PATHS

        # Auth: accept master token OR a provisioned per-user key (when keys exist in DB).
        if protected:
            provided = _provided_token(request)
            # Import lazily to avoid circular imports and to tolerate test isolation reloads.
            try:
                from . import auth as _auth_mod
                keys_active = _auth_mod.has_any_keys()
            except Exception:
                keys_active = False

            if settings.api_token or keys_active:
                # Check master token first.
                if provided == settings.api_token and settings.api_token:
                    # Master token: no project scoping.
                    request.state.project = None
                else:
                    # Try per-user key lookup.
                    key_record = None
                    if provided and keys_active:
                        try:
                            key_record = _auth_mod.lookup_key(provided)
                        except Exception:
                            key_record = None
                    if key_record is None:
                        log.warning("auth rejected for %s %s from %s", method, path,
                                    client_ip(request))
                        return _json_error(401, "Missing or invalid API credentials.")
                    # Attach project from key record.
                    request.state.project = key_record.get("project")
            else:
                # Open (dev mode): no token configured and no provisioned keys.
                request.state.project = None

        # Rate limit (per client IP), applied to all /api/* (incl. health is cheap; skip it).
        if is_api and path not in _OPEN_PATHS:
            ip = client_ip(request)
            allowed, retry = self._limiter.check(ip)
            if not allowed:
                log.warning("rate limit hit for %s (retry in %.1fs)", ip, retry)
                return _json_error(429, "Rate limit exceeded.",
                                   headers={"Retry-After": str(max(1, round(retry)))})

        # Body size cap for write methods.
        if method in ("POST", "PUT", "PATCH"):
            cl = request.headers.get("content-length")
            if cl is not None:
                try:
                    if int(cl) > self._max_body:
                        log.warning("body too large (%s bytes) for %s %s", cl, method, path)
                        return _json_error(413, "Request body too large.")
                except ValueError:
                    pass
            else:
                # No declared length: read+measure the streamed body, then re-inject it so
                # the downstream handler can still consume it.
                body = await request.body()
                if len(body) > self._max_body:
                    log.warning("body too large (%d bytes) for %s %s", len(body), method, path)
                    return _json_error(413, "Request body too large.")

        return await call_next(request)
