FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FEEDS_DB=/data/feeds.db

WORKDIR /app

# curl is REQUIRED — downloaders shell out to it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Non-root user; ensure the DB volume dir AND the OSV cache dir are writable by it.
# (/osv-cache is a named volume shared with the api; Docker seeds a fresh empty volume
#  with this dir's ownership, so it must be chowned to appuser in the image.)
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data /osv-cache \
    && chown -R appuser:appuser /app /data /osv-cache
USER appuser

VOLUME ["/data"]
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9000/feeds/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
