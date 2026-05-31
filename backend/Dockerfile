FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Offline OSV: install the official osv-scanner binary (pinned v2.3.8). Used by the
# scanner for air-gapped OSV discovery against the mirrored DBs (docs/OFFLINE_OSV.md).
ADD https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
RUN chmod +x /usr/local/bin/osv-scanner

# App code + packaging (registers the `sbom-scan` console script).
COPY app ./app
COPY pyproject.toml ./
RUN pip install --no-cache-dir --no-deps .

# Non-root user; create /data (SQLite: vex, scans, auth) and /osv-cache (shared OSV
# DB volume — osv-scanner writes lock files under XDG_CACHE_HOME). Both dirs must exist
# and be owned by appuser before Docker mounts the named volumes over them.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app \
    && mkdir -p /data /osv-cache && chown appuser:appuser /data /osv-cache
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
