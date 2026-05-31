# SBOM Visualizer — deployment helper targets.
#
#   make certs     generate self-signed TLS certs (if missing)
#   make build     build the api + web images
#   make up        ensure certs, then start the stack (detached, with build)
#   make down      stop and remove the stack
#   make logs          tail logs from all services
#   make restart       restart all services
#   make feeds-status  show the local KEV/EPSS/NVD mirror status
#   make feeds-refresh  force an immediate wholesale refresh of all feeds
#   make osv-refresh   force an immediate refresh of just the OSV mirror (~1.2GB)
#   make clean         down + remove images, volumes, and self-signed certs

COMPOSE     ?= docker compose
CERT        := certs/fullchain.pem
KEY         := certs/privkey.pem

.PHONY: certs build up down logs restart feeds-status feeds-refresh osv-refresh clean help

help:
	@echo "Targets: certs build up down logs restart feeds-status feeds-refresh osv-refresh clean"
	@echo "Quickstart:  make up   (then visit https://localhost)"

# Generate certs only if they don't already exist (the script is idempotent;
# this rule short-circuits when both files are present).
$(CERT) $(KEY):
	bash certs/generate-certs.sh

certs: $(CERT) $(KEY)

# Ensure a .env exists so Compose env_file + variable interpolation work.
.env:
	@test -f .env || cp .env.example .env
	@echo "Created .env from .env.example"

build:
	$(COMPOSE) build

up: certs .env
	$(COMPOSE) up -d --build
	@echo "Stack up. Visit https://localhost (accept the self-signed cert warning)."

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

restart:
	$(COMPOSE) restart

# Show the local mirror's per-feed status (rows, updatedAt, scheduler nextRun).
feeds-status:
	$(COMPOSE) exec feeds python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:9000/feeds/status',timeout=10).read().decode())"

# Force an immediate wholesale refresh of all feeds (runs in the background;
# poll `make feeds-status` to watch it complete).
feeds-refresh:
	$(COMPOSE) exec feeds python -c "import urllib.request; req=urllib.request.Request('http://localhost:9000/feeds/refresh?feed=all',method='POST'); print(urllib.request.urlopen(req,timeout=10).read().decode())"

# Force an immediate refresh of just the OSV mirror (~1.2GB, all ecosystems;
# runs in the background). Poll `make feeds-status` to watch it complete.
osv-refresh:
	$(COMPOSE) exec feeds python -c "import urllib.request; req=urllib.request.Request('http://localhost:9000/feeds/refresh?feed=osv',method='POST'); print(urllib.request.urlopen(req).read().decode())"

# `clean` also removes the named volumes via `--volumes`: `feeds-data` (the
# KEV/EPSS/NVD mirror DB) and `osv-db` (the ~1.2GB OSV mirror). The next `up`
# re-crawls + re-downloads everything from scratch.
clean:
	$(COMPOSE) down --rmi local --volumes --remove-orphans
	rm -f $(CERT) $(KEY)
	@echo "Removed images, volumes (incl. feeds-data + osv-db mirrors), and self-signed certs."
