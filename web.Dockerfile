# syntax=docker/dockerfile:1
###############################################################################
# web.Dockerfile — the `web` image.
#
# Multi-stage:
#   1. node:22-alpine  — `npm ci && npm run build` the Vite frontend -> dist/
#   2. nginx:1.27-alpine — serve dist/ + reverse-proxy /api, terminate TLS.
#
# Build context is the product root (.) so the build can see both frontend/
# and nginx/. See docker-compose.yml `web.build`.
###############################################################################

# ---- Stage 1: build the frontend -------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Install deps first (better layer caching). package-lock.json may not exist
# yet in the frontend stub; fall back to `npm install` if `npm ci` can't run.
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# Copy the rest of the frontend source and build.
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: nginx runtime ------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# Drop the stock default config; install ours.
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx/nginx.conf   /etc/nginx/nginx.conf
# Loaded as a TEMPLATE so the nginx entrypoint runs envsubst at container start.
# NGINX_ENVSUBST_FILTER (set in compose) restricts substitution to PUBLIC_HTTPS_PORT,
# leaving nginx runtime vars ($host, $request_uri, $scheme, …) untouched.
COPY nginx/default.conf /etc/nginx/templates/default.conf.template

# Built SPA -> nginx web root.
COPY --from=build /app/dist /usr/share/nginx/html

# Certs are mounted at runtime (read-only) at /etc/nginx/certs — not baked in.
# (No build-time `nginx -t`: it would fail because the mounted certs referenced
#  by ssl_certificate are only present at runtime.)
EXPOSE 80 443

STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]
