#!/usr/bin/env bash
###############################################################################
# generate-certs.sh — self-signed TLS cert for local / demo use.
#
# Writes  certs/fullchain.pem  +  certs/privkey.pem  (mounted into the web
# container at /etc/nginx/certs). Idempotent: skips regeneration if a valid,
# unexpired cert already exists (use FORCE=1 to override).
#
# SANs: DNS:localhost, DNS:*.localhost, IP:127.0.0.1 — plus optional extras.
#
# Env overrides:
#   CN=<name>          common name              (default: localhost)
#   EXTRA_SAN=<list>   comma-separated extra SANs, e.g.
#                      "DNS:sbom.example.com,IP:127.0.0.1"
#   DAYS=<n>           validity in days         (default: 825)
#   FORCE=1            regenerate even if a valid cert exists
###############################################################################
set -euo pipefail

# Resolve the directory this script lives in (so it works from any cwd).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CERT="${SCRIPT_DIR}/fullchain.pem"
KEY="${SCRIPT_DIR}/privkey.pem"

CN="${CN:-localhost}"
DAYS="${DAYS:-825}"
EXTRA_SAN="${EXTRA_SAN:-}"

# ---- Idempotency: keep an existing, still-valid cert unless FORCE=1 --------
if [[ "${FORCE:-0}" != "1" && -f "$CERT" && -f "$KEY" ]]; then
    # `-checkend 0` exits 0 if the cert is NOT expired.
    if openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1; then
        echo "==> Valid certificate already present at:"
        echo "      $CERT"
        echo "      $KEY"
        echo "    (set FORCE=1 to regenerate)"
        exit 0
    fi
    echo "==> Existing certificate is expired/invalid — regenerating."
fi

# ---- Assemble SAN list -----------------------------------------------------
SAN="DNS:localhost,DNS:*.localhost,IP:127.0.0.1"
if [[ -n "$EXTRA_SAN" ]]; then
    SAN="${SAN},${EXTRA_SAN}"
fi

echo "==> Generating self-signed certificate"
echo "      CN   = ${CN}"
echo "      SANs = ${SAN}"
echo "      days = ${DAYS}"

# Single-shot: key + self-signed cert with SANs via -addext (OpenSSL 1.1.1+).
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" \
    -out "$CERT" \
    -days "$DAYS" \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=${SAN}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

chmod 600 "$KEY"
chmod 644 "$CERT"

echo "==> Done. Wrote:"
echo "      $CERT"
echo "      $KEY  (mode 600)"
echo
echo "    Inspect with:"
echo "      openssl x509 -in certs/fullchain.pem -noout -subject -ext subjectAltName"
echo
cat <<'EOF'
---------------------------------------------------------------------------
Using REAL certificates instead of this self-signed one
---------------------------------------------------------------------------
The web container reads two files (mounted read-only at /etc/nginx/certs):

    certs/fullchain.pem   leaf cert + intermediate chain (PEM, leaf first)
    certs/privkey.pem     matching private key (PEM, unencrypted)

To swap in real certs, just replace those two files and restart `web`:

  * Let's Encrypt (certbot):
      certbot certonly --standalone -d sbom.example.com
      cp /etc/letsencrypt/live/sbom.example.com/fullchain.pem certs/fullchain.pem
      cp /etc/letsencrypt/live/sbom.example.com/privkey.pem   certs/privkey.pem
      docker compose restart web

  * A commercial CA: concatenate your leaf cert followed by the CA's
    intermediate bundle into fullchain.pem; put the key in privkey.pem.

No image rebuild is needed — certs are mounted, not baked in.
---------------------------------------------------------------------------
EOF
