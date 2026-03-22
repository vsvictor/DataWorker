#!/usr/bin/env bash
# generate-certs.sh – Generate a local CA and per-service TLS certificates.
# Run from repository root: bash deploy/certs/generate-certs.sh
#
# Requirements: openssl

set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYS=825   # macOS limit for self-signed; > 397 days still works for local use

echo "==> Generating local CA..."
openssl req -x509 -nodes -newkey rsa:4096 -days $DAYS \
  -keyout "$CERTS_DIR/ca.key" \
  -out    "$CERTS_DIR/ca.crt" \
  -subj "/CN=DataWorker-LocalCA/O=DataWorker/C=US"

for SERVICE in gateway auth-service user-service policy-service worker; do
  echo "==> Generating cert for $SERVICE..."
  # Key
  openssl genrsa -out "$CERTS_DIR/$SERVICE.key" 2048

  # CSR
  openssl req -new \
    -key  "$CERTS_DIR/$SERVICE.key" \
    -out  "$CERTS_DIR/$SERVICE.csr" \
    -subj "/CN=$SERVICE/O=DataWorker/C=US"

  # SAN extension
  cat > /tmp/$SERVICE-ext.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = DNS:$SERVICE, DNS:localhost, IP:127.0.0.1
EOF

  # Sign with local CA
  openssl x509 -req -days $DAYS \
    -in "$CERTS_DIR/$SERVICE.csr" \
    -CA "$CERTS_DIR/ca.crt" \
    -CAkey "$CERTS_DIR/ca.key" \
    -CAcreateserial \
    -extfile /tmp/$SERVICE-ext.cnf \
    -extensions v3_req \
    -out "$CERTS_DIR/$SERVICE.crt"

  rm "$CERTS_DIR/$SERVICE.csr" /tmp/$SERVICE-ext.cnf
  echo "   -> $SERVICE.crt / $SERVICE.key"
done

echo ""
echo "Done! Files written to $CERTS_DIR/"
echo "  ca.crt          — trust this in clients"
echo "  <service>.crt   — TLS certificate (in services)"
echo "  <service>.key   — private key"
