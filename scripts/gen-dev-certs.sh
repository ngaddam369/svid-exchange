#!/usr/bin/env bash
# gen-dev-certs.sh — Generate self-signed dev certs for local mTLS testing.
#
# Produces:
#   dev/certs/ca.crt / ca.key           — test CA
#   dev/certs/server.crt / server.key   — server cert (SAN: localhost, 127.0.0.1)
#   dev/certs/client.crt / client.key   — client cert (SAN: spiffe://.../order)
#
# These certs are git-ignored and only used with make run-local.
# In production, certs are issued by a SPIRE agent.

set -euo pipefail

CERTS_DIR="dev/certs"
mkdir -p "$CERTS_DIR"

# Skip if all certs are already present — run "make dev-certs-clean" to force regeneration.
if [[ -f "$CERTS_DIR/ca.crt" && -f "$CERTS_DIR/server.crt" && -f "$CERTS_DIR/client.crt" ]]; then
  echo "Dev certs already exist in $CERTS_DIR/ — skipping generation."
  echo "Delete $CERTS_DIR/ and rerun to regenerate."
  exit 0
fi

echo "Generating CA..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$CERTS_DIR/ca.key" \
  -out    "$CERTS_DIR/ca.crt" \
  -days 365 -nodes \
  -subj "/CN=svid-exchange-test-ca" 2>/dev/null

echo "Generating server cert (SAN: localhost, 127.0.0.1)..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$CERTS_DIR/server.key" \
  -out    "$CERTS_DIR/server.csr" \
  -nodes -subj "/CN=svid-exchange" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$CERTS_DIR/server-ext.cnf"
openssl x509 -req \
  -in     "$CERTS_DIR/server.csr" \
  -CA     "$CERTS_DIR/ca.crt" \
  -CAkey  "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out    "$CERTS_DIR/server.crt" \
  -days 365 \
  -extfile "$CERTS_DIR/server-ext.cnf" 2>/dev/null

echo "Generating client cert (SAN: spiffe://cluster.local/ns/default/sa/order)..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$CERTS_DIR/client.key" \
  -out    "$CERTS_DIR/client.csr" \
  -nodes -subj "/CN=order" 2>/dev/null
printf "subjectAltName=URI:spiffe://cluster.local/ns/default/sa/order" \
  > "$CERTS_DIR/client-ext.cnf"
openssl x509 -req \
  -in     "$CERTS_DIR/client.csr" \
  -CA     "$CERTS_DIR/ca.crt" \
  -CAkey  "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out    "$CERTS_DIR/client.crt" \
  -days 365 \
  -extfile "$CERTS_DIR/client-ext.cnf" 2>/dev/null

echo "Done — certs written to $CERTS_DIR/"
