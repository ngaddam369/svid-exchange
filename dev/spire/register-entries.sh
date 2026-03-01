#!/usr/bin/env bash
# register-entries.sh
#
# Runs once as the spire-init service in Docker Compose.
# Responsibilities:
#   1. Wait for the SPIRE server health endpoint to report ready.
#   2. Generate a join token for the agent and write it to the shared socket
#      volume so the agent container can read it at startup.
#   3. Register one workload entry per SPIFFE ID referenced in
#      config/policy.example.yaml, plus svid-exchange itself.
#
# All entries use the unix:uid:0 selector because every dev container runs
# as root (the default for scratch / alpine images).  In production, replace
# these selectors with k8s:sa or k8s:pod-label entries.

set -euo pipefail

# SPIRE CLI commands connect to the server via Unix socket, not TCP.
# The socket is on the shared spire-sockets volume (configured in server.conf).
SOCKET_PATH="/opt/spire/sockets/server.sock"
HEALTH_URL="http://spire-server:8080/ready"
TOKEN_FILE="/opt/spire/sockets/join-token"
TRUST_DOMAIN="cluster.local"

log() { echo "[register-entries] $*"; }

# ── 1. Wait for SPIRE server ─────────────────────────────────────────────────
# Use the HTTP health endpoint (Alpine has wget); the CLI healthcheck only
# works against a local admin socket which may not exist yet.

log "Waiting for SPIRE server to be ready at ${HEALTH_URL} ..."
until wget -qO- "$HEALTH_URL" > /dev/null 2>&1; do
  sleep 2
done
log "SPIRE server is ready."

# ── 2. Generate agent join token ─────────────────────────────────────────────
# No -spiffeID flag: the /spire/ namespace is reserved by SPIRE.
# SPIRE will assign the agent ID spiffe://<trust_domain>/spire/agent/join_token/<token>
# automatically when the agent attests.

log "Generating agent join token ..."
TOKEN=$(
  spire-server token generate \
    -socketPath "$SOCKET_PATH" \
    | awk '/^Token:/{print $2}'
)

if [[ -z "$TOKEN" ]]; then
  log "ERROR: token generation returned an empty value."
  exit 1
fi

echo "$TOKEN" > "$TOKEN_FILE"
log "Join token written to ${TOKEN_FILE}."

# The parent ID for workload entries is derived from the token value.
AGENT_ID="spiffe://${TRUST_DOMAIN}/spire/agent/join_token/${TOKEN}"
log "Agent parent ID: ${AGENT_ID}"

# ── 3. Register workload entries ─────────────────────────────────────────────
#
# create_entry <spiffe-id>
#   Creates the entry; on duplicate, logs a warning and continues so
#   the script is safe to re-run after a docker compose restart.

create_entry() {
  local spiffe_id="$1"
  log "Registering ${spiffe_id} ..."
  if ! spire-server entry create \
      -socketPath "$SOCKET_PATH" \
      -parentID   "$AGENT_ID"   \
      -spiffeID   "$spiffe_id"  \
      -selector   "unix:uid:0"  2>&1; then
    log "WARNING: entry for ${spiffe_id} may already exist — skipping."
  fi
}

# svid-exchange — the exchange service itself.
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/svid-exchange"

# Subjects from config/policy.example.yaml.
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/order"
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/warehouse"
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/api-gateway"

# Targets from config/policy.example.yaml (needed so downstream services can
# also attest and present tokens to other exchanges in future).
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/payment"
create_entry "spiffe://${TRUST_DOMAIN}/ns/default/sa/inventory"

log "All workload entries registered successfully."
