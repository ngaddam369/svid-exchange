# Getting Started

## Prerequisites

- [Go 1.26](https://go.dev) (managed via [mise](https://mise.jdx.dev))
- `golangci-lint` v2.10.1
- Docker + Docker Compose
- [grpcurl](https://github.com/fullstorydev/grpcurl) (for manual testing)

## Running locally

The quickest way to run the full stack is via Docker Compose. This starts SPIRE Server, SPIRE Agent, and svid-exchange together with workload entries pre-registered.

```bash
make compose-up
```

This runs the full verification checklist (build → lint → test → policy validation) before starting the stack. When ready, svid-exchange logs:

```
{"message":"mTLS via SPIRE Workload API","socket":"unix:///opt/spire/sockets/agent.sock"}
{"message":"gRPC listening","addr":":8080"}
{"message":"admin gRPC listening","addr":":8082"}
{"message":"health HTTP listening","addr":":8081"}
```

To start with all opt-in security features enabled, update `config/server.yaml` and generate the required secret first:

```yaml
# config/server.yaml — enable rate limiting and key rotation
rate_limit_rps:        10
rate_limit_burst:      10
key_rotation_interval: "24h"
```

```bash
# Generate a 32-byte HMAC key for audit log signing (secret — env var only)
export AUDIT_HMAC_KEY=$(openssl rand -hex 32)

# Start the stack with HMAC signing active
AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY docker compose up --build -d
```

With those features active, svid-exchange additionally logs:

```
{"message":"audit log HMAC signing enabled"}
{"message":"rate limiting enabled","rps":10,"burst":10}
{"message":"signing key rotation enabled","interval":"24h0m0s"}
```

Confirm it is healthy:

```bash
curl -s http://localhost:8081/health/ready   # → 200 OK
```

Stop the stack and remove all volumes:

```bash
make compose-down
```

## Testing a token exchange

### 1. Fetch SVIDs for all registered workloads

Fetch all X.509 SVIDs from the SPIRE Agent and copy them to the host:

```bash
docker exec svid-exchange-dev-spire-agent-1 mkdir -p /tmp/svid

docker exec svid-exchange-dev-spire-agent-1 \
  spire-agent api fetch x509 \
    -socketPath /opt/spire/sockets/agent.sock \
    -write /tmp/svid/

docker cp svid-exchange-dev-spire-agent-1:/tmp/svid/. /tmp/svid/
```

The fetch writes one `svid.N.pem` / `svid.N.key` / `bundle.N.pem` triple per registered workload entry. The index-to-identity mapping is not stable across fetches — build the full map in one pass using the URI SAN in each certificate:

```bash
for pem in /tmp/svid/svid.*.pem; do
  idx=$(basename "$pem" .pem | sed 's/svid\.//')
  id=$(openssl x509 -in "$pem" -noout -ext subjectAltName 2>/dev/null \
       | grep -o 'URI:.*' | sed 's/URI://')
  printf "svid.%s  →  %s\n" "$idx" "$id"
done
```

Example output for the dev stack (order varies):

```
svid.0  →  spiffe://cluster.local/ns/default/sa/api-gateway
svid.1  →  spiffe://cluster.local/ns/default/sa/inventory
svid.2  →  spiffe://cluster.local/ns/default/sa/payment
svid.3  →  spiffe://cluster.local/ns/default/sa/order
svid.4  →  spiffe://cluster.local/ns/default/sa/warehouse
svid.5  →  spiffe://cluster.local/ns/default/sa/svid-exchange
```

Use the index that maps to the identity you want to test as in the next step.

### 2. Send an exchange request

Pass the cert and key for the identity you want to test as. Using the example map above, `svid.3` is `order` — use it to request a token targeting `payment`:

```bash
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.3.pem \
  -key  /tmp/svid/svid.3.key \
  -proto proto/exchange/v1/exchange.proto \
  -d '{
    "target_service": "spiffe://cluster.local/ns/default/sa/payment",
    "scopes": ["payments:charge", "payments:refund"],
    "ttl_seconds": 120
  }' \
  localhost:8080 exchange.v1.TokenExchange/Exchange
```

Replace `svid.3` with whatever index your map shows for `order`.

Expected response:

```json
{
  "token": "<ES256 JWT>",
  "expiresAt": "<unix timestamp>",
  "grantedScopes": ["payments:charge", "payments:refund"],
  "tokenId": "<uuid>"
}
```

### 3. Available policy entries

| Subject | Target | Scopes |
|---------|--------|--------|
| `order` | `payment` | `payments:charge`, `payments:refund` |
| `warehouse` | `inventory` | `inventory:read`, `inventory:reserve` |
| `api-gateway` | `order` | `orders:read`, `orders:create` |

To test a denial, request a scope not listed in the policy. The server returns `PERMISSION_DENIED` and logs a denial event.

### 4. Observe Prometheus metrics

After making one or more exchange requests, query the `/metrics` endpoint to see counters and latency data:

```bash
curl -s http://localhost:8081/metrics | grep "^grpc_server"
```

Key series to watch:

```
grpc_server_started_total{...}                              5
grpc_server_handled_total{grpc_code="OK",...}               3
grpc_server_handled_total{grpc_code="PermissionDenied",...} 2
grpc_server_handling_seconds_count{...}                     5
grpc_server_handling_seconds_sum{...}                       0.000845
```

## Using the client library

Services that call svid-exchange can use the `pkg/client` package instead of managing token acquisition and caching themselves. It handles SPIFFE mTLS authentication, TTL-aware caching, and gRPC header injection in one place. See [Client Library](client-library.md) for details.

## Opt-in features

Several features are disabled by default and enabled via `config/server.yaml` (or environment variables where noted). Each has dedicated documentation covering motivation, configuration, and known limitations:

- [Distributed Tracing](features/distributed-tracing.md)
- [Rate Limiting](features/rate-limiting.md)
- [Audit Log Integrity](features/audit-log-integrity.md)

Prometheus metrics are always-on — no configuration needed. See [Prometheus Metrics](features/prometheus-metrics.md) for the full reference and limitations.

## E2E test

`test/e2e/` contains two stub microservices that exercise the full token exchange flow against the live Docker Compose stack:

- **e2e-caller** — fetches its SVID from the SPIRE Workload API, calls `Exchange()` over mTLS to obtain a JWT targeting `e2e-validator`, then makes an HTTP request to the validator with `Authorization: Bearer <token>`. Exits 0 on success.
- **e2e-validator** — listens for one HTTP request, verifies the JWT (signature via JWKS, audience, scope, and expiry), and exits after responding. Uses `pkg/client.Verifier` and `HasScope`.

Docker orchestration is handled by `test/e2e/docker-compose.yml`, a Compose overlay that adds three short-lived services to the running dev stack:

| Service | Purpose |
|---------|---------|
| `e2e-spire-init` | Registers the `e2e-caller` SPIFFE workload entry with SPIRE |
| `e2e-validator` | JWT validation HTTP server (exits after one request) |
| `e2e-caller` | Exchange caller; exit code determines test outcome |

To run the E2E test:

```bash
# Terminal 1 — start the base stack (if not already running)
make compose-up

# Terminal 2 — run the E2E test
make e2e
# equivalent: go test -v -tags e2e -timeout 120s ./test/e2e/
```

Expected output:

```
=== RUN   TestE2EFlow
  token_id=<uuid> granted_scopes=[e2e:ping]
PASS [happy path]
  act.sub=e2e-user
PASS [delegation: on_behalf_of sets act.sub]
  correctly denied: PermissionDenied
PASS [policy denial: disallowed scope]
  granted_scopes=[e2e:ping] (e2e:extra correctly filtered)
PASS [scope filter: superset request returns allowed subset]
PASS [health endpoint]
  http://svid-exchange:8081/metrics: found "grpc_server_started_total"
PASS [metrics endpoint]
E2E OK — all scenarios passed
--- PASS: TestE2EFlow (N.NNs)
PASS
```

The E2E test is excluded from `make verify` (no `-tags e2e` flag) and must be triggered explicitly.

## Make targets

| Target | Description |
|--------|-------------|
| `make build` | Compile the server binary (`bin/svid-exchange`) and the validate tool (`bin/svid-exchange-validate`) |
| `make test` | Run all tests with the race detector and print a coverage summary |
| `make lint` | Run `golangci-lint` — covers `govet`, `gofmt`, `staticcheck`, `errcheck`, and `unused` |
| `make verify` | Full checklist: `build → lint → test → docs-build` |
| `make proto` | Regenerate Go code from `.proto` files (requires `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`) |
| `make validate-policy` | Lint the policy file without starting the server; respects `POLICY_FILE` env var |
| `make docs-build` | Build the mdBook documentation site (silently skipped if `mdbook` is not installed) |
| `make compose-up` | Run `verify + validate-policy`, then start the full Docker Compose stack |
| `make compose-down` | Stop all services and remove named volumes (clean slate) |
| `make e2e` | Run the end-to-end test against the live Docker Compose stack (requires `make compose-up` first) |
| `make clean` | Remove the `bin/` directory |
| `make tidy` | Run `go mod tidy` and `go mod verify` |
