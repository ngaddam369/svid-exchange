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
{"message":"health HTTP listening","addr":":8081"}
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
grpc_server_started_total{...}                           5
grpc_server_handled_total{grpc_code="OK",...}            3
grpc_server_handled_total{grpc_code="PermissionDenied",...} 2
grpc_server_handling_seconds_count{...}                  5
grpc_server_handling_seconds_sum{...}                    0.000845
```

### 5. Enable distributed tracing (optional)

Tracing is opt-in. To see traces locally, start a Jaeger instance on the same Docker network and restart svid-exchange with the OTLP endpoint set:

```bash
docker run -d --name jaeger \
  --network svid-exchange-dev_default \
  -p 16686:16686 -p 4317:4317 \
  jaegertracing/all-in-one:1.65.0

OTEL_EXPORTER_OTLP_ENDPOINT=jaeger:4317 docker compose up svid-exchange --build -d
```

svid-exchange will log:

```
{"message":"OTLP tracing enabled","endpoint":"jaeger:4317"}
```

Make a few exchange requests, then open the Jaeger UI at `http://localhost:16686` and select the `svid-exchange` service to see the traces. Each `Exchange` RPC appears as a span with its operation name, latency, and gRPC status code.

### 6. Enable rate limiting (optional)

Rate limiting is opt-in. To activate it, pass `RATE_LIMIT_RPS` (and optionally `RATE_LIMIT_BURST`) when starting the stack:

```bash
RATE_LIMIT_RPS=2 RATE_LIMIT_BURST=2 docker compose up svid-exchange --build -d
```

svid-exchange will log:

```
{"message":"rate limiting enabled","rps":2,"burst":2}
```

Each SPIFFE ID gets its own independent token bucket. With the settings above, any identity is allowed 2 requests per second with a burst of 2. Requests that exceed the quota receive a `ResourceExhausted` gRPC error:

```
ERROR:
  Code: ResourceExhausted
  Message: rate limit exceeded for spiffe://cluster.local/ns/default/sa/order
```

The counter is tracked in Prometheus under the existing `grpc_server_handled_total` series:

```bash
curl -s http://localhost:8081/metrics | grep ResourceExhausted
# grpc_server_handled_total{grpc_code="ResourceExhausted",...} 3
```

When `RATE_LIMIT_RPS` is unset or `0`, rate limiting is disabled and all requests pass through without any quota check. See [Configuration](configuration.md#environment-variables) for the full option reference.

## Make targets

| Target | Description |
|--------|-------------|
| `make compose-up` | Run the full verification checklist, then start the Docker Compose stack |
| `make compose-down` | Stop all services and remove named volumes |
