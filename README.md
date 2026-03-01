# svid-exchange

A Zero Trust token exchange service. Services present a SPIFFE SVID (via mTLS) and receive a scoped, short-lived ES256 JWT in return — eliminating static shared secrets between microservices.

## How it works

1. The calling service connects over mTLS. Its SPIFFE ID is extracted from the client certificate at the transport layer — it cannot be forged in the request body.
2. The server evaluates a YAML policy: does this subject have permission to call this target with these scopes?
3. If permitted, a signed ES256 JWT is minted and returned. The token is scoped to the exact permissions the policy allows, capped to `max_ttl`.

```
caller (SVID)  →  svid-exchange  →  scoped JWT  →  target service
```

## Prerequisites

- Go 1.26 (managed via [mise](https://mise.jdx.dev))
- `golangci-lint` v2.10.1
- Docker + Docker Compose

## Running locally

```bash
make compose-up
```

Runs the full verification checklist (build → vet → lint → test), then starts SPIRE Server + Agent + svid-exchange via Docker Compose. Workload entries matching `config/policy.example.yaml` are registered automatically. mTLS certificates are fetched live from the SPIRE Workload API — no static cert files needed, and SVID rotation is transparent.

When the stack is ready, svid-exchange logs:

```
{"message":"mTLS via SPIRE Workload API","socket":"unix:///opt/spire/sockets/agent.sock"}
{"message":"gRPC listening","addr":":8080"}
{"message":"health HTTP listening","addr":":8081"}
```

Confirm it is healthy:

```bash
curl -s http://localhost:8081/health/ready   # → 200 OK
```

Other useful commands while the stack is running:

```bash
docker compose logs -f svid-exchange   # tail service logs
make compose-down                      # stop all services and wipe named volumes (clean slate)
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | *(required)* | UNIX socket path to the SPIRE Workload API (e.g. `unix:///opt/spire/sockets/agent.sock`) |
| `POLICY_FILE` | `config/policy.example.yaml` | Path to policy YAML |
| `GRPC_ADDR` | `:8080` | gRPC listen address |
| `HEALTH_ADDR` | `:8081` | Health HTTP listen address |

## Testing a token exchange

Requires [grpcurl](https://github.com/fullstorydev/grpcurl). All steps assume `make compose-up` is running.

### 1. Fetch a client SVID from the SPIRE agent

The SPIRE agent issues X.509 SVIDs to attested workloads. For local testing, fetch one directly from inside the agent container (it runs as root, matching the `unix:uid:0` selector registered for every dev workload entry):

```bash
docker exec svid-exchange-dev-spire-agent-1 mkdir -p /tmp/svid

docker exec svid-exchange-dev-spire-agent-1 \
  spire-agent api fetch x509 \
    -socketPath /opt/spire/sockets/agent.sock \
    -write /tmp/svid/

docker cp svid-exchange-dev-spire-agent-1:/tmp/svid/. /tmp/svid/
```

This writes one `svid.N.pem` / `svid.N.key` / `bundle.N.pem` triple per registered workload entry. The SPIFFE ID for each index is printed to stdout during the fetch — check the output to see which file maps to which identity.

### 2. Send an exchange request

Use `-insecure` to skip server-side hostname verification — SPIFFE SVIDs carry a URI SAN (`spiffe://…`), not a DNS name, so standard hostname checking does not apply. The server still enforces full mTLS: it rejects any connection that does not present a valid SPIRE-issued client certificate.

```bash
# order → payment (policy: order-to-payment)
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.0.pem \
  -key  /tmp/svid/svid.0.key \
  -d '{
    "target_service": "spiffe://cluster.local/ns/default/sa/payment",
    "scopes": ["payments:charge", "payments:refund"],
    "ttl_seconds": 120
  }' \
  localhost:8080 exchange.v1.TokenExchange/Exchange
```

Expected response:

```json
{
  "token": "<ES256 JWT>",
  "expiresAt": "<unix timestamp>",
  "grantedScopes": ["payments:charge", "payments:refund"],
  "tokenId": "<uuid>"
}
```

The audit log in `docker compose logs svid-exchange` shows the corresponding `token.exchange` event with `"granted":true`.

### 3. Try other policy entries

Match the SVID file to its SPIFFE ID using the fetch output, then swap in the corresponding cert and request body:

| Subject | Target | Scopes |
|---|---|---|
| `order` | `payment` | `payments:charge`, `payments:refund` |
| `warehouse` | `inventory` | `inventory:read`, `inventory:reserve` |
| `api-gateway` | `order` | `orders:read`, `orders:create` |

To test a denial, request a scope not listed in the policy — the server returns `PERMISSION_DENIED`.

## Policy

Policies are defined in YAML. See [`config/policy.example.yaml`](config/policy.example.yaml) for the format and field documentation.

## Make targets

| Target | Description |
|---|---|
| `make build` | Compile the server binary to `bin/` |
| `make test` | Run all tests with race detector and coverage summary |
| `make fmt` | Check gofmt formatting |
| `make vet` | Run go vet |
| `make lint` | Run golangci-lint |
| `make verify` | Full checklist: build → vet → lint → test |
| `make compose-up` | verify, then start SPIRE + svid-exchange via Docker Compose |
| `make compose-down` | Stop all Compose services and remove named volumes |
| `make proto` | Regenerate Go code from `.proto` files |
| `make tidy` | `go mod tidy` + `go mod verify` |
| `make clean` | Remove build artifacts (`bin/`) |
