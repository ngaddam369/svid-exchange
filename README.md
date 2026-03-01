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
- `openssl` (for dev cert generation)
- `golangci-lint` v2.10.1
- Docker + Docker Compose (for the full SPIRE dev environment)

## Running locally

```bash
make run-local
```

Runs the full verification checklist (build → vet → lint → test), generates dev certs if absent, then starts the server with mTLS on `:8080` and health endpoints on `:8081`.

### Full SPIRE dev environment

```bash
make compose-up
```

Runs the verification checklist, then starts SPIRE Server + Agent + svid-exchange via Docker Compose. Workload entries matching `config/policy.example.yaml` are registered automatically.

```bash
make compose-down   # stop all services and wipe named volumes (clean slate)
docker compose logs -f   # tail logs while running
```

Environment variables (all optional, shown with defaults):

| Variable | Default | Description |
|---|---|---|
| `POLICY_FILE` | `config/policy.example.yaml` | Path to policy YAML |
| `GRPC_ADDR` | `:8080` | gRPC listen address |
| `HEALTH_ADDR` | `:8081` | Health HTTP listen address |

`TLS_CERT_FILE`, `TLS_KEY_FILE`, and `TLS_CA_FILE` must be set — the server refuses to start without them. `make run-local` sets these automatically using the dev certs.

## Testing a token exchange

After `make run-local`, use [grpcurl](https://github.com/fullstorydev/grpcurl) with the dev client cert:

```bash
grpcurl \
  -cacert dev/certs/ca.crt \
  -cert dev/certs/client.crt \
  -key dev/certs/client.key \
  -d '{
    "target_service": "spiffe://cluster.local/ns/default/sa/payment",
    "scopes": ["payments:charge", "payments:refund"],
    "ttl_seconds": 300
  }' \
  localhost:8080 exchange.v1.TokenExchange/Exchange
```

The response contains a signed JWT, its expiry, the granted scopes, and a `token_id` (JTI) for future replay protection.

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
| `make run-local` | verify + dev-certs, then start the server with mTLS |
| `make compose-up` | verify + dev-certs, then start SPIRE + svid-exchange via Docker Compose |
| `make compose-down` | Stop all Compose services and remove named volumes |
| `make dev-certs` | Generate self-signed dev certs (skips if present) |
| `make dev-certs-clean` | Force-regenerate dev certs |
| `make proto` | Regenerate Go code from `.proto` files |
| `make tidy` | `go mod tidy` + `go mod verify` |
| `make clean` | Remove build artifacts (`bin/`) |
