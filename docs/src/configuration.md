# Configuration

## Config file

Non-secret configuration lives in a YAML file (default `config/server.yaml`). The path can be overridden with the `CONFIG_FILE` environment variable, which is how Kubernetes deployments can point at a ConfigMap-mounted file without changing any code.

```yaml
grpc_addr:   ":8080"
health_addr: ":8081"
admin_addr:  ":8082"

# Set to false to disable gRPC server reflection (recommended for production).
grpc_reflection: true

# OTLP gRPC endpoint for distributed tracing. Empty disables tracing.
otlp_endpoint: ""

# Per-SPIFFE-ID rate limiting (token bucket). 0 disables rate limiting.
rate_limit_rps:   0
rate_limit_burst: 0

# Signing key rotation interval (e.g. "24h"). Empty disables rotation.
key_rotation_interval: ""
```

## Environment variables

Secrets and deployment-specific paths are always set via environment variables and are never written to a config file.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | — | Yes | UNIX socket path to the SPIRE Workload API (e.g. `unix:///opt/spire/sockets/agent.sock`) |
| `AUDIT_HMAC_KEY` | — | No | Hex-encoded 32-byte key for audit log HMAC signing. Must be exactly 64 hex characters. Unset disables signing. |
| `CONFIG_FILE` | `config/server.yaml` | No | Path to the server config YAML file |
| `POLICY_FILE` | `config/policy.example.yaml` | No | Path to the policy YAML file. Overrides the compiled-in default. |
| `POLICY_DB` | `data/policy.db` | No | Path to the BoltDB file used to persist dynamic policies created via the admin API. The parent directory is created automatically. |

## HTTP endpoints

All HTTP endpoints are served on `health_addr` (default `:8081`, set in `config/server.yaml`).

| Path | Description |
|------|-------------|
| `/health/live` | Liveness probe — always returns `200 OK` while the process is running |
| `/health/ready` | Readiness probe — returns `200 OK` when policy and minter are initialised; `503` during shutdown |
| `/jwks` | JSON Web Key Set — public signing key for downstream JWT verification (RFC 7517) |
| `/metrics` | Prometheus text exposition — gRPC request counts, status codes, and latency histograms |

### Prometheus metrics

svid-exchange exposes standard gRPC server metrics via the `grpc_server_*` family:

| Metric | Type | Description |
|--------|------|-------------|
| `grpc_server_started_total` | Counter | Total RPCs received |
| `grpc_server_handled_total` | Counter | Total RPCs completed, labelled by `grpc_code` (e.g. `OK`, `PermissionDenied`) |
| `grpc_server_handling_seconds` | Histogram | RPC latency with buckets from 5ms to 10s |
| `grpc_server_msg_received_total` | Counter | Total request messages received |
| `grpc_server_msg_sent_total` | Counter | Total response messages sent |

All series are pre-populated at zero on startup for the `Exchange` method, so alerting rules work from day one without waiting for the first call.

### Distributed tracing

svid-exchange uses [OpenTelemetry](https://opentelemetry.io) for distributed tracing. Tracing is **opt-in** — the service runs normally without any trace backend configured.

When `otlp_endpoint` is set in `config/server.yaml`, every `Exchange` RPC produces a server span with:
- Operation name: `exchange.v1.TokenExchange/Exchange`
- W3C TraceContext propagation from incoming gRPC metadata (so upstream callers can link their spans)
- Buffered export via OTLP gRPC with graceful flush on shutdown

Point the field at any OTLP-compatible backend (Jaeger, Grafana Tempo, Datadog, Honeycomb, etc.). See [Distributed Tracing](features/distributed-tracing.md) for a local Jaeger setup.

## Policy file

Policies are defined in YAML. The server validates the file at startup and rejects any broken configuration before serving traffic.

### Format

```yaml
policies:
  - name: order-to-payment
    subject: "spiffe://cluster.local/ns/default/sa/order"
    target:  "spiffe://cluster.local/ns/default/sa/payment"
    allowed_scopes:
      - payments:charge
      - payments:refund
    max_ttl: 300
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable label used in audit logs |
| `subject` | string | SPIFFE ID of the calling service (must be a valid `spiffe://` URI) |
| `target` | string | SPIFFE ID of the target service (must be a valid `spiffe://` URI) |
| `allowed_scopes` | list | Complete set of scopes this subject may request for this target; must not be empty |
| `max_ttl` | int | Maximum token lifetime in seconds; must be greater than zero; requested TTL is capped to this value |

### Validation rules

The server (and the `svid-exchange-validate` CLI) reject policy files that contain:

- No policies at all
- An invalid `spiffe://` URI in `subject` or `target`
- An empty `allowed_scopes` list (the policy would always deny)
- A `max_ttl` of zero or negative
- Duplicate `(subject, target)` pairs (the second rule would be silently unreachable)

### Hot-reload

Call `ReloadPolicy` on the admin gRPC API to reload the policy file without restarting the process:

```bash
grpcurl -insecure \
  -cert /path/to/client.pem -key /path/to/client.key \
  -proto proto/admin/v1/admin.proto \
  localhost:8082 admin.v1.PolicyAdmin/ReloadPolicy
```

If the new file fails validation, the existing policy stays active and the RPC returns an `INTERNAL` error — no requests are disrupted.

The swap is atomic: in-flight requests finish against the old policy, and all subsequent requests see the new policy immediately. There is no window where a request can observe a partially-loaded policy.

### Linting without starting the server

```bash
# Using the validate binary directly
./bin/svid-exchange-validate config/policy.example.yaml

# Or via make
make validate-policy

# Or with a custom path
POLICY_FILE=/path/to/my-policy.yaml make validate-policy
```

Exit code is `0` on success, `1` on any validation error.

## Scope intersection

When a caller requests scopes, the server returns only the intersection of the requested scopes and the policy's `allowed_scopes`. Scopes not in `allowed_scopes` are silently dropped (not an error). If the intersection is empty, the exchange is denied.

```
requested:      [payments:charge, admin:delete]
allowed_scopes: [payments:charge, payments:refund]
granted:        [payments:charge]
```
