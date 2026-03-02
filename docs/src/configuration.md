# Configuration

## Environment variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | — | Yes | UNIX socket path to the SPIRE Workload API (e.g. `unix:///opt/spire/sockets/agent.sock`) |
| `POLICY_FILE` | `config/policy.example.yaml` | No | Path to the policy YAML file |
| `GRPC_ADDR` | `:8080` | No | gRPC listen address |
| `HEALTH_ADDR` | `:8081` | No | Health + JWKS + Prometheus metrics HTTP listen address |
| `GRPC_REFLECTION` | `true` | No | Set to `false` to disable gRPC server reflection (recommended for production) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | No | OTLP gRPC endpoint for trace export (e.g. `jaeger:4317`). When unset, a no-op tracer is used and no traces are collected. |

## HTTP endpoints

All HTTP endpoints are served on `HEALTH_ADDR` (default `:8081`).

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

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, every `Exchange` RPC produces a server span with:
- Operation name: `exchange.v1.TokenExchange/Exchange`
- W3C TraceContext propagation from incoming gRPC metadata (so upstream callers can link their spans)
- Buffered export via OTLP gRPC with graceful flush on shutdown

Point the variable at any OTLP-compatible backend (Jaeger, Grafana Tempo, Datadog, Honeycomb, etc.). See [Getting Started](getting-started.md) for a local Jaeger setup.

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
