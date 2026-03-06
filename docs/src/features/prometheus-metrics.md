# Prometheus Metrics

## What it is

svid-exchange exposes standard gRPC server metrics via the `grpc_server_*` family, served at `/metrics` on the health HTTP listener (`health_addr`, default `:8081`). Metrics are always on — no configuration is required.

## Why it exists

Without metrics, the only signal that something is wrong is either a user complaint or a grep through logs. Structured counters and latency histograms let you:

- **Set error-rate SLOs** — alert when `PermissionDenied` or `ResourceExhausted` rates spike above a threshold, which may indicate a misconfigured policy or a compromised workload.
- **Track latency** — the p99 of `grpc_server_handling_seconds` tells you whether the policy evaluation or JWT minting step is introducing unexpected latency.
- **Detect silent denials** — a rising `PermissionDenied` counter with no corresponding `OK` count suggests a workload is attempting calls it has no policy for.
- **Bootstrap alerting from day one** — all series are pre-populated at zero on startup via `grpc_prometheus.Register`, so alerting rules work before the first request lands.

## Metrics reference

| Metric | Type | Description |
|--------|------|-------------|
| `grpc_server_started_total` | Counter | Total RPCs received |
| `grpc_server_handled_total` | Counter | Total RPCs completed, labelled by `grpc_code` |
| `grpc_server_handling_seconds` | Histogram | RPC latency with buckets from 5 ms to 10 s |
| `grpc_server_msg_received_total` | Counter | Total request messages received |
| `grpc_server_msg_sent_total` | Counter | Total response messages sent |

Notable `grpc_code` label values for `grpc_server_handled_total`:

| Code | Meaning |
|------|---------|
| `OK` | Token issued |
| `PermissionDenied` | Policy denied the request |
| `ResourceExhausted` | Rate limit exceeded (when rate limiting is enabled) |
| `InvalidArgument` | Malformed request (missing target or scopes) |

## Usage

```bash
# All gRPC server series
curl -s http://localhost:8081/metrics | grep "^grpc_server"

# Just the handled totals
curl -s http://localhost:8081/metrics | grep "grpc_server_handled_total"
```

Example output after a mix of grants and denials:

```
grpc_server_handled_total{grpc_code="OK",...}               3
grpc_server_handled_total{grpc_code="PermissionDenied",...} 2
grpc_server_handled_total{grpc_code="ResourceExhausted",...} 0
```

## Limitations

- **No per-identity breakdown** — all series are aggregated at the method level. You cannot currently tell from metrics alone which SPIFFE ID is generating denials; cross-reference with audit logs for that.
- **Fixed histogram buckets** — latency buckets are hardcoded (5 ms to 10 s). If your p99 consistently falls outside these bounds the histogram will be less useful.
- **In-process only** — metrics reset on restart. Use a Prometheus remote write or federation setup if you need persistence across restarts.
