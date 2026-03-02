# Rate Limiting

## What it is

svid-exchange enforces a per-SPIFFE-ID token-bucket rate limit as a gRPC unary interceptor. Each caller identity gets its own independent bucket. Requests that exceed the configured quota are rejected with `ResourceExhausted` before the policy or minting logic is ever reached.

When `RATE_LIMIT_RPS` is unset or `0`, rate limiting is disabled and all requests pass through without any quota check.

## Why it exists

The policy layer protects *what* a workload can access. Rate limiting protects *how often* it can ask. Without it:

- A compromised workload could hammer the exchange service — exhausting its signing capacity or amplifying downstream damage by issuing tokens at an unbounded rate.
- A misconfigured workload in a retry loop could saturate the service for all other callers.
- There is no built-in defence against a workload attempting to exhaust token budgets of target services by rapidly requesting and discarding tokens.

Rate limiting acts as a **second line of defence** — it does not replace policy, but it bounds the blast radius of any single identity misbehaving.

### Why per-SPIFFE-ID

Limiting at the service level (a single global counter) would throttle legitimate callers when one misbehaves. Per-identity bucketing means a noisy workload only exhausts its own quota — other identities are unaffected.

## Interceptor position

```
gRPC transport (mTLS)
  └── metrics interceptor   ← counts all calls, including rate-limited ones
        └── rate limit      ← rejects here; Exchange() never runs
              └── Exchange()
```

Rate-limited calls are still recorded in `grpc_server_handled_total{grpc_code="ResourceExhausted"}`, so your dashboards reflect the true request volume.

## Enabling rate limiting

```bash
RATE_LIMIT_RPS=10 RATE_LIMIT_BURST=10 docker compose up svid-exchange --build -d
```

svid-exchange logs on startup:

```
{"message":"rate limiting enabled","rps":10,"burst":10}
```

`RATE_LIMIT_BURST` defaults to `ceil(RATE_LIMIT_RPS)` when unset, giving a burst capacity equal to one second's worth of quota.

### What a rate-limited caller sees

```
ERROR:
  Code: ResourceExhausted
  Message: rate limit exceeded for spiffe://cluster.local/ns/default/sa/order
```

### Observing in Prometheus

```bash
curl -s http://localhost:8081/metrics | grep ResourceExhausted
# grpc_server_handled_total{grpc_code="ResourceExhausted",...} 3
```

## Limitations

- **In-process state** — the token buckets live in memory and reset on restart. In a multi-replica deployment each replica maintains its own counters; a caller could make `N × RPS` requests across `N` replicas. A shared rate limiter (Redis, a sidecar) would be needed for strict enforcement at scale.
- **Per-identity, not per-target** — the limit applies to the total request rate from a SPIFFE ID, regardless of which target it is requesting tokens for. Per-target limits are not yet implemented.
- **No dynamic adjustment** — RPS and burst are set at startup via env vars. Changing them requires a restart. Dynamic per-identity limits configurable in the policy file are a planned enhancement.
