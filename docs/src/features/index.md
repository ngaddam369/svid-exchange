# Features

Each page below covers the motivation, configuration, and known limitations.

**Always-on** (no configuration required):

- [Prometheus Metrics](prometheus-metrics.md) — SLO-grade counters and latency histograms for every Exchange RPC

**Opt-in** (disabled by default; activated via environment variables):

- [Distributed Tracing](distributed-tracing.md) — OpenTelemetry spans exported to any OTLP-compatible backend
- [Rate Limiting](rate-limiting.md) — per-SPIFFE-ID token-bucket quota enforcement
- [Audit Log Integrity](audit-log-integrity.md) — HMAC-SHA256 signing and chained MACs for tamper-evident logs
