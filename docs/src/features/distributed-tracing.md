# Distributed Tracing

## What it is

svid-exchange emits OpenTelemetry spans for every `Exchange` RPC via a gRPC stats handler. Traces are exported over OTLP gRPC to any compatible backend (Jaeger, Grafana Tempo, Datadog, Honeycomb). When `otlp_endpoint` is empty (the default in `config/server.yaml`), a no-op tracer is used — zero overhead, no backend required.

## Why it exists

Logs and metrics answer *what happened* and *how often*. Traces answer *why was this request slow* and *how does this call fit into the wider request path*.

Concretely, tracing helps with:

- **Latency attribution** — if an Exchange RPC is slow, the span shows whether time was spent in policy evaluation, JWT minting, or network overhead.
- **Upstream correlation** — W3C TraceContext propagation means an upstream service's span and the Exchange span share the same trace ID. You can follow a single user request from the frontend, through the calling service, and into the Exchange handler in one trace view.
- **Production debugging** — rather than grepping logs for a specific token ID, you can find the trace for a problematic request and inspect its full context.

## Enabling tracing

Set `otlp_endpoint` in `config/server.yaml` to the gRPC address of your OTLP backend:

```yaml
otlp_endpoint: "jaeger:4317"
```

svid-exchange logs on startup:

```
{"message":"OTLP tracing enabled","endpoint":"jaeger:4317"}
```

### Local Jaeger setup

```bash
# Start Jaeger on the same Docker network as the stack
docker run -d --name jaeger \
  --network svid-exchange-dev_default \
  -p 16686:16686 -p 4317:4317 \
  jaegertracing/all-in-one:1.65.0
```

Then set `otlp_endpoint: "jaeger:4317"` in `config/server.yaml` and restart the stack.

Make a few exchange requests, then open `http://localhost:16686`, select the `svid-exchange` service, and find the `Exchange` spans.

## What each span contains

Every `Exchange` RPC produces one server span with:

- **Operation name** — `exchange.v1.TokenExchange/Exchange`
- **Duration** — full RPC latency from receive to send
- **gRPC status** — success or error code visible in the span status
- **W3C TraceContext** — incoming `traceparent` / `tracestate` headers from gRPC metadata are respected, linking the Exchange span to the caller's trace

## Limitations

- **No custom attributes yet** — the span does not carry SPIFFE ID, granted scopes, or policy name as span attributes. These would make filtering by identity practical; this is a planned enhancement.
- **No sampling configuration** — all requests are sampled. In high-throughput environments you will want to configure a tail- or head-based sampler via the standard OpenTelemetry SDK environment variables (`OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`).
- **Traces do not replace audit logs** — spans are best-effort and may be dropped under load or if the backend is unavailable. Audit logs are the authoritative record for compliance; traces are an operational debugging tool.
- **OTLP gRPC only** — HTTP/JSON OTLP is not currently supported. Use a local collector (e.g. OpenTelemetry Collector) if your backend requires it.
