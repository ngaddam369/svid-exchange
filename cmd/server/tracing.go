package main

import (
	"context"
	"fmt"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
)

// initTracing configures the global OpenTelemetry TracerProvider.
//
// When endpoint is non-empty, traces are exported via OTLP gRPC to that
// address. When endpoint is empty the function installs a no-op provider and
// returns immediately — the service works normally, just without traces.
//
// The returned shutdown function must be called during graceful shutdown so
// that any buffered spans are flushed to the backend before the process exits.
func initTracing(ctx context.Context, endpoint string, insecure bool) (shutdown func(context.Context) error, err error) {
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exp, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	// Empty schema URL lets Merge adopt the schema from resource.Default()
	// without a conflict — the ServiceName attribute is schema-independent.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("", semconv.ServiceNameKey.String("svid-exchange")),
	)
	if err != nil {
		return nil, fmt.Errorf("build OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// newTracingServerOption returns the gRPC stats handler that wraps every RPC
// in an OpenTelemetry server span. It propagates W3C TraceContext from
// incoming gRPC metadata, so callers that inject trace headers will have their
// spans joined to the same trace.
func newTracingServerOption() grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler())
}
