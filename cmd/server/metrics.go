package main

import (
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

// initMetrics enables per-RPC latency histograms and returns the unary server
// interceptor that records counts, status codes, and latencies for every RPC.
// Must be called before grpc.NewServer so the histogram options take effect.
func initMetrics() grpc.UnaryServerInterceptor {
	grpc_prometheus.EnableHandlingTimeHistogram()
	return grpc_prometheus.UnaryServerInterceptor
}

// registerMetrics pre-populates per-method series at zero for every service
// registered on s. Without this, a method only appears in /metrics after its
// first call, which makes alerting on absence unreliable.
func registerMetrics(s *grpc.Server) {
	grpc_prometheus.Register(s)
}

// newMetricsHandler returns an HTTP handler that serves the Prometheus text
// exposition format at /metrics.
func newMetricsHandler() http.Handler {
	return promhttp.Handler()
}
