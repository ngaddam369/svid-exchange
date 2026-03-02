package main

import (
	"context"
	"testing"
)

func TestInitTracingNoop(t *testing.T) {
	// OTEL_EXPORTER_OTLP_ENDPOINT is not set — should return a noop shutdown
	// function with no error.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

	shutdown, err := initTracing(context.Background())
	if err != nil {
		t.Fatalf("initTracing: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown function is nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown returned error: %v", err)
	}
}

func TestNewTracingServerOption(t *testing.T) {
	opt := newTracingServerOption()
	if opt == nil {
		t.Fatal("newTracingServerOption returned nil")
	}
}
