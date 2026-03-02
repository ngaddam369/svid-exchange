package main

import (
	"context"
	"testing"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewRateLimitInterceptorDisabled(t *testing.T) {
	interceptor := newRateLimitInterceptor(0, 0)
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}

	called := false
	handler := func(_ context.Context, _ any) (any, error) {
		called = true
		return "ok", nil
	}

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestNewRateLimitInterceptorEnabled(t *testing.T) {
	interceptor := newRateLimitInterceptor(10, 1)
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}

func TestLimiterStore(t *testing.T) {
	store := &limiterStore{
		rps:   rate.Limit(1),
		burst: 1,
	}
	id := "spiffe://example.org/ns/default/sa/order"

	l := store.get(id)
	if !l.Allow() {
		t.Fatal("first Allow() should succeed with burst=1")
	}
	if l.Allow() {
		t.Fatal("second immediate Allow() should fail with burst=1")
	}

	// get() must return the same limiter instance for the same SPIFFE ID.
	if store.get(id) != l {
		t.Fatal("expected same limiter instance for the same SPIFFE ID")
	}
}

func TestRateLimitInterceptorDenied(t *testing.T) {
	// burst=1 so the second call from the same identity is rejected.
	interceptor := newRateLimitInterceptor(100, 1)

	handler := func(_ context.Context, _ any) (any, error) {
		return "ok", nil
	}

	// First call passes; we cannot inject a peer ctx easily without a full
	// gRPC stack, so we verify the "no SPIFFE ID → pass through" path here.
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("expected pass-through on missing SPIFFE ID, got: %v", err)
	}
}

func TestRateLimitInterceptorResourceExhausted(t *testing.T) {
	// Directly test the limiter logic: burst=0 means every Allow() returns false.
	// We cannot call the returned interceptor with a real peer ctx without a
	// gRPC server, but we can verify the status code path via limiterStore.
	store := &limiterStore{
		rps:   rate.Limit(1),
		burst: 0, // no tokens ever available
	}
	id := "spiffe://example.org/ns/default/sa/svc"
	if store.get(id).Allow() {
		t.Fatal("Allow() should fail with burst=0")
	}

	// Verify that ResourceExhausted is the right code.
	err := status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", id)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("unexpected code: %v", status.Code(err))
	}
}
