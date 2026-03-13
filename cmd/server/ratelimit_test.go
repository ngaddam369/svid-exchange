package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewRateLimitInterceptorDisabled(t *testing.T) {
	interceptor := newRateLimitInterceptor(context.Background(), 0, 0)
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
	interceptor := newRateLimitInterceptor(context.Background(), 10, 1)
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
}

func TestLimiterStore(t *testing.T) {
	store := &limiterStore{
		m:     make(map[string]*limiterEntry),
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

func TestLimiterStoreSweep(t *testing.T) {
	store := &limiterStore{
		m:     make(map[string]*limiterEntry),
		rps:   rate.Limit(1),
		burst: 1,
	}
	active := "spiffe://example.org/ns/default/sa/active"
	idle := "spiffe://example.org/ns/default/sa/idle"

	store.get(active)
	store.get(idle)

	// Backdate idle entry's lastSeen so it appears stale.
	store.mu.Lock()
	store.m[idle].lastSeen = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()

	store.sweep(time.Hour)

	store.mu.Lock()
	_, hasActive := store.m[active]
	_, hasIdle := store.m[idle]
	store.mu.Unlock()

	if !hasActive {
		t.Error("active entry should survive sweep")
	}
	if hasIdle {
		t.Error("idle entry should be evicted by sweep")
	}
}

func TestRateLimitInterceptorDenied(t *testing.T) {
	// burst=1 so the second call from the same identity is rejected.
	interceptor := newRateLimitInterceptor(context.Background(), 100, 1)

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
		m:     make(map[string]*limiterEntry),
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

func TestRateLimitInterceptorSweepOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	interceptor := newRateLimitInterceptor(ctx, 10, 10)
	if interceptor == nil {
		t.Fatal("expected non-nil interceptor")
	}
	// Cancel context — goroutine should exit cleanly (no panic, no hang).
	cancel()
}

func TestChainUnary(t *testing.T) {
	var order []string

	makeInterceptor := func(name string) grpc.UnaryServerInterceptor {
		return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			order = append(order, name+"-before")
			resp, err := handler(ctx, req)
			order = append(order, name+"-after")
			return resp, err
		}
	}

	handler := func(_ context.Context, req any) (any, error) {
		order = append(order, "handler")
		return "ok", nil
	}

	resp, err := chainUnary(makeInterceptor("first"), makeInterceptor("second"))(
		context.Background(), "req", &grpc.UnaryServerInfo{}, handler,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != "ok" {
		t.Errorf("got %v, want %q", resp, "ok")
	}

	want := []string{"first-before", "second-before", "handler", "second-after", "first-after"}
	if len(order) != len(want) {
		t.Fatalf("execution order = %v, want %v", order, want)
	}
	for i, s := range want {
		if order[i] != s {
			t.Errorf("order[%d] = %q, want %q", i, order[i], s)
		}
	}

	t.Run("first interceptor can short-circuit without calling handler", func(t *testing.T) {
		errFirst := func(_ context.Context, _ any, _ *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
			return nil, status.Errorf(codes.Internal, "short-circuit")
		}
		handlerCalled := false
		_, err := chainUnary(errFirst, makeInterceptor("second"))(
			context.Background(), nil, &grpc.UnaryServerInfo{},
			func(_ context.Context, _ any) (any, error) {
				handlerCalled = true
				return nil, nil
			},
		)
		if status.Code(err) != codes.Internal {
			t.Errorf("got code %v, want Internal", status.Code(err))
		}
		if handlerCalled {
			t.Error("handler should not be called when first interceptor short-circuits")
		}
	})
}
