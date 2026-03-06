package main

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/spiffe"
)

// limiterStore holds a per-SPIFFE-ID token-bucket rate limiter.
// sync.Map ensures at-most-once limiter creation per identity.
type limiterStore struct {
	m     sync.Map // key: SPIFFE ID string, value: *rate.Limiter
	rps   rate.Limit
	burst int
}

// get returns the existing limiter for id, creating one on first call.
func (s *limiterStore) get(id string) *rate.Limiter {
	if v, ok := s.m.Load(id); ok {
		l, ok := v.(*rate.Limiter)
		if !ok {
			panic("limiterStore: unexpected value type")
		}
		return l
	}
	l := rate.NewLimiter(s.rps, s.burst)
	if actual, loaded := s.m.LoadOrStore(id, l); loaded {
		existing, ok := actual.(*rate.Limiter)
		if !ok {
			panic("limiterStore: unexpected value type")
		}
		return existing
	}
	return l
}

// newRateLimitInterceptor returns a gRPC unary interceptor that enforces a
// per-SPIFFE-ID token-bucket rate limit. When rps ≤ 0 the interceptor is a
// no-op pass-through so rate limiting can be disabled without a rebuild.
func newRateLimitInterceptor(rps float64, burst int) grpc.UnaryServerInterceptor {
	if rps <= 0 {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}

	store := &limiterStore{rps: rate.Limit(rps), burst: burst}

	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id, err := spiffe.ExtractID(ctx)
		if err != nil {
			// No SPIFFE ID present — let the handler surface the auth error.
			return handler(ctx, req)
		}
		if !store.get(id).Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded for %s", id)
		}
		return handler(ctx, req)
	}
}

// chainUnary chains two unary server interceptors into one so they can both
// be registered in the single grpc.UnaryInterceptor slot.
// Execution order: first wraps second wraps handler.
func chainUnary(first, second grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return first(ctx, req, info, func(ctx context.Context, req any) (any, error) {
			return second(ctx, req, info, handler)
		})
	}
}
