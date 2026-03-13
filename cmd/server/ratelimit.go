package main

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/spiffe"
)

// limiterIdleTTL is how long a SPIFFE ID must be idle before its bucket is
// evicted. Set to 1 hour — well beyond any realistic rate-limiting window.
const limiterIdleTTL = time.Hour

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// limiterStore holds a per-SPIFFE-ID token-bucket rate limiter.
// Entries idle longer than limiterIdleTTL are swept by a background goroutine
// started from newRateLimitInterceptor.
type limiterStore struct {
	mu    sync.Mutex
	m     map[string]*limiterEntry
	rps   rate.Limit
	burst int
}

// get returns the existing limiter for id, creating one on first call.
// It updates lastSeen on every call so the entry is not swept while active.
func (s *limiterStore) get(id string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		e.lastSeen = time.Now()
		return e.limiter
	}
	e := &limiterEntry{
		limiter:  rate.NewLimiter(s.rps, s.burst),
		lastSeen: time.Now(),
	}
	s.m[id] = e
	return e.limiter
}

// sweep removes entries that have been idle for longer than idleTTL.
func (s *limiterStore) sweep(idleTTL time.Duration) {
	cutoff := time.Now().Add(-idleTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.m {
		if e.lastSeen.Before(cutoff) {
			delete(s.m, id)
		}
	}
}

// newRateLimitInterceptor returns a gRPC unary interceptor that enforces a
// per-SPIFFE-ID token-bucket rate limit. When rps ≤ 0 the interceptor is a
// no-op pass-through so rate limiting can be disabled without a rebuild.
// The context controls the background sweep goroutine; pass rootCtx so it
// stops cleanly on server shutdown.
func newRateLimitInterceptor(ctx context.Context, rps float64, burst int) grpc.UnaryServerInterceptor {
	if rps <= 0 {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}

	store := &limiterStore{
		m:     make(map[string]*limiterEntry),
		rps:   rate.Limit(rps),
		burst: burst,
	}

	go func() {
		ticker := time.NewTicker(limiterIdleTTL / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				store.sweep(limiterIdleTTL)
			case <-ctx.Done():
				return
			}
		}
	}()

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
