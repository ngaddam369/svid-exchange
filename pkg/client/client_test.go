package client

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// mockExchanger implements the exchanger interface. Each Exchange call returns
// a unique token (call count appended) so tests can distinguish a cache hit
// from a real exchange.
type mockExchanger struct {
	mu          sync.Mutex
	calls       int
	expiresAt   int64                       // unix timestamp; 0 → now+300s
	err         error                       // when non-nil, Exchange returns this error
	lastRequest *exchangev1.ExchangeRequest // last request received
}

func (m *mockExchanger) Exchange(_ context.Context, req *exchangev1.ExchangeRequest, _ ...grpc.CallOption) (*exchangev1.ExchangeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRequest = req
	if m.err != nil {
		return nil, m.err
	}
	m.calls++
	exp := m.expiresAt
	if exp == 0 {
		exp = time.Now().Add(300 * time.Second).Unix()
	}
	return &exchangev1.ExchangeResponse{
		Token:     fmt.Sprintf("mock-token-%d", m.calls),
		ExpiresAt: exp,
	}, nil
}

func (m *mockExchanger) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// newWithExchanger creates a Client backed by exc, bypassing SPIFFE and gRPC.
func newWithExchanger(exc exchanger, target string, scopes []string, ttlSeconds int32) *Client {
	return &Client{
		exc: exc,
		opts: Options{
			TargetService: target,
			Scopes:        scopes,
			TTLSeconds:    ttlSeconds,
		},
	}
}

// newWithOpts creates a Client backed by exc with fully specified Options.
func newWithOpts(exc exchanger, opts Options) *Client {
	return &Client{exc: exc, opts: opts}
}

func TestToken(t *testing.T) {
	const targetID = "spiffe://test.local/payment"

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "cached token returned on second call",
			run: func(t *testing.T) {
				mock := &mockExchanger{}
				c := newWithExchanger(mock, targetID, []string{"read"}, 60)

				ctx := context.Background()
				tok1, err := c.Token(ctx)
				if err != nil {
					t.Fatalf("first Token: %v", err)
				}
				tok2, err := c.Token(ctx)
				if err != nil {
					t.Fatalf("second Token: %v", err)
				}
				if tok1 != tok2 {
					t.Errorf("second call returned different token: got %q, want %q", tok2, tok1)
				}
				if n := mock.callCount(); n != 1 {
					t.Errorf("Exchange called %d times, want 1", n)
				}
			},
		},
		{
			name: "token refreshed when past refreshAt",
			run: func(t *testing.T) {
				// TTL=1s → refreshAt = now+0.8s. After 900ms the cache guard
				// fails and Token() makes a second exchange call.
				exp := time.Now().Add(time.Second).Unix()
				mock := &mockExchanger{expiresAt: exp}
				c := newWithExchanger(mock, targetID, []string{"read"}, 1)

				ctx := context.Background()
				tok1, err := c.Token(ctx)
				if err != nil {
					t.Fatalf("first Token: %v", err)
				}
				time.Sleep(900 * time.Millisecond)

				tok2, err := c.Token(ctx)
				if err != nil {
					t.Fatalf("second Token after refresh window: %v", err)
				}
				if tok1 == tok2 {
					t.Error("expected new token after refresh window, got same")
				}
				if n := mock.callCount(); n != 2 {
					t.Errorf("Exchange called %d times, want 2", n)
				}
			},
		},
		{
			name: "background goroutine proactively refreshes token",
			run: func(t *testing.T) {
				mock := &mockExchanger{} // default: returns now+300s per call
				c := newWithExchanger(mock, targetID, []string{"read"}, 0)

				ctx := context.Background()
				if _, err := c.Token(ctx); err != nil {
					t.Fatalf("first Token: %v", err)
				}
				// Exchange called once. Override refreshAt to fire the goroutine soon.
				c.cached.mu.Lock()
				c.cached.refreshAt = time.Now().Add(50 * time.Millisecond)
				c.cached.mu.Unlock()

				// Start the goroutine after refreshAt is set so it sees a
				// non-zero value immediately and doesn't enter the 500ms poll.
				stopCtx, stop := context.WithCancel(context.Background())
				t.Cleanup(stop)
				go c.refreshLoop(stopCtx)

				// Wait long enough for the goroutine to fire and refresh.
				time.Sleep(200 * time.Millisecond)

				if n := mock.callCount(); n < 2 {
					t.Errorf("Exchange called %d times after background refresh, want >= 2", n)
				}

				// Token() should be a cache hit — goroutine already warmed the cache.
				callsBefore := mock.callCount()
				if _, err := c.Token(ctx); err != nil {
					t.Fatalf("Token after background refresh: %v", err)
				}
				if mock.callCount() != callsBefore {
					t.Error("Token() triggered a new Exchange after background refresh — cache was not warm")
				}
			},
		},
		{
			name: "OnBehalfOf forwarded in ExchangeRequest",
			run: func(t *testing.T) {
				mock := &mockExchanger{}
				c := newWithOpts(mock, Options{
					TargetService: targetID,
					Scopes:        []string{"read"},
					OnBehalfOf:    "delegate.jwt.token",
				})
				if _, err := c.Token(context.Background()); err != nil {
					t.Fatalf("Token: %v", err)
				}
				mock.mu.Lock()
				req := mock.lastRequest
				mock.mu.Unlock()
				if req == nil {
					t.Fatal("no request captured")
				}
				if req.OnBehalfOf != "delegate.jwt.token" {
					t.Errorf("OnBehalfOf = %q, want %q", req.OnBehalfOf, "delegate.jwt.token")
				}
			},
		},
		{
			name: "GRPCCredentials injects Authorization header",
			run: func(t *testing.T) {
				mock := &mockExchanger{}
				c := newWithExchanger(mock, targetID, []string{"read"}, 60)

				creds := c.GRPCCredentials()
				md, err := creds.GetRequestMetadata(context.Background())
				if err != nil {
					t.Fatalf("GetRequestMetadata: %v", err)
				}
				auth, ok := md["authorization"]
				if !ok {
					t.Fatal("authorization key missing from metadata")
				}
				if len(auth) < 8 || auth[:7] != "Bearer " {
					t.Errorf("authorization = %q, want \"Bearer <token>\"", auth)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestClientTokenConcurrent(t *testing.T) {
	const targetID = "spiffe://test.local/payment"
	mock := &mockExchanger{}
	c := newWithExchanger(mock, targetID, []string{"read"}, 60)

	ctx := context.Background()

	// Warm the cache with one call.
	if _, err := c.Token(ctx); err != nil {
		t.Fatalf("warm Token: %v", err)
	}

	// Force all subsequent calls to be at or past the refresh boundary.
	c.cached.mu.Lock()
	c.cached.refreshAt = time.Now()
	c.cached.mu.Unlock()

	const goroutines = 50
	var (
		wg    sync.WaitGroup
		empty atomic.Int64
		errs  atomic.Int64
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			tok, err := c.Token(ctx)
			if err != nil {
				errs.Add(1)
				return
			}
			if tok == "" {
				empty.Add(1)
			}
		}()
	}
	wg.Wait()

	if errs.Load() > 0 {
		t.Errorf("%d goroutines got errors from Token()", errs.Load())
	}
	if empty.Load() > 0 {
		t.Errorf("%d goroutines got empty tokens", empty.Load())
	}
}
