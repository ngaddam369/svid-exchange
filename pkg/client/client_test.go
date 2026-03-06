package client

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// mockExchanger implements the exchanger interface. Each Exchange call returns
// a unique token (call count appended) so tests can distinguish a cache hit
// from a real exchange.
type mockExchanger struct {
	mu        sync.Mutex
	calls     int
	expiresAt int64 // unix timestamp; 0 → now+300s
	err       error // when non-nil, Exchange returns this error
}

func (m *mockExchanger) Exchange(_ context.Context, _ *exchangev1.ExchangeRequest, _ ...grpc.CallOption) (*exchangev1.ExchangeResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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
