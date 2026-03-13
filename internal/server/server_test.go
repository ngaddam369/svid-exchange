package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/server"
	"github.com/ngaddam369/svid-exchange/internal/token"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// --- mock implementations (test-only) ---

type mockExtractor struct {
	id  string
	err error
}

func (m mockExtractor) ExtractID(_ context.Context) (string, error) {
	return m.id, m.err
}

type mockPolicy struct {
	result policy.EvalResult
}

func (m mockPolicy) Evaluate(_, _ string, _ []string, _ int32) policy.EvalResult {
	return m.result
}

type mockMinter struct {
	result     token.MintResult
	err        error
	lastAct    string             // actSubject passed to the most recent Mint call
	publicKeys []*ecdsa.PublicKey // returned by PublicKeys(); nil means no keys
}

func (m *mockMinter) Mint(_, _ string, _ []string, _ int32, actSubject string) (token.MintResult, error) {
	m.lastAct = actSubject
	return m.result, m.err
}

func (m *mockMinter) PublicKeys() []*ecdsa.PublicKey {
	return m.publicKeys
}

type mockAudit struct{}

func (mockAudit) LogExchange(_ audit.ExchangeEvent) {}

// --- test helpers ---

func okExtractor() mockExtractor {
	return mockExtractor{id: "spiffe://cluster.local/ns/default/sa/order"}
}

func okMinter() *mockMinter {
	return &mockMinter{result: token.MintResult{
		Token:     "signed-jwt",
		TokenID:   "test-jti",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}}
}

func allowedPolicy(scopes []string, ttl int32) mockPolicy {
	return mockPolicy{result: policy.EvalResult{
		Allowed:       true,
		GrantedScopes: scopes,
		GrantedTTL:    ttl,
	}}
}

func deniedPolicy() mockPolicy {
	return mockPolicy{result: policy.EvalResult{Allowed: false}}
}

// makeTestJWT builds a minimal JWT string with a fake signature for the given
// sub claim. Used in tests that verify forged/unsigned JWTs are rejected.
func makeTestJWT(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]string{"sub": sub})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"
}

// --- tests ---

func newValidReq() *exchangev1.ExchangeRequest {
	return &exchangev1.ExchangeRequest{
		TargetService: "spiffe://cluster.local/ns/default/sa/payment",
		Scopes:        []string{"payments:charge"},
		TtlSeconds:    300,
	}
}

func TestContextCancellation(t *testing.T) {
	t.Run("cancelled before policy eval returns Canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), okMinter(), mockAudit{})
		_, err := svc.Exchange(ctx, newValidReq())
		if status.Code(err) != codes.Canceled {
			t.Errorf("code = %v, want Canceled", status.Code(err))
		}
	})

	t.Run("deadline exceeded before policy eval returns DeadlineExceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
		defer cancel()

		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), okMinter(), mockAudit{})
		_, err := svc.Exchange(ctx, newValidReq())
		if status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("code = %v, want DeadlineExceeded", status.Code(err))
		}
	})
}

func TestReplayAndRevocation(t *testing.T) {
	t.Run("duplicate JTI is rejected with AlreadyExists", func(t *testing.T) {
		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), okMinter(), mockAudit{})

		_, err := svc.Exchange(context.Background(), newValidReq())
		if err != nil {
			t.Fatalf("first exchange failed: %v", err)
		}

		_, err = svc.Exchange(context.Background(), newValidReq())
		if status.Code(err) != codes.AlreadyExists {
			t.Errorf("second exchange: code = %v, want AlreadyExists", status.Code(err))
		}
	})

	t.Run("revoked JTI is rejected with PermissionDenied", func(t *testing.T) {
		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), okMinter(), mockAudit{})

		svc.Revoke("test-jti", time.Now().Add(time.Minute))

		_, err := svc.Exchange(context.Background(), newValidReq())
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("revoked exchange: code = %v, want PermissionDenied", status.Code(err))
		}
	})

	t.Run("expired JTI is not treated as a replay", func(t *testing.T) {
		// Mint with TTL=1; after expiry the cache entry is swept and a second
		// exchange with the same JTI is allowed again.
		shortMinter := &mockMinter{result: token.MintResult{
			Token:     "signed-jwt",
			TokenID:   "short-lived-jti",
			ExpiresAt: time.Now().Add(1 * time.Second),
		}}
		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 1), shortMinter, mockAudit{})

		_, err := svc.Exchange(context.Background(), newValidReq())
		if err != nil {
			t.Fatalf("first exchange failed: %v", err)
		}

		time.Sleep(1100 * time.Millisecond)

		_, err = svc.Exchange(context.Background(), newValidReq())
		if err != nil {
			t.Errorf("post-expiry exchange failed: %v", err)
		}
	})
}

func TestExchange(t *testing.T) {
	tests := []struct {
		name       string
		extractor  server.IDExtractor
		policy     server.PolicyEvaluator
		minter     server.TokenMinter
		req        *exchangev1.ExchangeRequest
		wantCode   codes.Code                               // codes.OK (zero value) means success expected
		wantScopes []string                                 // checked on success only
		check      func(t *testing.T, m server.TokenMinter) // optional post-exchange assertion
	}{
		{
			name:      "valid request",
			extractor: okExtractor(),
			policy:    allowedPolicy([]string{"payments:charge"}, 300),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge"},
				TtlSeconds:    300,
			},
			wantCode:   codes.OK,
			wantScopes: []string{"payments:charge"},
		},
		{
			name:      "both scopes granted",
			extractor: okExtractor(),
			policy:    allowedPolicy([]string{"payments:charge", "payments:refund"}, 300),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge", "payments:refund"},
				TtlSeconds:    300,
			},
			wantCode:   codes.OK,
			wantScopes: []string{"payments:charge", "payments:refund"},
		},
		{
			name:      "disallowed scope filtered by policy",
			extractor: okExtractor(),
			policy:    allowedPolicy([]string{"payments:charge"}, 60),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge", "admin:delete"},
				TtlSeconds:    60,
			},
			wantCode:   codes.OK,
			wantScopes: []string{"payments:charge"},
		},
		{
			name:      "SPIFFE extraction failed",
			extractor: mockExtractor{err: errors.New("no TLS info")},
			policy:    deniedPolicy(),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge"},
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name:      "missing target",
			extractor: okExtractor(),
			policy:    deniedPolicy(),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				Scopes: []string{"payments:charge"},
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name:      "missing scopes",
			extractor: okExtractor(),
			policy:    deniedPolicy(),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name:      "policy denied",
			extractor: okExtractor(),
			policy:    deniedPolicy(),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge"},
				TtlSeconds:    60,
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name:      "mint error",
			extractor: okExtractor(),
			policy:    allowedPolicy([]string{"payments:charge"}, 60),
			minter:    &mockMinter{err: errors.New("signing failed")},
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge"},
				TtlSeconds:    60,
			},
			wantCode: codes.Internal,
		},
		{
			name:      "delegation: malformed on_behalf_of rejected",
			extractor: okExtractor(),
			policy:    allowedPolicy([]string{"payments:charge"}, 300),
			minter:    okMinter(),
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://cluster.local/ns/default/sa/payment",
				Scopes:        []string{"payments:charge"},
				TtlSeconds:    300,
				OnBehalfOf:    "not.valid",
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := server.New(tc.extractor, tc.policy, tc.minter, mockAudit{})
			resp, err := svc.Exchange(context.Background(), tc.req)

			if tc.wantCode != codes.OK {
				if status.Code(err) != tc.wantCode {
					t.Errorf("code = %v, want %v", status.Code(err), tc.wantCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Token == "" {
				t.Error("token is empty")
			}
			if resp.TokenId == "" {
				t.Error("token_id is empty")
			}
			if resp.ExpiresAt == 0 {
				t.Error("expires_at is zero")
			}
			if len(resp.GrantedScopes) != len(tc.wantScopes) {
				t.Errorf("granted_scopes = %v, want %v", resp.GrantedScopes, tc.wantScopes)
			} else {
				for i, s := range tc.wantScopes {
					if resp.GrantedScopes[i] != s {
						t.Errorf("granted_scopes[%d] = %q, want %q", i, resp.GrantedScopes[i], s)
					}
				}
			}
			if tc.check != nil {
				tc.check(t, tc.minter)
			}
		})
	}
}

// TestOnBehalfOf tests the on_behalf_of validation path that requires a
// properly signed JWT from this service. Uses a real token.Minter to produce
// valid and expired tokens; the exchange server's mockMinter is pre-loaded with
// the same public keys so VerifyJWT can authenticate the delegate token.
func TestOnBehalfOf(t *testing.T) {
	delegateMinter, err := token.NewMinter()
	if err != nil {
		t.Fatalf("create delegate minter: %v", err)
	}

	// Mint a valid delegate token (sub = "user-xyz").
	delegateResult, err := delegateMinter.Mint(
		"user-xyz",
		"spiffe://cluster.local/ns/default/sa/payment",
		[]string{"read"}, 300, "")
	if err != nil {
		t.Fatalf("mint delegate token: %v", err)
	}

	// exchangeMinter is the mock used by the exchange server. It knows the
	// delegate minter's public keys so it can verify on_behalf_of tokens.
	exchangeMinter := &mockMinter{
		result: token.MintResult{
			Token:     "signed-jwt",
			TokenID:   "test-jti",
			ExpiresAt: time.Now().Add(5 * time.Minute),
		},
		publicKeys: delegateMinter.PublicKeys(),
	}

	t.Run("valid signed on_behalf_of: sub forwarded to minter", func(t *testing.T) {
		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), exchangeMinter, mockAudit{})
		_, err := svc.Exchange(context.Background(), &exchangev1.ExchangeRequest{
			TargetService: "spiffe://cluster.local/ns/default/sa/payment",
			Scopes:        []string{"payments:charge"},
			TtlSeconds:    300,
			OnBehalfOf:    delegateResult.Token,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := exchangeMinter.lastAct; got != "user-xyz" {
			t.Errorf("actSubject = %q, want %q", got, "user-xyz")
		}
	})

	t.Run("forged unsigned on_behalf_of is rejected", func(t *testing.T) {
		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), exchangeMinter, mockAudit{})
		_, err := svc.Exchange(context.Background(), &exchangev1.ExchangeRequest{
			TargetService: "spiffe://cluster.local/ns/default/sa/payment",
			Scopes:        []string{"payments:charge"},
			TtlSeconds:    300,
			OnBehalfOf:    makeTestJWT("admin"),
		})
		if code := status.Code(err); code != codes.InvalidArgument {
			t.Errorf("expected InvalidArgument for forged JWT, got %v: %v", code, err)
		}
	})

	t.Run("expired on_behalf_of is rejected", func(t *testing.T) {
		expiredResult, err := delegateMinter.Mint(
			"user-xyz",
			"spiffe://cluster.local/ns/default/sa/payment",
			[]string{"read"}, 1, "")
		if err != nil {
			t.Fatalf("mint expired token: %v", err)
		}
		time.Sleep(1100 * time.Millisecond)

		svc := server.New(okExtractor(), allowedPolicy([]string{"payments:charge"}, 300), exchangeMinter, mockAudit{})
		_, err = svc.Exchange(context.Background(), &exchangev1.ExchangeRequest{
			TargetService: "spiffe://cluster.local/ns/default/sa/payment",
			Scopes:        []string{"payments:charge"},
			TtlSeconds:    300,
			OnBehalfOf:    expiredResult.Token,
		})
		if code := status.Code(err); code != codes.InvalidArgument {
			t.Errorf("expected InvalidArgument for expired JWT, got %v: %v", code, err)
		}
	})
}
