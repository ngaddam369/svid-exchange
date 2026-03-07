package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ngaddam369/svid-exchange/internal/token"
)

func TestMiddleware(t *testing.T) {
	minter, err := token.NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub := minter.PublicKey()
		raw, err := pub.Bytes()
		if err != nil {
			http.Error(w, "key encode error", http.StatusInternalServerError)
			return
		}
		byteLen := (len(raw) - 1) / 2
		x := base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
		y := base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])
		doc := map[string]any{
			"keys": []map[string]string{
				{"kty": "EC", "alg": "ES256", "crv": "P-256", "x": x, "y": y},
			},
		}
		body, err := json.Marshal(doc)
		if err != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err = w.Write(body); err != nil {
			t.Logf("write JWKS: %v", err)
		}
	}))
	t.Cleanup(jwksServer.Close)

	const (
		subject  = "spiffe://test.local/order"
		audience = "spiffe://test.local/payment"
	)

	v, err := NewVerifier(context.Background(), jwksServer.URL)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	validToken := func() string {
		r, err := minter.Mint(subject, audience, []string{"read"}, 60, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		return r.Token
	}

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		wantCalled bool
		checkCtx   func(t *testing.T, ctx context.Context)
	}{
		{
			name:       "valid token passes through",
			authHeader: "Bearer " + validToken(),
			wantStatus: http.StatusOK,
			wantCalled: true,
		},
		{
			name:       "missing Authorization header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantCalled: false,
		},
		{
			name:       "malformed Bearer prefix",
			authHeader: "Token " + validToken(),
			wantStatus: http.StatusUnauthorized,
			wantCalled: false,
		},
		{
			name:       "invalid token rejected",
			authHeader: "Bearer not.a.jwt",
			wantStatus: http.StatusUnauthorized,
			wantCalled: false,
		},
		{
			name: "wrong audience rejected",
			authHeader: func() string {
				r, err := minter.Mint(subject, "spiffe://test.local/other", []string{"read"}, 60, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return "Bearer " + r.Token
			}(),
			wantStatus: http.StatusUnauthorized,
			wantCalled: false,
		},
		{
			name:       "ClaimsFromContext returns subject",
			authHeader: "Bearer " + validToken(),
			wantStatus: http.StatusOK,
			wantCalled: true,
			checkCtx: func(t *testing.T, ctx context.Context) {
				t.Helper()
				claims, ok := ClaimsFromContext(ctx)
				if !ok {
					t.Fatal("ClaimsFromContext: no claims in context")
				}
				if got := claims["sub"]; got != subject {
					t.Errorf("sub = %v, want %q", got, subject)
				}
			},
		},
		{
			name: "expired token rejected",
			authHeader: func() string {
				r, err := minter.Mint(subject, audience, []string{"read"}, 1, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				time.Sleep(1100 * time.Millisecond)
				return "Bearer " + r.Token
			}(),
			wantStatus: http.StatusUnauthorized,
			wantCalled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				called   bool
				innerCtx context.Context
			)
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				innerCtx = r.Context()
			})

			h := NewMiddleware(v, audience, inner)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			h.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if called != tc.wantCalled {
				t.Errorf("handler called = %v, want %v", called, tc.wantCalled)
			}
			if tc.checkCtx != nil && innerCtx != nil {
				tc.checkCtx(t, innerCtx)
			}
			// Confirm 401 body does not leak token details
			if w.Code == http.StatusUnauthorized {
				body := strings.TrimSpace(w.Body.String())
				if body != "unauthorized" {
					t.Errorf("401 body = %q, want %q", body, "unauthorized")
				}
			}
		})
	}
}
