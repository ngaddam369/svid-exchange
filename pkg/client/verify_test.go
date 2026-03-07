package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ngaddam369/svid-exchange/internal/token"
)

func TestVerifier(t *testing.T) {
	minter, err := token.NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	// Serve a JWKS document built from the minter's current public key,
	// using the same coordinate extraction as pubToJWK in cmd/server/jwks.go.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub := minter.PublicKey()
		raw, err := pub.Bytes() // 0x04 || X || Y
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

	const audience = "spiffe://test.local/payment"

	v, err := NewVerifier(context.Background(), jwksServer.URL)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := []struct {
		name    string
		token   func() string
		wantErr bool
	}{
		{
			name: "valid token verifies",
			token: func() string {
				r, err := minter.Mint("spiffe://test.local/order", audience, []string{"read"}, 60, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return r.Token
			},
		},
		{
			name: "wrong audience rejected",
			token: func() string {
				r, err := minter.Mint("spiffe://test.local/order", "spiffe://test.local/other", []string{"read"}, 60, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return r.Token
			},
			wantErr: true,
		},
		{
			name: "expired token rejected",
			token: func() string {
				r, err := minter.Mint("spiffe://test.local/order", audience, []string{"read"}, 1, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				time.Sleep(1100 * time.Millisecond)
				return r.Token
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token(), audience)
			if (err != nil) != tc.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// jwksHandlerFromMinter returns an HTTP handler that serves the public key of
// whatever minter is held in *current at the time of each request.
func jwksHandlerFromMinter(t *testing.T, mu *sync.Mutex, current **token.Minter) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		m := *current
		mu.Unlock()

		pub := m.PublicKey()
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
	}
}

func TestStartAutoRefresh(t *testing.T) {
	const audience = "spiffe://test.local/payment"

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "rotated key accepted after auto-refresh fires",
			run: func(t *testing.T) {
				minter1, err := token.NewMinter()
				if err != nil {
					t.Fatalf("NewMinter (original): %v", err)
				}
				minter2, err := token.NewMinter()
				if err != nil {
					t.Fatalf("NewMinter (rotated): %v", err)
				}

				var mu sync.Mutex
				active := minter1
				srv := httptest.NewServer(jwksHandlerFromMinter(t, &mu, &active))
				t.Cleanup(srv.Close)

				v, err := NewVerifier(context.Background(), srv.URL)
				if err != nil {
					t.Fatalf("NewVerifier: %v", err)
				}

				// Switch the JWKS server to the rotated key.
				mu.Lock()
				active = minter2
				mu.Unlock()

				// Token signed by rotated key fails before auto-refresh.
				tok2, err := minter2.Mint("spiffe://test.local/order", audience, []string{"read"}, 60, "")
				if err != nil {
					t.Fatalf("Mint (rotated): %v", err)
				}
				if _, err = v.Verify(tok2.Token, audience); err == nil {
					t.Fatal("expected Verify to fail before auto-refresh, got nil")
				}

				// Start auto-refresh and wait for first tick.
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				v.StartAutoRefresh(ctx, 50*time.Millisecond)
				time.Sleep(150 * time.Millisecond)

				// Token signed by rotated key now verifies.
				if _, err = v.Verify(tok2.Token, audience); err != nil {
					t.Errorf("Verify with rotated key after auto-refresh: %v", err)
				}
			},
		},
		{
			name: "transient JWKS error preserves cached keys",
			run: func(t *testing.T) {
				minter1, err := token.NewMinter()
				if err != nil {
					t.Fatalf("NewMinter: %v", err)
				}

				// JWKS server that can be made to fail.
				var mu sync.Mutex
				fail := false
				active := minter1
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					f := fail
					mu.Unlock()
					if f {
						http.Error(w, "server error", http.StatusInternalServerError)
						return
					}
					jwksHandlerFromMinter(t, &mu, &active)(w, r)
				}))
				t.Cleanup(srv.Close)

				v, err := NewVerifier(context.Background(), srv.URL)
				if err != nil {
					t.Fatalf("NewVerifier: %v", err)
				}

				// Make JWKS server return errors.
				mu.Lock()
				fail = true
				mu.Unlock()

				// Start auto-refresh; all ticks will fail.
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				v.StartAutoRefresh(ctx, 50*time.Millisecond)
				time.Sleep(150 * time.Millisecond)

				// Original key is still cached — tokens still verify.
				tok, err := minter1.Mint("spiffe://test.local/order", audience, []string{"read"}, 60, "")
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				if _, err = v.Verify(tok.Token, audience); err != nil {
					t.Errorf("Verify after failed refreshes: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
