package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
				r, err := minter.Mint("spiffe://test.local/order", audience, []string{"read"}, 60)
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return r.Token
			},
		},
		{
			name: "wrong audience rejected",
			token: func() string {
				r, err := minter.Mint("spiffe://test.local/order", "spiffe://test.local/other", []string{"read"}, 60)
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
				r, err := minter.Mint("spiffe://test.local/order", audience, []string{"read"}, 1)
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
