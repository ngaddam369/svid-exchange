package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ngaddam369/svid-exchange/internal/token"
	"github.com/rs/zerolog"
)

func TestNewJWKSHandler(t *testing.T) {
	m, err := token.NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	h := newJWKSHandler(m, zerolog.Nop())

	tests := []struct {
		name  string
		check func(t *testing.T, resp *http.Response)
	}{
		{
			name: "content-type is application/json",
			check: func(t *testing.T, resp *http.Response) {
				if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
			},
		},
		{
			name: "response contains exactly one key",
			check: func(t *testing.T, resp *http.Response) {
				var doc jwkSet
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if len(doc.Keys) != 1 {
					t.Fatalf("got %d keys, want 1", len(doc.Keys))
				}
			},
		},
		{
			name: "key fields have correct fixed values",
			check: func(t *testing.T, resp *http.Response) {
				var doc jwkSet
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					t.Fatalf("decode: %v", err)
				}
				k := doc.Keys[0]
				if k.Kty != "EC" {
					t.Errorf("kty = %q, want EC", k.Kty)
				}
				if k.Crv != "P-256" {
					t.Errorf("crv = %q, want P-256", k.Crv)
				}
				if k.Alg != "ES256" {
					t.Errorf("alg = %q, want ES256", k.Alg)
				}
				if k.Use != "sig" {
					t.Errorf("use = %q, want sig", k.Use)
				}
			},
		},
		{
			name: "x and y are 32-byte base64url coordinates",
			check: func(t *testing.T, resp *http.Response) {
				var doc jwkSet
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					t.Fatalf("decode: %v", err)
				}
				k := doc.Keys[0]
				xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
				if err != nil {
					t.Fatalf("decode x: %v", err)
				}
				if len(xBytes) != 32 {
					t.Errorf("x is %d bytes, want 32", len(xBytes))
				}
				yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
				if err != nil {
					t.Fatalf("decode y: %v", err)
				}
				if len(yBytes) != 32 {
					t.Errorf("y is %d bytes, want 32", len(yBytes))
				}
			},
		},
		{
			name: "kid is a 32-byte RFC 7638 SHA-256 thumbprint",
			check: func(t *testing.T, resp *http.Response) {
				var doc jwkSet
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					t.Fatalf("decode: %v", err)
				}
				kidBytes, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].Kid)
				if err != nil {
					t.Fatalf("decode kid: %v", err)
				}
				if len(kidBytes) != 32 {
					t.Errorf("kid is %d bytes, want 32 (SHA-256)", len(kidBytes))
				}
			},
		},
		{
			name: "response body is stable across requests",
			check: func(t *testing.T, resp *http.Response) {
				var doc1 jwkSet
				if err := json.NewDecoder(resp.Body).Decode(&doc1); err != nil {
					t.Fatalf("decode first: %v", err)
				}

				srv := httptest.NewServer(h)
				defer srv.Close()
				resp2, err := http.Get(srv.URL)
				if err != nil {
					t.Fatalf("second request: %v", err)
				}
				defer resp2.Body.Close()
				var doc2 jwkSet
				if err := json.NewDecoder(resp2.Body).Decode(&doc2); err != nil {
					t.Fatalf("decode second: %v", err)
				}
				if doc1.Keys[0].Kid != doc2.Keys[0].Kid {
					t.Errorf("kid changed between requests: %q vs %q",
						doc1.Keys[0].Kid, doc2.Keys[0].Kid)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()

			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			tc.check(t, resp)
		})
	}
}

func TestJWKSHandlerAfterRotation(t *testing.T) {
	m, err := token.NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	h := newJWKSHandler(m, zerolog.Nop())
	srv := httptest.NewServer(h)
	defer srv.Close()

	get := func(t *testing.T) jwkSet {
		t.Helper()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		var doc jwkSet
		if err = json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return doc
	}

	before := get(t)
	if len(before.Keys) != 1 {
		t.Fatalf("before rotation: got %d keys, want 1", len(before.Keys))
	}
	kidBefore := before.Keys[0].Kid

	if err = m.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	after := get(t)
	if len(after.Keys) != 2 {
		t.Fatalf("after rotation: got %d keys, want 2", len(after.Keys))
	}

	// The pre-rotation kid must still be present so in-flight tokens remain verifiable.
	found := false
	for _, k := range after.Keys {
		if k.Kid == kidBefore {
			found = true
			break
		}
	}
	if !found {
		t.Error("pre-rotation kid not present in post-rotation JWKS")
	}
}
