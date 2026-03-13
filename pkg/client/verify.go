package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksHTTPClient is used for all JWKS fetches. The 10 s timeout bounds how long
// Refresh can block independently of any caller-supplied context deadline. The
// 1 MiB body cap prevents a malicious or misconfigured endpoint from streaming
// an unbounded response into memory.
var jwksHTTPClient = &http.Client{Timeout: 10 * time.Second}

const jwksBodyLimit = 1 << 20 // 1 MiB

// Verifier fetches the signing public key from a JWKS endpoint and validates
// inbound JWTs. During a key rotation window the server publishes two keys;
// Verify tries all cached keys so tokens signed by either remain valid.
type Verifier struct {
	mu      sync.RWMutex
	keys    []*ecdsa.PublicKey
	jwksURL string
}

// NewVerifier creates a Verifier that fetches keys from jwksURL immediately.
// It returns an error if the endpoint is unreachable or the response is malformed.
func NewVerifier(ctx context.Context, jwksURL string) (*Verifier, error) {
	v := &Verifier{jwksURL: jwksURL}
	if err := v.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("verifier: initial JWKS fetch: %w", err)
	}
	return v, nil
}

// Refresh re-fetches the JWKS and updates the cached key set. Call this after
// a signing key rotation to pick up the new key immediately.
func (v *Verifier) Refresh(ctx context.Context) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() {
		if e := resp.Body.Close(); err == nil {
			err = e
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var doc jwksResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, jwksBodyLimit)).Decode(&doc); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make([]*ecdsa.PublicKey, 0, len(doc.Keys))
	for i, k := range doc.Keys {
		pub, err := jwkToPublicKey(k)
		if err != nil {
			return fmt.Errorf("key %d: %w", i, err)
		}
		keys = append(keys, pub)
	}

	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

// StartAutoRefresh starts a background goroutine that calls [Verifier.Refresh]
// on every interval tick. The goroutine exits when ctx is cancelled. Transient
// refresh errors are suppressed — the cached keys remain valid until the next
// successful refresh. Call this once after [NewVerifier] with an interval that
// matches or is shorter than the server's key_rotation_interval.
func (v *Verifier) StartAutoRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := v.Refresh(ctx); err != nil {
					continue // transient failure; cached keys remain valid until next tick
				}
			}
		}
	}()
}

// Verify validates token as an ES256 JWT issued by svid-exchange for audience.
// It returns the parsed claims on success. An error is returned if the
// signature, expiry, audience, or issuer check fails.
func (v *Verifier) Verify(token, audience string) (jwt.MapClaims, error) {
	v.mu.RLock()
	keys := v.keys
	v.mu.RUnlock()

	if len(keys) == 0 {
		return nil, fmt.Errorf("verifier: no keys loaded")
	}

	var lastErr error
	for _, pub := range keys {
		tok, err := jwt.Parse(token,
			func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return pub, nil
			},
			jwt.WithValidMethods([]string{"ES256"}),
			jwt.WithExpirationRequired(),
			jwt.WithAudience(audience),
			jwt.WithIssuer("svid-exchange"),
		)
		if err == nil {
			claims, ok := tok.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("verifier: unexpected claims type")
			}
			return claims, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("verifier: %w", lastErr)
}

// jwksResponse is the wire format of the /jwks endpoint.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey mirrors the fields emitted by pubToJWK in cmd/server/jwks.go.
type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwkToPublicKey decodes a JWK into an *ecdsa.PublicKey.
// It is the inverse of pubToJWK in cmd/server/jwks.go.
// The uncompressed point 0x04 || X || Y is reconstructed from the base64url
// coordinates and parsed via ecdsa.ParseUncompressedPublicKey, which performs
// on-curve validation using the modern crypto/ecdh API.
func jwkToPublicKey(k jwkKey) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %q / curve %q", k.Kty, k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	// Reconstruct the uncompressed point: 0x04 || X || Y
	uncompressed := make([]byte, 1+len(xBytes)+len(yBytes))
	uncompressed[0] = 0x04
	copy(uncompressed[1:], xBytes)
	copy(uncompressed[1+len(xBytes):], yBytes)

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}
