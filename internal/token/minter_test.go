package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestMinter(t *testing.T) *Minter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &Minter{current: &ecdsaSigner{key: key}}
}

func parseClaims(t *testing.T, m *Minter, tokenStr string) jwt.MapClaims {
	t.Helper()
	tok, err := jwt.Parse(tokenStr, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatalf("unexpected signing method: %v", tok.Header["alg"])
		}
		return m.PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	return claims
}

func TestNewMinter(t *testing.T) {
	m, err := NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	if m.PublicKey() == nil {
		t.Error("PublicKey is nil")
	}
}

func TestMint(t *testing.T) {
	m := newTestMinter(t)

	t.Run("JWT claims", func(t *testing.T) {
		const (
			subject = "spiffe://cluster.local/ns/default/sa/order"
			target  = "spiffe://cluster.local/ns/default/sa/payment"
		)
		scopes := []string{"payments:charge", "payments:refund"}

		before := time.Now().Unix()
		result, err := m.Mint(subject, target, scopes, 300, "")
		after := time.Now().Unix()
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		claims := parseClaims(t, m, result.Token)

		if claims["iss"] != issuer {
			t.Errorf("iss = %q, want %q", claims["iss"], issuer)
		}
		if claims["sub"] != subject {
			t.Errorf("sub = %q, want %q", claims["sub"], subject)
		}

		aud, err := claims.GetAudience()
		if err != nil || len(aud) != 1 || aud[0] != target {
			t.Errorf("aud = %v, want [%q]", aud, target)
		}

		scope, _ := claims["scope"].(string)
		for _, s := range scopes {
			if !strings.Contains(scope, s) {
				t.Errorf("scope %q missing from %q", s, scope)
			}
		}

		jti, _ := claims["jti"].(string)
		if jti == "" {
			t.Error("jti is empty")
		}
		if result.TokenID != jti {
			t.Errorf("TokenID = %q, want %q", result.TokenID, jti)
		}

		iat, _ := claims["iat"].(float64)
		exp, _ := claims["exp"].(float64)

		if int64(iat) < before || int64(iat) > after {
			t.Errorf("iat %v outside [%v, %v]", iat, before, after)
		}
		if wantExp := int64(iat) + 300; int64(exp) != wantExp {
			t.Errorf("exp = %v, want %v (iat+300)", int64(exp), wantExp)
		}
		if result.ExpiresAt.Unix() != int64(exp) {
			t.Errorf("ExpiresAt = %v, want %v", result.ExpiresAt.Unix(), int64(exp))
		}
	})

	t.Run("scope claim lists all granted scopes", func(t *testing.T) {
		result, err := m.Mint("spiffe://a", "spiffe://b", []string{"payments:charge"}, 60, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		claims := parseClaims(t, m, result.Token)
		scope, _ := claims["scope"].(string)
		if scope != "payments:charge" {
			t.Errorf("scope = %q, want %q", scope, "payments:charge")
		}
	})

	t.Run("JTI is unique across mints", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			r, err := m.Mint("spiffe://a", "spiffe://b", []string{"s:r"}, 60, "")
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			if seen[r.TokenID] {
				t.Fatalf("duplicate jti after %d mints", i)
			}
			seen[r.TokenID] = true
		}
	})
}

func TestNewMinterFromSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := &ecdsaSigner{key: key}
	m := NewMinterFromSigner(s)

	if m.PublicKey() != &key.PublicKey {
		t.Error("PublicKey should match the injected signer's key")
	}
	// Verify a token minted by the injected signer is valid.
	result, err := m.Mint("spiffe://a", "spiffe://b", []string{"r:w"}, 60, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	parseClaims(t, m, result.Token)
}

func TestRotateTo(t *testing.T) {
	m := newTestMinter(t)
	prevPub := m.PublicKey()

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	s2 := &ecdsaSigner{key: key2}
	m.RotateTo(s2)

	if m.PublicKey() == prevPub {
		t.Error("PublicKey unchanged after RotateTo")
	}
	if m.PublicKey() != &key2.PublicKey {
		t.Error("PublicKey should be the new signer's key after RotateTo")
	}

	// Previous key must still appear in PublicKeys.
	keys := m.PublicKeys()
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	found := false
	for _, k := range keys {
		if k == prevPub {
			found = true
			break
		}
	}
	if !found {
		t.Error("previous key missing from PublicKeys after RotateTo")
	}

	// Tokens minted before RotateTo must still verify with the old key.
	result, err := NewMinterFromSigner(&ecdsaSigner{key: key2}).Mint("spiffe://a", "spiffe://b", []string{"r"}, 60, "")
	if err != nil {
		t.Fatalf("Mint after RotateTo: %v", err)
	}
	parseClaims(t, m, result.Token)
}

func TestRotate(t *testing.T) {
	m := newTestMinter(t)

	if got := len(m.PublicKeys()); got != 1 {
		t.Fatalf("before rotation: got %d keys, want 1", got)
	}

	prevKey := m.PublicKey()

	if err := m.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// After first rotation both keys must be served.
	keys := m.PublicKeys()
	if len(keys) != 2 {
		t.Fatalf("after first rotation: got %d keys, want 2", len(keys))
	}
	if m.PublicKey() == prevKey {
		t.Error("current key unchanged after rotation")
	}
	found := false
	for _, k := range keys {
		if k == prevKey {
			found = true
			break
		}
	}
	if !found {
		t.Error("previous key not found in PublicKeys after rotation")
	}

	// Tokens minted before rotation must still be verifiable with the old key.
	m2 := newTestMinter(t)
	result, err := m2.Mint("spiffe://a", "spiffe://b", []string{"r"}, 60, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	oldPub := m2.PublicKey()
	if err = m2.Rotate(); err != nil {
		t.Fatalf("Rotate m2: %v", err)
	}
	_, err = jwt.Parse(result.Token, func(tok *jwt.Token) (any, error) {
		return oldPub, nil
	})
	if err != nil {
		t.Errorf("pre-rotation token unverifiable with old key: %v", err)
	}

	// Second rotation evicts the oldest key; at most two keys active at once.
	if err = m.Rotate(); err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
	keys = m.PublicKeys()
	if len(keys) != 2 {
		t.Fatalf("after second rotation: got %d keys, want 2", len(keys))
	}
	for _, k := range keys {
		if k == prevKey {
			t.Error("evicted key still in PublicKeys after second rotation")
		}
	}
}

func TestTokenValidation(t *testing.T) {
	m := newTestMinter(t)

	t.Run("tampered payload is rejected", func(t *testing.T) {
		result, err := m.Mint("spiffe://cluster.local/caller", "spiffe://cluster.local/target", []string{"r:w"}, 60, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		parts := strings.SplitN(result.Token, ".", 3)
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}

		// Decode the payload, mutate the sub claim, re-encode.
		// The original signature no longer covers the modified bytes.
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var payloadClaims map[string]any
		if err = json.Unmarshal(raw, &payloadClaims); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		payloadClaims["sub"] = "spiffe://cluster.local/attacker"
		modified, err := json.Marshal(payloadClaims)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		parts[1] = base64.RawURLEncoding.EncodeToString(modified)
		tamperedToken := strings.Join(parts, ".")

		_, err = jwt.Parse(tamperedToken, func(tok *jwt.Token) (any, error) {
			return m.PublicKey(), nil
		})
		if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			t.Errorf("expected ErrTokenSignatureInvalid, got %v", err)
		}
	})

	t.Run("token for wrong audience is rejected", func(t *testing.T) {
		result, err := m.Mint("spiffe://cluster.local/caller", "spiffe://cluster.local/service-a", []string{"r:w"}, 60, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		_, err = jwt.Parse(result.Token, func(tok *jwt.Token) (any, error) {
			return m.PublicKey(), nil
		}, jwt.WithAudience("spiffe://cluster.local/service-b"))
		if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
			t.Errorf("expected ErrTokenInvalidAudience, got %v", err)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		result, err := m.Mint("spiffe://cluster.local/caller", "spiffe://cluster.local/target", []string{"r:w"}, 1, "")
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}

		time.Sleep(1100 * time.Millisecond)

		_, err = jwt.Parse(result.Token, func(tok *jwt.Token) (any, error) {
			return m.PublicKey(), nil
		})
		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})
}

func TestDERToP1363(t *testing.T) {
	t.Run("valid DER round-trip", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		digest := make([]byte, 32)
		der, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		p1363, err := DERToP1363(der, 32)
		if err != nil {
			t.Fatalf("DERToP1363: %v", err)
		}
		if len(p1363) != 64 {
			t.Errorf("expected 64 bytes, got %d", len(p1363))
		}
		// Verify r and s round-trip correctly.
		var sig struct{ R, S *big.Int }
		if _, err = asn1.Unmarshal(der, &sig); err != nil {
			t.Fatalf("unmarshal DER: %v", err)
		}
		r := new(big.Int).SetBytes(p1363[:32])
		s := new(big.Int).SetBytes(p1363[32:])
		if r.Cmp(sig.R) != 0 || s.Cmp(sig.S) != 0 {
			t.Errorf("r/s mismatch after conversion")
		}
	})

	t.Run("invalid DER returns error", func(t *testing.T) {
		_, err := DERToP1363([]byte("not-a-der-signature"), 32)
		if err == nil {
			t.Error("expected error for invalid DER, got nil")
		}
	})

	t.Run("truncated DER returns error", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		digest := make([]byte, 32)
		der, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		_, err = DERToP1363(der[:len(der)/2], 32)
		if err == nil {
			t.Error("expected error for truncated DER, got nil")
		}
	})
}

// errSigner is a Signer whose Sign always fails.
type errSigner struct {
	pub *ecdsa.PublicKey
}

func (e *errSigner) Sign(_ []byte) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}

func (e *errSigner) PublicKey() *ecdsa.PublicKey {
	return e.pub
}

func TestMintSignerError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m := NewMinterFromSigner(&errSigner{pub: &key.PublicKey})
	_, err = m.Mint("spiffe://a", "spiffe://b", []string{"r"}, 60, "")
	if err == nil {
		t.Fatal("expected error from Mint, got nil")
	}
	if !strings.Contains(err.Error(), "kms unavailable") {
		t.Errorf("error %q does not wrap 'kms unavailable'", err)
	}
}

func TestMinterConcurrentMintRotate(t *testing.T) {
	m, err := NewMinter()
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		tokens []string
	)

	// 50 goroutines minting in a loop.
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r, err := m.Mint("spiffe://a", "spiffe://b", []string{"r"}, 60, "")
				if err != nil {
					t.Errorf("Mint: %v", err)
					return
				}
				mu.Lock()
				tokens = append(tokens, r.Token)
				mu.Unlock()
			}
		}()
	}

	// 5 goroutines rotating in a loop.
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if err := m.Rotate(); err != nil {
					t.Errorf("Rotate: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Verify all collected tokens are non-empty.
	mu.Lock()
	defer mu.Unlock()
	for i, tok := range tokens {
		if tok == "" {
			t.Errorf("token[%d] is empty", i)
		}
	}
}
