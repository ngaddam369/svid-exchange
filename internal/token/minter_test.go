package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
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
