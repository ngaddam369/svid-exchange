package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	return NewMinterFromKey(key)
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
		result, err := m.Mint(subject, target, scopes, 300)
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
		result, err := m.Mint("spiffe://a", "spiffe://b", []string{"payments:charge"}, 60)
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
			r, err := m.Mint("spiffe://a", "spiffe://b", []string{"s:r"}, 60)
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
