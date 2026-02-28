// Package token mints ES256 JWTs for granted exchange results.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	issuer    = "svid-exchange"
	maxTTLCap = 3600 // hard ceiling: 1 hour regardless of policy
)

// Minter signs JWTs with an ES256 private key.
type Minter struct {
	key *ecdsa.PrivateKey
}

// NewMinter generates an ephemeral ES256 key pair. In production, load the key
// from a secrets manager or KMS (see TODO.md — Key Management).
func NewMinter() (*Minter, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &Minter{key: key}, nil
}

// NewMinterFromKey creates a Minter using an existing key (for tests).
func NewMinterFromKey(key *ecdsa.PrivateKey) *Minter {
	return &Minter{key: key}
}

// PublicKey returns the public key for JWKS serving.
func (m *Minter) PublicKey() *ecdsa.PublicKey {
	return &m.key.PublicKey
}

// MintResult holds the signed token and its metadata.
type MintResult struct {
	Token         string
	TokenID       string
	ExpiresAt     time.Time
	GrantedScopes []string
}

// Mint signs a JWT for the given subject/target/scopes/ttl.
// ttlSeconds is capped to maxTTLCap.
func (m *Minter) Mint(subject, target string, scopes []string, ttlSeconds int32) (MintResult, error) {
	if ttlSeconds <= 0 || ttlSeconds > maxTTLCap {
		ttlSeconds = maxTTLCap
	}

	jti := uuid.New().String()
	now := time.Now().UTC()
	exp := now.Add(time.Duration(ttlSeconds) * time.Second)

	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   subject,
		"aud":   []string{target},
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   exp.Unix(),
		"jti":   jti,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(m.key)
	if err != nil {
		return MintResult{}, fmt.Errorf("sign token: %w", err)
	}

	return MintResult{
		Token:         signed,
		TokenID:       jti,
		ExpiresAt:     exp,
		GrantedScopes: scopes,
	}, nil
}
