// Package token mints ES256 JWTs for granted exchange results.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const issuer = "svid-exchange"

// Minter signs JWTs with an ES256 private key and supports key rotation.
// The zero value is not usable; use NewMinter.
type Minter struct {
	mu       sync.RWMutex
	current  *ecdsa.PrivateKey
	previous *ecdsa.PrivateKey
}

// NewMinter generates an ephemeral ES256 key pair. In production, load the key
// from a secrets manager or KMS.
func NewMinter() (*Minter, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &Minter{current: key}, nil
}

// PublicKey returns the current signing public key.
func (m *Minter) PublicKey() *ecdsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.current.PublicKey
}

// PublicKeys returns all currently active public keys. During a rotation
// window both the current key and the immediately preceding key are returned
// so that tokens signed before the rotation remain verifiable.
func (m *Minter) PublicKeys() []*ecdsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.previous == nil {
		return []*ecdsa.PublicKey{&m.current.PublicKey}
	}
	return []*ecdsa.PublicKey{&m.current.PublicKey, &m.previous.PublicKey}
}

// Rotate generates a new signing key. The current key is retained as the
// previous key so tokens signed before the rotation remain verifiable via
// PublicKeys() until the next rotation.
func (m *Minter) Rotate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	m.mu.Lock()
	m.previous = m.current
	m.current = key
	m.mu.Unlock()
	return nil
}

// MintResult holds the signed token and its metadata.
type MintResult struct {
	Token         string
	TokenID       string
	ExpiresAt     time.Time
	GrantedScopes []string
}

// Mint signs a JWT for the given subject/target/scopes/ttl with the current key.
// ttlSeconds must be positive; the policy layer is responsible for enforcing the ceiling.
func (m *Minter) Mint(subject, target string, scopes []string, ttlSeconds int32) (MintResult, error) {
	m.mu.RLock()
	key := m.current
	m.mu.RUnlock()

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
	signed, err := tok.SignedString(key)
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
