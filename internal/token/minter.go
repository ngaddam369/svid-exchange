// Package token mints ES256 JWTs for granted exchange results.
package token

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const issuer = "svid-exchange"

// KeyID returns the RFC 7638 SHA-256 thumbprint of pub encoded as a base64url
// string. This is used as the "kid" header in minted JWTs and as the key ID
// in the JWKS document.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	const p256Len = 65
	if len(raw) != p256Len || raw[0] != 0x04 {
		return "", fmt.Errorf("unexpected P-256 point: got %d bytes with prefix 0x%02x", len(raw), raw[0])
	}
	byteLen := (len(raw) - 1) / 2
	x := base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
	y := base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])
	type thumbInput struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	thumbJSON, err := json.Marshal(thumbInput{Crv: "P-256", Kty: "EC", X: x, Y: y})
	if err != nil {
		return "", fmt.Errorf("marshal thumbprint: %w", err)
	}
	sum := sha256.Sum256(thumbJSON)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Minter signs JWTs using a Signer and supports key rotation.
// The zero value is not usable; use NewMinter or NewMinterFromSigner.
type Minter struct {
	mu       sync.RWMutex
	current  Signer
	previous Signer
}

// NewMinter creates a Minter backed by a freshly generated ephemeral ES256
// key pair. The private key lives in process memory. For environments that
// require the private key to never leave a hardware boundary, use
// NewMinterFromSigner with a KMS-backed Signer implementation instead.
func NewMinter() (*Minter, error) {
	s, err := newECDSASigner()
	if err != nil {
		return nil, err
	}
	return NewMinterFromSigner(s), nil
}

// NewMinterFromSigner creates a Minter that signs JWTs with the provided
// Signer. Use this to plug in an AWS KMS, GCP Cloud KMS, or Vault Transit
// backend — the rest of the service (JWKS, rotation, Exchange) is unaffected.
func NewMinterFromSigner(s Signer) *Minter {
	return &Minter{current: s}
}

// PublicKey returns the current signing public key.
func (m *Minter) PublicKey() *ecdsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current.PublicKey()
}

// PublicKeys returns all currently active public keys. During a rotation
// window both the current key and the immediately preceding key are returned
// so that tokens signed before the rotation remain verifiable.
func (m *Minter) PublicKeys() []*ecdsa.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.previous == nil {
		return []*ecdsa.PublicKey{m.current.PublicKey()}
	}
	return []*ecdsa.PublicKey{m.current.PublicKey(), m.previous.PublicKey()}
}

// Rotate generates a new ephemeral ES256 signing key and promotes the current
// key to previous. Intended for in-process signing; for KMS-backed signers use
// RotateTo with the new signer pointing at the new key version.
func (m *Minter) Rotate() error {
	s, err := newECDSASigner()
	if err != nil {
		return err
	}
	m.RotateTo(s)
	return nil
}

// RotateTo replaces the current Signer with s. The current Signer is retained
// as previous for one rotation window so that tokens issued before the rotation
// remain verifiable via PublicKeys. Use this for KMS-managed key rotation:
// create a Signer pointing at the new KMS key version, then call RotateTo.
func (m *Minter) RotateTo(s Signer) {
	m.mu.Lock()
	m.previous = m.current
	m.current = s
	m.mu.Unlock()
}

// MintResult holds the signed token and its metadata.
type MintResult struct {
	Token         string
	TokenID       string
	ExpiresAt     time.Time
	GrantedScopes []string
}

// Mint signs a JWT for the given subject/target/scopes/ttl.
// The JWT is constructed manually so that any Signer backend — local key or
// KMS — can provide the signature without access to the private key bytes.
// ttlSeconds must be positive; the policy layer enforces the ceiling.
func (m *Minter) Mint(subject, target string, scopes []string, ttlSeconds int32, actSubject string) (MintResult, error) {
	m.mu.RLock()
	signer := m.current
	m.mu.RUnlock()

	kid, err := KeyID(signer.PublicKey())
	if err != nil {
		return MintResult{}, fmt.Errorf("compute key id: %w", err)
	}
	headerBytes, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{"ES256", "JWT", kid})
	if err != nil {
		return MintResult{}, fmt.Errorf("marshal jwt header: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)

	jti := uuid.New().String()
	now := time.Now().UTC()
	exp := now.Add(time.Duration(ttlSeconds) * time.Second)

	claims := map[string]any{
		"iss":   issuer,
		"sub":   subject,
		"aud":   []string{target},
		"scope": strings.Join(scopes, " "),
		"iat":   now.Unix(),
		"exp":   exp.Unix(),
		"jti":   jti,
	}
	if actSubject != "" {
		claims["act"] = map[string]any{"sub": actSubject}
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return MintResult{}, fmt.Errorf("marshal claims: %w", err)
	}

	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingString := header + "." + payload
	digest := sha256.Sum256([]byte(signingString))

	sig, err := signer.Sign(digest[:])
	if err != nil {
		return MintResult{}, fmt.Errorf("sign token: %w", err)
	}

	signed := signingString + "." + base64.RawURLEncoding.EncodeToString(sig)
	return MintResult{
		Token:         signed,
		TokenID:       jti,
		ExpiresAt:     exp,
		GrantedScopes: scopes,
	}, nil
}

// VerifyJWT validates an ES256 JWT produced by this service and returns its
// sub claim. The signature must match at least one of the provided public keys,
// the token must not be expired, and its issuer must be "svid-exchange".
// Audience is intentionally not checked: on_behalf_of tokens were issued for
// an intermediate service, not for svid-exchange.
func VerifyJWT(raw string, keys []*ecdsa.PublicKey) (string, error) {
	if len(keys) == 0 {
		return "", fmt.Errorf("no signing keys available")
	}
	var lastErr error
	for _, key := range keys {
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %q", t.Header["alg"])
			}
			return key, nil
		}, jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
		if err != nil {
			lastErr = err
			continue
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok || !tok.Valid {
			lastErr = fmt.Errorf("invalid token claims")
			continue
		}
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			return "", fmt.Errorf("JWT has no sub claim")
		}
		return sub, nil
	}
	return "", lastErr
}
