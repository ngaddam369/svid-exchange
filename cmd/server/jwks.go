package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// jwkKey is a single JSON Web Key (RFC 7517).
type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

// jwkSet is the JWKS document returned by /jwks.
type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

// newJWKSHandler builds an http.HandlerFunc that serves the public key as a
// JWKS document. The response body is computed once at startup and reused for
// every request. kid is the RFC 7638 SHA-256 thumbprint of the key.
func newJWKSHandler(pub *ecdsa.PublicKey) (http.HandlerFunc, error) {
	// pub.Bytes() returns the uncompressed point: 0x04 || X || Y.
	// Each coordinate is byteLen bytes (32 for P-256).
	raw, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	byteLen := (len(raw) - 1) / 2
	x := base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
	y := base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])

	// RFC 7638: thumbprint = SHA-256 of canonical JSON with members in
	// lexicographic order: crv, kty, x, y.
	type thumbInput struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	thumbJSON, err := json.Marshal(thumbInput{Crv: "P-256", Kty: "EC", X: x, Y: y})
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS thumbprint: %w", err)
	}
	sum := sha256.Sum256(thumbJSON)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	body, err := json.Marshal(jwkSet{Keys: []jwkKey{{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Alg: "ES256",
		Use: "sig",
		Kid: kid,
	}}})
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS body: %w", err)
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(body)
		_ = err // response write errors are not actionable in a handler
	}, nil
}
