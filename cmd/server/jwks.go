package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

// keyProvider returns the set of currently active public signing keys.
// During a rotation window more than one key may be active.
type keyProvider interface {
	PublicKeys() []*ecdsa.PublicKey
}

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

// newJWKSHandler returns an http.HandlerFunc that serves all active public keys
// as a JWKS document. The response is computed on each request so that key
// rotations are reflected immediately without a server restart.
func newJWKSHandler(kp keyProvider, log zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		set := jwkSet{Keys: make([]jwkKey, 0)}
		for _, pub := range kp.PublicKeys() {
			k, err := pubToJWK(pub)
			if err != nil {
				log.Error().Err(err).Msg("jwks: build key entry")
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			set.Keys = append(set.Keys, k)
		}
		body, err := json.Marshal(set)
		if err != nil {
			log.Error().Err(err).Msg("jwks: marshal response")
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err = w.Write(body); err != nil {
			log.Error().Err(err).Msg("jwks: write response")
		}
	}
}

// pubToJWK converts an ECDSA P-256 public key to a JSON Web Key.
// kid is the RFC 7638 SHA-256 thumbprint of the key.
func pubToJWK(pub *ecdsa.PublicKey) (jwkKey, error) {
	// pub.Bytes() returns the uncompressed point: 0x04 || X || Y.
	// Each coordinate is byteLen bytes (32 for P-256).
	raw, err := pub.Bytes()
	if err != nil {
		return jwkKey{}, fmt.Errorf("encode public key: %w", err)
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
		return jwkKey{}, fmt.Errorf("marshal thumbprint: %w", err)
	}
	sum := sha256.Sum256(thumbJSON)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	return jwkKey{
		Kty: "EC",
		Crv: "P-256",
		X:   x,
		Y:   y,
		Alg: "ES256",
		Use: "sig",
		Kid: kid,
	}, nil
}
