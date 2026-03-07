package client

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// HasScope reports whether claims contains scope in the space-delimited
// "scope" claim. Returns false if the claim is absent or not a string.
func HasScope(claims jwt.MapClaims, scope string) bool {
	raw, ok := claims["scope"].(string)
	if !ok {
		return false
	}
	for _, s := range strings.Fields(raw) {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether claims contains every scope in scopes.
// Returns true when scopes is empty.
func HasAllScopes(claims jwt.MapClaims, scopes []string) bool {
	for _, s := range scopes {
		if !HasScope(claims, s) {
			return false
		}
	}
	return true
}
