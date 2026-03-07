package client

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestHasScope(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		scope  string
		want   bool
	}{
		{
			name:   "single scope present",
			claims: jwt.MapClaims{"scope": "read"},
			scope:  "read",
			want:   true,
		},
		{
			name:   "one of multiple scopes",
			claims: jwt.MapClaims{"scope": "read write"},
			scope:  "write",
			want:   true,
		},
		{
			name:   "scope absent",
			claims: jwt.MapClaims{"scope": "read"},
			scope:  "write",
			want:   false,
		},
		{
			name:   "scope claim missing",
			claims: jwt.MapClaims{},
			scope:  "read",
			want:   false,
		},
		{
			name:   "scope claim wrong type",
			claims: jwt.MapClaims{"scope": 42},
			scope:  "read",
			want:   false,
		},
		{
			name:   "partial match not counted",
			claims: jwt.MapClaims{"scope": "read"},
			scope:  "rea",
			want:   false,
		},
		{
			name:   "extra whitespace handled",
			claims: jwt.MapClaims{"scope": "read  write"},
			scope:  "write",
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasScope(tc.claims, tc.scope); got != tc.want {
				t.Errorf("HasScope(%v, %q) = %v, want %v", tc.claims, tc.scope, got, tc.want)
			}
		})
	}
}

func TestHasAllScopes(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		scopes []string
		want   bool
	}{
		{
			name:   "all scopes present",
			claims: jwt.MapClaims{"scope": "read write delete"},
			scopes: []string{"read", "write"},
			want:   true,
		},
		{
			name:   "one scope missing",
			claims: jwt.MapClaims{"scope": "read write"},
			scopes: []string{"read", "delete"},
			want:   false,
		},
		{
			name:   "empty scopes list",
			claims: jwt.MapClaims{"scope": "read"},
			scopes: []string{},
			want:   true,
		},
		{
			name:   "all scopes missing",
			claims: jwt.MapClaims{"scope": "read"},
			scopes: []string{"write", "delete"},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasAllScopes(tc.claims, tc.scopes); got != tc.want {
				t.Errorf("HasAllScopes(%v, %v) = %v, want %v", tc.claims, tc.scopes, got, tc.want)
			}
		})
	}
}
