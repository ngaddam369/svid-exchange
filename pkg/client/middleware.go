package client

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey struct{}

// NewMiddleware returns an [http.Handler] that validates the JWT in the
// Authorization: Bearer header of every request using v. On success the
// parsed claims are stored in the request context and next is called.
// On failure a 401 Unauthorized response is written and next is not called.
func NewMiddleware(v *Verifier, audience string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(token, audience)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
	})
}

// ClaimsFromContext returns the [jwt.MapClaims] stored by [NewMiddleware] in ctx.
// The second return value is false if ctx was not produced by [NewMiddleware].
func ClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(contextKey{}).(jwt.MapClaims)
	return claims, ok
}
