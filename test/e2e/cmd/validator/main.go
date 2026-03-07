// Binary e2e-validator is a stub microservice used in the E2E test suite.
// It listens for a single HTTP request on /ping, validates the JWT in the
// Authorization: Bearer header against the svid-exchange JWKS endpoint, and
// exits 0 on success or 1 on any validation failure.
//
// Pass -healthcheck as the sole argument to perform a liveness probe (connects
// to the /healthz endpoint and exits 0 if reachable).
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/ngaddam369/svid-exchange/pkg/client"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		healthcheck()
		return
	}

	ctx := context.Background()
	jwksURL := envOr("JWKS_URL", "http://svid-exchange:8081/jwks")
	audience := envOr("AUDIENCE", "spiffe://cluster.local/ns/default/sa/e2e-validator")
	addr := envOr("ADDR", ":8888")
	requiredScope := envOr("REQUIRED_SCOPE", "e2e:ping")

	v, err := client.NewVerifier(ctx, jwksURL)
	if err != nil {
		fatalf("new verifier: %v", err)
	}

	// result holds the handler outcome so the main goroutine can exit with it.
	result := make(chan int, 1)

	srv := &http.Server{Addr: addr}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		code := handlePing(w, r, v, audience, requiredScope)
		// Shut down the server after responding so the process exits cleanly.
		go func() {
			if err := srv.Shutdown(context.Background()); err != nil {
				fmt.Fprintln(os.Stderr, "shutdown:", err)
			}
		}()
		result <- code
	})

	fmt.Printf("e2e-validator listening on %s\n", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatalf("listen: %v", err)
	}

	os.Exit(<-result)
}

// handlePing validates the Bearer JWT and returns an HTTP status code.
func handlePing(w http.ResponseWriter, r *http.Request, v *client.Verifier, audience, requiredScope string) int {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		fmt.Fprintln(os.Stderr, "missing or malformed Authorization header")
		return 1
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	claims, err := v.Verify(token, audience)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}

	if !client.HasScope(claims, requiredScope) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		fmt.Fprintf(os.Stderr, "token missing required scope %q\n", requiredScope)
		return 1
	}

	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, "OK"); err != nil {
		fmt.Fprintln(os.Stderr, "write response:", err)
	}
	fmt.Printf("validation OK: audience=%s scope=%s\n", audience, requiredScope)
	return 0
}

// healthcheck connects to the local /healthz endpoint and exits 0 if reachable.
func healthcheck() {
	addr := envOr("ADDR", ":8888")
	resp, err := http.Get("http://localhost" + addr + "/healthz")
	if err != nil {
		os.Exit(1)
	}
	if err := resp.Body.Close(); err != nil {
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "e2e-validator: "+format+"\n", args...)
	os.Exit(1)
}
