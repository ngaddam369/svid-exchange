// Binary e2e-caller is a stub microservice used in the E2E test suite.
// It runs the following scenarios end-to-end against the live Docker Compose
// stack and exits 0 only when every scenario passes:
//
//  1. happy path      — exchange SVID for JWT, validate via e2e-validator HTTP
//  2. delegation      — on_behalf_of JWT sets act.sub in minted token
//  3. policy denial   — disallowed scope returns PermissionDenied
//  4. scope filter    — requesting a superset of allowed scopes returns only the
//     policy-permitted subset
//  5. health endpoint — /health/ready returns 200
//  6. metrics         — /metrics serves grpc_server_ counters
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

func main() {
	ctx := context.Background()

	socket := envOr("SPIFFE_ENDPOINT_SOCKET", "unix:///opt/spire/sockets/agent.sock")
	exchangeAddr := envOr("EXCHANGE_ADDR", "svid-exchange:8080")
	validatorURL := envOr("VALIDATOR_URL", "http://e2e-validator:8888/ping")
	callerSPIFFEID := envOr("CALLER_SPIFFE_ID", "spiffe://cluster.local/ns/default/sa/e2e-caller")
	targetSPIFFEID := envOr("TARGET_SPIFFE_ID", "spiffe://cluster.local/ns/default/sa/e2e-validator")
	healthURL := envOr("HEALTH_URL", "http://svid-exchange:8081/health/ready")
	metricsURL := envOr("METRICS_URL", "http://svid-exchange:8081/metrics")

	// ── Workload API: fetch all SVIDs and trust bundles ─────────────────────
	wlClient, err := workloadapi.New(ctx, workloadapi.WithAddr(socket))
	if err != nil {
		fatalf("new workload client: %v", err)
	}
	defer func() {
		if err := wlClient.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close workload client:", err)
		}
	}()

	x509ctx, err := wlClient.FetchX509Context(ctx)
	if err != nil {
		fatalf("fetch X509 context: %v", err)
	}

	// Find the SVID for the e2e-caller identity.
	callerID, err := spiffeid.FromString(callerSPIFFEID)
	if err != nil {
		fatalf("parse caller SPIFFE ID: %v", err)
	}
	var callerSVID *x509svid.SVID
	for _, svid := range x509ctx.SVIDs {
		if svid.ID == callerID {
			callerSVID = svid
			break
		}
	}
	if callerSVID == nil {
		fatalf("SVID %q not found (got %d SVIDs)", callerSPIFFEID, len(x509ctx.SVIDs))
	}

	// ── mTLS gRPC connection ─────────────────────────────────────────────────
	tlsCfg := tlsconfig.MTLSClientConfig(
		fixedSVIDSource{callerSVID},
		x509ctx.Bundles,
		tlsconfig.AuthorizeAny(),
	)
	tlsCfg.MinVersion = tls.VersionTLS13

	conn, err := grpc.NewClient(exchangeAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		fatalf("dial svid-exchange: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close grpc conn:", err)
		}
	}()

	excClient := exchangev1.NewTokenExchangeClient(conn)

	// ── Run scenarios ────────────────────────────────────────────────────────
	run("happy path", testHappyPath(ctx, excClient, targetSPIFFEID, validatorURL))
	run("delegation: on_behalf_of sets act.sub", testDelegation(ctx, excClient, targetSPIFFEID))
	run("policy denial: disallowed scope", testPolicyDenial(ctx, excClient, targetSPIFFEID))
	run("scope filter: superset request returns allowed subset", testScopeFilter(ctx, excClient, targetSPIFFEID))
	run("health endpoint", testHTTPOK(healthURL, ""))
	run("metrics endpoint", testHTTPOK(metricsURL, "grpc_server_started_total"))

	fmt.Println("E2E OK — all scenarios passed")
}

// ── Scenario implementations ────────────────────────────────────────────────

// testHappyPath exchanges the caller SVID for a JWT, then calls the validator
// HTTP service and expects a 200 response.
func testHappyPath(ctx context.Context, c exchangev1.TokenExchangeClient, target, validatorURL string) error {
	resp, err := c.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: target,
		Scopes:        []string{"e2e:ping"},
		TtlSeconds:    60,
	})
	if err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	fmt.Printf("  token_id=%s granted_scopes=%v\n", resp.TokenId, resp.GrantedScopes)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validatorURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+resp.Token)

	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("call validator: %w", err)
	}
	defer func() {
		if err := httpResp.Body.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close body:", err)
		}
	}()

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("validator returned %d, want 200", httpResp.StatusCode)
	}
	return nil
}

// testDelegation exchanges with on_behalf_of set to a valid server-minted JWT,
// then decodes the returned JWT payload to confirm act.sub is present.
// on_behalf_of must be a JWT signed by the server's own key — a fake or
// unsigned token is rejected with InvalidArgument.
func testDelegation(ctx context.Context, c exchangev1.TokenExchangeClient, target string) error {
	// Obtain a valid server-minted JWT to use as the on_behalf_of token.
	first, err := c.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: target,
		Scopes:        []string{"e2e:ping"},
		TtlSeconds:    300,
	})
	if err != nil {
		return fmt.Errorf("initial exchange for obo token: %w", err)
	}

	// Exchange again with the first JWT as on_behalf_of. The minted token must
	// carry act.sub set to the sub from the delegated token.
	resp, err := c.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: target,
		Scopes:        []string{"e2e:ping"},
		TtlSeconds:    60,
		OnBehalfOf:    first.Token,
	})
	if err != nil {
		return fmt.Errorf("exchange with on_behalf_of: %w", err)
	}

	// Decode the minted JWT payload to verify the act claim.
	claims, err := decodeJWTPayload(resp.Token)
	if err != nil {
		return fmt.Errorf("decode JWT payload: %w", err)
	}
	actClaim, ok := claims["act"].(map[string]any)
	if !ok {
		return fmt.Errorf("act claim missing or wrong type in JWT payload")
	}
	actSub, ok := actClaim["sub"].(string)
	if !ok || actSub == "" {
		return fmt.Errorf("act.sub = %q, want non-empty", actSub)
	}
	fmt.Printf("  act.sub=%s\n", actSub)
	return nil
}

// testPolicyDenial requests a scope that is not in the policy and expects
// PermissionDenied.
func testPolicyDenial(ctx context.Context, c exchangev1.TokenExchangeClient, target string) error {
	_, err := c.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: target,
		Scopes:        []string{"e2e:notallowed"},
		TtlSeconds:    60,
	})
	if status.Code(err) != codes.PermissionDenied {
		return fmt.Errorf("expected PermissionDenied, got %v (err=%v)", status.Code(err), err)
	}
	fmt.Printf("  correctly denied: %v\n", status.Code(err))
	return nil
}

// testScopeFilter requests a superset of the allowed scopes and verifies that
// only the policy-permitted scopes are granted in the response.
func testScopeFilter(ctx context.Context, c exchangev1.TokenExchangeClient, target string) error {
	resp, err := c.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: target,
		Scopes:        []string{"e2e:ping", "e2e:extra"},
		TtlSeconds:    60,
	})
	if err != nil {
		return fmt.Errorf("exchange: %w", err)
	}
	if len(resp.GrantedScopes) != 1 || resp.GrantedScopes[0] != "e2e:ping" {
		return fmt.Errorf("granted_scopes = %v, want [e2e:ping]", resp.GrantedScopes)
	}
	fmt.Printf("  granted_scopes=%v (e2e:extra correctly filtered)\n", resp.GrantedScopes)
	return nil
}

// testHTTPOK GETs url and returns an error if the status is not 200 or if
// mustContain is set and is not present in the response body.
func testHTTPOK(url, mustContain string) error {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close body:", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	if mustContain != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		if !strings.Contains(string(body), mustContain) {
			return fmt.Errorf("GET %s: body does not contain %q", url, mustContain)
		}
		fmt.Printf("  %s: found %q\n", url, mustContain)
	}
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// decodeJWTPayload base64url-decodes the payload segment of a JWT and returns
// the parsed claims. The signature is not verified.
func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	return claims, json.Unmarshal(payload, &claims)
}

func run(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL [%s]: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("PASS [%s]\n", name)
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "e2e-caller: "+format+"\n", args...)
	os.Exit(1)
}

// fixedSVIDSource implements x509svid.Source for a single pre-selected SVID.
type fixedSVIDSource struct{ svid *x509svid.SVID }

func (s fixedSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }
