# Client Library

`pkg/client` handles the client side of the svid-exchange token flow. Without it, every service that calls svid-exchange has to implement token acquisition, caching, and header injection independently — and get the edge cases (expiry races, thundering herd on refresh, stale tokens) right on its own. The library provides one correct implementation of all three.

No new dependencies are needed. The package uses the same `go-spiffe/v2`, `grpc`, and `golang-jwt/jwt/v5` entries already in `go.mod`.

---

## Caller side — `Client`

`Client` covers three responsibilities: authenticating to svid-exchange, caching the returned token, and injecting it into outgoing gRPC calls.

**Authentication.** In production, `New` connects to svid-exchange over SPIFFE mTLS by fetching an X509-SVID from the local SPIRE Agent via the Workload API — the same mechanism the server itself uses. The Workload API socket is read from `Options.SpiffeSocket`, falling back to the `SPIFFE_ENDPOINT_SOCKET` environment variable.

**Caching.** Once a token is obtained, `Token` returns it from the in-memory cache on every subsequent call. A new exchange RPC is made only when the cached token has consumed 80% of its TTL (i.e. `refreshAt = expiresAt − ttl/5`). For a 300-second token this triggers refresh after 240 seconds — early enough to absorb a slow RPC or a brief network hiccup before the token actually expires. Concurrent callers are serialised behind a mutex: only one exchange call is ever in flight at a time, so there is no thundering herd.

**Background refresh.** `New` starts a background goroutine that wakes near `refreshAt` and proactively calls `Exchange` before any caller needs the token. If the service is idle for a long period and the cached token approaches its refresh window, the goroutine refreshes it silently — the next real RPC returns immediately from cache with no Exchange round-trip added to its latency. The goroutine is stopped automatically by `Close`.

**Token delegation.** Set `OnBehalfOf` in `Options` to a JWT previously obtained by the service (e.g. from an end-user login flow). The resulting token carries an `act` claim per RFC 8693: `sub` identifies the delegating service (authenticated via mTLS as usual) and `act.sub` carries the subject extracted from the `on_behalf_of` JWT. Downstream services can read both fields to see who is calling and for whom they are acting. Omitting `OnBehalfOf` gives the normal service-to-service behaviour with no `act` claim.

**gRPC injection.** `GRPCCredentials` returns a `credentials.PerRPCCredentials` value. Passing it to `grpc.NewClient` via `grpc.WithPerRPCCredentials` causes the gRPC transport to call `Token` before every outgoing RPC and attach the result as an `Authorization: Bearer` header automatically.

**HTTP injection.** `NewHTTPTransport` returns an `http.RoundTripper` that does the same for HTTP callers. Set it as the `Transport` field of an `http.Client` and every request will carry a fresh (or cached) token without any per-request code. Passing `nil` as the base transport uses `http.DefaultTransport`. The original request is never mutated — `NewHTTPTransport` clones it before setting the header, as required by the `http.RoundTripper` contract.

---

## Receiver side — `Verifier`

`Verifier` covers the other end: validating the JWTs that arrive at a service. It fetches the server's JWKS document on construction and caches the signing public keys. `Verify` checks the signature, expiry, audience, and issuer claims against those keys and returns the parsed claims on success.

During a signing key rotation the server publishes two keys simultaneously — the current key and the one it just replaced. `Verify` tries all cached keys, so tokens signed by either remain valid throughout the rotation window. After a rotation completes, call `Refresh` to drop the old key and pick up only the new one without restarting the process.

**Auto-refresh.** `StartAutoRefresh(ctx, interval)` starts a background goroutine that calls `Refresh` on every tick of the given interval. Pass an interval that matches or is shorter than the server's `key_rotation_interval` and key rotations are handled transparently — no manual `Refresh` calls needed. Transient JWKS errors are suppressed and the cached keys remain valid until the next successful refresh. The goroutine exits when ctx is cancelled.

**HTTP server middleware.** `NewMiddleware` wraps any `http.Handler` and validates the JWT on every request before passing it through. It extracts the token from the `Authorization: Bearer` header, calls `Verify`, and on success stores the parsed claims in the request context. On any failure — missing header, wrong prefix, bad signature, wrong audience, expired — it responds 401 and the inner handler is never called. Use `ClaimsFromContext` to retrieve the claims inside the handler. Error details are intentionally not included in the 401 response to avoid leaking internal information.

**Scope helpers.** `HasScope(claims, scope)` and `HasAllScopes(claims, scopes)` parse the space-delimited `scope` claim from `jwt.MapClaims` and report whether the token carries the required permission. Without them, every handler that gates on a scope has to split the claim string and iterate manually. `HasAllScopes` returns `true` when the scopes list is empty.

---

## Scope of this library

`pkg/client` is intentionally limited to the token consumption flow. It does not expose any capability to create, delete, or reload policies. That is a deliberate boundary.

Policy management changes the authorization rules of the entire system and belongs exclusively to platform or security teams — typically applied through deployment pipelines or operational tooling, not by the services themselves. Bundling policy management into the same client that every workload imports would mean any compromised service could potentially widen its own permissions. The admin API (`:8082`) is a separate, network-restricted endpoint for exactly this reason; workloads only need a path to the exchange endpoint (`:8080`).

If you need to manage policies programmatically, use the admin gRPC stubs directly in a purpose-built admin tool, scoped to operators. See [API Reference](api-reference.md) for the admin service definition.

---

## Cloud IAM Federation

Once a workload holds a JWT from svid-exchange it can go further and exchange it for native cloud credentials — all without storing any long-lived secrets.

`AssumeRoleWithJWT(ctx, jwt, roleARN, sessionName)` calls AWS STS `AssumeRoleWithWebIdentity` and returns an `AWSCredentials` struct containing the temporary `AccessKeyID`, `SecretAccessKey`, `SessionToken`, and `Expiration`. The JWT is the only credential required; no long-term AWS access keys are needed. The role must be configured to trust the svid-exchange issuer as a web identity provider.

`ExchangeForGCPToken(ctx, jwt, audience, serviceAccount, scopes)` uses GCP Workload Identity Federation to exchange the JWT for a GCP access token. `audience` is the workload identity pool provider resource name. If `serviceAccount` is non-empty, the federated token is used to impersonate that service account and its access token is returned; otherwise the federated token itself is returned. Scopes are the standard OAuth2 scopes the token should carry (e.g. `https://www.googleapis.com/auth/cloud-platform`).

---

## Testing

The production constructor (`New`) requires a live SPIRE Agent and a reachable svid-exchange server. Tests bypass both by wiring a mock directly to the unexported `exchanger` interface inside `package client`. The mock returns synthetic `ExchangeResponse` values and counts how many times `Exchange` was called, letting tests observe caching and refresh behaviour through the public `Token` API without touching any internal state.

For `Verifier` tests, an `httptest.NewServer` serves a synthetic JWKS document built from a real `token.Minter` public key, so the full signature verification path runs with no network dependency.
