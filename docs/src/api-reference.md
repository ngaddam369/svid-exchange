# API Reference

## gRPC service

**Service:** `exchange.v1.TokenExchange`

**Address:** `:8080` (configurable via `GRPC_ADDR`)

**Transport:** mTLS required — connections without a valid SPIRE-issued client certificate are rejected at the transport layer.

### Exchange

Validates the caller's SPIFFE identity, evaluates policy, and mints a scoped JWT.

```protobuf
rpc Exchange(ExchangeRequest) returns (ExchangeResponse);
```

#### ExchangeRequest

| Field | Type | Description |
|-------|------|-------------|
| `target_service` | string | SPIFFE ID of the target service |
| `scopes` | repeated string | Permission scopes being requested |
| `ttl_seconds` | int32 | Requested token lifetime in seconds; capped to the policy `max_ttl` |

#### ExchangeResponse

| Field | Type | Description |
|-------|------|-------------|
| `token` | string | Signed ES256 JWT |
| `expires_at` | int64 | Token expiration as a Unix timestamp |
| `granted_scopes` | repeated string | Scopes actually granted (policy-limited subset of requested) |
| `token_id` | string | JWT `jti` claim — unique identifier for this token |

#### gRPC status codes

| Code | Condition |
|------|-----------|
| `OK` | Exchange successful |
| `UNAUTHENTICATED` | No valid SPIFFE ID found in the peer certificate |
| `INVALID_ARGUMENT` | `target_service` is empty, or no scopes were requested |
| `PERMISSION_DENIED` | No policy permits this subject → target exchange, or the minted token ID has been revoked |
| `ALREADY_EXISTS` | The minted token ID was already issued (replay detected) |
| `RESOURCE_EXHAUSTED` | Per-identity rate limit exceeded (only when `RATE_LIMIT_RPS` is set) |
| `INTERNAL` | JWT signing failed (should not occur in normal operation) |

#### Example (grpcurl)

```bash
# Replace svid.N with the index for the 'order' workload.
# See Getting Started for how to identify the correct index.
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.N.pem \
  -key  /tmp/svid/svid.N.key \
  -d '{
    "target_service": "spiffe://cluster.local/ns/default/sa/payment",
    "scopes": ["payments:charge"],
    "ttl_seconds": 300
  }' \
  localhost:8080 exchange.v1.TokenExchange/Exchange
```

---

## HTTP endpoints

**Address:** `:8081` (configurable via `HEALTH_ADDR`)
**Transport:** plain HTTP — intended for internal infrastructure use only (health checks, key distribution, metrics scraping).

### GET /health/live

Liveness probe. Returns `200 OK` as long as the process is running.

```bash
curl http://localhost:8081/health/live
```

### GET /health/ready

Readiness probe. Returns `200 OK` when the service is ready to handle requests, `503 Service Unavailable` during shutdown.

```bash
curl http://localhost:8081/health/ready
```

### GET /metrics

Prometheus text exposition. Returns gRPC server metrics (`grpc_server_*` family) for scraping by Prometheus or any compatible collector. See [Configuration](configuration.md#prometheus-metrics) for the full metric list.

```bash
curl http://localhost:8081/metrics | grep "^grpc_server"
```

### GET /jwks

Returns the public signing key as a JSON Web Key Set (JWKS). Downstream services use this to verify the signature on JWTs issued by svid-exchange without any out-of-band key distribution.

The response body is computed once at startup from the minter's public key and reused for every request. The `kid` field is the RFC 7638 SHA-256 thumbprint of the key.

```bash
curl http://localhost:8081/jwks
```

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>",
      "alg": "ES256",
      "use": "sig",
      "kid": "<base64url SHA-256 thumbprint>"
    }
  ]
}
```

## JWT claims

Tokens minted by svid-exchange carry the following claims:

| Claim | Value |
|-------|-------|
| `iss` | `svid-exchange` |
| `sub` | Caller's SPIFFE ID |
| `aud` | Target service's SPIFFE ID (array) |
| `scope` | Space-separated granted scopes |
| `iat` | Issued-at timestamp |
| `exp` | Expiration timestamp |
| `jti` | Unique token ID (UUID) |

## JWT validation (target service)

Target services must validate every incoming token. The following checks are required:

| Check | Value to expect |
|-------|----------------|
| Signature | ES256 via the public key from `/jwks`; reject any other algorithm |
| `iss` | `svid-exchange` |
| `aud` | Must contain the target's own SPIFFE ID |
| `exp` | Must be in the future |
| `scope` | Space-separated; check that the required scope is present |

### Fetching the public key

Poll `/jwks` at startup and cache the response. Refresh when signature verification fails with an unknown `kid` — this covers key rotation without a fixed TTL.

```bash
curl http://svid-exchange:8081/jwks
```

The `kid` field (RFC 7638 SHA-256 thumbprint) uniquely identifies the key. A change in `kid` signals that a new signing key is active.

### Go example

Using [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt):

```go
import (
    "strings"
    "github.com/golang-jwt/jwt/v5"
)

// ecPub is *ecdsa.PublicKey fetched from /jwks
keyFunc := func(t *jwt.Token) (any, error) {
    if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return ecPub, nil
}

token, err := jwt.Parse(rawToken, keyFunc,
    jwt.WithIssuedAt(),
    jwt.WithIssuer("svid-exchange"),
    jwt.WithAudience("spiffe://cluster.local/ns/default/sa/payment"),
)
if err != nil {
    // token is invalid, expired, wrong audience, etc.
}

claims := token.Claims.(jwt.MapClaims)
scope, _ := claims["scope"].(string)

// scope is space-separated: "payments:charge payments:refund"
hasCharge := strings.Contains(" "+scope+" ", " payments:charge ")
```

**Important:** always pass `jwt.WithAudience(...)` set to your own service's SPIFFE ID. Without it, a token issued for a different target service will be accepted.
