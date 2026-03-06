# API Reference

## Data-plane gRPC service

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

---

## Admin gRPC service

**Service:** `admin.v1.PolicyAdmin`

**Address:** `:8082` (configurable via `ADMIN_ADDR`)

**Transport:** mTLS required — same SPIRE-issued certificates as the data-plane port.

> **Restrict this port.** The admin service can add and delete policies. It must not be reachable from workloads that consume the `TokenExchange` API. Use a firewall rule, Kubernetes `NetworkPolicy`, or a separate network interface to limit access to administrative clients only.

### CreatePolicy

Adds a new dynamic policy. Takes effect immediately and survives server restarts.

```protobuf
rpc CreatePolicy(CreatePolicyRequest) returns (CreatePolicyResponse);
```

**Request fields (`PolicyRule`):**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique human-readable identifier (used in audit logs) |
| `subject` | string | SPIFFE ID of the calling service |
| `target` | string | SPIFFE ID of the target service |
| `allowed_scopes` | repeated string | Scopes this subject may request for this target |
| `max_ttl` | int32 | Maximum token lifetime in seconds |

**Status codes:**

| Code | Condition |
|------|-----------|
| `OK` | Policy created and active |
| `INVALID_ARGUMENT` | Missing or invalid fields (empty name, bad SPIFFE ID, empty scopes, non-positive TTL) |
| `ALREADY_EXISTS` | The policy name or `(subject, target)` pair already exists in the YAML file or dynamic store |

#### Example (grpcurl)

```bash
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.N.pem \
  -key  /tmp/svid/svid.N.key \
  -proto proto/admin/v1/admin.proto \
  -d '{
    "rule": {
      "name": "order-to-inventory",
      "subject": "spiffe://cluster.local/ns/default/sa/order",
      "target":  "spiffe://cluster.local/ns/default/sa/inventory",
      "allowed_scopes": ["inventory:read"],
      "max_ttl": 60
    }
  }' \
  localhost:8082 admin.v1.PolicyAdmin/CreatePolicy
```

### DeletePolicy

Removes a dynamic policy by name. YAML-sourced policies cannot be deleted via the API — edit the YAML file and call `ReloadPolicy` instead.

```protobuf
rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);
```

| Code | Condition |
|------|-----------|
| `OK` | Policy removed |
| `INVALID_ARGUMENT` | Name is empty |
| `NOT_FOUND` | No dynamic policy with that name exists |
| `FAILED_PRECONDITION` | The policy was loaded from the YAML file |

#### Example (grpcurl)

```bash
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.N.pem \
  -key  /tmp/svid/svid.N.key \
  -proto proto/admin/v1/admin.proto \
  -d '{"name": "order-to-inventory"}' \
  localhost:8082 admin.v1.PolicyAdmin/DeletePolicy
```

### ListPolicies

Returns all active policies — both YAML-sourced and dynamic — with a `source` field so callers can distinguish them.

```protobuf
rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
```

Each entry in the response includes a `PolicyRule` and a `source` field: `"yaml"` for policies loaded from the file, `"dynamic"` for policies added via this API.

#### Example (grpcurl)

```bash
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.N.pem \
  -key  /tmp/svid/svid.N.key \
  -proto proto/admin/v1/admin.proto \
  localhost:8082 admin.v1.PolicyAdmin/ListPolicies
```

### ReloadPolicy

Re-reads the YAML policy file from disk and merges it with all dynamic policies atomically.

```protobuf
rpc ReloadPolicy(ReloadPolicyRequest) returns (ReloadPolicyResponse);
```

**Behaviour:**
- Re-reads `POLICY_FILE` from disk and validates its contents.
- If valid, atomically replaces the active YAML policy set and merges with all dynamic policies from the store.
- If the file is invalid, the currently active policy is unchanged and an error is returned.

**Status codes:**

| Code | Condition |
|------|-----------|
| `OK` | Policy file reloaded and active |
| `INTERNAL` | File is missing, unreadable, or contains invalid YAML |

#### Example (grpcurl)

```bash
grpcurl \
  -insecure \
  -cert /tmp/svid/svid.N.pem \
  -key  /tmp/svid/svid.N.key \
  -proto proto/admin/v1/admin.proto \
  localhost:8082 admin.v1.PolicyAdmin/ReloadPolicy
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
