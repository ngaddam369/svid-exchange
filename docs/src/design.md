# Design & Motivation

## The problem space

Microservices need to authenticate to each other. The challenge is doing so in a way that is:

1. **Tied to the running workload** — identity should belong to the process, not to a human, config file, or long-lived secret.
2. **Scoped** — a service should only be able to request the minimum permissions it needs for a specific operation, not a blanket token good for everything.
3. **Auditable** — every access decision should be logged with enough context to answer: *who asked, for what, against whom, and was it granted?* This matters for SOC 2, PCI-DSS, and HIPAA compliance where attributable access records are required.
4. **Short-lived** — credentials should expire quickly; rotation should be automatic, not operational.
5. **Secret-free** — API keys in environment variables, shared passwords in config files, and service account credentials on fixed rotation schedules are all a liability. The goal is zero static secrets anywhere in the system.

## mTLS vs token exchange

A common question is: *if services already authenticate over mTLS with SPIFFE SVIDs, why do we need token exchange at all?*

mTLS answers one question: **is this certificate valid?** It provides transport security and binary identity — the connection either passes the handshake or it doesn't. What mTLS does not provide is any concept of *what the caller is allowed to do* once identity is established.

Think of it this way: mTLS is *showing your badge at the building entrance*. Token exchange is *getting a specific keycard that only opens the rooms you're authorised to enter today, valid for the next five minutes*.

Concretely, token exchange adds:
- **Per-operation scoping** — a token is valid only for the declared `target` and the intersection of requested and allowed `scopes`; the same service cannot reuse it for a different operation
- **Audience binding** — the `aud` claim ties the token to a specific target SPIFFE ID; presenting it to any other service fails validation
- **Blast radius reduction** — a compromised workload's SVID expires within hours automatically; any tokens it obtained are short-lived by policy
- **Compliance auditability** — every token exchange is a logged, attributable event independent of the transport layer

## What already exists

| Solution | What it does | What's missing |
|----------|-------------|----------------|
| **SPIFFE / SPIRE** | Issues cryptographic workload identities (SVIDs) as short-lived X.509 certificates | Provides identity; does not produce scoped tokens for service-to-service calls |
| **Istio / Envoy authz** | Enforces access control at the service-mesh level transparently | Coarse-grained (service-level allow/deny); no per-operation scopes; no auditable token that the target can independently verify |
| **OAuth 2.0 `client_credentials`** | Issues tokens for machine-to-machine flows | Identity is a static `client_id` configured in an auth server — not tied to a live, attestable workload; requires a separate identity provider |
| **Kubernetes ServiceAccount JWTs** | Gives pods a verifiable identity token | Bound to a namespace and ServiceAccount; not scoped to a target service or operation; not portable outside Kubernetes |
| **AWS IRSA / GCP Workload Identity** | Maps workload identity to cloud IAM roles | Cloud-specific; not portable across environments or clouds; does not address service-to-service scoped access within a cluster |
| **SPIFFE Federation** | Extends SVID trust across trust domains | Still an identity mechanism, not a token exchange — it does not produce scoped JWTs |

## The gap

None of the above solutions provides a **portable, workload-native, scoped token exchange** that:

- Accepts a live, cryptographically-attested workload identity (SVID) as the credential
- Evaluates a policy to determine what that workload is allowed to do
- Returns a short-lived, scoped JWT that the *target* service can independently verify
- Produces a structured, tamper-evident audit trail for every decision

OAuth 2.0 comes closest in spirit but requires a separate identity provider and static client credentials — it has no native concept of "this token was requested by workload X as proven by its X.509 SVID." SPIRE provides the identity layer but stops there; what to do with it is left to the application.

## How svid-exchange bridges the gap

svid-exchange sits at the intersection of SPIFFE identity and scoped JWT authorization:

```
SVID (live workload identity)
    └── mTLS to svid-exchange
          └── SPIFFE ID extracted from peer cert (cannot be forged in payload)
                └── Policy evaluated: does subject have permission for target + scopes?
                      └── ES256 JWT minted: scoped, short-lived, audience-bound
                            └── Target service verifies JWT via /jwks (no out-of-band key distribution)
```

The key design decisions and their rationale:

| Decision | Rationale |
|----------|-----------|
| **Identity from transport, not payload** | The caller's SPIFFE ID comes from the mTLS peer certificate — it cannot be claimed in the request body. Forgery requires a valid SPIRE-issued cert, which requires workload attestation. |
| **Policy as code (YAML)** | Explicit allow-list of `(subject, target, scopes)` tuples. Denied by default. Auditable as a file in version control. |
| **Scope intersection** | The granted scopes are the intersection of what the caller requested and what the policy allows. A caller cannot escalate beyond the policy ceiling. |
| **Audience-bound JWTs** | The `aud` claim is set to the target's SPIFFE ID. A token issued for `payment` cannot be replayed to `inventory`. |
| **ES256 over RS256** | ECDSA P-256 keys are smaller (32 bytes vs 256+ bytes for RSA-2048) and faster to verify — relevant when every incoming request to the target service verifies a JWT. |
| **JWKS endpoint** | Downstream services fetch the public key directly — no shared secret, no manual key distribution, compatible with any standards-compliant JWT library. |

## Scope and design boundaries

svid-exchange is narrow by design. The following boundaries are deliberate — each could be crossed, but doing so would pull the system toward complexity that makes it harder to reason about and harder to trust.

**It depends on SPIRE; it does not replace it.** svid-exchange is a consumer of SPIFFE SVIDs, not an identity provider. Workload attestation, trust bundle management, and SVID rotation are SPIRE's job. Building a second identity layer here would mean replicating machinery that SPIRE already handles correctly, and splitting the root of trust across two systems.

**It complements a service mesh; it does not replace it.** Mutual TLS at the transport layer (Istio, Linkerd) and scoped authorization tokens solve different problems. A mesh ensures the *channel* is authenticated; svid-exchange ensures the *operation* is authorized. Collapsing the two would mean either losing per-operation scoping or coupling the mesh to a policy engine — neither is a good trade.

**It is not a general-purpose authorization server.** svid-exchange is purpose-built for the SPIFFE-to-JWT exchange pattern. OPA, Casbin, and full OAuth 2.0 servers handle richer policy models (attribute-based, role-hierarchical, user-facing flows). Adding those models here would make policy harder to audit and the denial surface harder to predict.

**It handles machine-to-machine flows only.** Human identity — OIDC, SAML, browser sessions — belongs in an identity provider. Mixing user and workload identity into the same exchange service conflates two trust models that should be reasoned about independently: attested workload identity (verifiable at the transport layer) and asserted user identity (verifiable only by an external IdP).

**Scopes are flat and explicit.** There is no wildcard matching, no role hierarchy, no implied permissions. `payments:*` does not automatically include `payments:charge`. This is intentional — implicit scope inheritance is where privilege escalation bugs hide. Every scope a caller can receive must be spelled out in a policy rule.

**It is not in the per-request hot path.** A caller exchanges its SVID for a JWT once, caches the token for its TTL, and presents it on every downstream call. Token verification happens independently at the target via `/jwks` — svid-exchange is not involved. This means a brief svid-exchange outage does not disrupt in-flight service traffic, and it cannot become a per-request latency bottleneck.

**Enforcement at the target is the target's responsibility.** svid-exchange ensures that only correctly attested, policy-permitted callers receive tokens. It cannot guarantee those tokens are validated before access is granted — that boundary belongs to the receiving service. The trust model only holds if both sides do their part.

## Current limitations

| Limitation | Notes |
|------------|-------|
| Signing key is ephemeral by default | `key_rotation_interval` bounds the exposure window per key; hardware-protected keys are supported via the `token.Signer` interface and a KMS adapter (see Security → KMS integration) |
| Rate limits are per-SPIFFE-ID, not per-target | The limit applies to the total exchange rate from an identity regardless of target; per-target granularity is not supported |
| Multi-replica rate limiting requires external state | Token buckets are in-process and reset on restart; a shared backend (Redis, sidecar) is needed for strict enforcement across replicas |
