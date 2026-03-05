# Introduction

**svid-exchange** is a Zero Trust token exchange service for microservice environments. Services present a SPIFFE SVID (via mTLS) and receive a scoped, short-lived ES256 JWT in return — eliminating static shared secrets between microservices.

## The Problem

In traditional microservice architectures, services authenticate to each other using static secrets: API keys, long-lived tokens, or shared passwords. These secrets:

- Must be distributed and rotated manually
- Are often over-scoped (a single key grants access to everything)
- Cannot be tied to a specific workload identity
- Are hard to audit — you can't tell *which instance* used a secret
- Create secret sprawl across environments (dev, staging, prod each need their own copies)
- Represent compliance risk — static credentials with no attributable identity make SOC 2, PCI-DSS, and HIPAA audit trails difficult to produce

## The Solution

svid-exchange leverages [SPIFFE](https://spiffe.io) workload identity as the root of trust. Every service in the mesh already has a SPIFFE SVID issued by SPIRE — a cryptographic identity tied to the workload, not to a human or config file.

```
caller (SVID)  →  svid-exchange  →  scoped JWT  →  target service
```

1. The caller connects over mTLS. Its SPIFFE ID is extracted from the client certificate — it cannot be forged in the request body.
2. A YAML policy is evaluated: does this subject have permission to call this target with these scopes?
3. If permitted, a signed ES256 JWT is minted. The token is scoped to the exact permissions the policy allows, capped to `max_ttl`.

## Key features

- **Identity from transport** — caller identity comes from the mTLS certificate, not the request payload
- **Policy-driven scoping** — explicit allow-list of (subject, target, scopes) tuples; denied by default
- **Short-lived tokens** — TTL capped by policy; no long-lived credentials to rotate
- **Zero static secrets** — no API keys, no shared passwords, no rotation scripts; identity is the credential
- **Audit trail** — every exchange (granted or denied) logged with full context; attributable to a specific workload for compliance purposes
- **JWKS endpoint** — downstream services can verify tokens without out-of-band key distribution
- **Dynamic SVID rotation** — SPIRE Workload API refreshes mTLS certificates automatically; no restarts needed
- **Replay protection** — every minted JTI is tracked server-side; duplicate token IDs are rejected before reaching the caller
- **Token revocation** — an in-memory revocation list permanently denies specific JTIs within their TTL
- **Dynamic policy management** — add or remove policies at runtime via the admin gRPC API without restarting; changes are persisted in BoltDB and survive restarts
- **Policy hot-reload** — send `SIGHUP` to reload the YAML policy file atomically; dynamic policies are preserved across reloads
