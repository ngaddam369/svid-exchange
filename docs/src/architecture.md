# Architecture

## Components

| Component | Role |
|-----------|------|
| **SPIRE Server** | Certificate authority; issues SVIDs to registered workloads |
| **SPIRE Agent** | Node-local daemon; attests workloads and serves the Workload API |
| **svid-exchange (gRPC)** | Token exchange service on `:8080`; validates identity, enforces policy, mints JWTs |
| **svid-exchange (HTTP)** | Health, JWKS, and metrics server on `:8081`; serves `/health/live`, `/health/ready`, `/jwks`, and `/metrics` |
| **Caller service** | Any SPIFFE-registered microservice requesting a token |
| **Target service** | The downstream service the caller wants to call; validates the JWT via `/jwks` |

## Token exchange flow

```mermaid
sequenceDiagram
    box #FEF3C7 Caller
    participant C as Caller (SVID)
    end
    box #D1FAE5 svid-exchange
    participant S as svid-exchange
    participant P as Policy (YAML)
    participant M as Minter (ES256)
    end
    box #FEF3C7 Target
    participant T as Target Service
    end

    C->>S: gRPC Exchange() over mTLS
    S->>S: Extract SPIFFE ID from peer cert
    S->>P: Evaluate(subject, target, scopes, ttl)
    alt denied
        P-->>S: Allowed=false
        S-->>C: PERMISSION_DENIED
    else allowed
        P-->>S: Allowed=true, granted scopes, TTL
        S->>M: Mint(subject, target, scopes, ttl)
        M-->>S: Signed ES256 JWT
        S-->>C: token + expires_at + granted_scopes + token_id
    end
    C->>T: Call with JWT in Authorization header
    T->>T: Verify JWT signature via /jwks
```

## mTLS and identity

svid-exchange uses the SPIRE Workload API (`X509Source`) to fetch and continuously rotate its own SVID. Every TLS handshake picks up the latest certificate without a process restart.

```mermaid
graph LR
    SS[SPIRE Server] -->|issues SVIDs| SA[SPIRE Agent]
    SA -->|Workload API| SX[svid-exchange]
    SA -->|Workload API| CS[Caller Service]
    CS -->|mTLS with SVID| SX
    SX -->|validates peer cert| SX

    classDef spire fill:#DBEAFE,stroke:#3B82F6,color:#1E3A8A
    classDef exchange fill:#D1FAE5,stroke:#10B981,color:#065F46
    classDef external fill:#FEF3C7,stroke:#F59E0B,color:#78350F

    class SS,SA spire
    class SX exchange
    class CS external
```