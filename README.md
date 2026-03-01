# svid-exchange

A Zero Trust token exchange service. Services present a SPIFFE SVID (via mTLS) and receive a scoped, short-lived ES256 JWT in return — eliminating static shared secrets between microservices.

```
caller (SVID)  →  svid-exchange  →  scoped JWT  →  target service
```

## Quick start

```bash
make compose-up
```

Runs the full verification checklist, then starts SPIRE Server + Agent + svid-exchange via Docker Compose with workload entries pre-registered.

## Documentation

**[Read the documentation](https://ngaddam369.github.io/svid-exchange/)**.
