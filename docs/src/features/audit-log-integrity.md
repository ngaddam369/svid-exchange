# Audit Log Integrity

## What it is

svid-exchange logs every exchange attempt — granted or denied — as structured JSON to stdout. When `AUDIT_HMAC_KEY` is set, each line is signed with HMAC-SHA256 and chained to the previous entry. This provides cryptographic tamper evidence: any modification, deletion, or reordering of log entries is detectable offline.

When `AUDIT_HMAC_KEY` is unset, the logger behaves exactly as before — plain JSON lines, no extra fields, no performance cost.

## Why it exists

An audit log is only useful if you can trust it. Without integrity protection:

- An insider with write access to the log destination can delete denial entries to hide unauthorized access attempts.
- A log pipeline with insufficient access controls can have entries modified in transit — changing `"granted":false` to `"granted":true`, for example.
- There is no way to prove to an auditor that the log you present matches what the service actually emitted.

HMAC signing addresses the *evidence* problem: even if you cannot prevent tampering, you can detect it.

## How it works

Each JSON line produced by zerolog is intercepted by an `io.Writer` wrapper before reaching stdout. Three fields are injected before the closing `}`:

| Field | Content |
|-------|---------|
| `seq` | Monotonically increasing integer starting at 1. A gap (e.g. 1 → 3) means a line was deleted. |
| `prev_hmac` | HMAC of the immediately preceding entry (all-zeros for the first). Chaining means any deletion or reordering also breaks the chain at the next entry. |
| `hmac` | `HMAC-SHA256(key, uint64_be(seq) \|\| prev_hmac \|\| original_line)` — covers every field in the original entry before injection. |

Example signed line:

```json
{
  "level": "info",
  "time": "2026-03-02T23:06:43Z",
  "event": "token.exchange",
  "subject": "spiffe://cluster.local/ns/default/sa/order",
  "target": "spiffe://cluster.local/ns/default/sa/payment",
  "granted": true,
  "seq": 1,
  "prev_hmac": "0000000000000000000000000000000000000000000000000000000000000000",
  "hmac": "6ecad2e0f71ebf41775e425f4ae42af25e839e8d81c111688531a3f69db64f4c"
}
```

## Enabling signing

### 1. Generate a key

```bash
openssl rand -hex 32
# e.g.: a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2
```

The key must be exactly 32 bytes (64 hex characters). Store it in a secrets manager — never alongside the logs.

### 2. Start the stack

```bash
AUDIT_HMAC_KEY=<your-64-hex-key> docker compose up svid-exchange --build -d
```

svid-exchange logs on startup:

```
{"message":"audit log HMAC signing enabled"}
```

## Offline verification

A verifier reads the log lines and recomputes each HMAC from first principles:

```
prev_mac = bytes(32)   # all zeros

for each line in audit.log:
    parse JSON → extract seq, prev_hmac, hmac, and all other fields
    reconstruct original_line = strip "seq", "prev_hmac", "hmac" fields, re-add closing }
    recompute = HMAC-SHA256(key, uint64_be(seq) || prev_mac || original_line)

    if recompute != hmac      → TAMPER DETECTED  (field-level modification)
    if seq != previous_seq+1  → GAP DETECTED     (line deleted)
    if prev_hmac != prev_mac  → CHAIN BROKEN     (deletion or reordering)

    prev_mac = stored_hmac
```

## Security concerns and known limitations

| Concern | Status | Notes |
|---------|--------|-------|
| Field-level tampering | **Mitigated** | HMAC covers every field in the original line before injection |
| Line deletion or reordering | **Mitigated** | Chained `prev_hmac` and `seq` gaps expose both |
| Key compromise | **Operational** | An attacker with the key can forge valid HMACs. Inject `AUDIT_HMAC_KEY` at runtime from a secrets manager (Vault, AWS Secrets Manager); never write it to disk alongside the logs |
| Real-time prevention | **Out of scope** | This is tamper-*evidence*, not tamper-*prevention*. Preventing tampering requires writing to an external append-only store (WORM S3, Kafka, write-restricted syslog sink) — an infrastructure decision outside the scope of this service |
