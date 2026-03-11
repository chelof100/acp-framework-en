# ACP Go — Reference Server

Reference implementation of the **Agent Control Protocol (ACP)** in Go 1.22.
HTTP server implementing the core protocol specifications for autonomous AI agent environments.

## Implemented Specifications

| Spec | Description | Status |
|------|-------------|--------|
| ACP-HP-1.0 | Handshake Protocol — challenge/verify with Proof of Possession | ✅ |
| ACP-SIGN-1.0 | Deterministic Ed25519 signatures with JCS (RFC 8785) | ✅ |
| ACP-CT-1.0 | Capability Tokens — verifiable permission delegation | ✅ |
| ACP-RISK-1.0 | Risk evaluation engine (score 0–100, 3 decision levels) | ✅ |
| ACP-REV-1.0 | Token and agent revocation | ✅ |
| ACP-REP-1.1 | Agent reputation engine | ✅ |
| ACP-API-1.0 | Validation middleware + response envelopes + OpenAPI spec | ✅ |
| ACP-EXEC-1.0 | Single-use Execution Tokens (max 300 seconds) | ✅ |
| ACP-LEDGER-1.0 | Append-only Audit Ledger with SHA-256 hash chain | ✅ |

## Package Structure

```
pkg/
├── api/         # ACP-API-1.0: middleware, request IDs, signed response envelopes
├── crypto/      # Primitives: Ed25519, JCS, SHA-256, base58, base64url
├── delegation/  # Capability token delegation chain
├── execution/   # ACP-EXEC-1.0: execution token issuance and consumption
├── handshake/   # ACP-HP-1.0: challenge/verify with Proof of Possession
├── iut/         # IUT — compliance runner against normative test vectors
├── ledger/      # ACP-LEDGER-1.0: append-only audit log with hash chain
├── registry/    # Agent registry with autonomy levels
├── reputation/  # ACP-REP-1.1: reputation engine
├── revocation/  # ACP-REV-1.0: revocation store
├── risk/        # ACP-RISK-1.0: risk evaluation and decision thresholds
└── tokens/      # ACP-CT-1.0: capability token issuance and verification
```

## Requirements

- Go 1.22+
- Dependencies: `github.com/gowebpki/jcs v1.0.1` (JCS RFC 8785, used by ledger)

## Build and Tests

```bash
# Build everything
go build ./...

# Run all tests
go test ./... -count=1

# Lint
go vet ./...
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACP_INSTITUTION_PUBLIC_KEY` | ✅ | — | Ed25519 public key (base64url). Required to start. |
| `ACP_INSTITUTION_PRIVATE_KEY` | ❌ | — | Ed25519 private key (base64url). Enables response signing. Without it, server runs in dev mode (unsigned responses). |
| `ACP_INSTITUTION_ID` | ❌ | `org.acp.server` | Institution identifier for the audit ledger. |
| `ACP_ADDR` | ❌ | `:8080` | Listen address and port. |
| `ACP_LOG_LEVEL` | ❌ | `info` | Log level. |

## Running

```bash
export ACP_INSTITUTION_PUBLIC_KEY="cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE"
export ACP_INSTITUTION_PRIVATE_KEY="<base64url_privkey_64_bytes>"
export ACP_INSTITUTION_ID="org.my-institution"
go run ./cmd/acp-server
```

### With Docker

```bash
docker compose up
```

Set `ACP_INSTITUTION_PUBLIC_KEY` and optionally `ACP_INSTITUTION_PRIVATE_KEY` in the environment or in a `.env` file.

## Endpoints

| Method | Path | Spec | Description |
|--------|------|------|-------------|
| `GET` | `/acp/v1/handshake/challenge` | ACP-HP-1.0 | Get challenge nonce for PoP |
| `POST` | `/acp/v1/verify` | ACP-HP-1.0 | Verify Proof of Possession |
| `POST` | `/acp/v1/agents` | ACP-API-1.0 | Register agent with public key |
| `GET` | `/acp/v1/agents/{agent_id}` | ACP-API-1.0 | Get agent data |
| `POST` | `/acp/v1/agents/{agent_id}/state` | ACP-API-1.0 | Change agent state (active/suspended/revoked) |
| `POST` | `/acp/v1/authorize` | ACP-RISK-1.0 | Request authorization — evaluates risk, returns APPROVED/DENIED/ESCALATED |
| `POST` | `/acp/v1/authorize/escalations/{id}/resolve` | ACP-RISK-1.0 | Resolve manual escalation |
| `POST` | `/acp/v1/tokens` | ACP-CT-1.0 | Issue capability token |
| `POST` | `/acp/v1/exec-tokens/{et_id}/consume` | ACP-EXEC-1.0 | Consume execution token (single-use) |
| `GET` | `/acp/v1/exec-tokens/{et_id}/status` | ACP-EXEC-1.0 | Query execution token status |
| `POST` | `/acp/v1/audit/query` | ACP-LEDGER-1.0 | Query audit ledger events |
| `GET` | `/acp/v1/audit/verify/{event_id}` | ACP-LEDGER-1.0 | Verify event chain integrity |
| `GET` | `/acp/v1/rev/check` | ACP-REV-1.0 | Check if a token is revoked |
| `POST` | `/acp/v1/rev/revoke` | ACP-REV-1.0 | Revoke token or agent |
| `GET` | `/acp/v1/rep/{agent_id}` | ACP-REP-1.1 | Get agent reputation |
| `GET` | `/acp/v1/rep/{agent_id}/events` | ACP-REP-1.1 | Agent reputation event history |
| `POST` | `/acp/v1/rep/{agent_id}/state` | ACP-REP-1.1 | Update reputation state |
| `GET` | `/acp/v1/health` | — | Health check with component status |

## ACP-LEDGER-1.0 — Audit Ledger

The ledger records all relevant system events in a verifiable chain:

- **11 event types**: `AUTHORIZATION`, `RISK_EVALUATION`, `REVOCATION`, `TOKEN_ISSUED`, `EXECUTION_TOKEN_ISSUED`, `EXECUTION_TOKEN_CONSUMED`, `AGENT_REGISTERED`, `AGENT_STATE_CHANGE`, `ESCALATION_CREATED`, `ESCALATION_RESOLVED`, `LEDGER_GENESIS`
- **SHA-256 hash chain** with JCS (RFC 8785) for determinism across implementations
- **Ed25519 institutional signatures** on every event
- **`chain_valid`** field in all query responses

```json
{
  "ver": "1.0",
  "event_id": "<uuid_v4>",
  "event_type": "AUTHORIZATION",
  "sequence": 42,
  "timestamp": 1718920000,
  "institution_id": "org.example.banking",
  "prev_hash": "<SHA-256_base64url_of_previous_event>",
  "payload": { "decision": "APPROVED", "risk_score": 28 },
  "hash": "<SHA-256_base64url_of_this_event>",
  "sig": "<institutional_Ed25519_signature>"
}
```

## Development Key (test only)

Deterministic seed — RFC 8037 key A:
```
seed:    9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
pubkey:  cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE
```

## Core Invariant

```
Execute(request) ≡ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

---

**Version:** 1.5.0 | **License:** Apache 2.0 | **Author:** Marcelo Fernandez — [TraslaIA](https://traslaia.com)
