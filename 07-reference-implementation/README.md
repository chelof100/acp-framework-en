# ACP Reference Implementation

> **Agent Control Protocol v1.0** — Reference Implementation

This directory contains the official reference implementation of ACP v1.0.

## Structure

```
reference-impl/
├── acp-go/              # Go — Institutional Validator (Reference Implementation)
│   ├── pkg/
│   │   ├── crypto/      # Ed25519 identity, AgentID derivation (ACP-SIGN-1.0)
│   │   ├── tokens/      # Capability Token parsing & 9-step verification (ACP-CT-1.0)
│   │   ├── handshake/   # Challenge/PoP server-side (ACP-HP-1.0)
│   │   ├── delegation/  # Delegation chain validation (ACP-CT-1.0 §7)
│   │   └── risk/        # Risk assessment engine (ACP-RISK-1.0)
│   ├── cmd/
│   │   └── acp-server/  # HTTP server exposing ACP endpoints
│   └── go.mod
│
└── sdk/
    └── python/          # Python — Agent SDK (for AI agents)
        ├── acp/
        │   ├── identity.py   # Ed25519 identity, AgentID
        │   ├── signer.py     # JCS canonicalization, token signing/verification
        │   └── client.py     # HTTP client with automatic PoP handshake
        ├── examples/
        │   └── agent_payment.py
        └── pyproject.toml
```

## Quick Start

### Go Server

```bash
cd acp-go

# Install dependencies
go mod tidy

# Run the server (requires institution public key)
export ACP_INSTITUTION_PUBLIC_KEY="<base64url-encoded-32-byte-pubkey>"
go run ./cmd/acp-server

# Server starts on :8080
```

### Python SDK

```bash
cd sdk/python

# Install
pip install -e ".[dev]"

# Run example
ACP_SERVER_URL=http://localhost:8080 python examples/agent_payment.py
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/acp/v1/challenge` | Issue one-time 128-bit nonce |
| `POST` | `/acp/v1/verify`    | Verify CT + PoP, return authorization decision |
| `GET`  | `/acp/v1/health`    | Health check |

### Challenge Request

```bash
curl http://localhost:8080/acp/v1/challenge
# {"challenge":"<base64url>","expires_in":"30s"}
```

### Verify Request

```bash
curl -X POST http://localhost:8080/acp/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "capability_token": { ...ACP-CT-1.0 token... },
    "requested_capability": "acp:cap:financial.payment",
    "requested_resource": "org.banco-soberano/accounts/ACC-001"
  }'
```

## Specifications Implemented

| Spec | Status | Description |
|------|--------|-------------|
| ACP-CT-1.0 | ✅ Full | Capability Token structure + 9-step verification |
| ACP-SIGN-1.0 | ✅ Full | Ed25519 + JCS + SHA-256 signing pipeline |
| ACP-HP-1.0 | ✅ Full | Challenge/PoP handshake with channel binding |
| ACP-CT-1.0 §7 | ✅ Full | Delegation chain validation |
| ACP-RISK-1.0 | ✅ Reference | Deterministic risk scoring |
| ACP-REV-1.0 | 🔲 Interface | Revocation interface defined, implementation pending |

## Design Decisions

**Go for the validator**: Concurrency (goroutines), type safety, small binaries,
`crypto/ed25519` in stdlib. Ideal for institutional deployments.

**Python for the SDK**: AI/ML agent ecosystem (LangChain, AutoGen, crewAI, Claude SDK)
is Python-native. `pip install acp-sdk` is the target distribution.

**Separation of concerns**: The Go validator is the source of truth for authorization.
The Python SDK is a client that produces correctly-structured requests.

## Security Notes

- Private keys MUST be stored in hardware security modules (HSM) in production
- The nonce store MUST be persistent (Redis/PostgreSQL) across server restarts
- TLS is MANDATORY in production (ACP does not provide transport security)
- Revocation endpoint (ACP-REV-1.0) MUST be implemented before production use
