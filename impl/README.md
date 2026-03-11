# ACP Reference Implementation

> **Agent Control Protocol v1.0** — Reference Implementation

This directory contains the official reference implementation of ACP v1.0.

## Structure

```
reference-impl/
├── acp-go/              # Go — Institutional Validator + IUT (Reference Implementation)
│   ├── pkg/
│   │   ├── crypto/      # Ed25519 identity, AgentID derivation (ACP-SIGN-1.0)
│   │   ├── tokens/      # Capability Token parsing & 9-step verification (ACP-CT-1.0)
│   │   ├── handshake/   # Challenge/PoP server-side (ACP-HP-1.0)
│   │   ├── delegation/  # Delegation chain validation (ACP-CT-1.0 §7)
│   │   ├── risk/        # Risk assessment engine (ACP-RISK-1.0)
│   │   └── iut/         # IUT evaluation core — L1/L2 compliance logic (ACP-IUT-PROTOCOL-1.0)
│   ├── cmd/
│   │   ├── acp-server/       # HTTP server exposing ACP endpoints
│   │   ├── acp-evaluate/     # IUT binary — STDIN→evaluate→STDOUT (ACP-IUT-PROTOCOL-1.0)
│   │   ├── acp-runner/       # Compliance runner — executes test suites (ACR-1.0)
│   │   └── acp-sign-vectors/ # Tool to sign PLACEHOLDER signatures in test vectors
│   └── go.mod
│
└── sdk/
    ├── python/          # Python — Agent SDK (for AI agents)
    │   ├── acp/
    │   │   ├── identity.py   # Ed25519 identity, AgentID
    │   │   ├── signer.py     # JCS canonicalization, token signing/verification
    │   │   └── client.py     # HTTP client with automatic PoP handshake
    │   ├── examples/
    │   │   └── agent_payment.py
    │   └── pyproject.toml
    └── typescript/      # TypeScript/Node.js — Agent SDK (zero runtime deps)
        ├── src/
        │   ├── identity.ts   # Ed25519 identity via node:crypto, AgentID, DID
        │   ├── signer.ts     # JCS canonicalize (RFC 8785), sign/verify
        │   └── client.ts     # HTTP client with automatic PoP handshake
        ├── tests/
        │   ├── identity.test.ts
        │   ├── signer.test.ts
        │   └── client.test.ts
        ├── package.json
        └── tsconfig.json
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

### TypeScript SDK

```bash
cd sdk/typescript

# Install (no runtime dependencies — Node.js 18+ only)
npm install

# Run tests
npm test
# 68 tests passed

# Use in your project
```
```typescript
import { AgentIdentity, ACPSigner, ACPClient } from './src';

const agent = AgentIdentity.generate();
const signer = new ACPSigner(agent);
const client = new ACPClient('http://localhost:8080', agent, signer);

await client.register();
const health = await client.health();
console.log(health); // { status: 'ok', version: '1.0.0' }
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/acp/v1/register`  | Register agent public key |
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
| ACP-IUT-PROTOCOL-1.0 | ✅ Full | IUT binary (acp-evaluate) — 12/12 test vectors PASS |
| ACR-1.0 | ✅ Full | Compliance runner (acp-runner) — L1–L5 certification |
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
