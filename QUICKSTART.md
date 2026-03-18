# ACP Framework — Quickstart

## One-liner (Docker)

```bash
# Start ACP server with the RFC 8037 dev key
docker run -p 8080:8080 \
  -e ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6EpJaJKKaVfvPT8mAQf97Vo8TInk \
  ghcr.io/chelof100/acp-server:latest
```

```bash
# Health check
curl http://localhost:8080/acp/v1/health
```

> For production: replace `ACP_INSTITUTION_PUBLIC_KEY` with your own Ed25519 public key.
> See `impl/go/.env.example` for all configuration options.

---

## Make targets

```bash
make demo          # start server in dev mode + health check
make test          # run all Go tests
make vectors       # run 51 conformance test vectors
make python-demo   # run Python admission control demo (no server needed)
make build         # build the Go server binary
```

---

## Choose your path

### Path A — Understand the protocol design

Start here to understand what ACP solves and how it is structured.

1. [`docs/admission-flow.md`](docs/admission-flow.md) — **Start here**: complete 6-step admission check guide
2. [`README.md`](README.md) — What ACP is and why it exists
3. [`ARCHITECTURE.md`](ARCHITECTURE.md) — Formal domain model and dependency graph
4. [`spec/core/ACP-SIGN-1.0.md`](spec/core/ACP-SIGN-1.0.md) — Base cryptographic layer
5. [`spec/core/ACP-CT-1.0.md`](spec/core/ACP-CT-1.0.md) — Capability Token format
6. [`spec/core/ACP-HP-1.0.md`](spec/core/ACP-HP-1.0.md) — Handshake Protocol

### Path B — Implement ACP

Start here if you want to build a conformant ACP implementation.

1. [`spec/governance/ACP-CONF-1.2.md`](spec/governance/ACP-CONF-1.2.md) — Normative conformance definition (L1–L5)
2. [`openapi/acp-api-1.0.yaml`](openapi/acp-api-1.0.yaml) — OpenAPI 3.1.0 spec for all HTTP endpoints
3. [`compliance/ACP-TS-1.1.md`](compliance/ACP-TS-1.1.md) — Test vector format
4. [`compliance/test-vectors/`](compliance/test-vectors/) — 51 normative test vectors (CORE · DCMA · HP · LEDGER · EXEC · PROV)
5. [`compliance/ACR-1.0.md`](compliance/ACR-1.0.md) — Compliance runner protocol

### Path C — Run the reference implementation

**Prerequisites:** Go 1.22+, Docker (optional)

**Step 1 — Build and start the server**

```bash
git clone https://github.com/chelof100/acp-framework-en
cd acp-framework-en/impl/go

# Generate a dev key
go run ./cmd/keygen

# Start the server (set your institution key)
export ACP_INSTITUTION_PUBLIC_KEY=<base64url_ed25519_public_key>
go run ./cmd/acp-server
```

**Step 2 — Health check**

```bash
curl http://localhost:8080/acp/v1/health
```

```json
{
  "acp_version": "1.0",
  "status": "operational",
  "timestamp": 1718920000,
  "components": {
    "policy_engine": "operational",
    "audit_ledger": "operational",
    "agent_registry": "operational",
    "rev_endpoint": "operational"
  }
}
```

**Step 3 — Run the conformance test vectors**

```bash
cd impl/go

# Build the IUT evaluator
go build ./cmd/acp-evaluate

# Run the compliance suite against all test vectors
go run ./cmd/acp-runner \
  --impl ./acp-evaluate \
  --suite ../../compliance/test-vectors

# Expected: 51/51 PASS → CONFORMANT L1–L3 (CORE + DCMA + HP + LEDGER + EXEC + PROV)
```

### Path D — Contribute to the framework

1. [`CONTRIBUTING.md`](CONTRIBUTING.md) — RFC process for normative changes
2. [`SECURITY.md`](SECURITY.md) — Responsible vulnerability disclosure

---

## Conformance Levels

| Level | Name | Required specs |
|---|---|---|
| **L1** | Core | SIGN · AGENT · CT · CAP-REG · HP · DCMA · MESSAGES |
| **L2** | Security | L1 + RISK · REV · ITA-1.0 |
| **L3** | Verifiable Execution | L2 + API · EXEC · LEDGER · PROVENANCE · POLICY-CTX · PSN |
| **L4** | Governance | L3 + PAY · REP-1.2 · ITA-1.1 · GOV-EVENTS · LIA · HIST · NOTIFY · DISC · BULK · CROSS-ORG · REP-PORTABILITY |
| **L5** | Federation | L4 + ACP-D · ITA-1.1 BFT quorum |

Most production deployments target **L3** or **L4**.

Full normative requirements: [`spec/governance/ACP-CONF-1.2.md`](spec/governance/ACP-CONF-1.2.md)

---

## Key Concepts

**Capability Token (CT):** Signed JSON object granting an agent permission to execute a specific action. Contains: agent DID, capabilities, expiry, issuer signature.

**ITA (Institutional Trust Anchor):** Entity authorized to issue Capability Tokens. Centralized (single key) or distributed (BFT quorum).

**DCMA (Delegation Chain):** Multi-hop delegation with non-escalation and transitive revocation guarantees.

**HP (Handshake Protocol):** Two-phase challenge/response protocol proving possession of a CT before any protected endpoint is accessed.

**DID (Decentralized Identifier):** Agent cryptographic identity, independent of provider or platform.

---

## Questions and Contributions

- General questions: [GitHub Discussions](https://github.com/chelof100/acp-framework-en/discussions)
- Security vulnerabilities: [`SECURITY.md`](SECURITY.md)
- Normative changes: RFC process in [`CONTRIBUTING.md`](CONTRIBUTING.md)
