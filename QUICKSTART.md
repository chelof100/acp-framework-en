# ACP Framework — Quickstart (15 minutes)

This framework has three levels. Start with the one that matches your role.

---

## The framework in 5 minutes

ACP is not just a protocol. It is a complete three-level framework:

| Level | What it defines | Where |
|---|---|---|
| **1 — Sovereign AI Architecture** | Why AI provider independence is an architectural requirement | [`01-sovereign-architecture/`](01-sovereign-architecture/) |
| **2 — GAT Model** | How to structure organizations that operate autonomous agents | [`02-gat-model/`](02-gat-model/) |
| **3 — ACP Protocol** | The cryptographically verifiable implementation of the above principles | [`03-acp-protocol/`](03-acp-protocol/) |

**Core invariant:**
```
Execute(request) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

---

## Choose your path (10 minutes)

### Path A — I want to understand the strategic framework

1. [`01-sovereign-architecture/Sovereign-AI-Architecture.md`](01-sovereign-architecture/Sovereign-AI-Architecture.md) — Why sovereignty
2. [`02-gat-model/GAT-Maturity-Model.md`](02-gat-model/GAT-Maturity-Model.md) — Maturity model 0-5
3. [`02-gat-model/Three-Layer-Architecture.md`](02-gat-model/Three-Layer-Architecture.md) — Synthesis of the 3 levels

### Path B — I want to understand the protocol design

1. [`02-gat-model/ACP-Architecture-Specification.md`](02-gat-model/ACP-Architecture-Specification.md) — Unified technical architecture
2. [`03-acp-protocol/specification/core/ACP-SIGN-1.0.md`](03-acp-protocol/specification/core/ACP-SIGN-1.0.md) — Base cryptographic layer
3. [`03-acp-protocol/specification/core/ACP-CT-1.0.md`](03-acp-protocol/specification/core/ACP-CT-1.0.md) — Capability Token format

### Path C — I want to implement ACP

1. [`03-acp-protocol/specification/governance/ACP-CONF-1.1.md`](03-acp-protocol/specification/governance/ACP-CONF-1.1.md) — What each level L1-L5 requires
2. [`03-acp-protocol/compliance/ACP-TS-1.1.md`](03-acp-protocol/compliance/ACP-TS-1.1.md) — Test vector format
3. [`03-acp-protocol/compliance/ACP-IUT-PROTOCOL-1.0.md`](03-acp-protocol/compliance/ACP-IUT-PROTOCOL-1.0.md) — Runner ↔ implementation contract
4. [`03-acp-protocol/compliance/ACR-1.0.md`](03-acp-protocol/compliance/ACR-1.0.md) — Run the compliance runner
5. [`03-acp-protocol/test-vectors/`](03-acp-protocol/test-vectors/) — 12 normative vectors ready to use

### Path E — I want to run the reference implementation

**Prerequisites:** Docker, Git, Go 1.21+ (or Docker only)

**Step 1 — Clone and start the server**
```bash
git clone https://github.com/chelof100/acp-framework-en
cd acp-framework-en/07-reference-implementation

# Start the Go server (uses RFC 8037 test key for development)
export ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE
docker compose up -d

# Verify
curl http://localhost:8080/acp/v1/health
# {"status":"ok","version":"1.0.0"}
```

**Step 2 — Choose your SDK**

*Python:*
```bash
cd sdk/python
pip install -e ".[dev]"
ACP_SERVER_URL=http://localhost:8080 python examples/agent_payment.py
```

*TypeScript (Node.js 18+):*
```bash
cd sdk/typescript
npm install
```
```typescript
import { AgentIdentity, ACPSigner, ACPClient } from './src';

const agent = AgentIdentity.generate();
const signer = new ACPSigner(agent);
const client = new ACPClient('http://localhost:8080', agent, signer);

// Register agent with institution
await client.register();
console.log('Agent ID:', agent.agentId);
console.log('DID:', agent.did);

// Health check
const health = await client.health();
console.log('Server:', health);
```

**Step 3 — Run the compliance suite**
```bash
cd 07-reference-implementation/acp-go

# Run IUT against all 12 ACP-TS-1.1 test vectors
go test ./pkg/iut/... -v
# 12/12 PASS → CONFORMANT L1+L2

# Or run the full compliance runner
go run ./cmd/acp-runner --impl ./acp-evaluate.exe --suite ../../../03-acp-protocol/test-vectors
```

→ Full reference docs: [`07-reference-implementation/README.md`](07-reference-implementation/README.md)

### Path D — I want to contribute to the framework

1. [`CONTRIBUTING.md`](CONTRIBUTING.md) — RFC process for normative changes
2. [`SECURITY.md`](SECURITY.md) — Responsible vulnerability disclosure
3. [`02-gat-model/Roadmap.md`](02-gat-model/Roadmap.md) — Current status and next steps

---

## Conformance Levels

| Level | Name | Requires |
|---|---|---|
| **L1** | CORE | SIGN + CT + CAP-REG + HP |
| **L2** | SECURITY | L1 + RISK + REV + ITA-1.0 |
| **L3** | FULL | L2 + API + EXEC + LEDGER |
| **L4** | EXTENDED | L3 + PAY + REP + ITA-1.1 |
| **L5** | DECENTRALIZED | L4 + ACP-D + BFT quorum |

Most production deployments target **L3** or **L4**.

---

## Key Concepts

**Capability Token (CT):** Signed JSON object granting an agent permission to execute a specific action. Contains: agent DID, permissions, expiry, issuer signature.

**ITA (Institutional Trust Anchor):** Entity authorized to issue Capability Tokens. Can be centralized (single key) or distributed (BFT quorum).

**DCMA (Delegation Chain):** Mechanism for agents to delegate sub-capabilities, with non-escalation and transitive revocation guarantees.

**DID (Decentralized Identifier):** Agent cryptographic identity, independent of provider or platform.

---

## Questions and Contributions

- General questions: GitHub Discussions
- Security vulnerabilities: [`SECURITY.md`](SECURITY.md)
- Normative changes: RFC process in [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Contact: info@traslaia.com
