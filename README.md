# ACP Framework — Agent Control Protocol

**Constitutional Architecture for Autonomous Agent Governance**

ACP (Agent Control Protocol) is a comprehensive governance and verifiable execution framework for autonomous AI agents.

It defines a unified framework that integrates:
- Architectural foundations of institutional sovereignty
- Formal governance model (GAT)
- Cryptographic control and delegation protocol
- Compliance and public certification infrastructure

ACP is not solely a messaging or signing protocol. It is a constitutional architecture that establishes formal rules under which an autonomous agent may act.

**Version:** 1.3 | **License:** Apache 2.0 | **Author:** Marcelo Fernandez — TraslaIA | info@traslaia.com

---

## The problem it solves

Organizations are deploying autonomous AI agents without answers to critical questions:

- Who authorized this agent to execute this action?
- Can I prove it cryptographically, after the fact?
- Can I revoke or restrict that authorization dynamically?
- Does this work with any AI provider?

**ACP Framework** is the complete answer to all four questions.

---

## Fundamental Invariant

```
Execute(request) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

No action is executed without these four conditions being cryptographically verifiable.

---

## The three framework levels

```
┌──────────────────────────────────────────────────────────────┐
│  LEVEL 1 — Sovereign AI Architecture                          │
│                                                               │
│  The WHY.                                                     │
│  Organizations need real independence from AI providers.      │
│  Sovereignty is not an option — it is an architectural        │
│  requirement.                                                 │
│                                                               │
│  → 01-sovereign-architecture/                                 │
├──────────────────────────────────────────────────────────────┤
│  LEVEL 2 — GAT Model                                          │
│  (Architectural Agent Governance)                             │
│                                                               │
│  The WHAT.                                                    │
│  Formal separation between decision and execution.            │
│  Structural traceability. Measurable maturity.                │
│                                                               │
│  → 02-gat-model/                                              │
├──────────────────────────────────────────────────────────────┤
│  LEVEL 3 — ACP Protocol v1.0                                  │
│  (Agent Control Protocol)                                     │
│                                                               │
│  The HOW.                                                     │
│  Cryptographic implementation of the above principles.        │
│  5 technical layers. 5 conformance levels. Certifiable.       │
│                                                               │
│  → 03-acp-protocol/                                           │
└──────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

### [`01-sovereign-architecture/`](01-sovereign-architecture/) — Level 1

The philosophical and strategic foundations. Why institutional sovereignty over AI agents is not optional.

| Document | Content |
|---|---|
| [Sovereign-AI-Architecture.md](01-sovereign-architecture/Sovereign-AI-Architecture.md) | Complete sovereignty framework |
| [Sovereign-AI-Architecture-Framework.md](01-sovereign-architecture/Sovereign-AI-Architecture-Framework.md) | Sovereignty framework full specification |
| [ACP-Foundational-Doctrine.md](01-sovereign-architecture/ACP-Foundational-Doctrine.md) | The three cryptographic pillars of the protocol |
| [Risk-without-Sovereign-Architecture.csv](01-sovereign-architecture/Risk-without-Sovereign-Architecture.csv) | Risk matrix without sovereign architecture |

---

### [`02-gat-model/`](02-gat-model/) — Level 2

The Architectural Agent Governance model. How to structure organizations that operate autonomous agents.

| Document | Content |
|---|---|
| [GAT-Maturity-Model.md](02-gat-model/GAT-Maturity-Model.md) | GAT Model v1.1 — Maturity Matrix levels 0-5 |
| [Three-Layer-Architecture.md](02-gat-model/Three-Layer-Architecture.md) | Synthesis of the 3 framework levels |
| [ACP-Architecture-Specification.md](02-gat-model/ACP-Architecture-Specification.md) | Unified technical architecture — 5 layers |
| [Roadmap.md](02-gat-model/Roadmap.md) | Protocol status and roadmap v1.x / v2.0 |
| [matrices/](02-gat-model/matrices/) | GAT maturity matrices (CSV) |

---

### [`03-acp-protocol/`](03-acp-protocol/) — Level 3

The technical implementation. Normative specification, compliance, and test vectors.

#### Technical Specification

**Core L1 — mandatory for any implementer**

| Document | Function |
|---|---|
| [ACP-SIGN-1.0.md](03-acp-protocol/specification/core/ACP-SIGN-1.0.md) | JCS serialization + Ed25519 signature |
| [ACP-CT-1.0.md](03-acp-protocol/specification/core/ACP-CT-1.0.md) | Capability Token structure and verification |
| [ACP-CAP-REG-1.0.md](03-acp-protocol/specification/core/ACP-CAP-REG-1.0.md) | Canonical capability registry |
| [ACP-HP-1.0.md](03-acp-protocol/specification/core/ACP-HP-1.0.md) | Handshake Protocol — proof of possession |
| [ACP-DCMA-1.0.md](03-acp-protocol/specification/core/ACP-DCMA-1.0.md) | Multi-agent chained delegation — non-escalation + transitive revocation |
| [ACP-AGENT-SPEC-0.3.md](03-acp-protocol/specification/core/ACP-AGENT-SPEC-0.3.md) | Formal agent ontology — `A=(ID,C,P,D,L,S)` |
| [ACP-MESSAGES-1.0.md](03-acp-protocol/specification/core/ACP-MESSAGES-1.0.md) | Protocol wire format — 5 normalized message types |

**Security L2 — token issuers**

| Document | Function |
|---|---|
| [ACP-RISK-1.0.md](03-acp-protocol/specification/security/ACP-RISK-1.0.md) | Deterministic risk engine (RS 0-100) |
| [ACP-REV-1.0.md](03-acp-protocol/specification/security/ACP-REV-1.0.md) | Revocation protocol (endpoint + CRL) |
| [ACP-ITA-1.0.md](03-acp-protocol/specification/security/ACP-ITA-1.0.md) | Institutional Trust Anchor — centralized model |
| [ACP-ITA-1.1.md](03-acp-protocol/specification/security/ACP-ITA-1.1.md) | Trust Anchor Governance — distributed BFT model |
| [ACP-REP-1.1.md](03-acp-protocol/specification/security/ACP-REP-1.1.md) | Reputation Extension — adaptive score [0,1] |

**Operations L3 — complete system**

| Document | Function |
|---|---|
| [ACP-API-1.0.md](03-acp-protocol/specification/operations/ACP-API-1.0.md) | Formal HTTP API with all endpoints |
| [ACP-EXEC-1.0.md](03-acp-protocol/specification/operations/ACP-EXEC-1.0.md) | Execution Tokens — single-use, 300s |
| [ACP-LEDGER-1.0.md](03-acp-protocol/specification/operations/ACP-LEDGER-1.0.md) | Append-only hash-chained Audit Ledger |
| [ACP-PAY-1.0.md](03-acp-protocol/specification/operations/ACP-PAY-1.0.md) | Payment Extension — capability with verifiable settlement |

**Governance — conformance levels**

| Document | Function |
|---|---|
| [ACP-CONF-1.1.md](03-acp-protocol/specification/governance/ACP-CONF-1.1.md) | **Conformance 5 cumulative levels L1-L5** (normative) |
| [ACP-CONF-1.0.md](03-acp-protocol/specification/governance/ACP-CONF-1.0.md) | ⚠️ Deprecated — superseded by CONF-1.1 |

**Decentralized L5 — ACP-D**

| Document | Function |
|---|---|
| [ACP-D-Specification.md](03-acp-protocol/specification/decentralized/ACP-D-Specification.md) | Complete ACP-D technical specification |
| [Architecture-Without-Central-Issuer.md](03-acp-protocol/specification/decentralized/Architecture-Without-Central-Issuer.md) | DID + VC + Self-Sovereign Capability model |
| [README-ACP-D.md](03-acp-protocol/specification/decentralized/README-ACP-D.md) | Context and differences from ACP v1.0 |

#### Compliance and Certification

Complete chain: specification → test suite → runner → public certification.

```
CONF-1.1 → TS-SCHEMA (form) → TS-1.0 (what to pass) → TS-1.1 (JSON format)
         → IUT-PROTOCOL (runner↔impl contract) → ACR-1.0 (executes)
         → CERT-1.0 (public verifiable badge)
```

| Document | Function |
|---|---|
| [ACP-TS-SCHEMA-1.0.md](03-acp-protocol/compliance/ACP-TS-SCHEMA-1.0.md) | Formal JSON Schema for test vectors (Draft 2020-12) |
| [ACP-TS-1.0.md](03-acp-protocol/compliance/ACP-TS-1.0.md) | Test Suite — required cases per level L1-L5 |
| [ACP-TS-1.1.md](03-acp-protocol/compliance/ACP-TS-1.1.md) | Normative vector format — deterministic, language-agnostic |
| [ACP-IUT-PROTOCOL-1.0.md](03-acp-protocol/compliance/ACP-IUT-PROTOCOL-1.0.md) | Runner ↔ IUT contract — STDIN/STDOUT, timeouts, manifest |
| [ACR-1.0.md](03-acp-protocol/compliance/ACR-1.0.md) | Official Compliance Runner — executes tests and issues certifications |
| [ACP-CERT-1.0.md](03-acp-protocol/compliance/ACP-CERT-1.0.md) | Public Certification System — badge ACP-CERT-YYYY-NNNN |

#### Normative Test Vectors

12 deterministic JSON vectors for validating implementations against ACP-TS-1.1.

| File | Layer | Type | Expected Result |
|---|---|---|---|
| [TS-CORE-POS-001](03-acp-protocol/test-vectors/TS-CORE-POS-001-valid-canonical-capability.json) | CORE | ✅ | `VALID` — canonical capability |
| [TS-CORE-POS-002](03-acp-protocol/test-vectors/TS-CORE-POS-002-valid-multiple-actions.json) | CORE | ✅ | `VALID` — multiple actions |
| [TS-CORE-NEG-001](03-acp-protocol/test-vectors/TS-CORE-NEG-001-expired-token.json) | CORE | ❌ | `REJECT / EXPIRED` |
| [TS-CORE-NEG-002](03-acp-protocol/test-vectors/TS-CORE-NEG-002-missing-expiry.json) | CORE | ❌ | `REJECT / MALFORMED_INPUT` |
| [TS-CORE-NEG-003](03-acp-protocol/test-vectors/TS-CORE-NEG-003-missing-nonce.json) | CORE | ❌ | `REJECT / MALFORMED_INPUT` |
| [TS-CORE-NEG-004](03-acp-protocol/test-vectors/TS-CORE-NEG-004-invalid-signature.json) | CORE | ❌ | `REJECT / INVALID_SIGNATURE` |
| [TS-CORE-NEG-005](03-acp-protocol/test-vectors/TS-CORE-NEG-005-revoked-token.json) | CORE | ❌ | `REJECT / REVOKED` |
| [TS-CORE-NEG-006](03-acp-protocol/test-vectors/TS-CORE-NEG-006-untrusted-issuer.json) | CORE | ❌ | `REJECT / UNTRUSTED_ISSUER` |
| [TS-DCMA-POS-001](03-acp-protocol/test-vectors/TS-DCMA-POS-001-valid-delegation-chain.json) | DCMA | ✅ | `VALID` — single-hop delegation |
| [TS-DCMA-NEG-001](03-acp-protocol/test-vectors/TS-DCMA-NEG-001-privilege-escalation.json) | DCMA | ❌ | `REJECT / ACCESS_DENIED` |
| [TS-DCMA-NEG-002](03-acp-protocol/test-vectors/TS-DCMA-NEG-002-revoked-delegator.json) | DCMA | ❌ | `REJECT / REVOKED` |
| [TS-DCMA-NEG-003](03-acp-protocol/test-vectors/TS-DCMA-NEG-003-delegation-depth-exceeded.json) | DCMA | ❌ | `REJECT / DELEGATION_DEPTH` |

---

### [`04-formal-analysis/`](04-formal-analysis/)

Formal security analysis, threat modeling, and systemic hardening.

| Document | Content |
|---|---|
| [Formal-Security-Model.md](04-formal-analysis/Formal-Security-Model.md) | Formal model with unforgeability and replay resistance theorems |
| [Formal-Security-Model-v2.md](04-formal-analysis/Formal-Security-Model-v2.md) | Updated version — probabilistic security bounds |
| [Threat-Model.md](04-formal-analysis/Threat-Model.md) | Complete STRIDE analysis |
| [Adversarial-Analysis.md](04-formal-analysis/Adversarial-Analysis.md) | 10 attack vectors with mitigations |
| [Systemic-Hardening.md](04-formal-analysis/Systemic-Hardening.md) | 10 operational hardening areas |
| [Security-Mathematical-Model.md](04-formal-analysis/Security-Mathematical-Model.md) | Formalization S = (A, K, T, R, V) |
| [Security-Reduction-EUF-CMA.md](04-formal-analysis/Security-Reduction-EUF-CMA.md) | Reduction to Ed25519 EUF-CMA security |
| [Formal-Decision-Engine-MFMD.md](04-formal-analysis/Formal-Decision-Engine-MFMD.md) | Formal Decision Engine — MFMD-ACP, states and transitions |

---

### [`05-implementation/`](05-implementation/)

Implementation guides: from concept to code.

| Document | Content |
|---|---|
| [Minimum-Required-Architecture.md](05-implementation/Minimum-Required-Architecture.md) | The 5 minimum components (MRA) for L1 |
| [Cryptographic-MVP.md](05-implementation/Cryptographic-MVP.md) | Minimum functional implementation |
| [Python-Prototype.md](05-implementation/Python-Prototype.md) | PME v0.1 — Python prototype with 6 test cases |

---

### [`06-publications/`](06-publications/)

Academic and technical documentation for external audiences.

| Document | Audience |
|---|---|
| [ACP-Whitepaper-v1.0.md](06-publications/ACP-Whitepaper-v1.0.md) | CTOs, architects, technical decision-makers |
| [ACP-Technical-Academic.md](06-publications/ACP-Technical-Academic.md) | Researchers, formal technical reviewers |
| [IEEE-NDSS-Paper-Structure.md](06-publications/IEEE-NDSS-Paper-Structure.md) | Paper draft — target IEEE S&P / NDSS |

---

## Conformance Levels

| Level | Name | Requires | For whom |
|---|---|---|---|
| **L1** | CORE | SIGN + CT + CAP-REG + HP | Every implementer |
| **L2** | SECURITY | L1 + RISK + REV + ITA-1.0 | Centralized token issuers |
| **L3** | FULL | L2 + API + EXEC + LEDGER | Complete centralized system |
| **L4** | EXTENDED | L3 + PAY + REP + ITA-1.1 | With economic and reputational extensions |
| **L5** | DECENTRALIZED | L4 + ACP-D + ITA-1.1 BFT | Byzantine fault-tolerant |

---

## Get Started (5 minutes)

```bash
# 1. Start the ACP server (Go reference implementation)
cd 07-reference-implementation
export ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE  # RFC 8037 test key
docker compose up -d

# 2. Verify the server is running
curl http://localhost:8080/acp/v1/health
# {"status":"ok","version":"1.0.0"}
```

**Python SDK** (Node/AI agent side):
```python
from acp import AgentIdentity, ACPSigner, ACPClient

# Generate agent identity
agent = AgentIdentity.generate()
signer = ACPSigner(agent)
client = ACPClient("http://localhost:8080", agent, signer)

# Register with the institution
client.register()

# Build and sign a capability token
token = {
    "ver": "1.0", "iss": "did:key:z<institution-key>",
    "sub": agent.agent_id, "cap": "acp:cap:financial.read",
    "resource": "account:12345", "iat": 1700000000, "exp": 1700003600, "nonce": "abc123"
}
signed = signer.sign_capability(token)

# Verify with the institution (full Challenge/PoP handshake)
result = client.verify(signed)
print(result)  # {"decision": "PERMIT", ...}
```

**TypeScript SDK** (Node.js):
```typescript
import { AgentIdentity, ACPSigner, ACPClient } from '@acp/sdk';

const agent = AgentIdentity.generate();
const signer = new ACPSigner(agent);
const client = new ACPClient('http://localhost:8080', agent, signer);

await client.register();

const token = {
  ver: '1.0', iss: 'did:key:z<institution-key>',
  sub: agent.agentId, cap: 'acp:cap:financial.read',
  resource: 'account:12345', iat: 1700000000, exp: 1700003600, nonce: 'abc123'
};
const signed = signer.signCapability(token);
const result = await client.verify(signed);
console.log(result); // { decision: 'PERMIT', ... }
```

→ Full documentation: [`QUICKSTART.md`](QUICKSTART.md) | [`07-reference-implementation/`](07-reference-implementation/)

---

## Roadmap

| Version | Status | Milestone |
|---|---|---|
| **v1.0** | ✅ Complete | 10 normative documents — centralized system |
| **v1.1** | ✅ Complete | PAY-1.0, REP-1.1, ITA-1.1 BFT + Architecture Spec |
| **v1.2** | ✅ Complete | CONF-1.1 (5 levels), complete compliance chain, 12 test vectors |
| **v1.3** | ✅ Complete | IUT binary (acp-evaluate, 12/12 PASS), compliance runner (ACR-1.0), Python SDK |
| **v1.4** | 🔄 In progress | SDK completeness — TypeScript (68 tests), Rust, Docker CI/CD |
| **v2.0** | 📋 Specified | Full ACP-D (BFT, ZK-proofs, DIDs) |
| **Paper** | ✍️ In preparation | Target IEEE S&P / NDSS |

---

*TraslaIA — Marcelo Fernandez — 2026 — Apache 2.0*
