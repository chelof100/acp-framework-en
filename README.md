# ACP Framework — Agent Control Protocol

**Constitutional Architecture for Autonomous Agent Governance**

ACP (Agent Control Protocol) is a formal governance and verifiable execution protocol for autonomous AI agents operating in institutional environments.

It is not a messaging format or a signing library. It is a **constitutional architecture**: a set of formal rules that determines under what conditions an autonomous agent may act, by whose authority, with what accountability, and with what retrospective proof.

**Version:** 1.10 | **License:** Apache 2.0 | **Author:** Marcelo Fernandez — TraslaIA | info@traslaia.com

→ Full architectural model: [`ARCHITECTURE.md`](ARCHITECTURE.md)

---

## The problem it solves

Organizations deploying autonomous AI agents face four questions with no current industry answer:

- **Who authorized** this agent to execute this action?
- **Can I prove it cryptographically**, after the fact?
- **Can I revoke or restrict** that authorization dynamically?
- **Does this work** with any AI provider or execution environment?

ACP is the complete answer to all four.

---

## Constitutional Invariant

```
Execute(request) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

No agent action executes unless all four conditions hold simultaneously and are verifiable after the fact from the audit record. This is the architectural constraint from which every spec derives.

---

## Architecture: 8-Layer Governance Stack

ACP is organized in eight cumulative layers. Each layer depends on all layers below it.

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 8 — RISK ARCHITECTURE                                     │
│  RISK-1.0 · PSN-1.0 · CROSS-ORG-1.0 · BULK-1.0                 │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 7 — REPUTATION                                            │
│  REP-1.2 (ITS + ERS composite) · REP-PORTABILITY                │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 6 — LIABILITY & TRUST                                     │
│  LIA-1.0 · ITA-1.0 · ITA-1.1 (BFT) · GOV-EVENTS-1.0           │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 5 — VERIFIABLE HISTORY                                    │
│  LEDGER-1.2 · HIST-1.0                                          │
├═════════════════════════════════════════════════════════════════╡
│  LAYER 4 — EXECUTION GOVERNANCE          ← constitutional core  │
│  EXEC-1.0 · POLICY-CTX-1.0 · PROVENANCE-1.0 · API-1.0          │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3 — DELEGATION                                            │
│  HP-1.0 · DCMA-1.0 · MESSAGES-1.0                               │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2 — CAPABILITY                                            │
│  CT-1.0 · CAP-REG-1.0                                           │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1 — IDENTITY                                              │
│  SIGN-1.0 · AGENT-1.0                                           │
└─────────────────────────────────────────────────────────────────┘
```

Layers 1–3: *who can do what, by what authority*
Layer 4: *enforcement of the constitutional invariant*
Layers 5–8: *evidentiary depth — what was done, with what consequence, by whom*

---

## How Specs Connect

The critical dependency chains every implementer must understand:

| Chain | Role |
|---|---|
| `SIGN → CT → HP → EXEC` | Execution authority — minimum path for any authorized action |
| `EXEC → LEDGER → HIST` | Audit trail — from execution to queryable, immutable history |
| `EXEC → POLICY-CTX + PROVENANCE` | Evidence layer — retrospective proof: *by what policy, through what chain* |
| `ITA → REP → REP-PORTABILITY` | Trust chain — institutional vouching → portable behavioral score |
| `LEDGER → LIA` | Liability chain — audit log → attributed liability traceability |
| `GOV-EVENTS → HIST` | Governance chain — institutional events visible in agent history |

→ Full dependency graph with formal properties: [`ARCHITECTURE.md`](ARCHITECTURE.md)

---

## Conformance Levels

| Level | Name | Layers | Required specs |
|---|---|---|---|
| **L1** | CORE | 1–3 | SIGN · AGENT · CT · CAP-REG · HP · DCMA · MESSAGES |
| **L2** | SECURITY | 1–3 + partial 6 | L1 + RISK · REV · ITA-1.0 |
| **L3** | FULL | 1–5 | L2 + API · EXEC · LEDGER · **PROVENANCE · POLICY-CTX** |
| **L4** | EXTENDED | 1–7 | L3 + **GOV-EVENTS** · PAY · REP-1.2 · ITA-1.1 · LIA · HIST · NOTIFY · DISC · BULK · CROSS-ORG · REP-PORTABILITY |
| **L5** | DECENTRALIZED | 1–8 | L4 + ACP-D · ITA-1.1 BFT quorum |

→ Normative conformance definition: [`spec/governance/ACP-CONF-1.1.md`](spec/governance/ACP-CONF-1.1.md)

---

## Specification Index

### [`spec/core/`](spec/core/) — Identity, Capability, Delegation (L1)

| Spec | Function |
|---|---|
| [ACP-SIGN-1.0](spec/core/ACP-SIGN-1.0.md) | JCS serialization + Ed25519 signing — foundation of all protocol objects |
| [ACP-AGENT-1.0](spec/core/ACP-AGENT-1.0.md) | Formal agent ontology — `A=(ID,C,P,D,L,S)` |
| [ACP-CT-1.0](spec/core/ACP-CT-1.0.md) | Capability Token — structure, issuance, verification |
| [ACP-CAP-REG-1.0](spec/core/ACP-CAP-REG-1.0.md) | Canonical capability registry — `acp:cap:*` namespace |
| [ACP-HP-1.0](spec/core/ACP-HP-1.0.md) | Handshake Protocol — cryptographic proof of capability possession |
| [ACP-DCMA-1.0](spec/core/ACP-DCMA-1.0.md) | Multi-hop delegation — non-escalation + transitive revocation |
| [ACP-MESSAGES-1.0](spec/core/ACP-MESSAGES-1.0.md) | Wire format — 5 normalized message types |
| [ACP-PROVENANCE-1.0](spec/core/ACP-PROVENANCE-1.0.md) | Authority Provenance — retrospective proof of delegation chain at execution |

### [`spec/security/`](spec/security/) — Trust, Risk, Revocation (L2)

| Spec | Function |
|---|---|
| [ACP-RISK-1.0](spec/security/ACP-RISK-1.0.md) | Deterministic risk engine — Risk Score RS (0–100) |
| [ACP-REV-1.0](spec/security/ACP-REV-1.0.md) | Revocation protocol — endpoint + CRL |
| [ACP-ITA-1.0](spec/security/ACP-ITA-1.0.md) | Institutional Trust Anchor — centralized model |
| [ACP-ITA-1.1](spec/security/ACP-ITA-1.1.md) | Trust Anchor Governance — distributed BFT model |
| [ACP-REP-1.2](spec/security/ACP-REP-1.2.md) | Reputation Extension — dual model ITS+ERS, composite score `0.6·ITS + 0.4·ERS` |

### [`spec/operations/`](spec/operations/) — Execution Governance, History (L3–L4)

| Spec | Function |
|---|---|
| [ACP-API-1.0](spec/operations/ACP-API-1.0.md) | HTTP API — all institutional endpoints |
| [ACP-EXEC-1.0](spec/operations/ACP-EXEC-1.0.md) | Execution Tokens — single-use, 300s validity |
| [ACP-LEDGER-1.2](spec/operations/ACP-LEDGER-1.2.md) | Audit Ledger — append-only, hash-chained |
| [ACP-POLICY-CTX-1.0](spec/operations/ACP-POLICY-CTX-1.0.md) | Policy Context Snapshot — signed policy state at execution time |
| [ACP-HIST-1.0](spec/operations/ACP-HIST-1.0.md) | History Query API — audited execution history |
| [ACP-LIA-1.0](spec/operations/ACP-LIA-1.0.md) | Liability Traceability — attributed liability chain |
| [ACP-PAY-1.0](spec/operations/ACP-PAY-1.0.md) | Payment Extension — verifiable financial capability |
| [ACP-PSN-1.0](spec/operations/ACP-PSN-1.0.md) | Policy Snapshot — signed point-in-time policy state |
| [ACP-NOTIFY-1.0](spec/operations/ACP-NOTIFY-1.0.md) | Notification Extension — events and webhooks |
| [ACP-DISC-1.0](spec/operations/ACP-DISC-1.0.md) | Discovery Extension — agent registry and resolution |
| [ACP-BULK-1.0](spec/operations/ACP-BULK-1.0.md) | Bulk Operations — batch capability execution |
| [ACP-CROSS-ORG-1.0](spec/operations/ACP-CROSS-ORG-1.0.md) | Cross-Org Protocol — inter-institutional agent interactions |

### [`spec/governance/`](spec/governance/) — Conformance, Process, Events (L1–L4)

| Spec | Function |
|---|---|
| [ACP-CONF-1.1](spec/governance/ACP-CONF-1.1.md) | **Conformance** — 5 cumulative levels L1-L5 (normative) |
| [ACP-TS-1.1](spec/governance/ACP-TS-1.1.md) | Test Suite 1.1 — normative vector format |
| [RFC-PROCESS](spec/governance/RFC-PROCESS.md) | Specification process — how ACP evolves |
| [RFC-REGISTRY](spec/governance/RFC-REGISTRY.md) | RFC registry — all active change proposals |
| [ACR-1.0](spec/governance/ACR-1.0.md) | Compliance Runner — executes tests, issues certifications |
| [ACP-GOV-EVENTS-1.0](spec/governance/ACP-GOV-EVENTS-1.0.md) | Governance Event Stream — formal taxonomy of 10 institutional event types |

### [`spec/decentralized/`](spec/decentralized/) — ACP-D (L5)

| Spec | Function |
|---|---|
| ACP-D-Specification | Complete ACP-D specification — DID + VC + Self-Sovereign Capability |
| Architecture-Without-Central-Issuer | Byzantine fault-tolerant model without central issuer |

---

## Compliance and Certification

Complete chain: specification → test vectors → runner → public certification badge.

```
CONF-1.1 → TS-SCHEMA (form) → TS-1.0 (cases) → TS-1.1 (JSON format)
         → IUT-PROTOCOL (runner↔impl contract) → ACR-1.0 (executes)
         → CERT-1.0 (public verifiable badge ACP-CERT-YYYY-NNNN)
```

| Document | Function |
|---|---|
| [ACP-TS-SCHEMA-1.0](compliance/ACP-TS-SCHEMA-1.0.md) | JSON Schema for test vectors (Draft 2020-12) |
| [ACP-TS-1.0](compliance/ACP-TS-1.0.md) | Test Suite — required cases per level L1-L5 |
| [ACP-TS-1.1](compliance/ACP-TS-1.1.md) | Normative vector format — deterministic, language-agnostic |
| [ACP-IUT-PROTOCOL-1.0](compliance/ACP-IUT-PROTOCOL-1.0.md) | Runner ↔ IUT contract — STDIN/STDOUT, timeouts, manifest |
| [ACR-1.0](compliance/ACR-1.0.md) | Official Compliance Runner |
| [ACP-CERT-1.0](compliance/ACP-CERT-1.0.md) | Public Certification System |

**Normative test vectors:** [`compliance/test-vectors/`](compliance/test-vectors/) — 12 deterministic JSON vectors (8 CORE + 4 DCMA).

---

## Quick Start

```bash
# Start the ACP reference server (Go)
cd impl/go
export ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6ggvPbw-uvmjgn-hWQpIRTkHcakE
docker compose up -d

curl http://localhost:8080/acp/v1/health
# {"status":"ok","version":"1.0.0"}
```

```python
from acp import AgentIdentity, ACPSigner, ACPClient

agent = AgentIdentity.generate()
client = ACPClient("http://localhost:8080", agent, ACPSigner(agent))
client.register()

token = {
    "ver": "1.0", "iss": "did:key:z<institution>",
    "sub": agent.agent_id, "cap": ["acp:cap:financial.read"],
    "resource": "account:12345", "iat": 1700000000, "exp": 1700003600, "nonce": "abc123"
}
result = client.verify(ACPSigner(agent).sign_capability(token))
print(result)  # {"decision": "PERMIT", ...}
```

→ Full guide: [`QUICKSTART.md`](QUICKSTART.md) | Reference implementations: [`impl/`](impl/)

---

## Roadmap

| Version | Status | Milestone |
|---|---|---|
| **v1.0** | ✅ | 10 normative specs — centralized system |
| **v1.1** | ✅ | PAY-1.0 · REP-1.1 · ITA-1.1 BFT |
| **v1.2** | ✅ | CONF-1.1 (5 levels) · compliance chain · 12 test vectors |
| **v1.3** | ✅ | IUT binary (12/12 PASS) · ACR-1.0 · Python SDK |
| **v1.4** | ✅ | TypeScript SDK · Rust SDK · Docker CI/CD |
| **v1.5** | ✅ | Go Reference Server — 9 specs implemented |
| **v1.6** | ✅ | AGENT-1.0 (formal ontology) · MESSAGES-1.0 · DCMA-1.0 |
| **v1.7** | ✅ | LIA-1.0 · PSN-1.0 · LEDGER-1.1 — bankability layer |
| **v1.8** | ✅ | REP-1.2 (ITS+ERS) · LEDGER-1.2 (extended events) |
| **v1.9** | ✅ | HIST-1.0 · NOTIFY-1.0 · DISC-1.0 · BULK-1.0 · CROSS-ORG-1.0 |
| **v1.10** | ✅ | PROVENANCE-1.0 · POLICY-CTX-1.0 · GOV-EVENTS-1.0 — evidence layer |
| **Paper** | ✍️ | Target IEEE S&P / NDSS |
| **v2.0** | 📋 | ACP-D full (BFT · ZK-proofs · DIDs) |

---

*TraslaIA — Marcelo Fernandez — 2026 — Apache 2.0*
