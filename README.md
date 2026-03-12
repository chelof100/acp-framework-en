# ACP — Agent Control Protocol

Verifiable governance for autonomous agents.

ACP defines who authorized an agent, what it executed, and who is accountable — across systems and institutions.

`Authority verification · Execution accountability · Institutional traceability`

---

## Why ACP Exists

Autonomous agents are moving from experimentation into production. They already interact with APIs, enterprise systems, financial infrastructure, and other agents.

When one acts across organizations, several questions immediately arise:

- Who authorized the agent to act?
- What capabilities does the agent actually have?
- What policy allowed the action?
- What exactly was executed?
- Can that execution be verified later?
- Can the full interaction history be reconstructed?

Today, most systems cannot answer these questions reliably.

ACP introduces the infrastructure to answer all of them.

---

## ACP vs Related Protocols

Several initiatives address how autonomous agents interact with systems.
Most focus on **tool access or communication**.
ACP focuses on **authority, execution verification, and institutional accountability**.

| Protocol | Focus | Scope boundary |
|---|---|---|
| MCP (Model Context Protocol) | Tool access for LLMs | Authority verification, policy enforcement, execution auditability |
| A2A (Agent-to-Agent) | Agent communication patterns | Institutional trust, governance, accountability chain |
| OpenAI Agents SDK | Tool orchestration | Cross-organization authority, provenance, liability |
| Agent Client Protocol ¹ | Runtime client/agent integration | Governance, delegation chains, verifiable execution history |
| **ACP (Agent Control Protocol)** | **Governance & accountability infrastructure** | **—** |

ACP addresses a different layer: **who authorized the action, under what policy, and who is accountable for the outcome**.

---

¹ ACP (Agent Control Protocol) is unrelated to other initiatives sharing the same acronym.

---

## How ACP Works

ACP treats agent interactions as **governable operations**, not simple requests.

Every interaction passes through six structured stages:

1. **Identity verification** — confirm who the agent is
2. **Capability validation** — confirm what the agent is authorized to do
3. **Policy authorization** — confirm the action is permitted under current policy
4. **Deterministic execution** — execute exactly what was authorized, nothing more
5. **Verifiable recording** — produce cryptographic proof of what occurred
6. **Trust update** — update reputation and attestation state based on the interaction

This allows interactions to become traceable, auditable and attributable across organizations.

---

## Constitutional Invariant

ACP execution is governed by a single architectural invariant.

```
Execute(request) ⟹
    ValidIdentity  ∧  ValidCapability  ∧  ValidDelegationChain  ∧  AcceptableRisk
```

| Condition | Meaning |
|---|---|
| `ValidIdentity` | The agent has a verified, signed identity |
| `ValidCapability` | The agent holds an authorized Capability Token |
| `ValidDelegationChain` | Every delegation step is traceable to an institutional root |
| `AcceptableRisk` | The risk score is within institutional policy thresholds |

No agent action is executed unless all four conditions are satisfied simultaneously.

The protocol layers exist to enforce this invariant at every interaction boundary.

---

## Protocol Architecture

ACP is organized in five protocol layers.
Each layer builds on the previous and adds a distinct governance capability.

```
                    ACP PROTOCOL ARCHITECTURE

             ┌──────────────────────────────────────┐
             │                ACTORS                │
             │       Humans · Systems · Agents      │
             └──────────────────────────────────────┘
                                │
                                ▼
==================================================================== L1 — CORE EXECUTION

┌──────────────────────────────────────────────────────────────────┐
│ IDENTITY & CAPABILITIES                                          │
│ SIGN · AGENT · CT · CAP-REG                                      │
│                                                                  │
│ Agent identity, credential verification and capability registry  │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│ POLICY & AUTHORITY                                               │
│ HP · DCMA                                                        │
│                                                                  │
│ Policy evaluation and authorization decision                     │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│ EXECUTION                                                        │
│ MESSAGES                                                         │
│                                                                  │
│ Deterministic command execution and interaction handling         │
└──────────────────────────────────────────────────────────────────┘

==================================================================== L2 — TRUST LAYER

┌──────────────────────────────────────────────────────────────────┐
│ RISK MANAGEMENT                                                  │
│ RISK · REV                                                       │
│                                                                  │
│ Risk scoring and revocation control                              │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ INTERACTION TRUST                                                │
│ ITA                                                              │
│                                                                  │
│ Trust attestations for interactions                              │
└──────────────────────────────────────────────────────────────────┘

==================================================================== L3 — VERIFIABLE EXECUTION

┌──────────────────────────────────────────────────────────────────┐
│ EXECUTION RECORD                                                 │
│ EXEC · POLICY-CTX                                                │
│                                                                  │
│ Proof of execution and policy context snapshot                   │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ PROVENANCE                                                       │
│ PROVENANCE GRAPH                                                 │
│                                                                  │
│ Interaction lineage and cross-system event tracking              │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ LEDGER                                                           │
│                                                                  │
│ Tamper-resistant storage for verifiable execution history        │
└──────────────────────────────────────────────────────────────────┘

==================================================================== L4 — GOVERNANCE

┌──────────────────────────────────────────────────────────────────┐
│ GOVERNANCE EVENTS                                                │
│ GOV-EVENTS                                                       │
│                                                                  │
│ Institutional governance tracking                                │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ REPUTATION & LIABILITY                                           │
│ REP · LIA                                                        │
│                                                                  │
│ Reputation accumulation and liability attribution                │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ HISTORICAL RECORD                                                │
│ HIST                                                             │
│                                                                  │
│ Verifiable long-term interaction history                         │
└──────────────────────────────────────────────────────────────────┘

==================================================================== L5 — FEDERATION

┌──────────────────────────────────────────────────────────────────┐
│ DECENTRALIZED ACP                                                │
│ ACP-D                                                            │
│                                                                  │
│ Cross-institution federation and verification                    │
└──────────────────────────────────────────────────────────────────┘
```

→ Formal domain model and dependency graph: [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Cross-Institution Interaction

ACP is designed for interactions between independent systems.
Every step produces a verifiable artifact that becomes part of the permanent interaction record.

```
      INSTITUTION A                               INSTITUTION B
┌─────────────────────────────┐           ┌─────────────────────────────┐
│                             │           │                             │
│           AGENT A           │           │           AGENT B           │
│                             │           │                             │
└──────────────┬──────────────┘           └──────────────┬──────────────┘
               │                                         │
               │  1  interaction request                 │
               └────────────────────────────────────────►│
                                                         ▼
                                          ┌───────────────────────────┐
                                          │       AUTHORITY (HP)      │
                                          │  policy evaluation        │
                                          │  capability validation    │
                                          │  risk / revocation check  │
                                          └─────────────┬─────────────┘
                                                        │  2  decision
                                                        ▼
                                          ┌───────────────────────────┐
                                          │        EXECUTION          │
                                          │  deterministic action     │
                                          │  command execution        │
                                          └─────────────┬─────────────┘
                                                        │  3  execution record
                                                        ▼
                                          ┌───────────────────────────┐
                                          │        PROVENANCE         │
                                          │  interaction lineage      │
                                          │  cross-org attribution    │
                                          └─────────────┬─────────────┘
                                                        │  4  verifiable record
                                                        ▼
                                          ┌───────────────────────────┐
                                          │          LEDGER           │
                                          │  execution hash           │
                                          │  policy context snapshot  │
                                          └─────────────┬─────────────┘
                                                        │  5  trust update
                                                        ▼
                                          ┌───────────────────────────┐
                                          │        REPUTATION         │
                                          │  ITA attestation          │
                                          │  reputation update        │
                                          └───────────────────────────┘
```

---

## Design Principles

### Explicit Authority
Every agent action must be authorized by a defined policy.
No implicit permissions. No ambient access.

### Deterministic Execution
Execution must match the authorized command exactly.
What was authorized is what gets executed — nothing more.

### Verifiable History
Every interaction produces cryptographically verifiable artifacts.
Execution can be proven after the fact, without trusting any single party.

### Institutional Accountability
Responsibility is always attributable to an identifiable actor.
Delegation chains are complete and traceable to an institutional root.

### Federated Trust
Independent systems can verify each other without a central authority.
Trust is earned through verifiable interaction history, not assumed.

---

## Protocol Components

### L1 · Core Execution
Identity, capabilities, policy enforcement and deterministic execution.

| Component | Role |
|---|---|
| **SIGN** | Cryptographic signing — foundation of all protocol objects |
| **AGENT** | Formal agent identity specification `A=(ID,C,P,D,L,S)` |
| **CT** | Capability Token — structure, issuance and verification |
| **CAP-REG** | Canonical capability registry `acp:cap:*` |
| **HP** | Handshake Protocol — cryptographic proof of capability possession |
| **DCMA** | Multi-hop delegation — non-escalation and transitive revocation |
| **MESSAGES** | Wire format — 5 normalized message types |

### L2 · Trust Layer
Dynamic risk evaluation and interaction trust management.

| Component | Role |
|---|---|
| **RISK** | Deterministic risk engine — Risk Score RS (0–100) |
| **REV** | Revocation protocol — endpoint and CRL |
| **ITA** | Institutional Trust Anchor — trust attestations per interaction |

### L3 · Verifiable Execution
Every interaction leaves a complete, cryptographically verifiable record.

| Component | Role |
|---|---|
| **EXEC** | Execution Tokens — single-use, 300s validity |
| **POLICY-CTX** | Policy Context Snapshot — signed policy state at execution time |
| **PROVENANCE** | Authority Provenance — retrospective proof of delegation chain |
| **LEDGER** | Audit Ledger — append-only, hash-chained |

### L4 · Governance
Long-term accountability and institutional oversight.

| Component | Role |
|---|---|
| **GOV-EVENTS** | Governance event stream — institutional tracking |
| **REP** | Reputation Extension — composite score `0.6·ITS + 0.4·ERS` |
| **LIA** | Liability Traceability — attributed liability chain |
| **HIST** | History Query API — audited execution history |

### L5 · Federation
Interoperability across independent institutions.

| Component | Role |
|---|---|
| **ACP-D** | Decentralized ACP — cross-institution federation, BFT quorum |

---

## Conformance Levels

Implementations may adopt ACP incrementally, starting from L1.

| Level | Name | What you get |
|---|---|---|
| **L1** | Core | Identity, capability tokens and execution |
| **L2** | Security | Risk scoring, revocation and trust anchors |
| **L3** | Verifiable Execution | Execution tokens, ledger and provenance |
| **L4** | Governance | Reputation, history and liability |
| **L5** | Federation | Decentralized ACP networks |

Full normative requirements per level:

| Level | Required specs |
|---|---|
| **L1** | SIGN · AGENT · CT · CAP-REG · HP · DCMA · MESSAGES |
| **L2** | L1 + RISK · REV · ITA-1.0 |
| **L3** | L2 + API · EXEC · LEDGER · PROVENANCE · POLICY-CTX |
| **L4** | L3 + GOV-EVENTS · REP · LIA · HIST · ITA-1.1 · PAY · NOTIFY · DISC · BULK · CROSS-ORG · REP-PORTABILITY |
| **L5** | L4 + ACP-D · ITA-1.1 BFT quorum |

→ Normative conformance definition: [`spec/governance/ACP-CONF-1.1.md`](spec/governance/ACP-CONF-1.1.md)

---

## Specifications

### L1 · Core Execution
- [ACP-SIGN-1.0](spec/core/ACP-SIGN-1.0.md) — cryptographic signing, foundation of all protocol objects
- [ACP-AGENT-1.0](spec/core/ACP-AGENT-1.0.md) — formal agent identity `A=(ID,C,P,D,L,S)`
- [ACP-CT-1.0](spec/core/ACP-CT-1.0.md) — Capability Token structure, issuance and verification
- [ACP-CAP-REG-1.0](spec/core/ACP-CAP-REG-1.0.md) — canonical capability registry `acp:cap:*`
- [ACP-HP-1.0](spec/core/ACP-HP-1.0.md) — Handshake Protocol, cryptographic proof of capability possession
- [ACP-DCMA-1.0](spec/core/ACP-DCMA-1.0.md) — multi-hop delegation, non-escalation and transitive revocation
- [ACP-MESSAGES-1.0](spec/core/ACP-MESSAGES-1.0.md) — wire format, 5 normalized message types

### L2 · Trust Layer
- [ACP-RISK-1.0](spec/security/ACP-RISK-1.0.md) — deterministic risk engine, Risk Score RS (0–100)
- [ACP-REV-1.0](spec/security/ACP-REV-1.0.md) — revocation protocol, endpoint and CRL
- [ACP-ITA-1.0](spec/security/ACP-ITA-1.0.md) — Institutional Trust Anchor, centralized model
- [ACP-ITA-1.1](spec/security/ACP-ITA-1.1.md) — Trust Anchor Governance, distributed BFT model

### L3 · Verifiable Execution
- [ACP-EXEC-1.0](spec/operations/ACP-EXEC-1.0.md) — Execution Tokens, single-use, 300s validity
- [ACP-POLICY-CTX-1.0](spec/operations/ACP-POLICY-CTX-1.0.md) — signed policy state at execution time
- [ACP-PROVENANCE-1.0](spec/core/ACP-PROVENANCE-1.0.md) — retrospective proof of delegation chain at execution
- [ACP-LEDGER-1.2](spec/operations/ACP-LEDGER-1.2.md) — audit ledger, append-only, hash-chained
- [ACP-API-1.0](spec/operations/ACP-API-1.0.md) — HTTP API, all institutional endpoints

### L4 · Governance
- [ACP-GOV-EVENTS-1.0](spec/governance/ACP-GOV-EVENTS-1.0.md) — institutional governance event stream
- [ACP-REP-1.2](spec/security/ACP-REP-1.2.md) — reputation extension, composite score `0.6·ITS + 0.4·ERS`
- [ACP-LIA-1.0](spec/operations/ACP-LIA-1.0.md) — attributed liability chain
- [ACP-HIST-1.0](spec/operations/ACP-HIST-1.0.md) — audited execution history query API
- [ACP-PAY-1.0](spec/operations/ACP-PAY-1.0.md) — verifiable financial capability extension
- [ACP-NOTIFY-1.0](spec/operations/ACP-NOTIFY-1.0.md) — events and webhooks
- [ACP-DISC-1.0](spec/operations/ACP-DISC-1.0.md) — agent registry and resolution
- [ACP-BULK-1.0](spec/operations/ACP-BULK-1.0.md) — batch capability execution
- [ACP-CROSS-ORG-1.0](spec/operations/ACP-CROSS-ORG-1.0.md) — inter-institutional agent interactions

### L5 · Federation
- [ACP-D-1.0](spec/decentralized/ACP-D-1.0.md) — decentralized ACP, cross-institution federation, BFT quorum

### Governance
- [ACP-CONF-1.1](spec/governance/ACP-CONF-1.1.md) — normative conformance definition
- [ACP-CHANGELOG](CHANGELOG.md) — version history

---

## Repository Structure

```
acp-framework/
├── spec/
│   ├── core/          ← L1: identity, capability, delegation
│   ├── security/      ← L2: trust, risk, revocation
│   ├── operations/    ← L3–L4: execution, ledger, governance
│   ├── governance/    ← conformance, events, process
│   └── decentralized/ ← L5: ACP-D
├── impl/
│   └── go/            ← reference implementation
├── ARCHITECTURE.md    ← formal domain model, dependency graph
├── CHANGELOG.md
└── README.md
```

---

## Quick Start

```bash
cd impl/go
docker compose up
```

Health check:

```bash
curl http://localhost:8080/acp/v1/health
```

```json
{"status":"ok","version":"1.0.0"}
```

---

## Roadmap

| Version | Status |
|---|---|
| v1.x | Core protocol and reference implementation — active |
| v2.0 | Decentralized ACP (ACP-D) — in design |
| future | ZK verification, decentralized governance |

---

## License

Apache 2.0
