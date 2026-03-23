# ACP — Agent Control Protocol

**Admission control for agent actions.**

Before any agent mutates system state, ACP answers four questions: *Who is this agent? What are they authorized to do? Is this action policy-compliant? Can the outcome be traced to an accountable institution?*

`Cryptographic identity · Scoped capability tokens · Verifiable delegation chains · Execution proof`

## Official Website

https://agentcontrolprotocol.xyz

## Paper

**Agent Control Protocol: Admission Control for Agent Actions**
Marcelo Fernandez (TraslaIA), 2026

DOI: [10.5281/zenodo.19150239](https://doi.org/10.5281/zenodo.19150239) — Zenodo (v1.15)

arXiv: [2603.18829](https://arxiv.org/abs/2603.18829)

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

### ACP vs Policy & Auth Systems

Engineers evaluating ACP often ask: "why not use OPA?" These systems are complementary, not competitive.

| System | What it does | What ACP adds |
|---|---|---|
| **OPA** (Open Policy Agent) | Evaluates policies from data and rules | Cryptographic agent identity + delegation chain + execution proof |
| **AWS IAM / Azure RBAC** | Static permission model for cloud resources | Dynamic agent-to-agent delegation with verifiable chain + ledger |
| **OAuth 2.0 + OIDC** | User and service authorization via tokens | Multi-hop agent delegation with non-escalation + institutional liability |
| **SPIFFE / SPIRE** | Cryptographic workload identity | ACP builds on workload identity to add capability scoping + governance |
| **ACP** | Admission control for agent actions | — |

OPA can be used as the policy evaluation engine *inside* an ACP-compliant system. ACP does not replace OPA — it adds the agent identity layer, delegation chain, and execution proof that OPA does not provide.

---

¹ ACP (Agent Control Protocol) is unrelated to other initiatives sharing the same acronym.

---

## ACP as Admission Control

Kubernetes uses an Admission Controller to intercept API requests before they reach the cluster — evaluating policies, enforcing quotas, rejecting non-compliant operations. ACP applies the same pattern to agent actions.

```
agent intent
    ↓
[1] Identity check       →  pkg/agent + pkg/hp       (ACP-AGENT-1.0, ACP-HP-1.0)
    ↓
[2] Capability check     →  pkg/ct + pkg/dcma         (ACP-CT-1.0, ACP-DCMA-1.0)
    ↓
[3] Policy check         →  pkg/risk + pkg/psn        (ACP-RISK-1.0, ACP-PSN-1.0)
    ↓
[4] ADMIT / DENY / ESCALATE
    ↓  (if ADMIT)
[5] Execution token      →  pkg/exec                  (ACP-EXEC-1.0)
    ↓
[6] Ledger record        →  pkg/ledger                (ACP-LEDGER-1.3)
    ↓
system state mutation
```

The difference from Kubernetes: ACP operates across institutional boundaries. An agent from Bank A can be admitted by Bank B without Bank B trusting Bank A's internal infrastructure — only the cryptographic proof matters.

---

## How ACP Works

ACP treats agent interactions as **governed operations**, not simple requests.

Every interaction passes through six structured stages:

1. **Identity verification** — confirm who the agent is (`ACP-AGENT-1.0`, `ACP-HP-1.0`)
2. **Capability validation** — confirm what the agent is authorized to do (`ACP-CT-1.0`, `ACP-DCMA-1.0`)
3. **Policy authorization** — confirm the action is permitted under current policy (`ACP-RISK-1.0`, `ACP-PSN-1.0`)
4. **Deterministic execution** — execute exactly what was authorized, nothing more (`ACP-EXEC-1.0`)
5. **Verifiable recording** — produce cryptographic proof of what occurred (`ACP-LEDGER-1.3`, `ACP-PROVENANCE-1.0`)
6. **Trust update** — update reputation and attestation state based on the interaction (`ACP-REP-1.2`, `ACP-LIA-1.0`)

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

→ **New to ACP? Start here:** [docs/admission-flow.md](docs/admission-flow.md) — the complete step-by-step guide to the admission check

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

## Active Specification Versions

Current active version per specification. This table is the authoritative reference for "which version to implement".

| Spec | Active version | Level |
|---|---|---|
| ACP-SIGN | 1.0 | L1 |
| ACP-AGENT | 1.0 | L1 |
| ACP-CT | 1.0 | L1 |
| ACP-CAP-REG | 1.0 | L1 |
| ACP-HP | 1.0 | L1 |
| ACP-DCMA | 1.0 | L1 |
| ACP-MESSAGES | 1.0 | L1 |
| ACP-RISK | 1.0 | L2 |
| ACP-REV | 1.0 | L2 |
| ACP-ITA | 1.1 | L2/L4 |
| ACP-API | 1.0 | L3 |
| ACP-EXEC | 1.0 | L3 |
| ACP-LEDGER | **1.3** | L3 |
| ACP-PROVENANCE | 1.0 | L3 |
| ACP-POLICY-CTX | 1.0 | L3 |
| ACP-PSN | 1.0 | L3 |
| ACP-PAY | 1.0 | L4 |
| ACP-REP | **1.2** | L4 |
| ACP-GOV-EVENTS | 1.0 | L4 |
| ACP-LIA | 1.0 | L4 |
| ACP-HIST | 1.0 | L4 |
| ACP-NOTIFY | 1.0 | L4 |
| ACP-DISC | 1.0 | L4 |
| ACP-BULK | 1.0 | L4 |
| ACP-CROSS-ORG | 1.0 | L4 |
| ACP-REP-PORTABILITY | 1.1 | L4 |
| **ACP-CONF** | **1.2** | — |

Superseded versions are archived in [`archive/specs/`](archive/specs/README.md).

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
| **L3** | L2 + API · EXEC · LEDGER · PROVENANCE · POLICY-CTX · PSN |
| **L4** | L3 + PAY · REP-1.2 · ITA-1.1 · GOV-EVENTS · LIA · HIST · NOTIFY · DISC · BULK · CROSS-ORG · REP-PORTABILITY |
| **L5** | L4 + ACP-D · ITA-1.1 BFT quorum |

→ Normative conformance definition: [`spec/governance/ACP-CONF-1.2.md`](spec/governance/ACP-CONF-1.2.md)

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
- [ACP-LEDGER-1.3](spec/operations/ACP-LEDGER-1.3.md) — audit ledger, append-only, hash-chained, mandatory institutional sig
- [ACP-PSN-1.0](spec/operations/ACP-PSN-1.0.md) — Process-Session Node, execution session tracking
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
- [ACP-CONF-1.2](spec/governance/ACP-CONF-1.2.md) — normative conformance definition (current)
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
├── openapi/
│   └── acp-api-1.0.yaml  ← OpenAPI 3.1.0 spec for all ACP-API-1.0 endpoints
├── compliance/
│   ├── ACP-TS-1.1.md      ← test vector format specification
│   ├── test-vectors/      ← single-shot conformance vectors (CORE · DCMA · HP · LEDGER · EXEC · RISK-2.0)
│   │   └── sequence/      ← stateful sequence vectors (ACR-1.0, 5 scenarios)
│   └── runner/            ← ACR-1.0 compliance runner (library mode + HTTP mode)
├── tla/
│   ├── ACP.tla            ← TLC-runnable formal model — Safety · LedgerAppendOnly · RiskDeterminism
│   └── ACP.cfg            ← TLC configuration (2 agents × 4 caps × 3 resources, depth 5)
├── archive/
│   └── specs/         ← superseded specification versions (historical reference)
├── impl/
│   └── go/            ← reference implementation
├── ARCHITECTURE.md    ← formal domain model, dependency graph
├── CHANGELOG.md
└── README.md
```

---

## Quick Start

```bash
# Option 1: Go reference server
cd impl/go
docker compose up

# Option 6: ACR-1.0 sequence compliance runner — validate ACP-RISK-2.0 stateful behavior
cd compliance/runner
go run . --mode library --dir ../test-vectors/sequence --strict
# PASS 5/5 — SEQ-BENIGN-001 SEQ-BOUNDARY-001 SEQ-PRIVJUMP-001 SEQ-FANOM-RULE3-001 SEQ-COOLDOWN-001

# Option 5: Multi-org demo — Org-A issues signed policy+reputation, Org-B validates independently
cd examples/multi-org-demo
docker compose up
# Org-A: http://localhost:8081  |  Org-B: http://localhost:8082

# Option 2: Python SDK — core admission control pattern (no server required)
cd impl/python
pip install -e .
python examples/admission_control_demo.py

# Option 3: Python SDK — LangChain integration (@acp_tool decorator)
cd impl/python
pip install -e .
python examples/langchain_agent_demo.py

# Option 4: LangChain + real LLM agent
pip install langchain langchain-openai
export OPENAI_API_KEY=sk-...
python examples/langchain_agent_demo.py --with-llm
```

Health check:

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

---

## Roadmap

| Item | Status |
|---|---|
| ACP-CONF-1.2 | ✅ Complete — sole normative conformance source |
| ACP-LEDGER-1.3 | ✅ Complete — sig normatively mandatory |
| OpenAPI spec (`openapi/acp-api-1.0.yaml`) | ✅ Complete — OpenAPI 3.1.0, all ACP-API-1.0 endpoints |
| Conformance test vectors (CORE · DCMA · HP · LEDGER · EXEC · PROV · PCTX · REP · RISK-2.0) | ✅ Complete — 73 signed + 65 unsigned RISK-2.0 test vectors |
| Reference implementation — 23 Go packages (L1–L4) | ✅ Complete — `impl/go/pkg/` covers all conformance levels |
| `pkg/psn` policy snapshot | ✅ Complete — atomic transitions, single ACTIVE snapshot |
| Python SDK — `ACPAdmissionGuard` + `@acp_tool` (LangChain) | ✅ Complete — `impl/python/` |
| ACP-RISK-2.0 — `F_anom` + Cooldown + `pkg/risk` | ✅ Complete — deterministic, sub-µs, 65 vectors |
| Payment-agent demo (`examples/payment-agent/`) | ✅ Complete — v1.16 |
| ACP-SIGN-2.0 — Post-quantum hybrid spec (Ed25519 + ML-DSA-65) | ✅ Complete — spec v1.16; HYBRID stub `pkg/sign2/` v1.17 |
| ACR-1.0 sequence compliance runner (`compliance/runner/`) | ✅ Complete — v1.17 · library + HTTP mode · 5/5 PASS |
| Sequence test vectors (`compliance/test-vectors/sequence/`) | ✅ Complete — v1.17 · 5 stateful scenarios |
| TLA+ formal model (`tla/ACP.tla`) | ✅ Complete — v1.17 · TLC-runnable · 0 violations |
| TypeScript / Rust SDKs | 🔜 On roadmap |
| v1.x | Core protocol and reference implementation — active |
| v2.0 | Decentralized ACP (ACP-D) — in design |
| future | ZK verification, decentralized governance |

---

## License

Apache 2.0
