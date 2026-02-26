# The Three-Layer Framework

**ACP — Agent Control Protocol | Vision Document**
**TraslaIA | Marcelo Fernandez | 2026**

---

## The problem this framework solves

Most AI governance initiatives jump directly to tools and protocols without first defining the strategic framework or the architectural model. The result is fragile, vendor-dependent, non-auditable automation.

This framework enforces the correct sequence:

> **Strategic Decision → Architectural Design → Operational Execution**

---

## The three layers

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   LEVEL 1 — SOVEREIGN AI ARCHITECTURE                          │
│                                                                 │
│   The WHY                                                       │
│   Strategic decision for every organization operating agents   │
│                                                                 │
│   • Model provider independence                                 │
│   • Substitution capability without redesign                   │
│   • Real institutional control over execution                  │
│   • Preserved local traceability                               │
│                                                                 │
│   Responsible: Board, CTO, executive leadership                │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   LEVEL 2 — GAT MODEL                                          │
│   (Architectural Agent Governance)                              │
│                                                                 │
│   The WHAT                                                      │
│   Design principles that make any agent governable             │
│                                                                 │
│   • Strict decision / execution separation                     │
│   • Mandatory structural traceability                          │
│   • Dynamic and graduated permission control                   │
│   • Continuous observability                                   │
│   • Multi-agent governance with delegation limits              │
│                                                                 │
│   Responsible: Architecture teams                              │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   LEVEL 3 — ACP PROTOCOL                                       │
│   (Agent Control Protocol)                                      │
│                                                                 │
│   The HOW                                                       │
│   Verifiable technical implementation of Level 2               │
│                                                                 │
│   • Agent cryptographic identity (Ed25519)                     │
│   • Capability Tokens — permissions with digital signature     │
│   • Handshake Protocol — stateless proof of possession         │
│   • Deterministic risk engine (score 0-100)                    │
│   • Execution Tokens — single-use authorization                │
│   • Audit Ledger — append-only hash-chained registry           │
│   • Transitive revocation                                      │
│                                                                 │
│   Responsible: Engineering teams                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Relationship between layers

ACP is not an alternative to the GAT Model or to Sovereign Architecture. It is their operational implementation.

```
Sovereign AI Architecture
    defines policy and strategic objectives
    ↓
GAT Model
    translates that policy into verifiable design principles
    ↓
ACP Protocol
    implements those principles with cryptography and formal messages
```

**Without Level 1:** Teams build without a strategic mandate, each in their own way.
**Without Level 2:** The protocol is applied without architectural coherence across systems.
**Without Level 3:** Principles remain in documents without verifiable implementation.

---

## The six internal layers of an agent (Level 2)

Every agent built under this framework exposes these six layers explicitly:

| # | Layer | Function | Implemented by |
|---|---|---|---|
| 1 | **Decision** | LLM / inference engine — proposes actions | Model provider |
| 2 | **Structural Validation** | Converts probabilistic output into verifiable JSON | Integration team |
| 3 | **Policy** | Evaluates permissions, risk and context deterministically | **ACP** |
| 4 | **Execution** | Interacts with real systems only if policy approves | Integration team |
| 5 | **State** | Contextual memory and history persistence | Integration team |
| 6 | **Observability** | Structured logging, metrics, alerts | **ACP Audit Ledger** |

**Principle P1:** The Decision Layer never accesses the Execution Layer directly.
Between them, the Policy Layer always exists — implemented by ACP.

---

## GAT Maturity Matrix

The implementation path is measured in six levels:

| Level | Name | Key capability | Typical time |
|---|---|---|---|
| 0 | Basic automation | Decision and execution coupled | — |
| 1 | Structural validation | Basic layer separation | 4–6 weeks |
| 2 | Full traceability | Logs + ACP Audit Ledger | 8–12 weeks |
| 3 | Dynamic control | Real-time permissions | 12–16 weeks |
| 4 | Multi-agent governance | Orchestration + delegation limits | 4–6 months |
| 5 | Sovereign architecture | Full provider decoupling | 6–9 months |

> Most current implementations do not exceed Level 1.
> ACP directly enables levels 2, 3 and 4.

---

## Why this sequence matters

The alternative — adopting tools without a framework — produces:

- **Deep technological dependency:** changing providers requires total redesign
- **Non-auditable automation:** there is no way to reconstruct what the agent decided and why
- **Silent privilege escalation:** agents acquire more access than declared
- **Fragmented responsibility:** in multi-agent systems, no one knows who executed what

Sovereign AI Architecture enforces structural discipline before technical implementation.

---

## Documents by level

| Level | Key documents |
|---|---|
| **1 — Sovereign** | [Sovereign-AI-Architecture.md](../01-sovereign-architecture/Sovereign-AI-Architecture.md) · [Sovereign-AI-Architecture-Framework.md](../01-sovereign-architecture/Sovereign-AI-Architecture-Framework.md) |
| **2 — GAT** | [GAT-Maturity-Model.md](GAT-Maturity-Model.md) · [ACP-Foundational-Doctrine.md](../01-sovereign-architecture/ACP-Foundational-Doctrine.md) |
| **3 — ACP** | [ACP-Whitepaper-v1.0.md](../06-publications/ACP-Whitepaper-v1.0.md) · [03-acp-protocol/specification/](../03-acp-protocol/specification/) |

---

*TraslaIA — Marcelo Fernandez — 2026*
