# ACP Architecture Overview

> **Agent Control Protocol (ACP)** — governance infrastructure for liability-aware autonomous systems.

## Core Invariant

```
Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

## Three-Layer Framework

| Layer | Name | Purpose |
|-------|------|---------|
| L1 | Sovereign AI Architecture | Foundational governance doctrine |
| L2 | GAT Model | Governance-Accountability-Traceability maturity model |
| L3 | ACP Protocol | Constitutional execution layer |

## Agent Governance Stack (8 Layers)

```
┌─────────────────────────────────────────────────────┐
│  L8  Risk Architecture         (ARAF integration)    │
│  L7  Reputation                                      │
│  L6  Liability Traceability                          │
│  L5  Verifiable History        (MIR integration)     │
│  L4  ► Execution Governance ◄  (ACP — this layer)   │
│  L3  Delegation                                      │
│  L2  Capability                                      │
│  L1  Identity                                        │
└─────────────────────────────────────────────────────┘
```

ACP is the **governance evidence layer**: it produces the cryptographic assertions, delegation proofs, and policy snapshots that layers L5–L8 consume.

## Conformance Levels (ACP-CONF-1.1)

| Level | Name | Description |
|-------|------|-------------|
| L1-CORE | Minimum | Identity + capability validation |
| L2-SECURITY | Secured | + Cryptographic signing (ACP-SIGN-1.0) |
| L3-FULL | Full | + Delegation chains (ACP-DCMA-1.0) |
| L4-EXTENDED | Extended | + History + risk scoring |
| L5-DECENTRALIZED | Sovereign | + No central issuer (ACP-D) |

## Key Specifications

- [`spec/core/`](../spec/core/) — Identity, capability, delegation, signing
- [`spec/governance/`](../spec/governance/) — Conformance, trust scoring, RFC process
- [`spec/operations/`](../spec/operations/) — API, bulk operations, runtime
- [`spec/extensions/`](../spec/extensions/) — History, privacy, cross-domain
- [`spec/decentralized/`](../spec/decentralized/) — Decentralized architecture (ACP-D)

## Ecosystem

- **MIR** (participation history layer) — consumes ACP verifiable history
- **ARAF** (risk architecture layer) — consumes ACP risk evidence
