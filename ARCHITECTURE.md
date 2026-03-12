# ACP Architecture

**Agent Control Protocol — Conceptual and Structural Model**

**Version:** 1.10
**Status:** Normative
**Last updated:** 2026-03-11

---

## Constitutional Axiom

Every architectural decision in ACP derives from a single invariant:

```
Execute(request) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

No autonomous agent action is executed unless all four conditions hold simultaneously and are **cryptographically verifiable after the fact**. This is not a policy — it is a hard architectural constraint. Any system that cannot prove this invariant for a past action is non-conformant.

---

## Domain Model

ACP operates on eight formal concepts. These are not implementation constructs — they are the entities the protocol reasons about.

### 1. Actor

Any entity with a cryptographic identity that can initiate or authorize requests. Actors are either **Agents** or **Institutions**. All actors hold Ed25519 key pairs; all protocol messages carry actor signatures.

### 2. Agent

An autonomous computational entity formally defined as:

```
A = (ID, C, P, D, L, S)
```

Where:
- `ID` — globally unique identifier (DID-compatible)
- `C` — capability set (subset of institutional CAP-REG)
- `P` — principal chain (delegation path from Institution)
- `D` — delegation scope (non-escalating capability subset)
- `L` — execution ledger reference (append-only audit trail)
- `S` — current lifecycle state (`{ACTIVE, SUSPENDED, REVOKED}`)

Agents do not self-authorize. Every capability they hold was granted through a verifiable delegation chain rooted at an Institution.

**Spec:** [`spec/core/ACP-AGENT-1.0.md`](spec/core/ACP-AGENT-1.0.md)

### 3. Institution

The sovereign principal of an ACP deployment. Institutions operate the Trust Anchor, issue Capability Tokens, maintain the Audit Ledger, and own the Policy Engine. An Institution is the root of trust for all delegation chains under its jurisdiction.

Institutions can federate through CROSS-ORG protocols while maintaining independent sovereignty.

**Spec:** [`spec/core/ACP-AGENT-1.0.md`](spec/core/ACP-AGENT-1.0.md) (institutional identity), [`spec/security/ACP-ITA-1.0.md`](spec/security/ACP-ITA-1.0.md) (trust anchor)

### 4. Authority

A formal, scoped, time-bounded right to execute a specific capability. Authority is never ambient — it must be explicitly granted, cryptographically signed, and traceable to an institutional root. Authority has three structural properties:

- **Scope:** the capability string (`acp:cap:*`) it covers
- **Temporal validity:** `delegated_at` / `valid_until` bounds
- **Chain integrity:** every intermediate step signed by its delegator

Authority is materialized as a **Capability Token** (CT) and proven via the **Handshake Protocol** (HP).

**Specs:** [`spec/core/ACP-CT-1.0.md`](spec/core/ACP-CT-1.0.md), [`spec/core/ACP-HP-1.0.md`](spec/core/ACP-HP-1.0.md)

### 5. Interaction

A protocol exchange that instantiates Authority into an executed action. Every Interaction produces an **Execution Token** (ET) — a single-use, 300-second artifact that binds: agent identity, capability scope, resource, risk score, policy state at execution time, and institutional signature.

Interactions are the atomic unit of accountability in ACP.

**Specs:** [`spec/operations/ACP-EXEC-1.0.md`](spec/operations/ACP-EXEC-1.0.md), [`spec/operations/ACP-POLICY-CTX-1.0.md`](spec/operations/ACP-POLICY-CTX-1.0.md)

### 6. Attestation

A cryptographically signed claim about trust state, issued by the Trust Anchor or an authorized verifier. Attestations include:

- **ITA certificates** — institutional trust status of an agent
- **Reputation scores** — composite behavioral history (ITS + ERS)
- **Compliance findings** — audit results bound to governance events
- **Authority Provenance** — retrospective proof of the delegation chain at execution time

Attestations are the evidence layer. They answer: *who vouches for this agent, and based on what?*

**Specs:** [`spec/security/ACP-ITA-1.0.md`](spec/security/ACP-ITA-1.0.md), [`spec/security/ACP-REP-1.2.md`](spec/security/ACP-REP-1.2.md), [`spec/core/ACP-PROVENANCE-1.0.md`](spec/core/ACP-PROVENANCE-1.0.md)

### 7. History

The ordered, append-only record of all Interactions and Governance Events for an Agent. History is immutable — entries are hash-chained and signed. History is the input to Reputation computation and the primary artifact for audit and liability resolution.

History has two components:
- **Ledger** — low-level execution log (one entry per ET, hash-chained)
- **Governance Event Stream** — institutional events (suspensions, policy updates, capability changes)

**Specs:** [`spec/operations/ACP-LEDGER-1.2.md`](spec/operations/ACP-LEDGER-1.2.md), [`spec/operations/ACP-HIST-1.0.md`](spec/operations/ACP-HIST-1.0.md), [`spec/governance/ACP-GOV-EVENTS-1.0.md`](spec/governance/ACP-GOV-EVENTS-1.0.md)

### 8. Reputation

A time-weighted composite score derived from History and Attestations. Reputation has two components:

- **ITS (Institutional Trust Score)** — weighted sum of ITA attestations from known trust anchors
- **ERS (Execution Reliability Score)** — ratio of successful to total executions, time-decayed

Composite formula: `REP = 0.6 · ITS + 0.4 · ERS`

Reputation is portable across institutions via REP-PORTABILITY, which defines a signed, verifiable export format for cross-institutional agent deployment.

**Specs:** [`spec/security/ACP-REP-1.2.md`](spec/security/ACP-REP-1.2.md), [`spec/operations/ACP-CROSS-ORG-1.0.md`](spec/operations/ACP-CROSS-ORG-1.0.md)

---

## Governance Stack

ACP is structured as eight cumulative layers. Each layer depends on all layers below it. The constitutional invariant is enforced at Layer 4 — every layer above it builds evidentiary depth.

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 8 — RISK ARCHITECTURE                                     │
│  Probabilistic risk scoring and cross-institutional events       │
│  RISK-1.0 · PSN-1.0 · CROSS-ORG-1.0 · BULK-1.0                 │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 7 — REPUTATION                                            │
│  Time-weighted behavioral score, portable across institutions    │
│  REP-1.2 (ITS + ERS composite) · REP-PORTABILITY                │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 6 — LIABILITY & TRUST                                     │
│  Who is responsible, who vouches, what changed institutionally   │
│  LIA-1.0 · ITA-1.0 · ITA-1.1 (BFT) · GOV-EVENTS-1.0           │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 5 — VERIFIABLE HISTORY                                    │
│  Append-only hash-chained audit record; input to reputation      │
│  LEDGER-1.2 · HIST-1.0                                          │
├═════════════════════════════════════════════════════════════════╡
│  LAYER 4 — EXECUTION GOVERNANCE          ← ACP core invariant   │
│  Execution Token lifecycle; policy state capture; provenance     │
│  EXEC-1.0 · POLICY-CTX-1.0 · PROVENANCE-1.0 · API-1.0          │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3 — DELEGATION                                            │
│  Proof of authority possession; multi-hop delegation             │
│  HP-1.0 · DCMA-1.0 · MESSAGES-1.0                               │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2 — CAPABILITY                                            │
│  Formal right definition; canonical capability registry          │
│  CT-1.0 · CAP-REG-1.0                                           │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1 — IDENTITY                                              │
│  Cryptographic identity; signing and serialization foundation    │
│  SIGN-1.0 · AGENT-1.0                                           │
└─────────────────────────────────────────────────────────────────┘
```

**Key properties:**
- Layers 1–3 establish *who can do what by what authority*
- Layer 4 enforces *the constitutional invariant at execution time*
- Layers 5–8 build the evidentiary record *of what was done and with what consequence*

The separation between Layer 4 and Layer 5 is critical: the invariant is enforced *before* execution, and verified *from the record* after. Both must hold for full conformance.

---

## Spec Dependency Map

Directed graph of normative dependencies between ACP specifications. An arrow `A → B` means B depends on A (B cannot be implemented without A).

```
SIGN-1.0 ──────────────────────────────────────────────────────┐
    │                                                           │
    ├──► AGENT-1.0 ──────────────────────────────────────────┐ │
    │        │                                               │ │
    ├──► CT-1.0 ──────────────────────────────────────────┐  │ │
    │        │                                            │  │ │
    ├──► CAP-REG-1.0 ──────────────────────────────────── │─►│ │
    │                                                     │  │ │
    └──► HP-1.0 ──────────────────────────────────────┐  │  │ │
             │                                         │  │  │ │
             └──► DCMA-1.0                             │  │  │ │
                                                       │  │  │ │
    MESSAGES-1.0 ◄─────────────────────────────────────┘  │  │ │
                                                           │  │ │
    RISK-1.0 ──────────────────────────────────────────┐  │  │ │
                                                        │  │  │ │
    EXEC-1.0 ◄──────────────────────────────────────────┘──┘  │ │
        │                                                      │ │
        ├──► LEDGER-1.2 ──────────────────────────────────┐   │ │
        │        │                                         │   │ │
        │        └──► HIST-1.0                             │   │ │
        │                                                  │   │ │
        ├──► POLICY-CTX-1.0 ◄──────────────────────────── │───┘ │
        │                                                  │     │
        └──► PROVENANCE-1.0 ◄─────────────────────────────┘─────┘

    ITA-1.0 ──────────────────────────────────────────────┐
        │                                                  │
        └──► REP-1.2 ─────────────────────────────────────►──► REP-PORTABILITY
                 │
                 └──► CROSS-ORG-1.0

    LEDGER-1.2 ──────────────────────────────────────────►──► LIA-1.0

    GOV-EVENTS-1.0 ◄── {ITA-1.x, REP-1.2, EXEC-1.0, LEDGER-1.2}
        │                (consumed by HIST-1.0 and risk systems)
        └──► HIST-1.0

    CONF-1.1 ────────────────────────────────────────────────────►
        (defines which specs are required at each conformance level)
```

**Critical chains for implementers:**

| Chain | Description |
|---|---|
| `SIGN → CT → HP → EXEC` | The execution authority chain — minimum path for any authorized action |
| `EXEC → LEDGER → HIST` | The audit trail chain — from execution to queryable history |
| `EXEC → POLICY-CTX + PROVENANCE` | The evidence layer — full retrospective proof of authorized execution |
| `ITA → REP → REP-PORTABILITY` | The trust chain — from institutional vouching to portable reputation |
| `LEDGER → LIA` | The liability chain — from audit log to liability traceability |
| `GOV-EVENTS → HIST` | The governance chain — institutional changes visible in agent history |

---

## Conformance Binding

Each conformance level maps to a specific set of layers. All levels are cumulative.

| Level | Name | Layers | Key specs added |
|---|---|---|---|
| **L1** | CORE | 1–3 | SIGN · AGENT · CT · CAP-REG · HP · DCMA · MESSAGES |
| **L2** | SECURITY | 1–3 + partial 6 | L1 + RISK · REV · ITA-1.0 |
| **L3** | FULL | 1–5 | L2 + API · EXEC · LEDGER · PROVENANCE · POLICY-CTX |
| **L4** | EXTENDED | 1–7 | L3 + GOV-EVENTS · PAY · REP-1.2 · ITA-1.1 · LIA · HIST · NOTIFY · DISC · BULK · CROSS-ORG · REP-PORTABILITY |
| **L5** | DECENTRALIZED | 1–8 | L4 + ACP-D · ITA-1.1 BFT quorum |

**Note on L3:** PROVENANCE-1.0 and POLICY-CTX-1.0 are required at L3-FULL. They complete the evidence layer that makes retrospective verification possible — without them, the Audit Ledger records *that* an action was taken but not *by what authority* or *under what policy*. These three together (LEDGER + PROVENANCE + POLICY-CTX) constitute the minimum evidentiary foundation for compliance audits.

---

## Execution Lifecycle

What happens when an agent executes an action under ACP:

```
1. IDENTITY CHECK        Agent presents signed identity (AGENT-1.0)
         │
         ▼
2. CAPABILITY CHECK      Institution verifies CT against CAP-REG
         │               Checks: scope, expiry, issuer signature
         ▼
3. DELEGATION CHECK      HP handshake proves possession of CT
         │               DCMA validates chain if multi-hop delegation
         ▼
4. RISK EVALUATION       RISK engine computes RS (0–100)
         │               Policy engine evaluates against current policy
         ▼
5. POLICY SNAPSHOT       POLICY-CTX captures signed snapshot of policy state
         │               Snapshot bound to this execution instance
         ▼
6. EXECUTION TOKEN       EXEC issues single-use ET (300s window)
         │               ET binds: agent, capability, resource, RS, policy_ref
         ▼
7. ACTION EXECUTION      Agent executes the authorized action
         │
         ▼
8. PROVENANCE CAPTURE    PROVENANCE records full delegation chain at execution time
         │               Properties P1–P5 verified; signed by institution
         ▼
9. LEDGER ENTRY          LEDGER appends hash-chained entry
         │               Entry references ET, PROVENANCE, POLICY-CTX
         ▼
10. REPUTATION UPDATE    REP-1.2 updates ERS component
          │              ITS unchanged unless ITA attestation changes
          ▼
    [QUERYABLE via HIST-1.0 · AUDITABLE via LIA-1.0]
```

---

## Key Formal Properties

Properties that any ACP-conformant system must preserve:

**P-INVARIANT:** `Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk`

**P-NON-ESCALATION:** A delegated capability is always a strict subset of the delegator's capability. No delegation can grant authority the delegator does not hold.

**P-TEMPORAL:** Every CT, ET, and PROVENANCE artifact has `valid_until` bounds. No artifact authorizes action outside its temporal window.

**P-CHAIN-COMPLETENESS:** `PROVENANCE.chain` includes every step from Institution to executing Agent. No gap in the chain is permitted.

**P-IMMUTABILITY:** Ledger entries are hash-chained. A tampered entry invalidates all subsequent entries. Gaps in sequence numbers are detectable.

**P-PORTABILITY:** A REP-PORTABILITY export from Institution A is cryptographically verifiable by Institution B without requiring A's online participation.

**P-REVOCABILITY:** Any capability or delegation can be revoked with immediate effect. DCMA enforces transitive revocation through the chain.

---

## Document Map

| Section | Document | Path |
|---|---|---|
| This document | ARCHITECTURE.md | `ARCHITECTURE.md` |
| Quick start | QUICKSTART.md | `QUICKSTART.md` |
| Architecture overview | architecture-overview.md | `docs/architecture-overview.md` |
| Full spec index | See `spec/` | `spec/` |
| Conformance requirements | ACP-CONF-1.1 | `spec/governance/ACP-CONF-1.1.md` |
| Compliance chain | ACR-1.0 + TS-1.1 | `compliance/` |

---

*TraslaIA — Marcelo Fernandez — 2026 — Apache 2.0*
