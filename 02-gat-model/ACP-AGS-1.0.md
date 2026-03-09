# ACP-AGS-1.0
## Agent Governance Stack — Architecture Reference
**Status:** Draft
**Version:** 1.0
**Type:** Architecture Reference Document
**Depends-on:** ACP-CT-1.0, ACP-SIGN-1.0, ACP-RISK-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.1, ACP-LIA-1.0, ACP-PSN-1.0, ACP-REV-1.0, ACP-ITA-1.0, ACP-CONF-1.0
**Related:** ACP-REP-1.2 (forward reference)

---

## 1. Scope

This document defines the reference architecture of the Agent Governance Stack (AGS): the layered model that positions ACP within a complete governance system for autonomous agents in financial environments.

The AGS is not a new protocol. It is the conceptual framework that describes how ACP components articulate with each other and with external layers to produce a system that is: auditable, secure, regulatorily compliant, and — in the sense of Carly Martin/ARAF — **bankable**.

A system is bankable when it simultaneously satisfies four properties:
1. **Risk-modelable** — The risk of each action can be quantified a priori.
2. **Auditable** — Every action can be independently reconstructed and verified.
3. **Predictable** — System behavior is deterministic given the same inputs.
4. **Accountable** — There is always an identifiable and assignable responsible party for each action.

The AGS is the architecture that makes all four properties possible in a real deployment.

---

## 2. The Agent Governance Stack — 8 Layers

```
┌─────────────────────────────────────────────────────────────┐
│  L8 — Risk Architecture                                      │
│       Quantitative risk model (ACP-RISK-1.0)                │
│       Policy Snapshots (ACP-PSN-1.0)                        │
├─────────────────────────────────────────────────────────────┤
│  L7 — Reputation Layer                                       │
│       Agent historical score (ACP-REP-1.2 →)               │
│       Fed by LIABILITY_RECORDs and execution_result          │
├─────────────────────────────────────────────────────────────┤
│  L6 — Liability Traceability                                 │
│       Responsibility materialization (ACP-LIA-1.0)          │
│       One LIABILITY_RECORD per consumed ET                   │
├─────────────────────────────────────────────────────────────┤
│  L5 — Verifiable History                                     │
│       Hash-chained Audit Ledger (ACP-LEDGER-1.1)            │
│       Append-only record of all ACP events                   │
├─────────────────────────────────────────────────────────────┤
│  L4 — Execution Governance       ◄── ACP Core               │
│       Execution Tokens (ACP-EXEC-1.0)                       │
│       Authorization flow (ACP-API-1.0)                      │
│       Revocation (ACP-REV-1.0)                              │
├─────────────────────────────────────────────────────────────┤
│  L3 — Delegation                                             │
│       Delegated Capability Tokens (ACP-CT-1.0 §7)          │
│       Delegation tree with depth and nonce                   │
├─────────────────────────────────────────────────────────────┤
│  L2 — Capabilities                                           │
│       Capability Registry (ACP-CAP-REG-1.0)                 │
│       Capability model and namespaces                        │
├─────────────────────────────────────────────────────────────┤
│  L1 — Identity                                               │
│       Institutional Trust Anchor (ACP-ITA-1.0)              │
│       Proof of Possession (ACP-HP-1.0)                      │
│       Serialization and signing (ACP-SIGN-1.0)              │
└─────────────────────────────────────────────────────────────┘
```

Layers have downward dependencies: L6 requires L5, L5 requires L4, etc. A partial implementation is valid up to the implemented level, but cannot claim full bankability without L6.

---

## 3. Layer Descriptions

### L1 — Identity

**Purpose:** Anchor the identity of each agent and institution to a verifiable cryptographic root.

**ACP Specs:** ACP-ITA-1.0, ACP-HP-1.0, ACP-SIGN-1.0

**Key components:**
- `AgentID`: Unique identifier derived from public key (ACP-SIGN-1.0).
- `institution_id`: Root institution identifier (ACP-ITA-1.0).
- `X-ACP-PoP`: Proof of Possession header in each HTTP request (ACP-HP-1.0).
- JCS (RFC 8785): Deterministic serialization for consistent hashing across implementations.

**Guarantee:** An external actor can verify the identity of any agent without trusting the institution, using only the published public key.

---

### L2 — Capabilities

**Purpose:** Define the space of possible system actions and the namespaces that organize them.

**ACP Specs:** ACP-CAP-REG-1.0, ACP-CT-1.0 §§1-6

**Key components:**
- Namespace `acp:cap:<domain>.<action>`: Canonical capability format.
- Capability Registry: Authority defining valid capabilities.
- `capability_baselines` in ACP-PSN-1.0: Base score per capability.

**Guarantee:** Every executable action is enumerated and defined. Actions outside the defined space cannot be executed.

---

### L3 — Delegation

**Purpose:** Model the authorization chain from the institution to the executing agent.

**ACP Specs:** ACP-CT-1.0 §7

**Key components:**
- Capability Token with `parent_token_nonce`: Links delegations in a tree.
- `delegation_depth`: Agent depth in the hierarchy.
- `autonomy_level`: Agent autonomy level (0–4), affects risk thresholds.

**Guarantee:** Every execution can be traced back to the institutional root token. It is not possible to execute an action without a valid delegation chain from the institution.

---

### L4 — Execution Governance (ACP Core)

**Purpose:** Control in real time which actions are executed, under what conditions, and with what result.

**ACP Specs:** ACP-EXEC-1.0, ACP-API-1.0, ACP-REV-1.0, ACP-RISK-1.0

**Key components:**
- Execution Token (ET): Atomic authorization per specific action. One-time use.
- `AUTHORIZATION` flow: Risk evaluation → decision (APPROVED/ESCALATED/DENIED).
- Revocation: Token invalidation before consumption (ACP-REV-1.0).
- `policy_snapshot_ref`: Reference to the policy snapshot active at evaluation time.

**Guarantee:** No action can be executed without a valid, non-revoked ET. The risk evaluation result is deterministic and auditable.

---

### L5 — Verifiable History

**Purpose:** Permanently, orderly, and immutably record all ACP events.

**ACP Specs:** ACP-LEDGER-1.1

**Key components:**
- Hash-chained append-only ledger: `prev_hash` cryptographically links events.
- 14 documented event types (genesis, AUTHORIZATION, RISK_EVALUATION, ET_ISSUED, ET_CONSUMED, REVOCATION, LIABILITY_RECORD, POLICY_SNAPSHOT_CREATED, REPUTATION_UPDATED, and others).
- Institutional signature per event: Guarantees non-repudiation.
- Integrity verification: Reconstructible from genesis.

**Guarantee:** No event can be deleted or retroactively modified without invalidating the chain. An external audit can verify the complete integrity of the history.

---

### L6 — Liability Traceability

**Purpose:** Materialize, for each execution, who is the assignable legal responsible party.

**ACP Specs:** ACP-LIA-1.0

**Key components:**
- `LIABILITY_RECORD`: One event per consumed ET. Includes complete `delegation_chain` and `liability_assignee`.
- Assignee rules: Human escalation → supervisor if autonomy_level < 2 → executor.
- `chain_incomplete`: Audited degradation when the chain cannot be reconstructed.
- `policy_snapshot_ref`: Policy context at execution time.

**Guarantee:** For every executed action there is an identifiable responsible party. This is the technical accountability requirement that enables bankability.

---

### L7 — Reputation Layer

**Purpose:** Build a quantitative behavioral history for each agent to inform future risk decisions.

**ACP Specs:** ACP-REP-1.2 (forward reference — pending)

**Projected key components:**
- `trust_score`: Continuous score derived from historical LIABILITY_RECORDs.
- Fed by `execution_result` in LIABILITY_RECORDs.
- `REPUTATION_UPDATED` event in ledger (ACP-LEDGER-1.1 §5.14).
- Input for `capability_baselines` calibration in ACP-PSN-1.0.

**Projected guarantee:** The risk of authorizing a specific agent is informed by its real execution history, not only by its static attributes.

---

### L8 — Risk Architecture

**Purpose:** Provide the quantitative model that converts execution attributes into an actionable risk score.

**ACP Specs:** ACP-RISK-1.0, ACP-PSN-1.0

**Key components:**
- Deterministic score function: `score = baseline + Σ(context_factors) + resource_factor`.
- Policy Snapshots: Immutable state of model parameters at each moment.
- Thresholds by `autonomy_level`: APPROVED / ESCALATED / DENIED.
- Temporal determinism: The same score MUST be produced given the same snapshot, always.

**Guarantee:** The risk model is risk-modelable in the ARAF sense: which parameters produced which decision can be audited at any future point.

---

## 4. Complete Transaction Flow

Example: Executing agent (`autonomy_level = 2`) requests to execute `acp:cap:financial.payment`.

```
1. [L1] Agent presents X-ACP-PoP to the ACP system.
        System verifies identity cryptographically (ACP-HP-1.0).

2. [L3] System retrieves agent's Capability Token.
        Verifies delegation_chain to institutional root token (ACP-CT-1.0).

3. [L8] System obtains active Policy Snapshot (ACP-PSN-1.0).
        Calculates risk_score = 35 (payment baseline) + 15 (off_hours) + 15 (sensitive) = 65.
        Threshold for autonomy_level 2: approved_max=39, escalated_max=69.
        Decision: ESCALATED (score 65 ≤ 69).

4. [L4] System issues Execution Token with status ESCALATED (ACP-EXEC-1.0).
        Records AUTHORIZATION event in ledger (ACP-LEDGER-1.1).
        AUTHORIZATION includes policy_snapshot_ref.

5. [L5] Append-only ledger records AUTHORIZATION with prev_hash and institutional sig.

6. [L4] Escalation process. Human supervisor approves.
        System records ESCALATION_RESOLVED in ledger.
        ET updated to APPROVED.

7. [L4] External system consumes ET (ACP-EXEC-1.0 §8).
        Ledger records EXECUTION_TOKEN_CONSUMED with execution_result=success.

8. [L6] System emits LIABILITY_RECORD (ACP-LIA-1.0).
        delegation_chain reconstructed from ledger.
        Rule 1 applies (escalation resolved by human) → liability_assignee = supervisor.
        LIABILITY_RECORD event added to ledger.

9. [L7] System updates agent trust_score (ACP-REP-1.2, future).
        REPUTATION_UPDATED event in ledger.
```

**Result:** The transaction is fully auditable, the responsible party is assigned (supervisor), and the risk model used is preserved in the referenced snapshot.

---

## 5. Coverage Table by Spec

| Spec | Layer(s) | Bankability |
|---|---|---|
| ACP-SIGN-1.0 | L1 | Auditable (verifiable signatures) |
| ACP-ITA-1.0 | L1 | Auditable (root of trust) |
| ACP-HP-1.0 | L1 | Auditable (verifiable authentication) |
| ACP-CAP-REG-1.0 | L2 | Predictable (defined action space) |
| ACP-CT-1.0 | L2, L3 | Predictable (deterministic delegation) |
| ACP-RISK-1.0 | L4, L8 | Risk-modelable (deterministic score) |
| ACP-REV-1.0 | L4 | Predictable (guaranteed revocation) |
| ACP-EXEC-1.0 | L4 | Auditable (one-time-use ET) |
| ACP-API-1.0 | L4 | Auditable (formal interfaces) |
| ACP-PSN-1.0 | L8 | Risk-modelable (immutable policy) |
| ACP-LEDGER-1.1 | L5 | Auditable (verifiable history) |
| ACP-LIA-1.0 | L6 | Accountable (assignable responsible party) |
| ACP-REP-1.2 | L7 | Risk-modelable (behavioral history) |
| ACP-CONF-1.0 | All | Auditable (formal certification) |

---

## 6. Phased Implementation Guide

Institutions can adopt the AGS incrementally. Each phase produces value on its own.

### Phase 1 — Identity & Capabilities (L1 + L2)
**Specs:** ACP-SIGN-1.0, ACP-ITA-1.0, ACP-HP-1.0, ACP-CAP-REG-1.0
**Outcome:** Agents with verifiable cryptographic identity and defined capability catalog.
**Bankability:** None yet — this is the necessary foundation.

### Phase 2 — Delegation (L3)
**Specs:** ACP-CT-1.0
**Outcome:** Auditable delegation tree from institution to each executing agent.
**Bankability:** Partial — predictable (who can do what is defined).

### Phase 3 — Execution Governance (L4) — ACP Core
**Specs:** ACP-RISK-1.0, ACP-EXEC-1.0, ACP-API-1.0, ACP-REV-1.0
**Outcome:** Real-time control of every executed action. No agent can act without a valid ET.
**Bankability:** Risk-modelable + Predictable. System operable in production.

### Phase 4 — Verifiable History (L5)
**Specs:** ACP-LEDGER-1.1, ACP-PSN-1.0
**Outcome:** Immutable record of the complete system history. Policy Snapshots for historical reconstruction.
**Bankability:** + Auditable. System audited by third parties.

### Phase 5 — Liability Traceability (L6) — Full Bankability
**Specs:** ACP-LIA-1.0
**Outcome:** For each execution, a legal responsible party is identified and recorded.
**Bankability:** + Accountable. **Fully bankable system.**

### Phase 6 — Reputation (L7)
**Specs:** ACP-REP-1.2
**Outcome:** Historical score of each agent informs future risk calculations.
**Bankability:** Enhanced risk-modelable. Risk calibrated by real history.

---

## 7. Cross-Institution Interoperability

**7.1 Federated trust model** — When two institutions operate with agents between them (B2B scenario), each institution maintains its own ledger, its own snapshots, and its own LIABILITY_RECORDs. Interoperability is enabled via ACP-ITA-1.0 (mutual recognition, pending in v1.1).

**7.2 `institution_id` as barrier** — Every ACP event is anchored to an `institution_id`. A LIABILITY_RECORD from institution A cannot claim responsibility for an execution in institution B.

**7.3 Cross-institution execution** — When an agent from institution A executes in the context of institution B:
- The ET is issued under institution B's authority.
- The LIABILITY_RECORD is recorded in institution B's ledger.
- The `delegation_chain` includes the cross-institution trust token issued by ITA.

**7.4 Federated audit** — A regulator with access to both ledgers can reconstruct the complete cross-institution flow. No trust in either institution individually is required.

---

## 8. Mapping to Regulatory Frameworks

| Framework | Requirement | AGS Layer | ACP Spec |
|---|---|---|---|
| Basel III / IV | Risk traceability | L8, L5 | ACP-RISK-1.0, ACP-LEDGER-1.1 |
| DORA (EU) | Operational resilience and records | L5, L4 | ACP-LEDGER-1.1, ACP-EXEC-1.0 |
| MiCA | Accountability in digital asset services | L6 | ACP-LIA-1.0 |
| SR 11-7 (Fed) | AI model validation and governance | L8, L6 | ACP-PSN-1.0, ACP-LIA-1.0 |
| ARAF (Carly Martin) | Bankability of agentic systems | L6, L8 | ACP-LIA-1.0, ACP-PSN-1.0 |
| MIR (Richard Whitney) | Agent auditability in markets | L5, L6 | ACP-LEDGER-1.1, ACP-LIA-1.0 |
| GDPR Art. 22 | Significant automated decisions | L4, L6 | ACP-EXEC-1.0, ACP-LIA-1.0 |

---

## 9. Relationship to Existing Architecture Documents

| Document | Relationship to AGS |
|---|---|
| ACP-Architecture-Specification.md | Unified ACP v1.0 technical architecture (pre-AGS). AGS extends its layered model. |
| Arquitectura-Tres-Capas.md | Three-layer conceptual model (Identity, Authorization, Operation). Mapped to L1–L4 of the AGS. |
| GAT-Maturity-Model.md | Implementation maturity model. Aligned with the 6 phases of §6. |
| ACP-CONF-1.0 | Defines formal conformance requirements by level. AGS §6 is the practical adoption guide. |

---

## 10. Stack Evolution

**v1.7.0 (current):** L1–L6 specified. L7 with defined interface (REPUTATION_UPDATED in ledger) pending formal spec.

**v1.8.0 (next):**
- ACP-REP-1.2: Full L7 specification (Reputation Layer).
- Formal consumption of REPUTATION_UPDATED from ACP-LEDGER-1.1.
- Calibration of `capability_baselines` in PSN based on reputation scores.

**v2.0.0 (roadmap):**
- ACP-ITA-1.1: Cross-institution mutual recognition (enables full §7).
- Post-quantum cryptography: Migration from Ed25519 to post-quantum algorithms.
- Version negotiation protocol between implementations.
