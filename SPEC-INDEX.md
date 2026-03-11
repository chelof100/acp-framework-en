# ACP Repository Index — Module Specifications

**Last updated:** 2026-03-11
**Repos:** `chelof100/acp-framework-en` (EN) · `chelof100/acp-framework` (ES)
**Protocol version:** ACP v1.x

This index catalogues every module in the ACP specification tree, its current status, its responsibility, and its position in the dependency graph. Modules are grouped by architectural layer.

---

## How to read this index

| Symbol | Meaning |
|--------|---------|
| ✅ Stable | Frozen. No breaking changes without a new version number. |
| 📐 Normative | Adopted and binding for conformance. |
| 🔧 Draft | Specification is complete but not yet ratified. |
| ⚠️ Deprecated | Superseded. Kept for historical reference only. |
| 🔬 Proposed | Experimental or forward-looking. Not yet in v1.x conformance path. |

---

## Layer 1 — Sovereign AI Architecture

Foundational doctrine. Not protocol specifications — conceptual and philosophical grounding for the entire stack.

| File | Responsibility |
|------|---------------|
| `Sovereign-AI-Architecture.md` | Core thesis: AI systems operating in institutional environments must be architecturally sovereign — authority-bearing, not authority-receiving. Defines the 3-Layer Framework. |
| `ACP-Foundational-Doctrine.md` | Invariant statement of ACP's constitutional guarantee: `Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk`. |
| `Sovereign-AI-Architecture-Framework.md` | Engineering translation of L1 into design requirements. Maps doctrine to concrete protocol obligations. |

---

## Layer 2 — GAT Model (Governance Architecture for Trusted Agents)

Architecture reference. Defines how ACP components assemble into a complete governance system.

| File | Status | Responsibility |
|------|--------|---------------|
| `ACP-AGS-1.0.md` | 🔧 Draft | **Agent Governance Stack** — 8-layer reference architecture (L1 Identity through L8 Compliance). Positions every ACP spec in the full system. Defines "bankability" as the four-property contract: risk-modelable, auditable, predictable, accountable. The conceptual hub that shows how specs interlock. |
| `Three-Layer-Architecture.md` | Reference | Narrative overview of Sovereign Architecture → GAT Model → ACP Protocol. |
| `GAT-Maturity-Model.md` | Reference | Progressive maturity levels for institutional ACP adoption. |
| `Roadmap.md` | Reference | v1.x → v2.0 development trajectory. |

---

## Layer 3 — ACP Protocol Specifications

The normative protocol layer. Organized into five groups: Core, Operations, Security, Governance, and Compliance.

---

### 3A. Core — Identity, Tokens, and Messaging

Foundational primitives that every other spec depends on. Must be implemented first.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-SIGN-1.0** | 1.0 | 🔧 Draft | **Serialization and Signing** — Canonical serialization using JCS (RFC 8785) + Ed25519 signatures (RFC 8032). Every ACP artifact that requires a signature MUST use this spec. Defines `AgentID = base58(SHA-256(pubkey))`. The cryptographic foundation of the entire protocol. |
| **ACP-CT-1.0** | 1.0 | 🔧 Draft | **Capability Token** — Structure, fields, issuance, verification, and delegation rules for the primary authorization artifact. A CT authorizes an agent to perform a specific action on a specific resource. Defines the delegation chain model and capability scope. |
| **ACP-CAP-REG-1.0** | 1.0 | 🔧 Draft | **Capability Type Registry** — Canonical namespace for capability identifiers (`acp:cap:<domain>.<action>`). Defines the core domains (data, service, finance, compliance, audit), risk baselines per capability, mandatory constraints, and the extension process for institution-specific capabilities. |
| **ACP-HP-1.0** | 1.0 | 🔧 Draft | **Handshake Protocol** — Stateless Proof-of-Possession mechanism. Requires the CT bearer to demonstrate possession of the agent's private key on every request. Closes the stolen-token vulnerability: a valid CT alone is not sufficient to act — the agent must prove key ownership. |
| **ACP-MESSAGES-1.0** | 1.0 | 📐 Normative | **Formal Message Specification** — Wire format for all ACP messages: required fields (`protocol_version`, `message_id`), JSON serialization rules, signature requirements, and anti-replay protection. Required at L1 conformance. |
| **ACP-AGENT-1.0** | 1.0 | 📐 Normative | **Agent Data Model** — Formal definition of an ACP agent: identity fields, autonomy levels (L1–L4), capability scope, provable security properties, and the agent state machine (ACTIVE → SUSPENDED → BANNED). Supersedes ACP-AGENT-SPEC-0.3. Required at L1 conformance. |
| **ACP-DCMA-1.0** | 1.0 | 📐 Normative | **Delegation Chain Model & Attestation** — Formal model for chained delegation: mathematical definition of the delegation space, no-privilege-escalation constraint, transitive revocation rule (revoking a parent revokes all descendants), and the attestation format for delegation steps. Required at L1 conformance. |

---

### 3B. Operations — Execution, Ledger, and Data Flows

Runtime machinery: how actions are authorized, executed, recorded, queried, and transmitted.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-EXEC-1.0** | 1.0 | 🔧 Draft | **Execution Token** — Single-use artifact that proves an action was authorized by ACP and may be executed exactly once. Defines ET structure, lifecycle (ISSUED → CONSUMED / EXPIRED), issuance by ACP node, and validation by target system. Target systems only need the institutional public key and this spec — they do not need the full ACP protocol. |
| **ACP-LEDGER-1.2** | 1.2 | ✅ Stable | **Audit Ledger** — Append-only, hash-chained event store. Defines 14 event types (LEDGER_GENESIS, AUTHORIZATION, RISK_EVALUATION, REVOCATION, TOKEN_ISSUED, EXECUTION_TOKEN_ISSUED, EXECUTION_TOKEN_CONSUMED, AGENT_REGISTERED, AGENT_STATE_CHANGE, ESCALATION_CREATED, ESCALATION_RESOLVED, LIABILITY_RECORD, POLICY_SNAPSHOT_CREATED, REPUTATION_UPDATED), the SHA-256 hash-chaining mechanism, event envelope format (ver, event_id, event_type, sequence, timestamp, institution_id, prev_hash, payload, sig), and corruption detection. The central auditability primitive of the protocol. |
| **ACP-LIA-1.0** | 1.0 | ✅ Stable | **Liability Traceability** — For every consumed Execution Token, emits a `LIABILITY_RECORD` event that materializes the full delegation chain and the assigned responsible party (`liability_assignee`). Ensures that regulators and auditors can deterministically identify who bears legal responsibility for any agent action. |
| **ACP-PSN-1.0** | 1.0 | ✅ Stable | **Policy Snapshot** — Solves the "policy drift" problem: creates immutable, signed snapshots of the active risk policy at a point in time. Guarantees that the exact policy governing a past decision can be reconstructed at audit time, even if the policy has since changed. |
| **ACP-HIST-1.0** | 1.0 | 🔧 Draft | **History Query API** — Query layer over the ACP Ledger. Filtered and paginated endpoints for programmatic ledger access. Defines the `ExportBundle` format: a portable, signed, self-verifiable collection of ledger events for sharing audit trail segments between institutions without requiring real-time API access. |
| **ACP-API-1.0** | 1.0 | 🔧 Draft | **HTTP API** — Complete HTTP API specification: all endpoints, request/response schemas, status codes, error contracts, authentication (HTTPS + TLS 1.2+), and anomalous-condition behavior. The integration surface for ACP node implementations. |
| **ACP-RISK-1.0** | 1.0 | 🔧 Draft | **Deterministic Risk Model** — Defines the risk evaluation function `Risk(agent, capability, resource, context, history) → [0, 100]`. Four factors: capability base risk, agent reputation, resource sensitivity, context modifier. Decision thresholds: PERMIT / PERMIT_WITH_MONITOR / ESCALATE / DENY. All evaluations are deterministic and auditable via the `RISK_EVALUATION` ledger event. |
| **ACP-DISC-1.0** | 1.0 | 🔧 Draft | **Agent Discovery** — Opt-in public capability registry enabling institutions to find agents by their advertised capabilities without knowing the `agent_id` in advance. Decoupled from the capability grant system (ACP-CT-1.0): advertising a capability does not grant it. |
| **ACP-BULK-1.0** | 1.0 | 🔧 Draft | **Bulk Operations** — Batch authorization (up to 100 requests per call) and bulk liability query for high-throughput deployments (payment platforms, trading systems, multi-tenant orchestrators). Reduces accumulated latency from individual HTTP calls. |
| **ACP-NOTIFY-1.0** | 1.0 | 🔧 Draft | **Push Notifications / Webhooks** — Real-time push delivery of ledger events to external systems (dashboards, audit systems, secondary agents, third-party integrations) via HTTP webhooks. Eliminates the need for active polling of the ledger. |
| **ACP-PAY-1.0** | 1.0 | 🔧 Draft | **Payment Extension** — Links capability-based authorization with verifiable economic settlement. Integrates settlement proof within the capability model without modifying the ACP core. Records the `PAYMENT_VERIFIED` event in the audit ledger. Conformance level L2+. |
| **ACP-PSN-EXPORT.md** | 1.0 | 🔧 Draft | **Policy Snapshot Cross-Institution Export** — Extends ACP-PSN-1.0 with a signed, verifiable export format for sharing Policy Snapshots between federated institutions. Guarantees authenticity (from declared source) and integrity (unmodified in transit) of exported policy states. |
| **ACP-CROSS-ORG-1.0** *(new)* | 1.0 | 📐 Normative | **Cross-Organizational Interaction Registry** — Defines `CROSS_ORG_INTERACTION` as a first-class ledger event type, closing the asymmetric audit trail problem: before this spec, cross-institutional actions were only recorded at the source institution. This spec ensures every trust-boundary crossing is recorded in both ledgers via the CrossOrgBundle bilateral transmission protocol. Adds 8 ActionTypes, 6 emission rules, a 7-step target validation procedure, `CrossOrgAck` acknowledgment, and cross-org query extensions on HIST-1.0. L4 conformance. |

---

### 3C. Security — Identity Federation, Reputation, and Revocation

Cross-institutional trust, agent reputation, and token lifecycle management.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-ITA-1.0** | 1.0 | 🔧 Draft | **Institutional Trust Anchor (Centralized)** — Defines how institutions are registered in ACP. The Root Institutional Key (RIK) is the institution's HSM-held Ed25519 key pair. The Authority Root Key (ARK) is the signing key for operational artifacts. Establishes how external verifiers resolve institutional keys — the foundation for cross-institutional trust. Model A (centralized): single ITA authority. |
| **ACP-ITA-1.1** | 1.1 | 🔧 Draft | **Inter-Authority Federation** — Extends ITA-1.0 with Federated Model B: multiple independently-operated ITA authorities that mutually recognize each other via bilaterally signed `FederationRecord`s. Enables cross-authority verification without a single point of trust. Defines FederationRegistry (public), cross-authority resolution (1-hop, non-transitive), revocation propagation, and BFT quorum (n ≥ 3f+1) for authority consensus. |
| **ACP-RISK-1.0** | 1.0 | 🔧 Draft | *(see 3B — also listed under Operations for its role in the execution path)* |
| **ACP-REV-1.0** | 1.0 | 🔧 Draft | **Revocation Protocol** — Defines revocation mechanisms for Capability Tokens and agents (REVOCATION ledger event). Specifies status query protocol, offline behavior (fail-closed by default), and transitive revocation: revoking a token in a delegation chain invalidates all descendant tokens derived from it. |
| **ACP-REP-1.1** | 1.1 | ⚠️ Deprecated | **Reputation Extension (superseded)** — Original reputation model. Defines the scoring model, agent state machine, event taxonomy, and query API. Maintained for historical reference. **New implementations must use ACP-REP-1.2.** |
| **ACP-REP-1.2** | 1.2 | ✅ Stable | **Reputation & Trust Layer** — Supersedes REP-1.1 with three additions: (1) `ExternalReputationScore (ERS)` — portable cross-institutional score derived from LEDGER-1.2 events; (2) Dual Trust Bootstrap — new agents initialize ERS from a signed institutional attestation (ceiling ERS ≤ 0.195); (3) Reputation Decay — temporal degradation on inactivity. Composite formula: `0.6·ITS + 0.4·ERS`. Backwards compatible with REP-1.1. AGS L7. |
| **ACP-REP-PORTABILITY-1.0** *(new)* | 1.0 | 📐 Normative | **Reputation Portability** — Implements ACP-REP-1.1 §12.1. Defines the bilateral protocol for transporting an agent's reputation from its home institution to a foreign institution. Issues a signed `ReputationAttestation` (score ceiling: 0.85) with eligibility gates (`event_count ≥ 10`, `ITS ≥ 0.50`). Target institution computes initial ERS using a discount formula: `score × (1 - 1/(1 + refs/10)) × 0.85`. Non-transitive: attestations cannot be re-attested onward. Two new ledger event types: `REPUTATION_ATTESTATION_ISSUED`, `REPUTATION_ATTESTATION_RECEIVED`. L4 conformance. |

---

### 3D. Governance — Conformance and RFC Process

Conformance framework and protocol evolution process.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-CONF-1.0** | 1.0 | ⚠️ Deprecated | **Conformance v1.0** — Original 3-level conformance framework (L1–L3). Superseded by ACP-CONF-1.1. Maintained for historical reference of ACP v1.0. |
| **ACP-CONF-1.1** | 1.1 | 📐 Normative | **Conformance v1.1** — 5-level cumulative conformance framework: **L1-CORE** (SIGN, CT, HP, AGENT, MESSAGES, DCMA) → **L2-SECURITY** (RISK, REV, ITA-1.1, REP-1.2) → **L3-OPERATIONS** (EXEC, LEDGER-1.2, LIA, API) → **L4-FEDERATION** (ITA-1.1 federation, CROSS-ORG, REP-PORTABILITY) → **L5-DECENTRALIZED** (ACP-D). Each level includes all lower levels. Replaces the profile model from v1.0. |
| **ACR-1.0** | 1.0 | 🔧 Draft | **ACP Compliance Runner** — Command-line tool specification for executing ACP-TS-1.1 test suites against an implementation. Enables automated conformance verification and CI/CD integration. |
| `RFC-PROCESS.md` | — | Active | Defines how ACP specifications are proposed, reviewed, ratified, and deprecated through the RFC process. Governance rules for protocol evolution. |
| `RFC-REGISTRY.md` | — | Active | Canonical list of all active, accepted, deferred, and withdrawn RFCs. |

---

### 3E. Compliance — Testing, Certification, and IUT Protocol

Operational machinery for verifying and certifying conformance.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-TS-1.0** | 1.0 | ⚠️ Superseded | Original test suite format. Replaced by ACP-TS-1.1. |
| **ACP-TS-1.1** | 1.1 | 📐 Normative | **Test Vector Format** — Normative format for ACP compliance test vectors. Deterministic, reproducible, language-agnostic. All conformance test cases must be expressed in this format. Required for certification. |
| **ACP-IUT-PROTOCOL-1.0** | 1.0 | 📐 Normative | **IUT Communication Protocol** — Defines how the Compliance Runner (ACR-1.0) communicates with an Implementation Under Test: STDIN/STDOUT/STDERR channels, JSON UTF-8 format, one JSON object per execution. Enables runner-agnostic testing of any ACP implementation. |
| **ACP-CERT-1.0** | 1.0 | 🔧 Draft | **Certification** — Process for publishing verifiable conformance: implementor runs the official runner, generates `report.json`, submits to the ACP Certification Authority, reproducibility is verified, signed certificate is issued. Defines the certification identifier format and governance. |

---

### 3F. Decentralized — ACP-D (v2.0 Target)

Extension of ACP to decentralized environments without a central issuer. Not in the v1.x conformance path.

| Spec | Version | Status | Responsibility |
|------|---------|--------|---------------|
| **ACP-D-Specification.md** | — | 🔬 Proposed | **Decentralized ACP** — Eliminates the central ITA issuer by replacing it with: Decentralized Identifiers (DIDs), Verifiable Credentials (VCs), and cryptographically derived capability tokens that can be verified without querying a central authority. Self-Sovereign Capability model. Target conformance level: L5-DECENTRALIZED in ACP-CONF-1.1. v2.0 design. |
| `Architecture-Without-Central-Issuer.md` | — | 🔬 Proposed | Design analysis for issuer-free ACP. Threat model, trust bootstrapping, and protocol changes required for decentralization. |

---

## Layer 4 — Formal Analysis

Mathematical security models. Not specs — proofs and adversarial analyses.

| File | Responsibility |
|------|---------------|
| `Formal-Security-Model.md` / `v2` | Formal security model: adversarial model, security properties as mathematical predicates, safety invariants. |
| `Security-Reduction-EUF-CMA.md` | EUF-CMA (Existential Unforgeability under Chosen Message Attack) reduction for ACP-SIGN-1.0. Proves that breaking ACP token integrity requires breaking Ed25519. |
| `Adversarial-Analysis.md` | Systematic adversarial analysis: attack classes, mitigations, residual risks. |
| `Threat-Model.md` | Threat actor taxonomy, attack surfaces, and security boundaries. |
| `Formal-Decision-Engine-MFMD.md` | Formal model of the Multi-Factor Multi-Domain decision engine underpinning ACP-RISK-1.0. |
| `Systemic-Hardening.md` | Defense-in-depth measures for production deployments. |
| `Security-Mathematical-Model.md` | Mathematical formalization of the protocol's security properties. |
| `Logical-Architectural-View.md` | Logical architecture as a formal system. |

---

## Layer 5 — Implementation

| Directory | Responsibility |
|-----------|---------------|
| `05-implementation/` | Cryptographic MVP, minimum required architecture, and Python prototype. Implementation guidance derived from the formal specs. |
| `07-reference-implementation/acp-go/` | Reference implementation in Go. Packages: `ledger`, `reputation`, `token`, `risk`, `sign`. Authoritative executable translation of the core specs. |
| `07-reference-implementation/sdk/python/` | Python SDK. Client library for interacting with an ACP node. |
| `07-reference-implementation/sdk/typescript/` | TypeScript SDK. Client library for browser and Node.js environments. |

---

## Layer 6 — Publications

| File | Responsibility |
|------|---------------|
| `ACP-Whitepaper-v1.0.md` | Executive-level whitepaper: motivation, architecture overview, use cases. |
| `ACP-Technical-Academic.md` | Academic technical paper. Formal treatment of the protocol for peer review. |
| `IEEE-NDSS-ACP-1.0.md` | IEEE NDSS conference paper submission. |

---

## Dependency Graph (abridged)

```
ACP-CONF-1.1
├── L1-CORE
│   ├── ACP-SIGN-1.0          ← cryptographic base
│   ├── ACP-CT-1.0            ← capability tokens
│   ├── ACP-CAP-REG-1.0       ← capability namespace
│   ├── ACP-HP-1.0            ← proof-of-possession
│   ├── ACP-MESSAGES-1.0      ← wire format
│   ├── ACP-AGENT-1.0         ← agent data model
│   └── ACP-DCMA-1.0          ← delegation chains
│
├── L2-SECURITY
│   ├── ACP-RISK-1.0          ← risk evaluation
│   ├── ACP-REV-1.0           ← token/agent revocation
│   ├── ACP-ITA-1.0/1.1       ← institutional trust anchors
│   └── ACP-REP-1.2           ← reputation & trust
│       └── (supersedes ACP-REP-1.1)
│
├── L3-OPERATIONS
│   ├── ACP-EXEC-1.0          ← execution tokens
│   ├── ACP-LEDGER-1.2        ← audit ledger (14 event types)
│   │   ├── ACP-LIA-1.0       ← liability records
│   │   ├── ACP-PSN-1.0       ← policy snapshots
│   │   └── ACP-HIST-1.0      ← query layer + ExportBundle
│   └── ACP-API-1.0           ← HTTP API
│
├── L4-FEDERATION
│   ├── ACP-CROSS-ORG-1.0     ← cross-org interaction registry [NEW]
│   └── ACP-REP-PORTABILITY-1.0 ← reputation portability [NEW]
│
└── L5-DECENTRALIZED
    └── ACP-D                 ← DID + VC + self-sovereign capability [v2.0]

Extensions (any level):
├── ACP-BULK-1.0              ← batch operations
├── ACP-DISC-1.0              ← agent discovery
├── ACP-NOTIFY-1.0            ← webhooks
├── ACP-PAY-1.0               ← payment settlement
└── ACP-PSN-EXPORT.md         ← policy snapshot cross-org export
```

---

## Module Count

| Group | Count |
|-------|-------|
| L1 Sovereign Architecture | 3 |
| L2 GAT Model | 4 |
| L3A Core | 7 |
| L3B Operations | 11 |
| L3C Security | 6 |
| L3D Governance | 4 |
| L3E Compliance | 4 |
| L3F Decentralized | 2 |
| L4 Formal Analysis | 8 |
| L5 Implementation | 3 |
| L6 Publications | 4 |
| **Total** | **56** |
