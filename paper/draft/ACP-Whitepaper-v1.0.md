# Agent Control Protocol
## ACP v1.11
### Admission Control for Agent Actions

**Author:**
Marcelo Fernandez
TraslaIA
info@traslaia.com | www.traslaia.com
March 2026
Draft Standard · Version 1.11 · B2B Use

---

## Abstract

Agent Control Protocol (ACP) is a formal technical specification for governance of autonomous agents in B2B institutional environments. ACP is the **admission control layer between agent intent and system state mutation**: before any agent action reaches execution, it must pass a cryptographic admission check that validates identity, capability scope, delegation chain, and policy compliance simultaneously.

ACP defines the mechanisms of cryptographic identity, capability-based authorization, deterministic risk evaluation, verifiable chained delegation, transitive revocation, and immutable auditing that a system must implement for autonomous agents to operate under explicit institutional control.

ACP operates as an additional layer on top of RBAC and Zero Trust, without replacing them. It is designed specifically for the problem that neither model solves: governing what an autonomous agent can do, under what conditions, with what limits, and with complete traceability for external auditing — including across organizational boundaries.

The v1.11 specification is composed of 36 technical documents organized into five conformance levels (L1–L5). It includes a Go reference implementation of 22 packages covering all L1–L4 capabilities, 42 signed conformance test vectors (Ed25519 + SHA-256), and an OpenAPI 3.1.0 specification for all HTTP endpoints. It defines more than 62 verifiable requirements, 12 prohibited behaviors, and the mechanisms for interoperability between institutions.

---

## Contents

1. The Problem ACP Solves
   - 1.1 The structural gap
   - 1.2 Why RBAC and Zero Trust are insufficient
   - 1.3 The concrete scenario ACP prevents
2. What ACP Is
   - 2.1 Definition
   - 2.2 Design principles
   - 2.3 Formal agent model
   - 2.4 Layered architecture
3. Technical Mechanisms
   - 3.1 Serialization and signing (ACP-SIGN-1.0)
   - 3.2 Capability Token (ACP-CT-1.0)
   - 3.3 Handshake and Proof-of-Possession (ACP-HP-1.0)
   - 3.4 Deterministic risk evaluation (ACP-RISK-1.0)
   - 3.5 Verifiable chained delegation
   - 3.6 Execution Token (ACP-EXEC-1.0)
   - 3.7 Audit Ledger (ACP-LEDGER-1.0)
4. Inter-Institutional Trust
   - 4.1 Institutional Trust Anchor (ACP-ITA-1.0)
   - 4.2 Mutual recognition between authorities (ACP-ITA-1.1)
   - 4.3 Institutional key rotation and revocation
5. Security Model
   - 5.1 Threat Model (STRIDE)
   - 5.2 Guaranteed security properties
   - 5.3 Declared residual risks
6. Conformance and Interoperability
   - 6.1 Conformance levels
   - 6.2 Conformance declaration
   - 6.3 Prohibited behaviors
   - 6.4 B2B interoperability conditions
7. Use Cases
   - 7.1 Financial sector — Inter-institutional payment agents
   - 7.2 Digital government — Document processing
   - 7.3 Enterprise AI — Multi-company orchestration
   - 7.4 Critical infrastructure — Monitoring and actuation agents
8. Specification Status
   - 8.1 v1.0 Documents — Complete
   - 8.2 v1.1 Documents — Complete
   - 8.3 v2.0 Roadmap — Planned
9. How to Implement ACP
   - 9.1 Minimum requirements for L1 conformance
   - 9.2 Additional requirements for L3 conformance
   - 9.3 What ACP does not prescribe
10. Conclusion
- Appendix A — Glossary
- Appendix B — References

---

## 1. The Problem ACP Solves

Autonomous agents are being deployed in institutional environments without a technical standard to govern their behavior. This is not a tooling problem — it is a protocol problem.

### 1.1 The structural gap

When an autonomous agent makes a decision and executes it, there is a critical moment between both actions. In current models, that moment does not formally exist: the decision and the execution are the same event. The agent decides and acts. There is no intermediate validation. There is no point of intervention. There is no structured record of why the decision was made.

This is acceptable when a human executes that action, because the human bears responsibility and can be questioned. An autonomous agent cannot be questioned. It can only be audited — and only if there is something to audit.

> The problem is not whether agents are trustworthy. The problem is that currently no formal technical mechanism exists that allows an institution to demonstrate that its agents operated within authorized limits.

### 1.2 ACP as Admission Control

The clearest frame for understanding what ACP does is the Kubernetes Admission Controller analogy.

Kubernetes intercepts every API request before it reaches the cluster and runs it through a sequence of admission checks — ValidatingWebhookConfiguration, ResourceQuota enforcement, OPA Gatekeeper policies. If any check fails, the request is rejected before touching cluster state.

ACP applies this pattern to agent actions:

```
agent intent
    ↓
[1] Identity check     (ACP-AGENT-1.0, ACP-HP-1.0)     — is this agent who they claim to be?
    ↓
[2] Capability check   (ACP-CT-1.0, ACP-DCMA-1.0)      — does the agent hold a token for this?
    ↓
[3] Policy check       (ACP-RISK-1.0, ACP-PSN-1.0)     — is this action within current policy?
    ↓
[4] ADMIT / DENY / ESCALATE
    ↓  (if ADMIT)
[5] Execution token    (ACP-EXEC-1.0)                   — single-use cryptographic proof of admit
    ↓
[6] Ledger record      (ACP-LEDGER-1.3)                 — immutable signed audit entry
    ↓
system state mutation
```

The critical difference from Kubernetes: ACP's admission check operates across institutional boundaries. An agent from Bank A can be admitted by Bank B without Bank B trusting Bank A's internal infrastructure — the cryptographic proof is self-contained and verifiable with Bank A's published public key alone.

This "admission control" framing also clarifies the relationship with related tools:
- **OPA (Open Policy Agent)** can serve as the policy evaluation engine inside Step 3 — ACP does not replace OPA, it adds the identity and delegation chain layers above it
- **AWS IAM / Azure RBAC** model static role permissions for humans — ACP adds dynamic agent delegation with execution proof
- **OAuth 2.0** handles API access tokens — ACP extends delegation to multi-agent chains with non-escalation and verifiable provenance
- **SPIFFE / SPIRE** provides cryptographic workload identity — ACP builds on that identity to add capability scoping and governance

### 1.3 Why RBAC and Zero Trust are insufficient

RBAC (Role-Based Access Control) and Zero Trust are the predominant control layers in enterprise environments. Both are necessary. Neither solves the problem of governing autonomous agents:

| Criterion | RBAC | Zero Trust | ACP |
|-----------|------|------------|-----|
| Designed for | Human users with roles | Network and resource access | Autonomous institutional agents |
| Native cryptographic identity | No | Partial | Yes — Ed25519 mandatory |
| Verifiable dynamic delegation | No | No | Yes — chained and auditable |
| Decision / execution separation | No | No | Yes — Execution Tokens |
| Real-time risk evaluation | No | Partial | Yes — deterministic and reproducible |
| Multi-institutional auditing | Non-standard | Non-standard | Native — signed ledger |
| Transitive delegation revocation | No | No | Yes — formal propagation |
| B2B interoperability for agents | Unstructured | Unstructured | Central protocol design |

ACP does not replace RBAC or Zero Trust. It adds a governance layer oriented specifically to autonomous agents that operates above existing controls.

### 1.4 The concrete scenario ACP prevents

Consider the following scenario, which occurs today in multiple organizations with advanced automation systems:

**Scenario without ACP**

A financial processing agent receives instructions from another agent to execute a transfer. The agent executes the action. If the instruction was legitimate, everything works. If the instruction was compromised, injected, or generated by an unauthorized agent, the transfer occurs anyway. No formal mechanism exists to prevent it, nor is there a technical record that allows reconstructing the authorization chain.

**Scenario with ACP**

The agent requesting the transfer must present a Capability Token cryptographically signed by the issuing institution, demonstrate possession of the associated private key, and the request passes through the risk engine before receiving an Execution Token. The ET is single-use. The entire chain is recorded in the Audit Ledger with an externally verifiable institutional signature.

---

## 2. What ACP Is

A formal technical specification — not a framework, not a platform, not a set of best practices. A protocol with precise definitions, formal state models, verifiable flows, and explicit conformance requirements.

### 2.1 Definition

Agent Control Protocol (ACP) is a technical specification that defines the mechanisms by which autonomous institutional agents are identified, authorized, monitored, and governed in B2B environments. It establishes the formal contract between an agent, the institution that operates it, and the institutions with which it interacts.

**Core principle:**

```
Execute(request) ⟹ ValidIdentity(agent) ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

No action of an ACP agent can be executed without all four predicates being simultaneously true. If any fails, the action is denied. No exceptions.

### 2.2 Design principles

ACP was designed with five principles that are non-negotiable at implementation time:

- **P1 Fail Closed.** On any internal component failure, the action is denied. Never approved by default.
- **P2 Identity is cryptography.** `AgentID = base58(SHA-256(public_key))`. No usernames. No arbitrary IDs. Identity cannot be claimed — it must be demonstrated in every request.
- **P3 Delegation does not expand privileges.** The delegated agent's permissions are always a strict subset of the delegator's permissions. This property is cryptographically verified at every chain hop.
- **P4 Complete auditability.** Every decision — approved, denied, or escalated — is recorded in an append-only ledger with institutional signature. Not just successes. Everything.
- **P5 External verification possible.** Any institution can verify ACP artifacts from another institution using only the public key registered in the ITA. No dependency on proprietary systems.

### 2.3 Formal agent model

In ACP, an agent is a formal tuple with well-defined state:

```
A = ( AgentID , capabilities , autonomy_level , state , limits )
```

| Field | Type | Description |
|-------|------|-------------|
| AgentID | String (43-44 chars) | `base58(SHA-256(pk))`. Derived from public key. Immutable. |
| capabilities | List of strings | Explicit permissions. Format: `acp:cap:<domain>.<action>`. Never abstract roles. |
| autonomy_level | Integer 0–4 | Determines risk evaluation thresholds. 0 = no autonomy. 4 = maximum. |
| state | Enum | `active \| restricted \| suspended \| revoked`. Transition to `revoked` is unidirectional. |
| limits | Object | Rate limits, maximum amounts, time windows. Not modifiable at runtime. |

### 2.4 Layered architecture

ACP does not replace existing security infrastructure. It is added as an upper layer with specific responsibility:

```
ACP Layer     — Autonomous agent governance: identity, authorization, risk, auditing
RBAC Layer    — Role-based access control for human users
Zero Trust    — Continuous identity and network access verification
```

---

## 3. Technical Mechanisms

ACP defines six interdependent mechanisms. Each has its own formal specification, state model, data structure, protocol flow, and error codes.

### 3.1 Serialization and signing (ACP-SIGN-1.0)

Every verification in ACP begins with signature verification. ACP-SIGN-1.0 defines the exact process that produces a binary result — valid or invalid — without ambiguity:

- **Canonicalization with JCS (RFC 8785).** Produces a deterministic representation of the JSON object, independent of field order and the system that generated it.
- **SHA-256 hash** over the canonical output in UTF-8.
- **Ed25519 signature (RFC 8032)** over the hash. 32-byte key, 64-byte signature.
- **Base64url encoding** without padding for transmission.

Signature verification precedes all semantic validation. An object with an invalid signature is rejected without processing its content. This rule has no exceptions (PROHIB-003, PROHIB-012).

### 3.2 Capability Token (ACP-CT-1.0)

The Capability Token is ACP's central artifact. It is a signed JSON object that specifies exactly what an agent can do, on what resource, for how long, and whether it can delegate that capability to other agents.

```json
{
  "ver": "1.0",
  "iss": "<AgentID_issuer>",
  "sub": "<AgentID_subject>",
  "cap": ["acp:cap:financial.payment"],
  "res": "org.example/accounts/ACC-001",
  "exp": 1718923600,
  "nonce": "<128bit_CSPRNG_base64url>",
  "deleg": { "allowed": true, "max_depth": 2 },
  "parent_hash": null,
  "sig": "<Ed25519_base64url>"
}
```

**Critical fields:** `exp` is mandatory — a token without expiry is invalid by definition. The 128-bit nonce prevents replay attacks. `parent_hash` chains delegated tokens in a verifiable way. The signature covers all fields except `sig`.

### 3.3 Handshake and Proof-of-Possession (ACP-HP-1.0)

Possessing a valid Capability Token is not sufficient to act. ACP-HP-1.0 requires that the bearer demonstrate in every request that they possess the private key corresponding to the AgentID declared in the token. This eliminates the possibility of impersonating an agent with a stolen token.

The protocol is stateless — it does not establish sessions, does not produce a `session_id`, does not require server-side state between requests. The proof occurs in every interaction:

- The receiving system issues a 128-bit challenge generated by CSPRNG, valid for 30 seconds and single-use.
- The agent signs the challenge together with the HTTP method, path, and body hash of the request.
- The receiver verifies the signature using the agent's public key, obtained from the ITA.
- The challenge is deleted immediately after use — it cannot be reused.

This sequence guarantees four formal properties: identity authentication, cryptographic request binding, anti-replay, and transport channel independence.

### 3.4 Deterministic risk evaluation (ACP-RISK-1.0)

Each authorization request passes through a deterministic risk function that produces a Risk Score (RS) in the range [0, 100]. The same input always produces the same result — no stochastic elements, no machine learning in the critical path.

```
RS = min(100,  B(c)  +  F_ctx(x)  +  F_hist(h)  +  F_res(r))
```

| Factor | Description | Example values |
|--------|-------------|----------------|
| B(c) | Baseline by capability | `*.read = 0` \| `financial.payment = 35` \| `financial.transfer = 40` |
| F_ctx(x) | Request context | Non-corporate IP +20 \| Outside business hours +15 \| Timestamp drift +30 |
| F_hist(h) | Agent history (24h) | Recent denial +20 \| No prior history +10 \| Anomalous frequency +15 |
| F_res(r) | Resource classification | `public = 0` \| `internal = 5` \| `sensitive = 15` \| `restricted = 45` |

The RS determines the decision according to the thresholds configured for the agent's `autonomy_level`. With `autonomy_level` 2 (standard): RS ≤ 39 → APPROVED, RS 40–69 → ESCALATED, RS ≥ 70 → DENIED. An agent with `autonomy_level` 0 always receives DENIED, without executing the function.

Every evaluation generates a complete record with all applied factors, intermediate values, and the final decision. This allows the calculation to be fully reproduced from the audit log.

### 3.5 Verifiable chained delegation

ACP allows an agent to delegate capabilities to another agent, which in turn can delegate to a third, up to the maximum depth defined in the root token. Delegation is a mechanism with three guaranteed properties:

- **No privilege escalation.** The delegated agent's capability set is always a subset of the delegator's set. This property is cryptographically verified at every hop via the `parent_hash` field.
- **Bounded depth.** The `max_depth` field of the root token establishes the chain limit. A chain that exceeds that limit is invalid.
- **Transitive revocation.** Revoking an agent's token automatically invalidates all delegated tokens that descend from it. Zombie delegations are impossible by design.

Verifying a delegation chain requires verifying each token from the requester to the institutional root, validating signature, expiry, and constraints at each hop. The complete chain is recorded in the Audit Ledger.

### 3.6 Execution Token (ACP-EXEC-1.0)

The separation between authorization and execution is a core principle of ACP. When the authorization engine approves a request, it does not return a generic permission — it returns an Execution Token (ET): a single-use artifact with a short lifetime that authorizes exactly that action, on that resource, at that moment.

- An ET can only be consumed once. If presented twice, the second presentation is rejected (PROHIB-002).
- An expired ET is invalid even if it was never used.
- The target system that receives and consumes the ET notifies the ACP endpoint of the consumption, closing the audit cycle.

This mechanism ensures that even an APPROVED authorization is not executable indefinitely. It closes the window between the moment an action is approved and the moment it is executed.

### 3.7 Audit Ledger (ACP-LEDGER-1.0)

The Audit Ledger is a chain of cryptographically signed events where each event includes the hash of the previous event, forming a structure that makes it impossible to modify or delete an event without invalidating the entire subsequent chain:

```
hash_n = SHA-256( event_n || hash_n-1 )
```

The ledger records all ACP lifecycle event types: GENESIS, AUTHORIZATION (including DENIED and ESCALATED, not just APPROVED), RISK_EVALUATION, TOKEN_ISSUED, TOKEN_REVOKED, EXECUTION_TOKEN_ISSUED, and EXECUTION_TOKEN_CONSUMED.

Institutions with FULL conformance level expose the ledger via the `GET /acp/v1/audit/query` endpoint, allowing external partners to verify the chain integrity using only the institutional ITA public key. Modifying or deleting ledger events is a prohibited behavior (PROHIB-007, PROHIB-008).

---

## 4. Inter-Institutional Trust

In a B2B environment, agents of one institution interact with another institution's systems. ACP defines the exact mechanism by which this trust is established, verified, and can be revoked.

### 4.1 Institutional Trust Anchor (ACP-ITA-1.0)

The ITA is the authoritative registry that links an `institution_id` to an Ed25519 public key. It is the only point where ACP depends on an out-of-band mechanism: the initial distribution of the ITA authority's public key. Once that key is resolved, all subsequent verification is autonomous and cryptographic.

Each institution registers in the ITA its Root Institutional Key (RIK) — the private key it holds in HSM and never leaves it. All ACP artifacts from that institution (tokens, ledger events, API responses) are signed with that key. Any third party can verify them by resolving the public key from the ITA.

### 4.2 Mutual recognition between authorities (ACP-ITA-1.1)

When two institutions operate under different ITA authorities, ACP-ITA-1.1 defines the mutual recognition protocol. The process requires both authorities to sign a Mutual Recognition Agreement (MRA), which establishes:

- The scope of recognition (included capabilities, accessible resources, conditions).
- The agreement's validity period and renewal process.
- The proxy resolution mechanism: when authority A receives a query about an institution registered with authority B, authority A can resolve the key using the MRA's ProxyRecord.

Recognition is explicitly non-transitive. If A recognizes B and B recognizes C, A does not automatically recognize C. Each bilateral relationship requires its own signed MRA. This prevents uncontrolled expansion of the trust graph.

### 4.3 Institutional key rotation and revocation

ACP defines two key management processes: normal rotation and emergency rotation.

Normal rotation includes a transition period of up to 7 days during which both keys (old and new) are valid. This allows artifacts signed with the old key to be verified during the transition, without service interruptions.

Emergency rotation is activated when a key is compromised. The result is immediate: the key is marked as `revoked`, all artifacts signed with it are invalid from that moment, and there is no transition period. This is correct and expected — the compromise of an institutional key is a maximum-priority security event.

---

## 5. Security Model

ACP explicitly defines which threats it mitigates, which properties it guarantees, and which risks fall outside its scope. Clarity about the protocol's limits is part of the specification.

### 5.1 Threat Model (STRIDE)

| Category | Threat | Mitigation in ACP |
|----------|--------|-------------------|
| Spoofing | AgentID impersonation | `AgentID = SHA-256(pk)`. Without valid signature with corresponding `sk` → immediate DENIED. |
| Tampering | Token or event alteration | Ed25519 covers all fields. Chained ledger — altering one event invalidates the entire subsequent chain. |
| Repudiation | Agent denies executed action | ActionRequest digitally signed. Non-repudiation guaranteed by design. |
| Info Disclosure | Capability exposure | Tokens reveal only the necessary subset. Channel confidentiality depends on TLS. |
| Denial of Service | Request or escalation flooding | Rate limits per `agent_id`. `WithinLimits()` includes anomalous frequency control. |
| Elevation | Delegation that expands privileges | `Constraints_delegated ⊆ Constraints_original`. Cryptographically verified at each hop. |

### 5.2 Guaranteed security properties

ACP guarantees the following properties when the implementation is compliant with the specification:

- **Artifact integrity.** EUF-CMA security of Ed25519. Impossible to modify a token or event without invalidating the signature.
- **Identity authenticity.** Only whoever possesses `sk` can generate a valid signature under the corresponding `pk`. The probability of forgery is negligible.
- **No privilege escalation via delegation.** Demonstrable by induction over the delegation chain.
- **Anti-replay.** The single-use challenge in ACP-HP-1.0 makes reusing a proof of possession useless — the challenge was already consumed.
- **Effective revocation.** `Valid(t) = valid_signature ∧ not_expired ∧ not_revoked ∧ valid_delegation`. All four conditions must be true.

### 5.3 Declared residual risks

ACP explicitly declares what it cannot resolve:

- **Total compromise of the RIK held in HSM.** ACP defines the emergency rotation process but cannot prevent a physical compromise of the custody infrastructure.
- **Coordinated institutional collusion.** If multiple institutions act maliciously in a coordinated manner, they can generate valid artifacts. ACP guarantees traceability, not prevention of malicious agreements between parties.
- **Implementation failures.** ACP is a specification. An implementation that violates prohibited behaviors can compromise all protocol guarantees. Conformance requires formal testing.
- **ITA bootstrap.** The only point that depends on an out-of-band channel. Once the ITA root key is resolved, everything subsequent is autonomous.

---

## 6. Conformance and Interoperability

ACP defines three conformance levels with verifiable requirements. An implementation publicly declares its level via a standard endpoint. There is no partial conformance within a level.

### 6.1 Conformance levels

| Level | Required documents | Enabled capability |
|-------|-------------------|-------------------|
| L1 — CORE | ACP-SIGN-1.0 \| ACP-CT-1.0 \| ACP-CAP-REG-1.0 \| ACP-HP-1.0 | Token issuance and verification with cryptographic proof of possession |
| L2 — SECURITY | L1 + ACP-RISK-1.0 \| ACP-REV-1.0 \| ACP-ITA-1.0 | Risk evaluation, transitive revocation, inter-institutional delegation |
| L3 — FULL | L2 + ACP-API-1.0 \| ACP-EXEC-1.0 \| ACP-LEDGER-1.0 | Complete ACP system with verifiable inter-institutional auditing |

### 6.2 Conformance declaration

Every compliant implementation MUST expose a public endpoint without authentication:

```
GET https://<contact_endpoint>/acp/v1/conformance
```

This endpoint returns the institutional conformance declaration: achieved level, implemented documents, declared institutional extensions, and declaration date. It allows any external partner to verify the conformance level of a counterparty before establishing an ACP relationship.

### 6.3 Prohibited behaviors

ACP defines 12 behaviors that no compliant implementation can exhibit. If an implementation exhibits any of them, it cannot declare conformance at any level:

| Code | Prohibited behavior |
|------|---------------------|
| PROHIB-001 | Approving a request when any evaluation component fails |
| PROHIB-002 | Reusing an already-consumed Execution Token |
| PROHIB-003 | Omitting signature verification on any incoming artifact |
| PROHIB-004 | Treating a not-found `token_id` as active in a revocation context |
| PROHIB-005 | Allowing state transition from `revoked` |
| PROHIB-006 | Issuing an ET without a prior APPROVED AuthorizationDecision |
| PROHIB-007 | Modifying or deleting Audit Ledger events |
| PROHIB-008 | Silencing ledger corruption detection |
| PROHIB-009 | Ignoring `max_depth` in delegation chains |
| PROHIB-010 | Implementing an offline policy more permissive than defined in ACP-REV-1.0 |
| PROHIB-011 | Approving requests from agents with `autonomy_level` 0 |
| PROHIB-012 | Continuing to process an artifact with an invalid signature |

### 6.4 B2B interoperability conditions

ACP establishes three levels of interoperability between institutions, each with precise conditions:

- **L1 Interoperability:** Institution A can verify tokens from institution B if both implement ACP-CONF-L1, A has access to B's public key (via ITA or out-of-band), and B's tokens use ACP-SIGN-1.0 algorithms.
- **L2 Interoperability:** A can delegate to B's agents if both implement ACP-CONF-L2, are registered in a common ITA or with mutual recognition, and B's revocation endpoint is accessible to A.
- **L3 Interoperability:** A can audit B's ledger if B implements ACP-CONF-L3, A can resolve B's public key via ITA, and B exposes `GET /acp/v1/audit/query`.

---

## 7. Use Cases

ACP is sector-agnostic. The mechanisms are the same regardless of industry. What varies is the configuration of capabilities, resources, and autonomy levels.

### 7.1 Financial sector — Inter-institutional payment agents

ACP-PAY-1.0 extends the capability registry with formal specifications for `acp:cap:financial.payment` and `acp:cap:financial.transfer`. Each financial operation executed by an ACP agent includes:

- Mandatory constraints in the token: `max_amount`, `currency`. Without these constraints, the token is invalid for financial operations.
- 12 specific validation steps for payment operations, including limit verification, beneficiary validation, and time window control.
- 11 proprietary error codes (PAY-001 to PAY-011) for precise failure diagnosis.
- Ledger record with all operation fields, enabling complete regulatory auditing.

In a financial B2B scenario, Bank A can authorize an agent to execute payments up to a defined amount to pre-approved beneficiaries, in a specific time window, with a complete record verifiable by the receiving Bank B without needing shared proprietary systems.

### 7.2 Digital government — Document processing

Government agents that process documents can operate under ACP with `autonomy_level` 1 or 2, requiring human review for any action with a Risk Score above the configured threshold. The institutional ITA guarantees that only agents certified by the government authority can access classified resources. Ledger traceability is forensic evidence for regulatory audits and transparency processes.

### 7.3 Enterprise AI — Multi-company orchestration

In agent pipelines that cross the boundaries of multiple organizations, ACP allows each organization to maintain formal control over what other organizations' agents can do in their systems. Chained delegation allows an agent in company A to operate in company B's systems with explicitly delegated capabilities, without B needing to trust A's internal controls — only the chain of signed tokens.

### 7.4 Critical infrastructure — Monitoring and actuation agents

For systems where an incorrect action has irreversible consequences, ACP allows configuring `autonomy_level` 0 for all agents acting on critical systems. Any actuation request is DENIED without evaluating the Risk Score, and must pass through human review. The ledger provides the forensic record needed for post-incident analysis.

---

## 8. Specification and Implementation Status

ACP v1.11 is a complete Draft Standard specification with a full Go reference implementation.

### 8.1 Active Specifications — v1.11 (36 documents)

**L1 — Core Execution**

| Document | Title |
|----------|-------|
| ACP-SIGN-1.0 | Serialization and Signature |
| ACP-AGENT-1.0 | Agent Identity |
| ACP-CT-1.0 | Capability Tokens |
| ACP-CAP-REG-1.0 | Capability Registry |
| ACP-HP-1.0 | Handshake / Proof-of-Possession |
| ACP-DCMA-1.0 | Delegated Chain Multi-Agent |
| ACP-MESSAGES-1.0 | Wire Message Format |
| ACP-PROVENANCE-1.0 | Authority Provenance |

**L2 — Security**

| Document | Title |
|----------|-------|
| ACP-RISK-1.0 | Deterministic Risk Engine |
| ACP-REV-1.0 | Revocation Protocol |
| ACP-ITA-1.0 | Institutional Trust Anchor |
| ACP-ITA-1.1 | ITA Mutual Recognition |
| ACP-REP-1.2 | Reputation Module |
| ACP-REP-PORTABILITY-1.0 | Reputation Portability |

**L3 — Verifiable Execution**

| Document | Title |
|----------|-------|
| ACP-API-1.0 | HTTP API |
| ACP-EXEC-1.0 | Execution Tokens |
| ACP-LEDGER-1.3 | Audit Ledger (mandatory institutional sig) |
| ACP-PSN-1.0 | Policy Snapshot |
| ACP-POLICY-CTX-1.0 | Policy Context Snapshot |
| ACP-LIA-1.0 | Liability Attribution |
| ACP-HIST-1.0 | History Query API |

**L4 — Extended Governance**

| Document | Title |
|----------|-------|
| ACP-PAY-1.0 | Financial Capability |
| ACP-NOTIFY-1.0 | Event Notifications |
| ACP-DISC-1.0 | Service Discovery |
| ACP-BULK-1.0 | Batch Operations |
| ACP-CROSS-ORG-1.0 | Cross-Organization Bundles |
| ACP-GOV-EVENTS-1.0 | Governance Event Stream |

**Governance**

| Document | Title |
|----------|-------|
| ACP-CONF-1.2 | Conformance — sole normative source |
| ACP-TS-1.1 | Test Vector Format |
| RFC-PROCESS | Specification Process |
| RFC-REGISTRY | Specification Registry |
| ACR-1.0 | Change Request Process |
| ACP-GOV-EVENTS-1.0 | Governance Events |

Superseded versions archived in `archive/specs/` (CONF-1.0, CONF-1.1, LEDGER-1.2, REP-1.1, AGENT-SPEC-0.3).

### 8.2 Reference Implementation — Complete (22 Go packages)

The Go reference implementation in `impl/go/` covers all L1–L4 conformance levels:

| Package | Spec | Level |
|---------|------|-------|
| `pkg/handshake` | ACP-HP-1.0 | L1 |
| `pkg/tokens` | ACP-CT-1.0 | L1 |
| `pkg/delegation` | ACP-DCMA-1.0 | L1 |
| `pkg/registry` | ACP-CAP-REG-1.0 | L1 |
| `pkg/risk` | ACP-RISK-1.0 | L2 |
| `pkg/revocation` | ACP-REV-1.0 | L2 |
| `pkg/reputation` | ACP-REP-1.2 | L2/L4 |
| `pkg/execution` | ACP-EXEC-1.0 | L3 |
| `pkg/ledger` | ACP-LEDGER-1.3 | L3 |
| `pkg/psn` | ACP-PSN-1.0 | L3 |
| `pkg/policyctx` | ACP-POLICY-CTX-1.0 | L3 |
| `pkg/provenance` | ACP-PROVENANCE-1.0 | L3 |
| `pkg/lia` | ACP-LIA-1.0 | L3/L4 |
| `pkg/hist` | ACP-HIST-1.0 | L4 |
| `pkg/govevents` | ACP-GOV-EVENTS-1.0 | L4 |
| `pkg/notify` | ACP-NOTIFY-1.0 | L4 |
| `pkg/disc` | ACP-DISC-1.0 | L4 |
| `pkg/bulk` | ACP-BULK-1.0 | L4 |
| `pkg/crossorg` | ACP-CROSS-ORG-1.0 | L4 |
| `pkg/pay` | ACP-PAY-1.0 | L4 |

All 22 packages pass `go test ./...`. A Python SDK (`impl/python/`) covers the ACP-HP-1.0 handshake and all ACP-API-1.0 endpoints.

### 8.3 Conformance Test Vectors — 42 signed vectors

The `compliance/test-vectors/` directory contains 42 signed test vectors per `ACP-TS-1.1`:

| Suite | Positive | Negative | Spec |
|-------|----------|----------|------|
| CORE (SIGN, CT, HP) | 4 | 4 | L1 |
| DCMA | 2 | 2 | L1 |
| HP | 2 | 8 | L1 |
| LEDGER | 3 | 8 | L3 |
| EXEC | 2 | 7 | L3 |

All positive vectors carry real Ed25519 signatures (RFC 8037 Test Key A) and real SHA-256 hash chains.

### 8.4 Roadmap

| Item | Status |
|------|--------|
| Core specs (L1-L4) | ✅ Complete |
| Go reference implementation (22 packages) | ✅ Complete |
| Conformance test vectors (42 signed) | ✅ Complete |
| OpenAPI 3.1.0 (`openapi/acp-api-1.0.yaml`) | ✅ Complete |
| Python SDK (`impl/python/`) | ✅ Complete (L1 + full API client) |
| L5 Decentralized (ACP-D) | 🔜 Specification in design |
| Post-quantum algorithm migration | 🔜 Research phase |
| IETF RFC submission | 🔜 After L5 stabilization |

---

## 9. How to Implement ACP

ACP is a specification — it does not require adopting any specific platform. It can be implemented on top of existing infrastructure. What it requires is precision in the cryptographic mechanisms and rigor in compliance with the defined flows.

### 9.1 Minimum requirements for L1 conformance

To achieve the minimum conformance level (L1 — CORE), an organization needs:

- **Ed25519 public key infrastructure.** Key pair for each agent. The algorithm is non-negotiable — Ed25519 is the only one defined in v1.0.
- **JCS implementation (RFC 8785).** Deterministic canonicalization for all signed artifacts.
- **Capability Token issuance and verification** with all mandatory fields per ACP-CT-1.0 §5.
- **Handshake endpoint** to issue and verify challenges (ACP-HP-1.0 §6).
- **Capability registry** with the core domains of ACP-CAP-REG-1.0.

### 9.2 Additional requirements for L3 conformance

For full conformance (L3 — FULL) add:

- Root Institutional Key held in HSM with documented rotation process.
- Registration with an ITA authority (centralized or federated model).
- Deterministic risk engine with the four factors of ACP-RISK-1.0.
- Revocation endpoint (Mechanism A — online endpoint, or Mechanism B — CRL).
- Append-only storage for the Audit Ledger with per-event signing.
- Complete HTTP API per ACP-API-1.0, including health and conformance endpoints.
- Public conformance declaration at `GET /acp/v1/conformance`.

### 9.3 What ACP does not prescribe

ACP defines the *what* — the mechanisms, flows, data structures, requirements. It does not prescribe the *how* of internal implementation:

- Programming language or framework.
- Database or storage system for the ledger.
- HSM provider or key custody infrastructure.
- ITA provider (may be operated internally in the centralized model).
- Specific integration with existing RBAC or Zero Trust systems.

---

## 10. Conclusion

Autonomous agents are already operating in institutional environments. The question is not whether they will operate — it is whether they will do so with or without formal governance. ACP proposes that they operate with formal governance, with verifiable mechanisms, and with traceability that can withstand an external audit.

ACP is not the first attempt to control autonomous agents. It is the first attempt to do so through a formal technical specification with precise state models, demonstrable security properties, and verifiable conformance requirements. The difference between a best-practices policy and a formal protocol is exactly that: behaviors are defined, failures have specific error codes, and conformance can be verified.

The goal of ACP is not to make agents more capable. It is to make them governable. That is a necessary condition for their institutional deployment to be sustainable at scale.

The v1.11 specification is complete. A full Go reference implementation (22 packages, L1–L4) and 42 signed conformance test vectors are publicly available at github.com/chelof100/acp-framework-en. The specification and implementation are available for technical review, pilot implementation, and formal standardization process.

TraslaIA invites organizations interested in adopting ACP, contributing to its evolution, or participating in the standardization process to reach out directly.

**Marcelo Fernandez | TraslaIA**
info@traslaia.com | www.traslaia.com

---

## Appendix A — Glossary

| Term | Definition |
|------|------------|
| AgentID | Cryptographic identifier of an agent: `base58(SHA-256(Ed25519_public_key))`. Immutable and unforgeable. |
| Capability Token (CT) | Signed JSON artifact that authorizes an agent to perform specific actions on a defined resource during a limited period. |
| Execution Token (ET) | Single-use artifact issued after an APPROVED AuthorizationDecision. Authorizes exactly that action at that moment. |
| ITA | Institutional Trust Anchor. Authoritative registry linking `institution_id` to institutional Ed25519 public key. |
| RIK | Root Institutional Key. Institution's Ed25519 key pair. The private key is held in HSM and never leaves it. |
| Risk Score (RS) | Integer in [0, 100] produced by the deterministic risk function of ACP-RISK-1.0. Determines the authorization decision. |
| Autonomy Level | Integer 0–4 assigned to an agent that determines the applicable risk evaluation thresholds. |
| Proof-of-Possession (PoP) | Cryptographic proof that the bearer of a CT possesses the private key corresponding to the declared AgentID. |
| Audit Ledger | Chain of signed events where `hash_n = SHA-256(event_n \|\| hash_n-1)`. Append-only and immutable. |
| MRA | Mutual Recognition Agreement. Bilateral document signed by two ITA authorities to enable cross-authority interoperability. |
| ESCALATED | ACP engine decision when the RS is in the intermediate range. The action is not executed until explicit resolution by a human authority or agent with sufficient level. |
| Fail Closed | Design principle: on any internal failure, the action is denied. Never approved by default. |

---

## Appendix B — References

| Reference | Description |
|-----------|-------------|
| RFC 8785 | JSON Canonicalization Scheme (JCS). IETF, 2020. |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA). IETF, 2017. |
| ACP-SIGN-1.0 | Serialization and Signature Specification. TraslaIA, 2026. |
| ACP-CT-1.0 | Capability Token Specification. TraslaIA, 2026. |
| ACP-CAP-REG-1.0 | Capability Registry Specification. TraslaIA, 2026. |
| ACP-HP-1.0 | Handshake Protocol / Proof-of-Possession Specification. TraslaIA, 2026. |
| ACP-RISK-1.0 | Deterministic Risk Model Specification. TraslaIA, 2026. |
| ACP-REV-1.0 | Revocation Protocol Specification. TraslaIA, 2026. |
| ACP-ITA-1.0 | Institutional Trust Anchor Specification. TraslaIA, 2026. |
| ACP-ITA-1.1 | ITA Mutual Recognition Protocol. TraslaIA, 2026. |
| ACP-API-1.0 | HTTP API Specification. TraslaIA, 2026. |
| ACP-EXEC-1.0 | Execution Token Specification. TraslaIA, 2026. |
| ACP-LEDGER-1.3 | Audit Ledger Specification (mandatory institutional sig). TraslaIA, 2026. |
| ACP-PAY-1.0 | Financial Capability Specification. TraslaIA, 2026. |
| ACP-REP-1.2 | Reputation Module Specification. TraslaIA, 2026. |
| ACP-CONF-1.2 | Conformance Specification (sole normative source). TraslaIA, 2026. |
| ACP-PSN-1.0 | Policy Snapshot Specification. TraslaIA, 2026. |
| ACP-PROVENANCE-1.0 | Authority Provenance Specification. TraslaIA, 2026. |
| ACP-POLICY-CTX-1.0 | Policy Context Snapshot. TraslaIA, 2026. |
| ACP-GOV-EVENTS-1.0 | Governance Event Stream. TraslaIA, 2026. |
| ACP-LIA-1.0 | Liability Attribution Specification. TraslaIA, 2026. |
| ACP-HIST-1.0 | History Query API Specification. TraslaIA, 2026. |
| ACP-CROSS-ORG-1.0 | Cross-Organization Bundles. TraslaIA, 2026. |
| Open Policy Agent | https://www.openpolicyagent.org — policy evaluation engine |
| SPIFFE/SPIRE | https://spiffe.io — cryptographic workload identity |
| RFC 7519 | JSON Web Token (JWT). IETF, 2015. |
| RFC 6749 | OAuth 2.0 Authorization Framework. IETF, 2012. |
| Saltzer & Schroeder (1975) | The Protection of Information in Computer Systems. IEEE. |

The complete specification is publicly available at: https://github.com/chelof100/acp-framework-en
Official website: https://agentcontrolprotocol.xyz
Contact: info@traslaia.com
