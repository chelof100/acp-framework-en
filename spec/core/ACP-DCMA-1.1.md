# ACP-DCMA-1.1
## Delegation Chain Model & Attestation

**Status:** Normative
**Version:** 1.1
**Type:** Core Protocol Specification
**Supersedes:** ACP-DCMA-1.0
**Depends-on:** ACP-CT-1.0, ACP-SIGN-1.0, ACP-HIST-1.0
**Required-by:** ACP-CONF-1.2 (L1 — Core Conformance)
**Integration note:** DCMA payloads are included in `AUTHORIZATION` and `LIABILITY_RECORD` ledger events (ACP-LEDGER-1.3 §5.2, §5.12). This is a write-only operational integration; ACP-LEDGER-1.3 is not required for DCMA's formal delegation model to be correct.

> This specification is **normative**. It defines the formal chained delegation model, no-escalation constraints, transitive revocation, maximum delegation depth, and the delegation record schema required for interoperability with ACP-PROVENANCE-1.0. All ACP v1.x implementations that support delegation MUST comply with the formal properties defined here.
>
> **Changes from DCMA-1.0:**
> - §6: `δ_max` is now a global normative hard cap (7 hops), not a purely institutional parameter.
> - §11: "Limited depth" property now references normative §15.
> - §15 (NEW): Maximum Delegation Depth — normative limit, error code DCMA-006.
> - §16 (NEW): Delegation Record Schema — canonical record format for interoperability with PROVENANCE-1.0 and cross-institutional lookup.
> - §14.4: Revocation timestamp precision clarified; millisecond precision RECOMMENDED.

---

## 1. Extension of the Formal Space

We add:

𝐷 → set of delegations

𝐼 → set of institutions

An agent now belongs to an institution:

Owner(a) ∈ I

## 2. Formal Definition of Delegation

A delegation is a tuple:

d = (aᵢ, aⱼ, c, σ, τ)

Where:

aᵢ = delegating agent

aⱼ = delegated agent

c = delegated capability

σ = additional constraints

τ = temporal validity interval

Interpretation:

Agent aᵢ delegates capability c to agent aⱼ under constraints σ and time τ.

## 3. Valid Delegation Predicate

ValidDelegation(d)

Is true if:

ValidID(aᵢ)

ValidID(aⱼ)

HasCapability(aᵢ, c)

Valid cryptographic signature of aᵢ

Current time ∈ τ

Constraints σ compatible with original limits

## 4. Delegated Capability

We define:

DelegatedCapability(aⱼ, c)

True if a valid delegation exists:

∃d ∈ D such that d = (aᵢ, aⱼ, c, σ, τ) ∧ ValidDelegation(d)

The capability predicate is then redefined as:

HasCapability′(aⱼ, c) ⟺ HasCapability(aⱼ, c) ∨ DelegatedCapability(aⱼ, c)

## 5. No-Escalation Constraint

Delegation cannot expand privileges.

Formally:

Constraints(c_delegated) ⊆ Constraints(c_original)

And:

σ ⊆ OriginalLimits(aᵢ, c)

If the delegate attempts to execute outside those constraints:

Decision(req) = Denied

## 6. Chained Delegation

Allows controlled transitivity.

Chain:

a₁ → a₂ → a₃

Is valid if:

Each intermediate delegation is valid.

No cumulative constraint is violated.

Delegation depth ≤ min(δ_institutional, δ_global)

Where:
- `δ_global = 7` is the **normative hard cap** defined in §15 of this specification.
- `δ_institutional` is an institution-specific limit that MAY be lower than 7 but MUST NOT exceed 7.

We define:

DelegationDepth(aₖ) ≤ δ_max

Where `δ_max = min(δ_institutional, 7)`.

See §15 for normative depth enforcement, DCMA-006 error code, and rationale.

## 7. Formal Evaluation with Delegation

The authorization rule is modified:

Authorized(req) ⟺ ValidID(a) ∧ HasCapability′(a, c) ∧ PolicySatisfied(...) ∧ WithinLimits(...) ∧ AcceptableRisk(...)

The difference lies in HasCapability′.

## 8. Accountability Chaining

Each delegation generates a record:

eₐ = (aᵢ, aⱼ, c, σ, τ, hash_prev)

For an action executed under delegation, the ledger must be able to reconstruct:

a₁ → a₂ → ... → aₖ

Mandatory property:

Execution(aₖ, c) ⇒ TraceableChain(a₁, ..., aₖ)

If it cannot be reconstructed → not valid.

See §16 for the canonical delegation record format required for full traceability.

## 9. Transitive Revocation

If:

Revoke(aᵢ)

Then:

∀d where delegator = aᵢ ⇒ Invalid(d)

And recursively:

Every dependent chain becomes invalid.

This prevents zombie delegations.

## 10. Inter-Institutional Model

For delegation between institutions:

Owner(aᵢ) ≠ Owner(aⱼ)

Requires:

TrustAnchor(Owner(a_i), Owner(a_j))

Cross-validation of certificates

Auditable record by both parties

B2B delegation is only valid if both institutions can verify the signature.

## 11. Security Properties

ACP delegation guarantees:

No privilege escalation.

Propagated revocation.

Complete traceability.

Limited depth (normative hard cap: 7 hops — see §15).

Mandatory signature at each hop (see §16).

## 12. Structural Difference from RBAC

RBAC allows role assignment.
It does not model:

Delegation with dynamic constraints.

Verifiable chaining.

Formal transitive revocation.

Multi-institutional accountability.

ACP does.

## 13. Critical Point

ACP now has:

Formal decision model

Identity model

Chained delegation model

Demonstrable security properties

Auditable structure

---

## 14. Transitive Revocation — Normative Timing

Section 9 defines the formal property of transitive revocation. This section establishes the propagation timing requirements that every conformant implementation MUST satisfy.

### 14.1 Maximum Propagation

From the moment Revoke(aᵢ) is recorded in the revocation system:

The verifier MUST guarantee that every subsequent verification within τ_propagation ≤ 60 seconds rejects:

- Tokens issued by aᵢ
- Tokens from any delegation chain where aᵢ is a delegator (direct or transitive)

The verifier MUST consult revocation status on every authorization decision, without exception.

### 14.2 Revocation Status Cache

If the verifier uses a cache of revocation status:

- The cache TTL MUST be ≤ 30 seconds.
- Expired entries MUST be invalidated before the next authorization query.
- The verifier MUST accept forced cache refresh upon any revocation notification received via event channel.

An implementation that does not use a cache MUST query the revocation store in real time on every decision.

### 14.3 In-Flight Requests

If a revocation occurs while an execution request is in progress:

- The verifier MUST re-evaluate the revocation status of the agent and its delegation chain before issuing the final execution confirmation.
- A request approved before the revocation MUST be denied if the revocation is detected before the final confirmation.
- The system MUST emit a REVOKED error with a reference to the jti of the affected token.

### 14.4 Atomicity of Revocation

Revoke(aᵢ) has atomic effect on the system state:

- There is no intermediate state where aᵢ is partially revoked.
- All dependent delegations (direct and transitive) become invalid simultaneously from the revocation timestamp.
- The revocation timestamp MUST be recorded with second-level precision and SHOULD be recorded with millisecond precision for high-frequency audit environments.
- The revocation timestamp MUST be queryable by auditors.

### 14.5 Non-Compliance Due to Timing

An implementation is NOT conformant with respect to transitive revocation if it:

- Accepts tokens issued by a revoked agent more than 60 seconds after the revocation timestamp.
- Uses a revocation cache with TTL > 30 seconds.
- Confirms executions without re-evaluating revocation status when the revocation occurred during request processing.
- Does not record the revocation timestamp with at least second-level precision.

---

## 15. Maximum Delegation Depth

### 15.1 Normative Hard Cap

Every conformant ACP implementation MUST enforce a maximum delegation chain depth of **7 hops**.

```
δ_global = 7
```

**Formal requirement:**

```
ValidChain(chain) ⟺ len(chain) ≤ 7 ∧ ∀i ∈ chain: ValidDelegation(chain[i])
```

Any request presenting a delegation chain with `len(chain) > 7` MUST be rejected with error code:

```
DCMA-006: Maximum delegation depth exceeded
{
  "error": "DCMA-006",
  "message": "Delegation chain exceeds maximum depth of 7 hops",
  "chain_length": <actual_length>,
  "max_allowed": 7
}
```

### 15.2 Institutional Sub-Limits

An institution MAY configure a local limit `δ_institutional ≤ 7`. The effective limit is:

```
δ_max = min(δ_institutional, 7)
```

Institutions MUST NOT configure `δ_institutional > 7`. Any such configuration MUST be rejected at startup with a configuration error.

If no institutional limit is configured, `δ_max = 7` applies.

### 15.3 Depth Counting

Depth is counted as the number of delegation links in the chain, not the number of agents:

```
a₁ → a₂           depth = 1
a₁ → a₂ → a₃      depth = 2
...
a₁ → ... → a₈     depth = 7  (maximum)
a₁ → ... → a₉     depth = 8  (DCMA-006 — REJECTED)
```

The principal agent (a₁, the original holder of the capability) does not count toward the depth limit.

### 15.4 Rationale

Real institutional delegation chains rarely exceed 4 hops:

```
principal → department-head → team-lead → specialist → executor
```

The limit of 7 provides headroom for complex multi-institution chains while bounding:

1. **Computational cost:** O(depth) verification complexity — capped at O(7) = O(1) in practice.
2. **DoS surface:** Artificially deep chains cannot be used to saturate the verification subsystem.
3. **Audit clarity:** Chains longer than 7 are difficult to audit manually; they indicate a structural problem in the delegation model.

### 15.5 Error Code Registry Addition

| Code | Meaning | HTTP status |
|------|---------|-------------|
| DCMA-001 | Invalid delegator identity | 401 |
| DCMA-002 | Capability escalation detected | 403 |
| DCMA-003 | Delegation expired | 401 |
| DCMA-004 | Broken chain (missing intermediate delegation) | 400 |
| DCMA-005 | Revoked delegation in chain | 401 |
| **DCMA-006** | **Maximum delegation depth exceeded (> 7 hops)** | **400** |

---

## 16. Delegation Record Schema

### 16.1 Purpose

This section defines the canonical **Delegation Record** format. Every conformant implementation MUST store delegation records in this format to enable:

1. Cross-institutional delegation lookup.
2. Interoperability with ACP-PROVENANCE-1.0 `DelegationStep` construction.
3. Retrospective audit queries via ACP-HIST-1.0.

### 16.2 Canonical Schema

```json
{
  "delegation_id": "DEL-<institution_id>-<local_id>",
  "delegator": "<AgentID>",
  "delegatee": "<AgentID>",
  "capability": "<ACP capability string>",
  "constraints": {},
  "issued_at": "<unix_seconds>",
  "expires_at": "<unix_seconds>",
  "depth": <integer 1..7>,
  "parent_delegation_id": "<DEL-... or null if root>",
  "sig": "<base64url Ed25519 signature>"
}
```

**Field definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `delegation_id` | string | MUST | Globally unique ID. Format: `DEL-<institution_id>-<local_id>` |
| `delegator` | string | MUST | ACP AgentID of the delegating agent |
| `delegatee` | string | MUST | ACP AgentID of the delegated agent |
| `capability` | string | MUST | ACP capability string (subset of delegator's capability) |
| `constraints` | object | MUST | Additional constraints (empty object if none) |
| `issued_at` | integer | MUST | Unix timestamp (seconds) when delegation was issued |
| `expires_at` | integer | MUST | Unix timestamp (seconds) when delegation expires |
| `depth` | integer | MUST | Depth in the chain (1 = direct delegation from principal) |
| `parent_delegation_id` | string\|null | MUST | ID of the parent delegation, or null if root |
| `sig` | string | MUST | Ed25519 signature by delegator over all fields except `sig`, in JCS canonical form |

### 16.3 Delegation ID Format

```
delegation_id = "DEL-" + institution_id + "-" + local_id
```

- `institution_id`: The ACP institution identifier (as registered in ACP-ITA-1.0).
- `local_id`: A locally unique identifier within the institution. MAY be a UUID, a monotonically increasing integer, or any other locally unique string. MUST NOT contain hyphens that would ambiguously parse as institution_id separators.
- The full `delegation_id` MUST be globally unique.

**Example:** `DEL-acme-corp-8a4f2b1c-00a3-4d2e-b9f1-2c3d4e5f6a7b`

### 16.4 Signature Computation

The `sig` field covers all other fields in JCS canonical form (RFC 8785):

```
sig = Ed25519Sign(delegator_private_key, JCS(record_without_sig))
```

This signature is what PROVENANCE-1.0 uses as `delegation_sig` in `DelegationStep` objects.

### 16.5 Delegation Record Store

Every conformant implementation MUST maintain a queryable Delegation Record Store:

- **Write:** Records are written atomically when a delegation is issued.
- **Read:** Records MUST be queryable by `delegation_id`, by `delegator`, and by `delegatee`.
- **Retention:** Records MUST be retained for the full audit period (minimum as defined by applicable regulations; default 7 years).
- **Cross-institutional lookup:** A delegation issued by Institution A and used in a chain presented to Institution B MUST be retrievable by Institution B through ACP-HIST-1.0 query `?type=delegation&id=<delegation_id>`.

### 16.6 Integration with ACP-PROVENANCE-1.0

When constructing a `ProvenanceRecord` (PROVENANCE-1.0 §4.3), each `DelegationStep.delegation_id` MUST reference a valid record in the Delegation Record Store, and `DelegationStep.delegation_sig` MUST equal the `sig` field of that record.

This creates a cryptographically verifiable link between the provenance proof and the underlying delegation records.

---

## Appendix: Error Code Summary

| Code | Introduced | Meaning |
|------|-----------|---------|
| DCMA-001 | 1.0 | Invalid delegator identity |
| DCMA-002 | 1.0 | Capability escalation detected |
| DCMA-003 | 1.0 | Delegation expired |
| DCMA-004 | 1.0 | Broken chain (missing intermediate) |
| DCMA-005 | 1.0 | Revoked delegation in chain |
| DCMA-006 | **1.1** | Maximum delegation depth exceeded (> 7 hops) |
