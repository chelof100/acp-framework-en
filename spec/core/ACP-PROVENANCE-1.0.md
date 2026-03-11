# ACP-PROVENANCE-1.0
## Authority Provenance Specification

**Status:** Draft
**Version:** 1.0
**Type:** Core Protocol Specification
**Depends-on:** ACP-SIGN-1.0, ACP-DCMA-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.2
**Required-by:** ACP-CONF-1.1 (L3-FULL), ACP-LIA-1.0

> This specification is **normative**. It defines the Authority Provenance object — the structured artifact that proves, at execution time, the complete chain of authority behind an agent action. Implementations claiming L3-FULL conformance MUST produce a valid `AuthorityProvenance` object for every execution.

---

## 1. Scope

This document defines:

1. The **Authority Provenance object** (`AuthorityProvenance`) — its structure, required fields, and signature contract.
2. The **provenance validation algorithm** — how a verifier reconstructs and checks the chain.
3. **Binding rules** — how `AuthorityProvenance` attaches to Execution Tokens and Ledger entries.
4. **Audit semantics** — how provenance enables retrospective authority reconstruction.

### What this is NOT

- This is not a delegation mechanism. Delegation is defined in ACP-DCMA-1.0.
- This is not a policy enforcement mechanism. Policy enforcement is defined in ACP-EXEC-1.0.
- This is not a revocation mechanism. Revocation is defined in ACP-REV-1.0.

`AuthorityProvenance` is a **retrospective proof artifact** — it answers: *by what authority was this action taken, at this moment, through this chain?*

---

## 2. Motivation

The ACP core invariant is:

```
Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

ACP-DCMA-1.0 ensures `ValidDelegationChain` holds at delegation time. However, at audit or dispute time, a verifier needs to reconstruct the full authority chain from evidence available at the moment of execution — not from a live system query. This creates a distinct requirement: a self-contained, signed, verifiable snapshot of the authority state that existed when the action was authorized.

Without `AuthorityProvenance`, the following questions cannot be answered from audit trail alone:
- Who was the original principal that authorized the capability?
- Which intermediate delegators were active at execution time?
- Under which policy version was the delegation valid?
- Was the delegator's own delegation still valid at that moment?

---

## 3. Definitions

**Principal:** The institution or human that originates authority. The root of every delegation chain.

**Delegator:** An agent that holds a capability and passes a subset of it to an executor via ACP-DCMA-1.0.

**Executor:** The agent that presents the `AuthorityProvenance` at execution time.

**Delegation step:** A single `(delegator, executor, capability_subset, delegation_id, valid_at)` tuple in the chain.

**Authority scope:** The intersection of all capability subsets across the delegation chain. MUST be equal to or narrower than the Execution Token's requested capability.

**Provenance signature:** An Ed25519 signature over the canonical JSON serialization of the `AuthorityProvenance` object, produced by the ACP institutional key (ACP-ITA-1.0).

---

## 4. AuthorityProvenance Object

### 4.1 Top-level structure

```json
{
  "ver": "1.0",
  "provenance_id": "<uuid_v4>",
  "execution_id": "<et_id of the bound Execution Token>",
  "captured_at": "<unix_seconds>",
  "principal": "<institution_id>",
  "executor": "<AgentID>",
  "authority_scope": "<ACP capability string>",
  "chain": [ <DelegationStep>, ... ],
  "policy_ref": "<policy_id>:<policy_version>",
  "policy_hash": "<sha256_hex of policy document at captured_at>",
  "sig": "<base64url Ed25519 signature>"
}
```

### 4.2 Field definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | MUST | Always `"1.0"` |
| `provenance_id` | UUID v4 | MUST | Unique identifier for this provenance object |
| `execution_id` | string | MUST | `et_id` of the Execution Token this object is bound to |
| `captured_at` | integer | MUST | Unix seconds. Timestamp of provenance capture. MUST be within the ET's validity window |
| `principal` | string | MUST | Institution ID that is the root authority source |
| `executor` | string | MUST | AgentID of the agent presenting the ET |
| `authority_scope` | string | MUST | ACP capability string representing the effective scope. MUST be ≤ scope in ET |
| `chain` | array | MUST | Ordered delegation steps from principal to executor. Minimum 1 element |
| `policy_ref` | string | MUST | `<policy_id>:<policy_version>` of the institutional policy in force |
| `policy_hash` | string | MUST | SHA-256 hex digest of the policy document at `captured_at` |
| `sig` | string | MUST | Base64url Ed25519 signature of the canonical JSON (excluding `sig` field) |

### 4.3 DelegationStep object

```json
{
  "step": 1,
  "delegator": "<AgentID or institution_id>",
  "executor": "<AgentID>",
  "delegation_id": "<DEL-XXXX>",
  "capability_subset": "<ACP capability string>",
  "delegated_at": "<unix_seconds>",
  "valid_until": "<unix_seconds>",
  "delegation_sig": "<base64url Ed25519 signature of this step>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `step` | integer | MUST | Position in chain, starting at 1 |
| `delegator` | string | MUST | AgentID or institution_id of the delegating party. Step 1 delegator MUST be `principal` |
| `executor` | string | MUST | AgentID receiving authority in this step |
| `delegation_id` | string | MUST | Reference to the delegation record in ACP-DCMA-1.0 |
| `capability_subset` | string | MUST | Capability subset passed in this step. MUST be ⊆ previous step's `capability_subset` |
| `delegated_at` | integer | MUST | Unix seconds when the delegation was created |
| `valid_until` | integer | MUST | Unix seconds of delegation expiry. MUST be ≥ `captured_at` |
| `delegation_sig` | string | MUST | Ed25519 signature of this step by `delegator`'s key |

---

## 5. Formal Properties

### P1 — Chain completeness
The chain MUST form a continuous path from `principal` to `executor`:

```
chain[1].delegator = principal
chain[i].executor = chain[i+1].delegator  (for all i < len(chain))
chain[last].executor = executor
```

### P2 — Capability monotone restriction
Each step MUST not expand capability:

```
capability_subset(step_i+1) ⊆ capability_subset(step_i)
authority_scope ⊆ capability_subset(step_last)
```

### P3 — Temporal validity
Every step MUST be valid at `captured_at`:

```
∀ step ∈ chain: step.valid_until ≥ captured_at
```

### P4 — Provenance binding
The `execution_id` MUST match the `et_id` of the Execution Token that triggered the action. A provenance object MUST NOT be reused across different executions.

### P5 — Signature integrity
The `sig` field covers the canonical JSON of the `AuthorityProvenance` object with `sig` set to `""` (empty string), serialized with keys in lexicographic order, no whitespace, UTF-8 encoding.

---

## 6. Validation Algorithm

```
ValidateProvenance(ap, et, policy_store):
  1. Verify ap.ver == "1.0"
  2. Verify ap.execution_id == et.et_id
  3. Verify ap.captured_at is within et.valid_from..et.expires_at
  4. Verify P1: chain completeness
  5. Verify P2: capability monotone restriction
  6. Verify P3: temporal validity (all steps valid at ap.captured_at)
  7. Verify each step.delegation_sig against delegator's registered public key (ACP-AGENT-1.0)
  8. Verify ap.policy_hash against policy_store.get(ap.policy_ref, at=ap.captured_at)
  9. Verify ap.sig (institutional signature) over canonical JSON
  → VALID | INVALID(reason)
```

An invalid `AuthorityProvenance` MUST cause the associated ledger entry to be marked `provenance_invalid`. It does NOT retroactively void the execution (which may have already occurred), but it is a compliance failure under ACP-CONF-1.1 L3.

---

## 7. Binding to Execution Token

The Execution Token (ACP-EXEC-1.0) MUST include the `provenance_id` field when the implementation targets L3-FULL or higher:

```json
{
  "et_id": "...",
  "provenance_id": "<uuid_v4 matching AuthorityProvenance.provenance_id>",
  ...
}
```

The `AuthorityProvenance` object MUST be stored in the Audit Ledger (ACP-LEDGER-1.2) as a `PROVENANCE` event type, linked to the `EXECUTION` event via `execution_id`.

---

## 8. Binding to Audit Ledger

The ledger entry for the execution event MUST reference the provenance:

```json
{
  "event_type": "EXECUTION",
  "et_id": "...",
  "provenance_id": "...",
  "provenance_status": "valid | invalid | missing"
}
```

`provenance_status: missing` is permitted only for L1-CORE and L2-SECURITY implementations. L3-FULL and above MUST NOT produce `missing`.

---

## 9. Minimal vs. Full Provenance

For implementations targeting L1-CORE or L2-SECURITY, a **minimal provenance** structure is RECOMMENDED but not required:

```json
{
  "ver": "1.0",
  "provenance_id": "<uuid_v4>",
  "execution_id": "<et_id>",
  "captured_at": "<unix_seconds>",
  "principal": "<institution_id>",
  "executor": "<AgentID>",
  "authority_scope": "<capability>",
  "chain": []
}
```

A minimal provenance with `chain: []` indicates direct institutional authorization with no intermediate delegation. It still MUST include a valid `sig`.

---

## 10. Error Codes

| Code | Meaning |
|------|---------|
| `PROV-001` | Chain incomplete — break detected between steps |
| `PROV-002` | Capability escalation — step expands capability from previous |
| `PROV-003` | Expired delegation step — `valid_until` < `captured_at` |
| `PROV-004` | Step signature invalid |
| `PROV-005` | Institutional signature invalid |
| `PROV-006` | Policy hash mismatch |
| `PROV-007` | `execution_id` does not match bound ET |
| `PROV-008` | `captured_at` outside ET validity window |
| `PROV-009` | Executor mismatch — `chain[last].executor` ≠ `executor` |

---

## 11. Conformance

| Conformance Level | Requirement |
|-------------------|-------------|
| L1-CORE | MAY omit provenance entirely |
| L2-SECURITY | SHOULD produce minimal provenance (chain: []) |
| L3-FULL | MUST produce full provenance with complete chain |
| L4-EXTENDED | MUST produce full provenance + bind to reputation query (ACP-REP-1.2) |
| L5-DECENTRALIZED | MUST produce full provenance with DID-based delegation steps |

---

## 12. Normative References

- ACP-SIGN-1.0 — Serialization and signing
- ACP-DCMA-1.0 — Delegation chain model and attestation
- ACP-EXEC-1.0 — Execution token specification
- ACP-LEDGER-1.2 — Audit ledger
- ACP-LIA-1.0 — Liability attribution (consumes AuthorityProvenance)
- ACP-CONF-1.1 — Conformance levels
