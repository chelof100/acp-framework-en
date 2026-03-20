> **Status:** Superseded
> **Superseded by:** ACP-POLICY-CTX-1.1
> **Superseded date:** 2026-03-19

# ACP-POLICY-CTX-1.0
## Policy Context Snapshot Specification

**Status:** Draft
**Version:** 1.0
**Type:** Operations Protocol Specification
**Depends-on:** ACP-SIGN-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.2, ACP-PROVENANCE-1.0
**Required-by:** ACP-CONF-1.1 (L3-FULL), ACP-LIA-1.0

> This specification is **normative**. It defines the Policy Context Snapshot (`PolicyContextSnapshot`) — the signed record of the exact policy state that was in force at the moment an agent action was authorized. Implementations claiming L3-FULL conformance MUST produce a valid `PolicyContextSnapshot` for every execution.

---

## 1. Scope

This document defines:

1. The **PolicyContextSnapshot** object — its structure, required fields, and evaluation record.
2. **Snapshot capture semantics** — when and how the snapshot MUST be taken.
3. **Binding rules** — how the snapshot attaches to Execution Tokens and Ledger entries.
4. **Retrospective verification** — how a verifier uses the snapshot to reconstruct the policy decision.

### What this is NOT

- This is not a policy language or policy enforcement engine. ACP does not define how policies are written.
- This is not a real-time policy query mechanism.
- This is not a delegation mechanism (see ACP-DCMA-1.0).

`PolicyContextSnapshot` is a **point-in-time evidence artifact** — it preserves the policy state at execution time so that, at any future point, a verifier can confirm that the action was policy-compliant when it occurred.

---

## 2. Motivation

Autonomous agent actions may be audited weeks or months after the fact — for compliance reviews, legal disputes, or liability attribution (ACP-LIA-1.0). By that time, the institutional policy may have changed. Without a cryptographic snapshot of the policy in force at execution time, it is impossible to demonstrate retroactively whether the action was authorized.

The `PolicyContextSnapshot` solves this by capturing:
1. Which policy document governed the action.
2. What version and hash that document had at execution time.
3. What the policy evaluation result was for the specific request.
4. Which evaluation steps produced that result.

This enables **deterministic retrospective policy reconstruction** — a verifier can re-execute the policy evaluation against the snapshotted inputs and confirm the captured result.

---

## 3. Definitions

**Policy:** An institutional document or ruleset that determines whether a specific agent action is authorized. ACP does not mandate a policy language; the snapshot format is language-agnostic.

**Policy version:** A monotonically increasing identifier (semver or integer) that changes whenever the policy document changes.

**Policy hash:** A SHA-256 digest of the canonical byte representation of the policy document at `snapshot_at`.

**Evaluation result:** The output of applying the policy to the specific execution request — `APPROVED`, `DENIED`, or `ESCALATED`.

**Evaluation context:** The set of inputs fed to the policy engine: agent identity, requested capability, resource, risk score, delegation status, and any additional parameters.

**Snapshot boundary:** The policy MUST be captured as it existed at `snapshot_at`, not as it exists at verification time.

---

## 4. PolicyContextSnapshot Object

### 4.1 Top-level structure

```json
{
  "ver": "1.0",
  "snapshot_id": "<uuid_v4>",
  "execution_id": "<et_id of the bound Execution Token>",
  "provenance_id": "<provenance_id of bound AuthorityProvenance>",
  "snapshot_at": "<unix_seconds>",
  "policy": {
    "policy_id": "<string>",
    "policy_version": "<string>",
    "policy_hash": "<sha256_hex>",
    "policy_engine": "<string>"
  },
  "evaluation_context": {
    "agent_id": "<AgentID>",
    "requested_capability": "<ACP capability string>",
    "resource": "<resource identifier>",
    "risk_score": "<float 0.0–1.0>",
    "delegation_active": "<boolean>",
    "additional_params": { }
  },
  "evaluation_result": {
    "decision": "APPROVED | DENIED | ESCALATED",
    "checks": [ <EvaluationCheck>, ... ],
    "denial_reason": "<string or null>"
  },
  "sig": "<base64url Ed25519 signature>"
}
```

### 4.2 Field definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | MUST | Always `"1.0"` |
| `snapshot_id` | UUID v4 | MUST | Unique identifier for this snapshot |
| `execution_id` | string | MUST | `et_id` of the bound Execution Token |
| `provenance_id` | string | SHOULD | `provenance_id` of the bound `AuthorityProvenance` (MUST at L3-FULL) |
| `snapshot_at` | integer | MUST | Unix seconds. MUST be within the ET's validity window |
| `policy` | object | MUST | Policy identification block |
| `evaluation_context` | object | MUST | Inputs to the policy evaluation |
| `evaluation_result` | object | MUST | Output of the policy evaluation |
| `sig` | string | MUST | Base64url Ed25519 institutional signature |

### 4.3 Policy block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_id` | string | MUST | Stable identifier for the policy (e.g. `payment_policy`) |
| `policy_version` | string | MUST | Version at `snapshot_at` (e.g. `v3.2`) |
| `policy_hash` | string | MUST | SHA-256 hex of the policy document at `snapshot_at` |
| `policy_engine` | string | SHOULD | Identifier of the policy engine used (e.g. `opa`, `cedar`, `custom`) |

### 4.4 Evaluation context block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | MUST | AgentID of the executor |
| `requested_capability` | string | MUST | ACP capability string from the execution request |
| `resource` | string | MUST | Resource identifier the action targets |
| `risk_score` | float | SHOULD | Risk score at time of evaluation (from ACP-RISK-1.0). `null` if not computed |
| `delegation_active` | boolean | MUST | Whether the delegation chain was active at `snapshot_at` |
| `additional_params` | object | MAY | Institution-specific evaluation parameters |

### 4.5 Evaluation result block

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `decision` | string | MUST | `APPROVED`, `DENIED`, or `ESCALATED` |
| `checks` | array | MUST | Ordered list of evaluation checks performed |
| `denial_reason` | string | MUST if DENIED | Human-readable denial reason. `null` if APPROVED |

### 4.6 EvaluationCheck object

```json
{
  "check_name": "<string>",
  "result": "passed | failed | skipped",
  "value": "<evaluated value or null>"
}
```

Example checks:
```json
[
  { "check_name": "amount_within_limit",  "result": "passed", "value": "1500.00 <= 5000.00" },
  { "check_name": "supplier_verified",    "result": "passed", "value": "true" },
  { "check_name": "delegation_active",    "result": "passed", "value": "true" },
  { "check_name": "risk_below_threshold", "result": "passed", "value": "0.12 <= 0.30" }
]
```

---

## 5. Capture Semantics

### 5.1 When to capture

The snapshot MUST be captured at the moment the policy evaluation is run — not before and not after. The `snapshot_at` timestamp MUST reflect the actual evaluation moment.

### 5.2 Relationship to Execution Token

The ET is issued only after the policy evaluation returns `APPROVED`. Therefore:

```
snapshot_at ≤ et.issued_at ≤ et.expires_at
execution_id references the ET issued on the basis of this APPROVED snapshot
```

A snapshot with `decision: DENIED` does NOT produce an Execution Token.

### 5.3 Immutability

Once captured and signed, a `PolicyContextSnapshot` is immutable. The policy may change after `snapshot_at` — the snapshot preserves the state as it was. A verifier MUST use `policy_hash` to retrieve the historical policy document, not the current one.

---

## 6. Validation Algorithm

```
ValidatePolicyContextSnapshot(pcs, et, policy_store):
  1. Verify pcs.ver == "1.0"
  2. Verify pcs.execution_id == et.et_id
  3. Verify pcs.snapshot_at within et validity window
  4. Retrieve policy_doc = policy_store.get(pcs.policy.policy_id, version=pcs.policy.policy_version)
  5. Verify sha256(policy_doc) == pcs.policy.policy_hash
  6. Re-execute policy evaluation with pcs.evaluation_context → expected_decision
  7. Verify expected_decision == pcs.evaluation_result.decision
  8. Verify pcs.sig (institutional signature) over canonical JSON
  → VALID | INVALID(reason)
```

Step 6 (re-execution) requires the verifier to have access to the policy engine identified in `policy_engine` and the policy document retrieved in step 4. If the policy engine is unavailable, validation can proceed to step 7 without step 6 but MUST be flagged as `partially_verified`.

---

## 7. Binding to Audit Ledger

The ledger entry for every authorized execution MUST include:

```json
{
  "event_type": "POLICY_SNAPSHOT",
  "snapshot_id": "...",
  "execution_id": "...",
  "decision": "APPROVED | DENIED | ESCALATED",
  "policy_id": "...",
  "policy_version": "...",
  "policy_hash": "..."
}
```

For `DENIED` decisions, the ledger MUST record the snapshot even though no ET is issued. This creates an auditable record of rejected authorization attempts.

---

## 8. Policy Store Requirements

An ACP-compliant institution MUST maintain a **Policy Store** — an append-only record of all policy versions, keyed by `(policy_id, policy_version)`, with content-addressable access via `policy_hash`. The Policy Store MUST retain all historical policy versions for at least the institutional retention period.

The Policy Store API (if exposed) MUST be authenticated per ACP-API-1.0.

---

## 9. Error Codes

| Code | Meaning |
|------|---------|
| `PCTX-001` | `execution_id` does not match bound ET |
| `PCTX-002` | `snapshot_at` outside ET validity window |
| `PCTX-003` | Policy document not found in policy store |
| `PCTX-004` | Policy hash mismatch |
| `PCTX-005` | Policy re-evaluation disagrees with captured decision |
| `PCTX-006` | Institutional signature invalid |
| `PCTX-007` | Required field missing |
| `PCTX-008` | `decision: APPROVED` but no bound ET found |

---

## 10. Conformance

| Conformance Level | Requirement |
|-------------------|-------------|
| L1-CORE | MAY omit entirely |
| L2-SECURITY | SHOULD record policy_id and policy_hash in ledger |
| L3-FULL | MUST produce full `PolicyContextSnapshot` for every execution |
| L4-EXTENDED | MUST produce full snapshot + bind `denial_reason` to reputation events (ACP-REP-1.2) |
| L5-DECENTRALIZED | MUST produce full snapshot with decentralized policy store reference |

---

## 11. Normative References

- ACP-SIGN-1.0 — Serialization and signing
- ACP-EXEC-1.0 — Execution token specification
- ACP-LEDGER-1.2 — Audit ledger
- ACP-PROVENANCE-1.0 — Authority provenance (complementary artifact)
- ACP-RISK-1.0 — Risk scoring (source of `risk_score`)
- ACP-LIA-1.0 — Liability attribution (consumes PolicyContextSnapshot)
- ACP-CONF-1.1 — Conformance levels
