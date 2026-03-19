# ACP-POLICY-CTX-1.1
## Policy Context Snapshot Specification

**Status:** Draft
**Version:** 1.1
**Type:** Operations Protocol Specification
**Supersedes:** ACP-POLICY-CTX-1.0
**Depends-on:** ACP-SIGN-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.3, ACP-PROVENANCE-1.0
**Required-by:** ACP-CONF-1.2 (L3-FULL), ACP-LIA-1.0

> This specification is **normative**. It defines the Policy Context Snapshot (`PolicyContextSnapshot`) — the signed record of the exact policy state that was in force at the moment an agent action was authorized, including temporal validity of the policy at capture time. Implementations claiming L3-FULL conformance MUST produce a valid `PolicyContextSnapshot` conforming to this specification for every execution.

---

## 1. Scope

This document defines:

1. The **PolicyContextSnapshot** object — its structure, required fields, and evaluation record.
2. **Snapshot capture semantics** — when and how the snapshot MUST be taken.
3. **Temporal validity** — how freshness of the captured policy is enforced.
4. **Freshness enforcement model** — hybrid producer/verifier constraint.
5. **Binding rules** — how the snapshot attaches to Execution Tokens and Ledger entries.
6. **Retrospective verification** — how a verifier uses the snapshot to reconstruct the policy decision.

### What this is NOT

- This is not a policy language or policy enforcement engine. ACP does not define how policies are written.
- This is not a real-time policy query mechanism.
- This is not a delegation mechanism (see ACP-DCMA-1.1).

`PolicyContextSnapshot` is a **point-in-time evidence artifact** — it preserves the policy state at execution time so that, at any future point, a verifier can confirm that the action was policy-compliant when it occurred and that the policy was current at the time it was evaluated.

---

## 2. Motivation

ACP-POLICY-CTX-1.0 records `policy_hash` (which policy was used) and `snapshot_at` (when evaluation occurred), but does not record when the policy document was fetched from the policy store. This creates a temporal validity gap: a stale cached policy could be used for evaluation, and the snapshot would pass all 1.0 validations without any indication that the policy was out of date at the time of capture.

ACP-POLICY-CTX-1.1 closes this gap by adding:

1. **`policy_captured_at`** — when the policy was retrieved from the policy store.
2. **`delta_max`** — the producer's declared maximum permitted staleness.
3. **Freshness enforcement** — a hybrid model that ensures neither the producer nor an attacker can bypass the verifier's staleness limit.

This enables **temporally verified retrospective policy reconstruction** — a verifier can confirm not only that the action was policy-compliant, but that the policy was valid and current at the moment of evaluation.

---

## 3. Definitions

**Policy:** An institutional document or ruleset that determines whether a specific agent action is authorized. ACP does not mandate a policy language; the snapshot format is language-agnostic.

**Policy version:** A monotonically increasing identifier (semver or integer) that changes whenever the policy document changes.

**Policy hash:** A SHA-256 digest of the canonical byte representation of the policy document at `snapshot_at`.

**Evaluation result:** The output of applying the policy to the specific execution request — `APPROVED`, `DENIED`, or `ESCALATED`.

**Evaluation context:** The set of inputs fed to the policy engine: agent identity, requested capability, resource, risk score, delegation status, and any additional parameters.

**Snapshot boundary:** The policy MUST be captured as it existed at `snapshot_at`, not as it exists at verification time.

**`policy_captured_at`** [NEW]: Unix seconds timestamp when the policy document was retrieved from the policy store. MUST be provided by the caller. MUST NOT be generated inside the snapshot creation function.

**`delta_max`** [NEW]: Maximum permitted interval in seconds between `policy_captured_at` and `snapshot_at`, as declared by the producer. Subject to enforcement by the verifier.

**freshness** [NEW]: `freshness = snapshot_at − policy_captured_at`. The age of the policy document at the moment of evaluation.

**clock skew** [NEW]: Small temporal drift between clocks of different systems. Tolerance: 5 seconds.

**`verifier.delta_max_allowed`** [NEW]: Maximum policy staleness accepted by a verifying institution. Default normative value: 300 seconds. Institutions MAY define a lower value. Institutions MUST NOT set it above 300 seconds.

---

## 4. PolicyContextSnapshot Object

### 4.1 Top-level structure

```json
{
  "ver": "1.1",
  "snapshot_id": "<uuid_v4>",
  "execution_id": "<et_id of the bound Execution Token>",
  "provenance_id": "<provenance_id of bound AuthorityProvenance>",
  "snapshot_at": "<unix_seconds>",
  "policy_captured_at": "<unix_seconds>",
  "delta_max": "<integer_seconds>",
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
    "checks": [ "<EvaluationCheck>", "..." ],
    "denial_reason": "<string or null>"
  },
  "sig": "<base64url Ed25519 signature>"
}
```

### 4.2 Field definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | MUST | `"1.1"` |
| `snapshot_id` | UUID v4 | MUST | Unique identifier for this snapshot |
| `execution_id` | string | MUST | `et_id` of the bound Execution Token |
| `provenance_id` | string | SHOULD | `provenance_id` of the bound `AuthorityProvenance` (MUST at L3-FULL) |
| `snapshot_at` | integer | MUST | Unix seconds. MUST be within the ET's validity window |
| `policy_captured_at` | integer | MUST at L3 | Unix seconds. When the policy was retrieved from the policy store. Provided by caller, not generated internally. |
| `delta_max` | integer | MUST at L3 | Max permitted staleness seconds declared by producer. MUST NOT exceed `verifier.delta_max_allowed`. |
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

### 5.3 Temporal Validity [UPDATED]

Two temporal constraints MUST hold independently:

**(a) Ordering constraint:**

```
policy_captured_at ≤ snapshot_at
```

Exception — clock skew: if `policy_captured_at > snapshot_at` and
`(policy_captured_at − snapshot_at) ≤ 5s`, the snapshot is accepted as clock drift.
If the skew exceeds 5 seconds → PCTX-009.

**(b) Freshness constraint:**

```
(snapshot_at − policy_captured_at) ≤ delta_max
```

These two constraints are independent. `delta_max` does NOT apply to clock skew cases. A clock skew condition is a distinct failure mode from staleness.

### 5.4 Freshness Enforcement Model [NEW]

The effective freshness limit is:

```
effectiveMax = min(snapshot.delta_max, verifier.delta_max_allowed)
```

All freshness validations MUST use `effectiveMax`, not `snapshot.delta_max` alone.

**`verifier.delta_max_allowed`:**
- Default normative value: **300 seconds** (consistent with ET validity window)
- Institutions MAY define a lower value
- Institutions MUST NOT set it above 300 seconds
- `snapshot.delta_max` MUST NOT exceed `verifier.delta_max_allowed` → else PCTX-009

**Rationale:** The producer declares its tolerance; the verifier enforces its own limit. A producer cannot inflate `delta_max` to bypass the verifier's policy. The `min()` ensures that whichever limit is stricter prevails.

### 5.5 Offline Execution Constraint [NEW]

At L3-FULL, a `PolicyContextSnapshot` whose freshness constraints are not met MUST be rejected (PCTX-009). This includes:

- Agents operating offline with stale cached policies
- Deferred snapshots captured hours before evaluation
- Any snapshot where `(snapshot_at − policy_captured_at) > effectiveMax`

There is no offline override flag. Offline mode is incompatible with L3-FULL policy freshness requirements.

### 5.6 Capture Responsibility [NEW]

`policy_captured_at` MUST be provided by the system that retrieves the policy from the policy store. It MUST NOT be generated inside the snapshot creation function (`Capture()`).

`delta_max` MUST also be provided by the caller. The snapshot creation function MUST NOT infer or default these values.

---

## 6. Validation Algorithm [UPDATED]

```
ValidatePolicyContextSnapshot(pcs, et, verifier_config):

  1. Verify pcs.ver ∈ {"1.0", "1.1"}
     → else PCTX-010

  2. Verify pcs.execution_id == et.et_id
     → else PCTX-001

  3. Verify pcs.snapshot_at within ET validity window
     → else PCTX-002

  4. If pcs.ver == "1.0":
        skip freshness validation (backward compat §12)
        goto step 9

  5. Verify pcs.policy_captured_at present (non-zero)
     → else PCTX-009

  6. Temporal ordering with clock skew tolerance (§5.3):
        diff = pcs.snapshot_at − pcs.policy_captured_at
        if diff < 0:
            if |diff| ≤ 5s → accept (clock skew)
            else → PCTX-009

  7. Verify pcs.delta_max present (non-zero)
     → else PCTX-009

  8. Freshness enforcement (§5.4):
        effectiveMax = min(pcs.delta_max, verifier_config.delta_max_allowed)
        if pcs.delta_max > verifier_config.delta_max_allowed → PCTX-009
        if diff > effectiveMax → PCTX-009

  9. Retrieve policy_doc = policy_store.get(pcs.policy.policy_id,
                                            version=pcs.policy.policy_version)
     → else PCTX-003

 10. Verify sha256(policy_doc) == pcs.policy.policy_hash
     → else PCTX-004

 11. Re-execute policy evaluation with pcs.evaluation_context → expected_decision
     Verify expected_decision == pcs.evaluation_result.decision
     → else PCTX-005

 12. Verify pcs.sig (institutional signature) over canonical JSON
     → else PCTX-006

 13. Return VALID
```

Step 11 (re-execution) requires the verifier to have access to the policy engine identified in `policy_engine` and the policy document retrieved in step 9. If the policy engine is unavailable, validation can proceed without step 11 but MUST be flagged as `partially_verified`.

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

## 9. Execution Requirements — Cross-Spec Enforcement [NEW]

### 9.1 DCMA Integration

At L3-FULL, any agent execution governed by ACP-DCMA-1.1 MUST be accompanied by a valid `PolicyContextSnapshot` conforming to this specification (ver: `"1.1"`). An execution without a valid snapshot MUST NOT be considered L3-compliant.

### 9.2 Cross-Organization Integration

At L3-FULL, `CROSS_ORG_INTERACTION` events (ACP-CROSS-ORG-1.1) MUST include a valid `PolicyContextSnapshot`. The snapshot MUST be transmitted as part of the interaction bundle.

### 9.3 Independent Validation

Receiving institutions MUST independently validate the freshness of any `PolicyContextSnapshot` included in a cross-org interaction. The receiving institution applies its own `verifier.delta_max_allowed`, not the sender's.

### 9.4 Failure Semantics

Any snapshot that fails freshness validation MUST cause the containing interaction or execution to be rejected with error PCTX-009.

> **Note:** Formal per-spec rules (DCMA-RULE-7, CROSS-RULE-9, CROSS-RULE-10) will be added in future versions of those specifications. §9 of this spec establishes the normative requirement for L3-compliant implementations now.

---

## 10. Error Codes [UPDATED]

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
| `PCTX-009` | Policy capture stale or invalid — covers: missing `policy_captured_at`, freshness exceeded, `snapshot.delta_max > verifier.delta_max_allowed`, clock skew exceeded |

---

## 11. Conformance [UPDATED]

| Conformance Level | Requirement |
|-------------------|-------------|
| L1-CORE | MAY omit entirely |
| L2-SECURITY | SHOULD record `policy_id` and `policy_hash` in ledger |
| L3-FULL | MUST produce full `PolicyContextSnapshot` (ver `"1.1"`) with `policy_captured_at`, `delta_max`, and freshness validation |
| L4-EXTENDED | MUST produce full snapshot + bind `denial_reason` to reputation events (ACP-REP-1.2) |
| L5-DECENTRALIZED | MUST produce full snapshot with decentralized policy store reference |

---

## 12. Compatibility Model [NEW]

ACP-POLICY-CTX-1.1 is backward-compatible with 1.0:

- All fields from 1.0 are preserved unchanged.
- Snapshots with `ver: "1.0"` remain valid; freshness validation is skipped entirely.
- `ver: "1.1"` snapshots add `policy_captured_at` and `delta_max` (MUST at L3-FULL).
- A 1.1 verifier MUST accept both `"1.0"` and `"1.1"` snapshots.
- When `ver == "1.0"`, the validation algorithm jumps from step 3 directly to step 9 (§6).

---

## 13. Non-Goals (ACP-POLICY-CTX-1.1)

The following are explicitly out of scope for this version:

- Multi-policy evaluation (array of policies per execution)
- Policy document expiration semantics
- Policy store identity or URL binding
- Policy distribution consistency across organizations

These may be addressed in ACP-POLICY-CTX-2.0.

---

## 14. Normative References [UPDATED]

- ACP-SIGN-1.0 — Serialization and signing
- ACP-EXEC-1.0 — Execution token specification
- ACP-LEDGER-1.3 — Audit ledger
- ACP-PROVENANCE-1.0 — Authority provenance (complementary artifact)
- ACP-RISK-1.0 — Risk scoring (source of `risk_score`)
- ACP-LIA-1.0 — Liability attribution (consumes PolicyContextSnapshot)
- ACP-CONF-1.2 — Conformance levels
- ACP-DCMA-1.1 — Delegation chain model
- ACP-CROSS-ORG-1.1 — Cross-organization interactions
