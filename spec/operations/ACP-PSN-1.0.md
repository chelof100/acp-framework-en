# ACP-PSN-1.0
## Policy Snapshot Specification
**Status:** Stable
**Version:** 1.0
**Depends-on:** ACP-RISK-1.0, ACP-SIGN-1.0, ACP-LEDGER-1.2
**Required-by:** ACP-LEDGER-1.2, ACP-LIA-1.0

---

## 1. Scope

This document defines the Policy Snapshot mechanism within the ACP ecosystem. It specifies the structure of a snapshot, its lifecycle, the atomic transition process between snapshots, and the query and creation endpoints.

The objective is to solve the "policy drift" problem: when an audit is conducted weeks after an execution, the active risk policy may have changed. The Policy Snapshot guarantees that the exact policy that governed a decision can be deterministically reconstructed at any future point in time.

---

## 2. Definitions

**Policy Snapshot:** Immutable, signed record of the complete state of the risk policy at a specific instant. Once created, it cannot be modified.

**Active snapshot:** The only snapshot with `effective_until: null` at any given moment. Every new risk evaluation MUST reference the active snapshot.

**Superseded snapshot:** Snapshot that was replaced by a subsequent one. Its `effective_until` is fixed to the `effective_from` of the successor snapshot.

**Snapshot transition:** Atomic process by which a new snapshot becomes active and the previous one becomes superseded. There can be no instant without an active snapshot.

**policy_version:** Semantic string (semver) identifying the logical version of the policy.

**Policy drift:** Phenomenon where the policy at the time of an audit differs from the policy active at the time of execution. The Policy Snapshot eliminates this risk.

---

## 3. Principles

**3.1 Immutability** — A Policy Snapshot, once created and signed, is immutable.

**3.2 Active snapshot uniqueness** — At all times there MUST exist exactly one active snapshot (`effective_until: null`). The transition is atomic.

**3.3 Full temporal coverage** — The `[effective_from, effective_until)` ranges of all snapshots MUST cover the complete timeline without gaps from the creation of the first snapshot.

**3.4 Permanent referenceability** — Every snapshot, including superseded ones, MUST remain available for query indefinitely. Snapshots are never deleted.

**3.5 Institutional signature** — Every snapshot MUST be signed with the institutional key (ACP-SIGN-1.0). The signature covers all snapshot fields except `sig`.

---

## 4. Policy Snapshot Structure

```json
{
  "ver": "1.0",
  "snapshot_id": "<uuid_v4>",
  "institution_id": "org.example.banking",
  "policy_version": "2.1.0",
  "effective_from": 1718900000,
  "effective_until": null,
  "thresholds": {
    "default": {
      "approved_max": 39,
      "escalated_max": 69
    },
    "by_autonomy_level": {
      "0": {"approved_max": -1, "escalated_max": -1},
      "1": {"approved_max": 19, "escalated_max": 100},
      "2": {"approved_max": 39, "escalated_max": 69},
      "3": {"approved_max": 59, "escalated_max": 79},
      "4": {"approved_max": 79, "escalated_max": 89}
    }
  },
  "capability_baselines": {
    "acp:cap:financial.payment": 35,
    "acp:cap:financial.transfer": 40,
    "acp:cap:data.read": 10,
    "acp:cap:data.write": 25
  },
  "context_factors": {
    "off_hours": 15,
    "non_corporate_ip": 20,
    "high_frequency": 10
  },
  "resource_factors": {
    "public": 0,
    "sensitive": 15,
    "critical": 30
  },
  "custom_factors": {},
  "created_at": 1718900000,
  "created_by": "<AgentID>",
  "sig": "<institutional_signature>"
}
```

---

## 5. Field Specification

**5.1 `ver`** — ACP-PSN schema version. MUST be `"1.0"` for snapshots conforming to this document.

**5.2 `snapshot_id`** — Unique, immutable UUID v4. Primary reference key across all ACP systems.

**5.3 `institution_id`** — Identifier of the institution that owns the snapshot. MUST match the `institution_id` of the ledger where it is registered.

**5.4 `policy_version`** — Semver string of the logical policy version. Increment when any threshold or factor changes.

**5.5 `effective_from`** — Unix timestamp (seconds) of the snapshot's validity start. MUST be ≥ `effective_from` of the previous snapshot.

**5.6 `effective_until`** — Unix timestamp of the validity end. `null` indicates the active snapshot. Set to the `effective_from` of the successor snapshot when superseded.

**5.7 `thresholds`** — Object with risk evaluation thresholds:
- `default`: Global thresholds when no specific `autonomy_level` rule applies.
- `by_autonomy_level`: Map `autonomy_level` → thresholds. `approved_max`: maximum score for automatic approval. `escalated_max`: maximum score for escalation (above this → denial). `-1` indicates the level cannot execute any action.

**5.8 `capability_baselines`** — Map of capability → base score. Capabilities not listed use `default.approved_max / 2` as baseline.

**5.9 `context_factors`** — Map of context factor → score increment. Factors are summed when the corresponding condition is detected during evaluation.

**5.10 `resource_factors`** — Map of resource classification → score increment. The factor corresponding to the target resource's classification is applied.

**5.11 `custom_factors`** — Extensible map for institution-defined custom factors. MUST follow the `string → integer` format.

**5.12 `created_at`** — Unix timestamp of snapshot creation. MUST equal `effective_from`.

**5.13 `created_by`** — AgentID of the agent or system that created the snapshot.

**5.14 `sig`** — Institutional signature (ACP-SIGN-1.0) over all fields except `sig`. Computed over `base64url(SHA-256(JCS(snapshot without sig)))`.

---

## 6. Lifecycle

**States:**
- `ACTIVE`: snapshot with `effective_until: null`. Exactly one at a time.
- `SUPERSEDED`: snapshot with a fixed `effective_until`. Terminal state.

**Transitions:**
```
ACTIVE → SUPERSEDED  (via Snapshot Transition §7)
```

No transition exists from SUPERSEDED to any other state.

---

## 7. Snapshot Transition (Atomic Process)

When a new policy must be activated:

**7.1 Pre-condition:** Exactly one ACTIVE snapshot MUST exist.

**7.2 Atomic sequence:**
1. Create new snapshot with `effective_from = T_now`, `effective_until = null`, `policy_version` incremented if there are changes.
2. Sign the new snapshot (ACP-SIGN-1.0).
3. In an atomic transaction:
   a. Set `effective_until = T_now` on the previous ACTIVE snapshot.
   b. Persist the new snapshot as ACTIVE.
4. Emit `POLICY_SNAPSHOT_CREATED` event in the Audit Ledger (ACP-LEDGER-1.2 §5.13).

**7.3 Atomicity:** If step 3 fails, the state MUST revert. The system cannot be left without an ACTIVE snapshot or with two simultaneous ACTIVE snapshots.

**7.4 `effective_until` of superseded snapshot:** MUST equal the `effective_from` of the new snapshot. This guarantees temporal coverage with no gaps or overlaps.

---

## 8. Use in Risk Evaluation

**8.1 Mandatory reference** — Every `AUTHORIZATION` and `RISK_EVALUATION` ledger event MUST include `policy_snapshot_ref` with the UUID of the ACTIVE snapshot at the time of evaluation.

**8.2 Determinism** — Given a `policy_snapshot_ref`, any actor can exactly replicate the risk calculation performed at execution time, regardless of policy changes made afterwards.

**8.3 Obtaining the active snapshot** — Implementors SHOULD cache the active snapshot in memory. The cache MUST be invalidated upon detecting a `POLICY_SNAPSHOT_CREATED` event in the ledger.

---

## 9. Endpoints

### 9.1 `GET /acp/v1/policy-snapshots/active`

Returns the currently active snapshot.

**Response 200:**
```json
{
  "snapshot": { /* complete Policy Snapshot */ },
  "retrieved_at": 1718925000
}
```
**Response 503:** `PSN-005` if no active snapshot exists (invalid system state).

---

### 9.2 `GET /acp/v1/policy-snapshots/{snapshot_id}`

Returns a specific snapshot by ID (includes superseded).

**Response 200:** Complete Policy Snapshot.
**Response 404:** `PSN-001`

---

### 9.3 `GET /acp/v1/policy-snapshots?from=&to=`

Lists snapshots active within a time range. Useful for historical audits.

**Query params:**
- `from`: Unix timestamp start (required)
- `to`: Unix timestamp end (default: now)
- `include_superseded`: boolean (default: true)

**Response 200:**
```json
{
  "items": [
    {
      "snapshot_id": "<uuid>",
      "policy_version": "2.1.0",
      "effective_from": 1718900000,
      "effective_until": 1719000000,
      "status": "SUPERSEDED"
    }
  ],
  "total_count": 3
}
```

---

### 9.4 `POST /acp/v1/policy-snapshots`

Creates a new snapshot and activates it (executes Snapshot Transition §7).

**Request body:**
```json
{
  "policy_version": "2.2.0",
  "thresholds": { },
  "capability_baselines": { },
  "context_factors": { },
  "resource_factors": { },
  "custom_factors": {}
}
```

**Response 201:**
```json
{
  "snapshot_id": "<uuid>",
  "effective_from": 1719000000,
  "previous_snapshot_id": "<uuid>",
  "ledger_event_id": "<uuid>"
}
```

**Response 409:** `PSN-004` if a transition is already in progress.
**Response 422:** `PSN-006` if thresholds are invalid.

---

## 10. Historical Verification

**10.1 External verification flow:**

1. Obtain `policy_snapshot_ref` from the event to audit (AUTHORIZATION or LIABILITY_RECORD).
2. Retrieve snapshot via `GET /acp/v1/policy-snapshots/{snapshot_id}`.
3. Verify snapshot `sig` with the institutional public key.
4. Verify that `effective_from ≤ executed_at < effective_until` (or `effective_until: null` if it was the last).
5. Re-execute the risk calculation using the retrieved snapshot.
6. Compare result with the decision recorded in the ledger.

**10.2 Proof of non-alteration:** The institutional signature on the snapshot guarantees it cannot have been retroactively modified. An external auditor can verify this with the published institutional public key.

---

## 11. Interoperability

**11.1 Cross-institution references** — When an agent from institution A executes in the context of institution B, the `policy_snapshot_ref` MUST reference the snapshot of the institution where execution occurs (institution B).

**11.2 Export** — Implementations MAY export snapshots in signed JSON format for verification by third parties without access to the institutional system.

**11.3 Schema versioning** — The `ver` field allows schema evolution. Implementations MUST reject snapshots with an unknown `ver` with error `PSN-003`.

---

## 12. Error Codes

| Code | Condition |
|---|---|
| `PSN-001` | Snapshot not found for the given ID |
| `PSN-002` | Invalid signature: snapshot has been altered or key does not match |
| `PSN-003` | Schema version (`ver`) not supported by this implementation |
| `PSN-004` | Snapshot transition in progress: cannot create a new snapshot concurrently |
| `PSN-005` | No active snapshot exists: invalid system state |
| `PSN-006` | Invalid thresholds: values out of range or incorrect structure |
