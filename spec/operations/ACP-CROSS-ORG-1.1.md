# ACP-CROSS-ORG-1.1 — Cross-Organizational Interaction Registry

**Version:** 1.1
**Status:** Active
**Supersedes:** ACP-CROSS-ORG-1.0
**Dependencies:** ACP-LEDGER-1.3, ACP-ITA-1.1, ACP-HIST-1.0, ACP-LIA-1.0, ACP-SIGN-1.0
**Implements:** ACP-CONF-1.2 Conformance Level L4
**Related:** ACP-REP-PORTABILITY-1.0

---

## Changelog

- **v1.1** — Adds fault-tolerant bilateral protocol. Introduces `interaction_id` (UUIDv7) as mandatory correlation identifier for deduplication across retries. Defines derived interaction status model (§9). Adds formal retry protocol: 3 attempts, backoff +30s/+60s/+120s (§8). Formalises `pending_review` SLA (24h) and state transitions (§8.4). Registers `CROSS_ORG_ACK` as a first-class event type in ACP-LEDGER-1.3 §5. Adds error codes CROSS-012 through CROSS-015. Updates dependency from ACP-LEDGER-1.2 to ACP-LEDGER-1.3.
- **v1.0** — Initial specification: `CROSS_ORG_INTERACTION` event type, CrossOrgBundle bilateral transmission protocol, CrossOrgAck, HIST-1.0 query extensions.

---

## Abstract

ACP-CROSS-ORG-1.1 defines the `CROSS_ORG_INTERACTION` and `CROSS_ORG_ACK` event types, making cross-system interactions between organizations first-class, auditable entities in the ACP ledger. It extends ACP-CROSS-ORG-1.0 with a complete fault-tolerant bilateral protocol: a mandatory correlation identifier (`interaction_id`), a formal retry mechanism with deterministic backoff, a derived interaction status model, and a formal `pending_review` state machine with SLA enforcement.

---

## 1. Scope

This document defines:

- The `CROSS_ORG_INTERACTION` and `CROSS_ORG_ACK` event types and their payload schemas
- The rules for emission: who emits, when, and under what conditions
- The bilateral verification protocol: how the target institution validates an incoming interaction
- The fault-tolerant retry protocol: what happens when transmission or acknowledgment fails
- The derived interaction status model: how `cross_org_status` is computed from ledger events
- The `pending_review` state machine: SLA, transitions, and expiry
- The query and export extensions on top of ACP-HIST-1.0 for cross-org filtering
- Conformance requirements

This document does **not** define:
- How federation between institutions is established (see ACP-ITA-1.1)
- How reputation is updated from cross-org events (see ACP-REP-PORTABILITY-1.0)
- Payment flows across institutions (see ACP-PAY-1.0)

---

## 2. Terminology

**CROSS_ORG_INTERACTION:** An ACP ledger event emitted when an agent from a source institution executes an action directed at or producing verifiable effects at a target institution.

**CROSS_ORG_ACK:** A first-class ACP ledger event type emitted by the target institution to acknowledge receipt and validation of a CrossOrgBundle. Registered in ACP-LEDGER-1.3 §5. Stored in both source and target ledgers.

**CrossOrgBundle:** A signed, self-verifiable package containing one or more `CROSS_ORG_INTERACTION` events, designed to be transmitted to the target institution and stored in its ledger.

**interaction_id:** A UUIDv7 identifier assigned to a cross-org interaction at the moment the source emits the first `CROSS_ORG_INTERACTION` event. This identifier is **immutable** and **reused across all retries** of the same logical interaction. It is the canonical deduplication key at the target.

**event_id:** A UUIDv4 identifier unique to a specific ledger event emission. Each retry produces a new `event_id` in the source ledger while reusing the same `interaction_id`.

**Derived interaction status:** The computed state of a cross-org interaction, derived from events present in the ledger. Status is never stored directly — it is always computed from the event record. See §9.

**ActionType:** Enumeration of cross-organizational action categories. Extensible; institutions may define domain-specific subtypes prefixed with `x:`.

**PayloadHash:** SHA-256 hash of the canonical representation (JCS, RFC 8785) of the interaction payload. The payload itself is never transmitted — only the hash.

**ZKP:** Zero-knowledge proof, optional field. Allows a source institution to prove a property of the interaction (e.g., "the amount transferred is within regulatory limits") without revealing the full payload.

---

## 3. Motivation

The ACP authorization model is institutional: each institution maintains its own ledger, its own agents, and its own risk evaluation. When two institutions interact, the existing model captures:

- The `AUTHORIZATION` on the source side (source ledger)
- The `LIABILITY_RECORD` on the source side (source ledger)
- Nothing on the target side unless it independently generates events

This creates an **asymmetric audit trail**: the source institution has a complete record, the target has nothing unless it implements custom instrumentation. External auditors and regulators cannot reconstruct the full cross-institutional flow from a single ledger.

ACP-CROSS-ORG-1.0 closed the asymmetry gap. ACP-CROSS-ORG-1.1 closes the **fault-tolerance gap**: what happens when any step in the 5-step bilateral protocol fails. Without a defined retry protocol, a target that receives a bundle but crashes before writing to its ledger creates an inconsistent audit trail. Without a formal status model, the `cross_org_status` query filter in §10 is undefined semantically. Without a `pending_review` SLA, interactions can remain unresolved indefinitely.

---

## 4. Event Type: `CROSS_ORG_INTERACTION`

### 4.1 Envelope

The event follows the standard ACP-LEDGER-1.3 envelope:

```json
{
  "ver": "1.3",
  "event_id": "<uuid_v4>",
  "event_type": "CROSS_ORG_INTERACTION",
  "sequence": 42,
  "timestamp": "<unix_timestamp_ms>",
  "institution_id": "<source_institution_id>",
  "prev_hash": "<sha256_of_previous_event_canonical>",
  "payload": { ... },
  "hash": "<sha256_base64url_of_event>",
  "sig": "<ed25519_base64url_over_canonical_envelope>"
}
```

The `institution_id` in the envelope is **always the source institution** — the institution whose agent initiated the interaction. The target institution stores this event in its own ledger with its own envelope wrapping the CrossOrgBundle (see §7).

### 4.2 Payload Schema

```json
{
  "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
  "event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
  "timestamp": "2026-03-18T12:00:00Z",
  "source_institution_id": "INST-A",
  "target_institution_id": "INST-B",
  "action_type": "DATA_SHARE",
  "payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "delegation_chain": [
    {
      "agent_id": "AGT-001",
      "institution_id": "INST-A",
      "capability": "acp:cap:data.share",
      "sig": "base64url(ed25519_sig_over_delegation_step)"
    }
  ],
  "authorization_id": "<uuid_of_AUTHORIZATION_event_in_source_ledger>",
  "liability_record_id": "<uuid_of_LIABILITY_RECORD_in_source_ledger>",
  "attempt_number": 1,
  "proof": "zkp_base64url_encoded_optional_or_null",
  "ack_required": true,
  "metadata": {
    "protocol_version": "1.1",
    "domain": "finance",
    "classification": "confidential"
  }
}
```

### 4.3 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `interaction_id` | string (UUIDv7) | ✓ | Globally unique interaction identifier. Assigned at first emission. **Reused across all retries of the same logical interaction.** Primary deduplication key at the target. MUST be immutable once assigned. |
| `event_id` | string (UUIDv4) | ✓ | Unique identifier for this specific ledger event. Each retry generates a new `event_id`. |
| `timestamp` | string (ISO 8601) | ✓ | UTC timestamp of this emission. |
| `source_institution_id` | string | ✓ | ACP institution ID of the initiating institution. MUST match the envelope `institution_id`. |
| `target_institution_id` | string | ✓ | ACP institution ID of the receiving institution. MUST be registered in the ITA federation (ACP-ITA-1.1). |
| `action_type` | string (enum) | ✓ | Category of cross-org action. See §4.4. |
| `payload_hash` | string (hex, 64 chars) | ✓ | SHA-256 of the JCS-canonical interaction payload. Payload itself is never transmitted. MUST be identical across all retries. |
| `delegation_chain` | array | ✓ | Ordered list of delegation steps from root capability to acting agent. Minimum 1 entry. |
| `authorization_id` | string (UUID) | ✓ | UUID of the `AUTHORIZATION` event in the **source** ledger that authorized this interaction. |
| `liability_record_id` | string (UUID) | ✓ | UUID of the `LIABILITY_RECORD` event in the **source** ledger. MUST be emitted before or at the same sequence as this event. |
| `attempt_number` | integer | ✓ | 1-based attempt counter. First emission: `1`. Each retry increments this field. MUST be monotonically increasing per `interaction_id`. |
| `proof` | string \| null | ○ | Optional ZK-proof. Format: `zkp:<scheme>:<base64url_data>`. |
| `ack_required` | boolean | ✓ | When `true`, the target institution MUST emit a `CROSS_ORG_ACK` and transmit it back. |
| `metadata` | object | ○ | Domain-specific metadata. Keys reserved: `protocol_version`, `domain`, `classification`. |

### 4.4 ActionType Enumeration

| ActionType | Description |
|-----------|-------------|
| `DATA_SHARE` | Source shares data (dataset, report, stream) with target. |
| `SERVICE_INVOCATION` | Source agent invokes a service endpoint at target. |
| `DELEGATION_TRANSFER` | Source transfers a capability delegation to an agent at target. |
| `COMPLIANCE_QUERY` | Source queries regulatory/compliance status at target. |
| `FINANCIAL_SETTLEMENT` | Source initiates a financial settlement directed at target. Requires ACP-PAY-1.0. |
| `AUDIT_REQUEST` | Source requests an audit segment (ExportBundle) from target. |
| `REPUTATION_QUERY` | Source queries agent reputation data at target. See ACP-REP-PORTABILITY-1.0. |
| `x:<custom>` | Institution-defined. MUST be prefixed `x:` to avoid collisions with reserved types. |

---

## 5. Emission Rules

**CROSS-RULE-1:** A `CROSS_ORG_INTERACTION` event MUST be emitted by the **source institution** in its own ledger for every action that crosses an institutional trust boundary, as defined by the active federation (ACP-ITA-1.1).

**CROSS-RULE-2:** The event MUST be emitted **after** the `LIABILITY_RECORD` for the same execution. The `liability_record_id` field MUST reference an event that already exists in the source ledger.

**CROSS-RULE-3:** The `authorization_id` MUST reference an `AUTHORIZATION` event that preceded this interaction in the source ledger. If the `AUTHORIZATION` event cannot be found, emission is prohibited and the interaction MUST be blocked.

**CROSS-RULE-4:** The `payload_hash` MUST be computed over the JCS-canonical form of the full interaction payload before transmission. It is never updated after emission.

**CROSS-RULE-5:** If `ack_required` is `true`, the source institution MUST implement the retry protocol defined in §8. If no `CrossOrgAck` is received after the maximum number of attempts, the source MUST set `retry_exhausted = true` in its observability metadata (§8.5) and emit an `ESCALATION_CREATED` event.

**CROSS-RULE-6:** If a federation between `source_institution_id` and `target_institution_id` does not exist (verified via `GET /ita/v1/federation/resolve/{target_institution_id}`), the event MUST NOT be emitted and MUST return error CROSS-004.

**CROSS-RULE-7:** The `interaction_id` MUST be assigned at first emission and MUST remain identical across all retries. The `payload_hash` and `action_type` MUST be identical across all retries of the same `interaction_id`. Implementations MUST NOT assign a new `interaction_id` for a retry.

---

## 6. Full Example

### 6.1 Interaction: Institution A shares a data report with Institution B

**Sequence in source ledger (INST-A):**

```
seq 38: AUTHORIZATION          → auth_id: "auth-9a3f..."
seq 39: EXECUTION_TOKEN_CONSUMED → et_id: "et-7c2b..."
seq 40: LIABILITY_RECORD       → lia_id: "lia-5d1e..."
seq 41: CROSS_ORG_INTERACTION  → interaction_id: "01951b2c...", event_id: "e7f9c8a1...", attempt_number: 1
```

**Full CROSS_ORG_INTERACTION event (seq 41, first attempt):**

```json
{
  "ver": "1.3",
  "event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
  "event_type": "CROSS_ORG_INTERACTION",
  "sequence": 41,
  "timestamp": 1742299200000,
  "institution_id": "INST-A",
  "prev_hash": "9f3bc2a1e4d7890123456789abcdef0123456789abcdef0123456789abcdef01",
  "payload": {
    "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
    "event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
    "timestamp": "2026-03-18T12:00:00Z",
    "source_institution_id": "INST-A",
    "target_institution_id": "INST-B",
    "action_type": "DATA_SHARE",
    "payload_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "delegation_chain": [
      {
        "agent_id": "AGT-001",
        "institution_id": "INST-A",
        "capability": "acp:cap:data.share",
        "sig": "base64url_sig_AGT001_over_delegation_step"
      }
    ],
    "authorization_id": "auth-9a3f-4b2c-8d1e-567890abcdef",
    "liability_record_id": "lia-5d1e-4c3b-9a2f-890123abcdef",
    "attempt_number": 1,
    "proof": null,
    "ack_required": true,
    "metadata": {
      "protocol_version": "1.1",
      "domain": "finance",
      "classification": "confidential"
    }
  },
  "hash": "base64url_sha256_of_event",
  "sig": "base64url_ed25519_sig_INST_A_over_canonical_event"
}
```

---

## 7. CrossOrgBundle — Bilateral Transmission Protocol

### 7.1 Bundle structure

After emitting the event in the source ledger, the source institution packages it for transmission to the target:

```json
{
  "bundle_id": "<uuid_v4>",
  "bundle_version": "1.1",
  "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
  "source_institution_id": "INST-A",
  "target_institution_id": "INST-B",
  "created_at": "2026-03-18T12:00:01Z",
  "attempt_number": 1,
  "events": [
    { "<full CROSS_ORG_INTERACTION event as above>" }
  ],
  "evidence": {
    "authorization_export": "<ExportBundle from HIST-1.0 filtered to auth_id>",
    "liability_export": "<ExportBundle from HIST-1.0 filtered to lia_id>"
  },
  "sig": "base64url_ed25519_sig_INST_A_over_canonical_bundle"
}
```

The `evidence` block is optional but RECOMMENDED. The `interaction_id` in the bundle MUST match the `interaction_id` in all contained events.

### 7.2 Transmission endpoint

The source institution POSTs the bundle to the target's ACP node:

```
POST /acp/v1/cross-org/receive
Content-Type: application/json

Body: <CrossOrgBundle>
```

### 7.3 Target validation steps

Upon receiving a CrossOrgBundle, the target institution MUST:

1. **Verify federation:** `GET /ita/v1/federation/resolve/{source_institution_id}` — confirm active federation exists.
2. **Verify bundle signature:** validate `sig` against source institution's ARK (obtained via ITA federation).
3. **Verify each event signature:** validate each event's `sig` using the source institution's ARK.
4. **Verify hash chain integrity:** if multiple events in bundle, verify sequential `prev_hash` linkage.
5. **Verify references (optional):** if `evidence.authorization_export` is present, verify ExportBundle integrity per HIST-1.0 §7.
6. **Check idempotency by `interaction_id`:** if an event with the same `interaction_id` has already been successfully recorded in the local ledger (with an `accepted` ACK already emitted), return 200 OK with the existing ACK without re-processing. This is the canonical deduplication check.
7. **Record in local ledger:** emit a `CROSS_ORG_INTERACTION` event in the target's own ledger with `institution_id` = target institution's ID and a reference to the original `interaction_id`.

### 7.4 CrossOrgAck — `CROSS_ORG_ACK` Ledger Event

If `ack_required` is `true`, the target institution MUST emit a `CROSS_ORG_ACK` event in its ledger (per ACP-LEDGER-1.3 §5.15) and transmit the payload to the source:

```json
{
  "ack_id": "<uuid_v4>",
  "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
  "original_event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
  "target_institution_id": "INST-B",
  "source_institution_id": "INST-A",
  "validated_at": "2026-03-18T12:00:02Z",
  "status": "accepted",
  "ledger_sequence": 17,
  "sig": "base64url_ed25519_sig_INST_B_over_canonical_ack"
}
```

`status` values: `accepted` | `rejected` (with `rejection_reason`) | `pending_review`.

The source institution MUST store the `CROSS_ORG_ACK` in its own ledger as a `CROSS_ORG_ACK` event (per ACP-LEDGER-1.3 §5.15).

**ACK precedence rule:** A `CROSS_ORG_ACK` with `status: accepted` or `status: rejected` received at any point MUST cancel any pending retry timer. An ACK always takes precedence over retry state.

---

## 8. Fault Tolerance and Retry Protocol

### 8.1 Model

ACP-CROSS-ORG-1.1 uses an **explicit async model**: the source institution does not block waiting for a `CROSS_ORG_ACK`. Eventual consistency is declared: the source ledger MAY record a `CROSS_ORG_INTERACTION` before the target records it. The `interaction_id` provides the correlation anchor across all institutions and all attempts.

### 8.2 Retry Specification

When `ack_required: true` and no `CROSS_ORG_ACK` is received within 300 seconds of each attempt:

| Attempt | Wait before retry | Cumulative wait |
|---------|------------------|-----------------|
| 1 (initial) | — | 0s |
| 2 (retry 1) | 300s + 30s backoff | 330s |
| 3 (retry 2) | 300s + 60s backoff | 690s |
| After attempt 3 | no further retry | — |

**CROSS-RULE-8:** Each retry MUST reuse the same `interaction_id`. Each retry MUST emit a new `CROSS_ORG_INTERACTION` event in the source ledger with a new `event_id` and incremented `attempt_number`.

**CROSS-RULE-9:** The `payload_hash`, `action_type`, `authorization_id`, and `liability_record_id` MUST be identical across all retry events for the same `interaction_id`. A retry with a modified payload is a protocol violation.

**CROSS-RULE-10:** If a valid `CROSS_ORG_ACK` (status `accepted` or `rejected`) arrives at any point during the retry sequence, the source MUST cancel all pending retry timers and MUST NOT emit further retry events for that `interaction_id`.

**CROSS-RULE-11:** After exhausting all retries without receiving a `CROSS_ORG_ACK`, the source MUST:
- Set `retry_exhausted = true` in its local observability record (§8.5).
- Emit an `ESCALATION_CREATED` event referencing the `interaction_id`.
- Return error CROSS-012.

### 8.3 Source Ledger Sequence for a Retry

```
seq 41: CROSS_ORG_INTERACTION  → interaction_id: "01951b2c...", event_id: "e7f9c8a1...", attempt_number: 1
        [300s timeout — no ACK received]
seq 44: CROSS_ORG_INTERACTION  → interaction_id: "01951b2c...", event_id: "f8a0d9b2...", attempt_number: 2
        [300s timeout — no ACK received]
seq 47: CROSS_ORG_INTERACTION  → interaction_id: "01951b2c...", event_id: "a1b2c3d4...", attempt_number: 3
        [300s timeout — retry exhausted]
seq 48: ESCALATION_CREATED     → interaction_id: "01951b2c..."
```

### 8.4 `pending_review` State Machine

When the target emits `CROSS_ORG_ACK` with `status: pending_review`, the interaction requires human or system review at the target before a final determination.

**SLA:** A `pending_review` interaction MUST be resolved within **24 hours** of the ACK timestamp. The `review_deadline` field in the ACK payload specifies the exact deadline in Unix seconds.

```json
{
  "ack_id": "<uuid_v4>",
  "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
  "original_event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
  "target_institution_id": "INST-B",
  "source_institution_id": "INST-A",
  "validated_at": "2026-03-18T12:00:02Z",
  "status": "pending_review",
  "review_deadline": 1742385602,
  "ledger_sequence": 17,
  "sig": "base64url_ed25519_sig_INST_B_over_canonical_ack"
}
```

**Formal transitions:**

```
pending_review → accepted    (target emits new CROSS_ORG_ACK with status: accepted)
pending_review → rejected    (target emits new CROSS_ORG_ACK with status: rejected)
pending_review → expired     (now > review_deadline; no explicit event — derived state, see §9)
```

**CROSS-RULE-12:** A `pending_review` ACK does NOT cancel retry timers. The source MUST continue its retry sequence independently. If a final ACK (`accepted` or `rejected`) arrives, it MUST cancel retries per CROSS-RULE-10.

**CROSS-RULE-13:** A target MUST NOT emit a `pending_review → pending_review` transition. Each `pending_review` ACK opens exactly one review window. Replacing a `pending_review` with another `pending_review` is a protocol violation and MUST return error CROSS-015.

### 8.5 Observability Metadata

Each source institution SHOULD maintain a local (non-ledger) observability record per `interaction_id`. This record is never stored in the ledger — it is operational metadata for monitoring and alerting:

```json
{
  "interaction_id": "01951b2c-7e3f-7a1d-a8b4-5c9d8e7f6012",
  "attempt_count": 1,
  "last_attempt_at": "2026-03-18T12:00:00Z",
  "last_attempt_event_id": "e7f9c8a1-5b2c-4d3e-987f-1234567890ab",
  "ack_received": false,
  "retry_exhausted": false,
  "ack_latency_ms": null
}
```

When an ACK is received: set `ack_received = true`, compute `ack_latency_ms` as `validated_at - last_attempt_at` in milliseconds.

---

## 9. Derived Interaction Status

The `cross_org_status` query filter (§10) and the operational state of any interaction are **derived** from ledger events. There is no mutable status field. No `CROSS_ORG_STATUS_UPDATE` event type exists.

Given an `interaction_id`, the derived status is computed as follows:

| Derived Status | Condition |
|----------------|-----------|
| `pending_ack` | At least one `CROSS_ORG_INTERACTION` event exists for this `interaction_id`; no `CROSS_ORG_ACK` exists. |
| `acked` | A `CROSS_ORG_ACK` with `status: accepted` exists for this `interaction_id`. |
| `rejected` | A `CROSS_ORG_ACK` with `status: rejected` exists for this `interaction_id`. |
| `pending_review` | A `CROSS_ORG_ACK` with `status: pending_review` exists; no subsequent `accepted` or `rejected` ACK exists; `now ≤ review_deadline`. |
| `expired` | A `CROSS_ORG_ACK` with `status: pending_review` exists; `now > review_deadline`; no final ACK exists. |

**Precedence rules (applied in order):**
1. If `accepted` ACK exists → status is `acked` (regardless of any `pending_review` ACKs).
2. If `rejected` ACK exists → status is `rejected` (regardless of any `pending_review` ACKs).
3. If `pending_review` ACK exists and `now > review_deadline` → status is `expired`.
4. If `pending_review` ACK exists and `now ≤ review_deadline` → status is `pending_review`.
5. Otherwise → status is `pending_ack`.

**Verification rule:** An implementation computing derived status MUST read the ledger at query time. Derived status MUST NOT be cached beyond the request scope without invalidation.

---

## 10. Query Extensions (HIST-1.0)

This specification adds a cross-org filter parameter to the existing `GET /acp/v1/audit/query` endpoint defined in ACP-HIST-1.0:

### New filter parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Set to `CROSS_ORG_INTERACTION` or `CROSS_ORG_ACK` to filter exclusively. |
| `interaction_id` | string | Filter by interaction_id (all events and ACKs for one interaction). |
| `source_institution_id` | string | Filter by source institution. |
| `target_institution_id` | string | Filter by target institution. |
| `action_type` | string | Filter by action type enum (§4.4). |
| `cross_org_status` | string | `acked` / `pending_ack` / `rejected` / `pending_review` / `expired` — derived per §9. |

### Cross-org agent history extension

```
GET /acp/v1/audit/agents/{agent_id}/cross-org-history
```

Returns all `CROSS_ORG_INTERACTION` events where the agent in `delegation_chain` participated, across both source and target perspectives.

**Response:**
```json
{
  "agent_id": "AGT-001",
  "cross_org_summary": {
    "total_interactions": 47,
    "as_source": 31,
    "as_target": 16,
    "action_types": {
      "DATA_SHARE": 22,
      "SERVICE_INVOCATION": 15,
      "COMPLIANCE_QUERY": 10
    },
    "institutions_interacted": ["INST-B", "INST-C", "INST-D"]
  },
  "events": [ "..." ]
}
```

### Cross-org export

```
POST /acp/v1/audit/export
```

With body including `event_types: ["CROSS_ORG_INTERACTION", "CROSS_ORG_ACK"]` and optional `interaction_id` or `target_institution_id` filter. The resulting ExportBundle is independently verifiable per HIST-1.0 §7.

---

## 11. Interaction Flow

```mermaid
flowchart TD
    A[Agent at Inst A] -->|Executes action| B[Source Ledger / Inst A]
    B -->|seq N-2: AUTHORIZATION| B
    B -->|seq N-1: LIABILITY_RECORD| B
    B -->|seq N: CROSS_ORG_INTERACTION\ninteraction_id assigned\nattempt_number=1| B
    B -->|CrossOrgBundle POST /acp/v1/cross-org/receive| C[Target ACP Node / Inst B]
    C -->|1. Verify federation ITA-1.1| C
    C -->|2. Verify bundle sig| C
    C -->|3. Dedup by interaction_id| C
    C -->|4. Record in Target Ledger| D[Target Ledger / Inst B]
    D -->|CROSS_ORG_ACK\nstatus: accepted| B
    B -->|Store CROSS_ORG_ACK| B
    B -->|No ACK in 300s?\nRetry with same interaction_id\nnew event_id, attempt_number++| C
    B -->|3 retries exhausted?\nEscalation + CROSS-012| E[Escalation]
    D --> F[Auditor / Regulator]
    B --> F
    F -->|HIST-1.0 ExportBundle\ncross-org query by interaction_id| F
```

---

## 12. Integration Reference

| Spec | Integration Point |
|------|------------------|
| **ACP-LEDGER-1.3** | `CROSS_ORG_INTERACTION` and `CROSS_ORG_ACK` are registered event types in ACP-LEDGER-1.3 §5. Both follow the standard envelope, hash chaining, and signature rules. `CROSS_ORG_ACK` is defined in §5.15. |
| **ACP-ITA-1.1** | Federation resolution is prerequisite for every emission (§5, CROSS-RULE-6). ARK from ITA-1.1 is used for bundle signature verification (§7.3 step 2). |
| **ACP-HIST-1.0** | Query extensions are additive on top of existing endpoints (§10). ExportBundle format from HIST-1.0 §7 is reused for evidence in CrossOrgBundle (§7.1). |
| **ACP-LIA-1.0** | Every `CROSS_ORG_INTERACTION` MUST reference a `LIABILITY_RECORD` (`liability_record_id` field). Together they produce a complete cross-institutional audit chain. |
| **ACP-REP-PORTABILITY-1.0** | `CROSS_ORG_INTERACTION` events with `action_type: REPUTATION_QUERY` trigger the portability protocol. |

---

## 13. Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| CROSS-001 | 400 | Malformed event: missing required field. |
| CROSS-002 | 400 | `payload_hash` is not a valid 64-char hex string. |
| CROSS-003 | 400 | `delegation_chain` is empty or contains invalid entry. |
| CROSS-004 | 403 | No active federation between `source_institution_id` and `target_institution_id` (ITA-1.1 check failed). |
| CROSS-005 | 404 | `authorization_id` not found in source ledger. |
| CROSS-006 | 404 | `liability_record_id` not found in source ledger. |
| CROSS-007 | 409 | Interaction with `interaction_id` already successfully recorded (idempotent accept). |
| CROSS-008 | 422 | Bundle signature verification failed. |
| CROSS-009 | 422 | Individual event signature verification failed. |
| CROSS-010 | 503 | ITA federation registry unreachable (resolution failed). |
| CROSS-011 | 504 | `ack_required: true` but no `CrossOrgAck` received within single-attempt timeout (300s). |
| CROSS-012 | 503 | Retry limit exceeded (3 attempts). Escalation triggered. |
| CROSS-013 | 408 | `pending_review` SLA expired: no resolution within 24 hours of review_deadline. |
| CROSS-014 | 409 | Duplicate `interaction_id` with different `payload_hash` or `action_type` (payload tampering attempt). |
| CROSS-015 | 422 | Invalid ACK transition: `pending_review → pending_review` is prohibited. |

---

## 14. Conformance Requirements

A conformant ACP-CROSS-ORG-1.1 implementation:

**MUST:**
- Assign a UUIDv7 `interaction_id` at first emission and reuse it across all retries (CROSS-RULE-7)
- Emit `CROSS_ORG_INTERACTION` for every cross-institutional action per §5
- Follow all CROSS-RULE-1 through CROSS-RULE-13 emission rules
- Verify federation before emission (CROSS-RULE-6)
- Implement `POST /acp/v1/cross-org/receive` endpoint (§7.2)
- Perform all validation steps on incoming bundles (§7.3)
- Deduplicate incoming bundles by `interaction_id` (§7.3 step 6)
- Emit `CROSS_ORG_ACK` as a first-class LEDGER-1.3 event when `ack_required: true` (§7.4)
- Store `CROSS_ORG_INTERACTION` events in the target ledger upon successful receipt (§7.3 step 7)
- Implement the retry protocol: 3 attempts, backoff +30s/+60s/+120s (§8.2)
- Cancel retry timers upon receipt of a valid accepted/rejected ACK (CROSS-RULE-10)
- Implement `pending_review` SLA enforcement: 24h deadline (§8.4)
- Compute derived interaction status per §9 rules
- Support `interaction_id`, `cross_org_status`, and `event_type=CROSS_ORG_ACK` filter in HIST-1.0 query endpoint (§10)
- Return all error codes defined in §13 with the specified HTTP status codes

**SHOULD:**
- Include `evidence` block in CrossOrgBundle (§7.1)
- Implement `GET /acp/v1/audit/agents/{agent_id}/cross-org-history` (§10)
- Maintain observability metadata per `interaction_id` (§8.5)

**MAY:**
- Include ZKP `proof` field for compliance-sensitive interactions
- Define domain-specific `x:` ActionType extensions
- Implement rate limiting per institution pair (recommended: 1000 rpm per federation)

---

## 15. Dependencies

```
ACP-CROSS-ORG-1.1
├── ACP-LEDGER-1.3        (event envelope, hash chaining, CROSS_ORG_ACK §5.15)
├── ACP-ITA-1.1           (federation verification)
├── ACP-HIST-1.0          (query layer, ExportBundle)
├── ACP-LIA-1.0           (liability_record_id prerequisite)
└── ACP-SIGN-1.0          (Ed25519 signatures, AgentID derivation)
```
