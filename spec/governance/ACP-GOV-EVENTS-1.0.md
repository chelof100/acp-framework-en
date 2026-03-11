# ACP-GOV-EVENTS-1.0
## Governance Event Stream Specification

**Status:** Draft
**Version:** 1.0
**Type:** Governance Protocol Specification
**Depends-on:** ACP-SIGN-1.0, ACP-LEDGER-1.2, ACP-REV-1.0, ACP-HIST-1.0
**Required-by:** ACP-CONF-1.1 (L4-EXTENDED)

> This specification is **normative**. It defines the canonical taxonomy and structure of ACP governance events — institutional events that change the authority, status, or policy context of agents. Implementations claiming L4-EXTENDED conformance MUST emit governance events using the types and structure defined here.

---

## 1. Scope

This document defines:

1. The **Governance Event** object — the canonical structure for all institutional governance events.
2. The **official event type taxonomy** — 10 normative event types with formal semantics.
3. **Emission rules** — which system actors MUST produce each event and when.
4. **Stream semantics** — ordering guarantees, deduplication, and cross-institutional delivery.
5. **Query interface** — how governance events are accessed via ACP-HIST-1.0.

### Relationship to existing specs

| Spec | Governs | Governance Events adds |
|------|---------|----------------------|
| ACP-REV-1.0 | Revocation protocol | `delegation_revoked`, `capability_suspended` event types |
| ACP-HIST-1.0 | Ledger query access | Governance event filters and stream endpoint |
| ACP-LEDGER-1.2 | Storage structure | `GOVERNANCE` event category |
| ACP-REP-1.2 | Reputation scoring | `sanction_applied`, `agent_suspended` as reputation inputs |

Governance events are emitted *by* the above mechanisms and form a unified stream that consumers (MIR, ARAF, external auditors) can subscribe to.

---

## 2. Motivation

ACP defines strong execution-time governance. However, the system also generates institutional events that change the authority landscape between executions — delegations are revoked, agents are suspended, policies are updated. These events:

1. Are currently scattered across ACP-REV-1.0, ACP-DCMA-1.0, and implementation-specific logs.
2. Have no canonical format that external systems (MIR, ARAF) can reliably consume.
3. Lack formal semantics — the same concept may be recorded differently by different institutions.

This specification creates the **Governance Event Stream**: a formally typed, signed, ordered record of every change to the authority state of the ACP ecosystem.

---

## 3. Definitions

**Governance event:** A signed record of an institutional action that changes the authority, status, or policy context of one or more agents.

**Stream:** The ordered, append-only sequence of all governance events within an institutional boundary.

**Event producer:** The system component (ACP server, compliance runner, policy engine) that MUST emit a governance event in response to an institutional action.

**Event consumer:** An external system (MIR, ARAF, auditor) that subscribes to the governance event stream.

**Evidence reference:** A pointer to an existing ACP ledger entry that provides cryptographic evidence for the event.

---

## 4. Governance Event Object

### 4.1 Top-level structure

```json
{
  "ver": "1.0",
  "event_id": "<uuid_v4>",
  "event_type": "<GOVERNANCE_EVENT_TYPE>",
  "institution_id": "<institution_id>",
  "agent_id": "<AgentID or null>",
  "triggered_by": "<AgentID or institution_id>",
  "timestamp": "<unix_seconds>",
  "effective_at": "<unix_seconds>",
  "reason": "<string>",
  "evidence_ref": "<ledger_entry_id or null>",
  "payload": { },
  "sig": "<base64url Ed25519 signature>"
}
```

### 4.2 Field definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | MUST | Always `"1.0"` |
| `event_id` | UUID v4 | MUST | Unique identifier for this event |
| `event_type` | string | MUST | One of the 10 normative types defined in §5 |
| `institution_id` | string | MUST | Institution emitting the event |
| `agent_id` | string | MUST if event targets an agent, otherwise `null` | AgentID of the affected agent |
| `triggered_by` | string | MUST | AgentID or institution_id that caused the event |
| `timestamp` | integer | MUST | Unix seconds. Time the event was recorded |
| `effective_at` | integer | MUST | Unix seconds. Time the governance change takes effect. MAY equal `timestamp` |
| `reason` | string | MUST | Human-readable reason for the event |
| `evidence_ref` | string | SHOULD | Ledger entry ID that provides evidence (e.g. the ledger entry of the policy violation) |
| `payload` | object | MUST | Event-type-specific fields (see §5) |
| `sig` | string | MUST | Base64url Ed25519 institutional signature |

---

## 5. Normative Event Type Taxonomy

### 5.1 `delegation_revoked`

**Trigger:** A delegation issued under ACP-DCMA-1.0 is revoked before its natural expiry.

**Producer:** ACP revocation subsystem (ACP-REV-1.0).

**Payload:**
```json
{
  "delegation_id": "<DEL-XXXX>",
  "delegator": "<AgentID>",
  "delegatee": "<AgentID>",
  "capability_affected": "<ACP capability string>",
  "revocation_id": "<REV-XXXX>"
}
```

**Downstream effects:** All execution tokens derived from this delegation that have not been consumed MUST be invalidated. The ACP server MUST reject any ET presentation referencing the revoked delegation.

---

### 5.2 `agent_suspended`

**Trigger:** An agent is administratively suspended by an institution. All active capabilities and delegations of the agent are frozen.

**Producer:** ACP administrative subsystem.

**Payload:**
```json
{
  "suspension_id": "<SUSP-XXXX>",
  "suspended_until": "<unix_seconds or null>",
  "capabilities_frozen": ["<ACP capability string>", ...],
  "active_delegations_frozen": ["<DEL-XXXX>", ...]
}
```

**Downstream effects:** The agent cannot initiate new requests or receive new delegations until reinstated. Existing unconsumed ETs MUST be invalidated. `suspended_until: null` means indefinite suspension.

---

### 5.3 `agent_reinstated`

**Trigger:** A suspended agent is restored to active status.

**Producer:** ACP administrative subsystem.

**Payload:**
```json
{
  "suspension_id": "<SUSP-XXXX matching original suspension>",
  "reinstated_by": "<AgentID or institution_id>",
  "capabilities_restored": ["<ACP capability string>", ...]
}
```

**Note:** Reinstated agents do not automatically recover revoked delegations. Each revoked delegation requires a new delegation under ACP-DCMA-1.0.

---

### 5.4 `policy_updated`

**Trigger:** An institutional policy governing ACP decisions is updated. Produces a new `policy_version`.

**Producer:** Policy management subsystem.

**Payload:**
```json
{
  "policy_id": "<string>",
  "previous_version": "<string>",
  "new_version": "<string>",
  "new_policy_hash": "<sha256_hex>",
  "breaking_change": "<boolean>",
  "affected_capabilities": ["<ACP capability string>", ...]
}
```

**Note:** `breaking_change: true` indicates that existing authorized executions may be affected. All `PolicyContextSnapshot` objects with `policy_version == previous_version` remain valid for the actions they already authorized — they are NOT retroactively invalidated.

---

### 5.5 `authority_transferred`

**Trigger:** The authority over an agent (ownership or supervision rights) is transferred from one institution or principal to another.

**Producer:** ACP institutional management subsystem.

**Payload:**
```json
{
  "transfer_id": "<XFER-XXXX>",
  "from_institution": "<institution_id>",
  "to_institution": "<institution_id>",
  "transferred_capabilities": ["<ACP capability string>", ...],
  "acceptance_ref": "<ledger_entry_id of acceptance proof>"
}
```

**Security note:** An `authority_transferred` event MUST include a verifiable acceptance proof from the receiving institution. Unilateral transfers are invalid.

---

### 5.6 `sanction_applied`

**Trigger:** A formal sanction is applied to an agent or institution as a result of a compliance violation, audit finding, or legal order.

**Producer:** ACP compliance subsystem or institutional authority.

**Payload:**
```json
{
  "sanction_id": "<SANC-XXXX>",
  "sanction_type": "capability_restriction | delegation_limit | audit_escalation | full_suspension",
  "scope": "<AgentID or institution_id>",
  "violation_ref": "<ledger_entry_id>",
  "duration": "<unix_seconds or null>",
  "external_order_ref": "<string or null>"
}
```

**Note:** `external_order_ref` allows referencing an external legal or regulatory order (e.g. court order reference number). This field enables ACP to serve as evidence infrastructure in legal proceedings.

---

### 5.7 `capability_suspended`

**Trigger:** A specific ACP capability is suspended for an agent, without suspending the agent itself. The agent may continue to use other capabilities.

**Producer:** ACP revocation subsystem.

**Payload:**
```json
{
  "capability": "<ACP capability string>",
  "suspended_until": "<unix_seconds or null>",
  "reason_code": "<string>"
}
```

---

### 5.8 `capability_reinstated`

**Trigger:** A previously suspended specific capability is restored for an agent.

**Producer:** ACP revocation subsystem.

**Payload:**
```json
{
  "capability": "<ACP capability string>",
  "reinstated_by": "<AgentID or institution_id>"
}
```

---

### 5.9 `trust_anchor_rotated`

**Trigger:** An institutional trust anchor (ACP-ITA-1.0/1.1) rotates its key material. All consumers of the public key must update their trust store.

**Producer:** ACP institutional key management subsystem.

**Payload:**
```json
{
  "old_key_id": "<key_id>",
  "new_key_id": "<key_id>",
  "rotation_type": "scheduled | emergency",
  "overlap_period": "<seconds>",
  "new_public_key": "<base64url Ed25519 public key>"
}
```

**Note:** During `overlap_period`, both old and new keys are valid. This allows existing ETs signed under the old key to be consumed without error.

---

### 5.10 `compliance_finding`

**Trigger:** A compliance check (ACR-1.0) or audit produces a finding against an agent or institution that requires governance action.

**Producer:** ACP compliance runner (ACR-1.0) or external auditor.

**Payload:**
```json
{
  "finding_id": "<FIND-XXXX>",
  "severity": "critical | major | minor",
  "finding_type": "<string>",
  "affected_spec": "<ACP-SPEC-VERSION>",
  "remediation_required": "<boolean>",
  "remediation_deadline": "<unix_seconds or null>",
  "evidence_refs": ["<ledger_entry_id>", ...]
}
```

---

## 6. Stream Semantics

### 6.1 Ordering guarantee

Within a single institution, governance events MUST be ordered by `timestamp` and assigned a monotonically increasing `sequence` number. Events with the same `timestamp` are ordered by `event_id` (lexicographic).

### 6.2 Deduplication

Each `event_id` is globally unique. A consumer receiving a duplicate `event_id` MUST discard the duplicate and log a warning.

### 6.3 Cross-institutional delivery

When a governance event in institution A affects an agent or delegation that spans institution B, the event MUST be forwarded to institution B's stream as a `CROSS_ORG` tagged copy (ACP-CROSS-ORG-1.0). The receiving institution MAY reject cross-institutional governance events that do not include a valid `sig` from the originating institution.

---

## 7. Query Interface (via ACP-HIST-1.0)

Governance events are accessible via the standard ACP-HIST-1.0 query endpoint with `event_type` filters from the taxonomy defined in §5.

### Additional governance-specific filters

| Filter | Description |
|--------|-------------|
| `event_category=governance` | Returns only governance events |
| `severity=critical\|major\|minor` | Filters `compliance_finding` events by severity |
| `breaking_change=true` | Returns only `policy_updated` events with `breaking_change: true` |
| `sanction_type=<type>` | Filters `sanction_applied` by type |

### Stream subscription endpoint

```
GET /acp/v1/governance/stream
```

Parameters:
- `since=<unix_seconds>` — return events after this timestamp
- `types=<comma-separated event types>` — filter by type
- `agent_id=<AgentID>` — filter by affected agent

Response: newline-delimited JSON, one `GovernanceEvent` per line, ordered by `sequence`.

---

## 8. Conformance

| Conformance Level | Requirement |
|-------------------|-------------|
| L1-CORE | MAY omit governance event emission entirely |
| L2-SECURITY | MUST emit `delegation_revoked` and `trust_anchor_rotated` |
| L3-FULL | MUST emit all revocation and suspension types (5.1, 5.2, 5.3, 5.7, 5.8) |
| L4-EXTENDED | MUST emit all 10 event types and expose stream endpoint |
| L5-DECENTRALIZED | MUST emit all 10 types via decentralized event bus with cryptographic ordering |

---

## 9. Ecosystem Consumption

### MIR (Participation History Layer)
Consumes: `delegation_revoked`, `agent_suspended`, `agent_reinstated`, `authority_transferred`
Purpose: Build verifiable participation history for agents across institutions.

### ARAF (Risk Architecture Layer)
Consumes: `sanction_applied`, `compliance_finding`, `policy_updated`, `agent_suspended`
Purpose: Feed governance signals into risk scoring and liability models.

### External auditors
Consumes: all types via ExportBundle (ACP-HIST-1.0)
Purpose: Third-party compliance verification and legal proceedings.

---

## 10. Error Codes

| Code | Meaning |
|------|---------|
| `GEVE-001` | Unknown event type |
| `GEVE-002` | Institutional signature invalid |
| `GEVE-003` | Required payload field missing for event type |
| `GEVE-004` | `effective_at` before `timestamp` |
| `GEVE-005` | `evidence_ref` references nonexistent ledger entry |
| `GEVE-006` | Duplicate `event_id` received |
| `GEVE-007` | Cross-institutional event missing originating signature |

---

## 11. Normative References

- ACP-SIGN-1.0 — Serialization and signing
- ACP-LEDGER-1.2 — Audit ledger storage
- ACP-REV-1.0 — Revocation protocol (source of revocation events)
- ACP-HIST-1.0 — History query API (stream access)
- ACP-DCMA-1.0 — Delegation model (source of delegation events)
- ACP-ITA-1.0, ACP-ITA-1.1 — Trust anchor management (source of rotation events)
- ACP-REP-1.2 — Reputation protocol (consumer of sanction and suspension events)
- ACP-CROSS-ORG-1.0 — Cross-organizational operations (stream forwarding)
- ACP-CONF-1.1 — Conformance levels
- ACR-1.0 — ACP Compliance Runner (source of compliance findings)
