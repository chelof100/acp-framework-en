# ACP-LIA-1.0
## Liability Traceability Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-EXEC-1.0, ACP-LEDGER-1.0, ACP-CT-1.0, ACP-PSN-1.0
**Required-by:** ACP-LEDGER-1.1, ACP-REP-1.2

---

## 1. Scope

This document defines the liability traceability mechanism within the ACP ecosystem. It specifies the structure of the `LIABILITY_RECORD` event, the rules for assigning `liability_assignee`, the process for constructing the delegation chain, and the query endpoints.

The objective is to materialize, for each consumed Execution Token (ET), an auditable record that allows regulators, auditors, and financial counterparties to deterministically identify who bears legal responsibility for each action executed by an autonomous agent.

---

## 2. Definitions

**LIABILITY_RECORD:** ACP event that materializes the delegation chain and the assigned responsible party for a specific execution. Emitted once per consumed ET.

**liability_assignee:** Agent or entity to whom legal responsibility for the execution is assigned. Determined by the rules defined in §6.

**delegation_chain:** Array ordered by `depth` ASC that reconstructs the complete delegation chain from the root token (institutional) to the executing agent.

**chain_incomplete:** Boolean indicator. `true` if the complete chain could not be reconstructed. Records audited degradation.

**Bankability:** Property of a system to be risk-modelable, auditable, predictable, and to have assignable accountability. The LIABILITY_RECORD is the technical instrument that enables bankability.

---

## 3. Principles

**3.1 One record per execution** — Exactly one `LIABILITY_RECORD` is emitted per ET consumed with a final result (`success`, `failure`, `unknown`).

**3.2 Immutability** — The LIABILITY_RECORD is append-only. Once emitted, it cannot be modified or deleted.

**3.3 Determinism** — Given the same ET and the same delegation tokens in the ledger, the produced LIABILITY_RECORD MUST be identical.

**3.4 Audited degradation** — If the chain cannot be fully reconstructed, the record is emitted regardless with `chain_incomplete: true`. The record is never omitted.

**3.5 PSN dependency** — Every LIABILITY_RECORD MUST reference the Policy Snapshot active at the time of execution via `policy_snapshot_ref`.

---

## 4. LIABILITY_RECORD Event Structure

```json
{
  "ver": "1.0",
  "event_id": "<uuid_v4>",
  "event_type": "LIABILITY_RECORD",
  "sequence": 1587,
  "timestamp": 1718920150,
  "institution_id": "org.example.banking",
  "prev_hash": "<SHA-256_base64url_of_previous_event>",
  "payload": {
    "liability_id": "<uuid_v4>",
    "et_id": "<uuid>",
    "authorization_id": "<uuid>",
    "agent_id": "<AgentID>",
    "capability": "acp:cap:financial.payment",
    "resource": "org.example/accounts/ACC-001",
    "delegation_chain": [
      {
        "depth": 0,
        "token_nonce": "<nonce_root>",
        "agent_id": "<AgentID_institution>",
        "issued_at": 1718900000
      },
      {
        "depth": 1,
        "token_nonce": "<nonce_1>",
        "agent_id": "<AgentID_supervisor>",
        "issued_at": 1718910000
      },
      {
        "depth": 2,
        "token_nonce": "<nonce_2>",
        "agent_id": "<AgentID_executor>",
        "issued_at": 1718920000
      }
    ],
    "delegation_depth": 2,
    "liability_assignee": "<AgentID>",
    "policy_snapshot_ref": "<uuid>",
    "execution_result": "success",
    "executed_at": 1718920150,
    "consumed_by_system": "org.example/systems/payment-processor",
    "chain_incomplete": false
  },
  "hash": "<SHA-256_base64url_of_this_event>",
  "sig": "<institutional_signature>"
}
```

---

## 5. Payload Field Specification

**5.1 `liability_id`** — Unique UUID v4 per record. Primary query key.

**5.2 `et_id`** — UUID of the consumed Execution Token. Direct reference to ACP-EXEC-1.0. MUST exist in the ledger as an `EXECUTION_TOKEN_CONSUMED` event.

**5.3 `authorization_id`** — UUID of the prior `AUTHORIZATION` event that authorized the execution. MUST exist in the ledger.

**5.4 `agent_id`** — AgentID of the agent that executed the action. Corresponds to the agent at maximum `depth` in `delegation_chain`.

**5.5 `capability`** — Capability exercised. Format `acp:cap:<domain>.<action>`. Derived from the referenced ET.

**5.6 `resource`** — Resource the agent acted upon. Derived from the referenced ET.

**5.7 `delegation_chain`** — Array of objects ordered by `depth` ASC:
- `depth`: Integer ≥ 0. `depth 0` = institutional root token.
- `token_nonce`: Nonce of the delegation token at that level.
- `agent_id`: AgentID of the agent that issued the token at that level.
- `issued_at`: Unix timestamp of token issuance.

Array length MUST equal `delegation_depth + 1`.

**5.8 `delegation_depth`** — Integer ≥ 0. Depth of the executing agent in the chain. `0` = direct institutional action.

**5.9 `liability_assignee`** — AgentID of the assigned responsible party. Determined by the rules in §6.

**5.10 `policy_snapshot_ref`** — UUID of the Policy Snapshot (ACP-PSN-1.0) active at `executed_at`. MUST correspond to a snapshot with `effective_from ≤ executed_at` and `effective_until = null` or `effective_until > executed_at`.

**5.11 `execution_result`** — Enum: `success` | `failure` | `unknown`. `unknown` is used when the result could not be determined before the ET timeout.

**5.12 `executed_at`** — Unix timestamp of execution. Taken from the referenced `EXECUTION_TOKEN_CONSUMED` event.

**5.13 `consumed_by_system`** — Identifier of the external system that consumed the ET. Taken from the corresponding field in `EXECUTION_TOKEN_CONSUMED`.

**5.14 `chain_incomplete`** — Boolean. `false` by default. `true` if any token in the chain could not be retrieved from the ledger. When `true`, `delegation_chain` may be partial.

---

## 6. liability_assignee Assignment Rules

Rules are evaluated in order. The first matching rule applies.

**Rule 1 — Human-resolved escalation:**
```
IF ESCALATION_RESOLVED event exists for this et_id
AND ESCALATION_RESOLVED.resolver_type == "human"
THEN liability_assignee = ESCALATION_RESOLVED.resolver_agent_id
```

**Rule 2 — Autonomy level < 2:**
```
IF delegation_chain[delegation_depth - 1].agent_id is an identifiable supervisor
AND executing agent's autonomy_level < 2
THEN liability_assignee = delegation_chain[delegation_depth - 1].agent_id
```
*(The immediate supervisor assumes responsibility when the executor operates with restricted autonomy)*

**Rule 3 — Default (autonomous executor):**
```
ELSE liability_assignee = agent_id  (the executing agent)
```

**Note:** When `chain_incomplete: true`, if the supervisor cannot be determined from the truncated chain, Rule 3 applies.

---

## 7. delegation_chain Construction Rules

**7.1 Data source** — The chain is constructed exclusively from events in the Audit Ledger (ACP-LEDGER-1.0). No external input is accepted for construction.

**7.2 Construction order** — The delegation tree is traversed backwards from the ET, following `parent_token_nonce` references until the root token (`depth 0`) is reached.

**7.3 Root token** — The token at `depth 0` MUST be issued by the institution (`institution_id`). If an institutional token is not reached, `chain_incomplete` MUST be `true`.

**7.4 AgentID consistency** — The `agent_id` in `delegation_chain[depth_max]` MUST match the `agent_id` field of the LIABILITY_RECORD.

**7.5 Timestamps** — `issued_at` in `delegation_chain` MUST be monotonically increasing with `depth`. A child token cannot have been issued before its parent.

---

## 8. Emission Process

**8.1 Trigger** — The LIABILITY_RECORD is emitted upon detecting the `EXECUTION_TOKEN_CONSUMED` event in the ledger with `status = final`.

**8.2 Sequence:**
1. Read `EXECUTION_TOKEN_CONSUMED` event for the `et_id`.
2. Read the `AUTHORIZATION` event referenced by the ET.
3. Reconstruct `delegation_chain` from the ledger (§7).
4. Obtain the active Policy Snapshot at `executed_at` from ACP-PSN-1.0.
5. Apply §6 rules to determine `liability_assignee`.
6. Build the LIABILITY_RECORD payload.
7. Compute `hash` = `base64url(SHA-256(JCS(event without hash and sig)))`.
8. Sign with institutional key → `sig` field.
9. Write event to ledger (append-only).

**8.3 Atomicity** — Steps 7–9 MUST be atomic. If the write fails, the process retries with the same `liability_id` (idempotent by `liability_id`).

**8.4 Maximum latency** — The LIABILITY_RECORD SHOULD be emitted within 5 seconds of the trigger. High-load implementations MAY use up to 30 seconds.

---

## 9. Endpoints

### 9.1 `GET /acp/v1/liability/{liability_id}`

Retrieves a LIABILITY_RECORD by its unique identifier.

**Response 200:**
```json
{
  "liability_id": "<uuid>",
  "et_id": "<uuid>",
  "authorization_id": "<uuid>",
  "agent_id": "<AgentID>",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "delegation_chain": [...],
  "delegation_depth": 2,
  "liability_assignee": "<AgentID>",
  "policy_snapshot_ref": "<uuid>",
  "execution_result": "success",
  "executed_at": 1718920150,
  "consumed_by_system": "org.example/systems/payment-processor",
  "chain_incomplete": false,
  "ledger_event_id": "<uuid>",
  "ledger_sequence": 1587
}
```

**Response 404:** `LIA-001`

---

### 9.2 `GET /acp/v1/liability/by-et/{et_id}`

Retrieves the LIABILITY_RECORD associated with a specific ET.

**Response 200:** Same schema as §9.1.
**Response 404:** `LIA-001` if the ET has no LIABILITY_RECORD yet.
**Response 202:** If the ET was consumed but the LIABILITY_RECORD has not yet been emitted (`LIA-007` state).

---

### 9.3 `GET /acp/v1/liability/by-agent/{agent_id}`

Lists LIABILITY_RECORDs where `agent_id` or `liability_assignee` match the given agent.

**Query params:**
- `role`: `executor` | `assignee` | `any` (default: `any`)
- `from`: Unix timestamp start (default: 0)
- `to`: Unix timestamp end (default: now)
- `limit`: Max records (default: 100, max: 1000)
- `cursor`: Opaque pagination cursor

**Response 200:**
```json
{
  "items": [...],
  "next_cursor": "<opaque>",
  "total_count": 47
}
```

---

## 10. External Verification

**10.1 Audit flow** — An external auditor can verify a LIABILITY_RECORD as follows:

1. Retrieve the LIABILITY_RECORD via `GET /acp/v1/liability/{liability_id}`.
2. Verify that `ledger_event_id` exists in the ledger and corresponds to the LIABILITY_RECORD.
3. Verify ledger integrity from genesis to the event (ACP-LEDGER-1.0 §8).
4. Verify the institutional signature `sig` on the event.
5. Verify that `policy_snapshot_ref` corresponds to a valid Policy Snapshot active at `executed_at` (ACP-PSN-1.0 §10).
6. Verify that `delegation_chain` is consistent with the tokens in the ledger.
7. Re-apply §6 rules to confirm `liability_assignee`.

**10.2 Regulatory export** — Implementations MAY provide an export endpoint that returns the LIABILITY_RECORD together with all ledger events required for independent verification (AUTHORIZATION, EXECUTION_TOKEN_CONSUMED, relevant delegation tokens).

---

## 11. Anomalous Behavior

**11.1 ET consumed without prior AUTHORIZATION** — `chain_incomplete: true`, `authorization_id: null`, `liability_assignee` = Rule 3 (executor). Record is emitted regardless.

**11.2 Policy Snapshot unavailable** — Error `LIA-003`. The emission process MUST retry. No LIABILITY_RECORD is emitted with `policy_snapshot_ref: null`.

**11.3 Cycle in delegation_chain** — If a cycle is detected, construction stops, `chain_incomplete: true`, and the level where the cycle was detected is not included.

**11.4 Construction timeout** — If `delegation_chain` construction exceeds 10 seconds, the record is emitted with the partial chain available and `chain_incomplete: true`.

---

## 12. Error Codes

| Code | Condition |
|---|---|
| `LIA-001` | LIABILITY_RECORD not found for the given identifier |
| `LIA-002` | delegation_chain not reconstructible: insufficient tokens in ledger |
| `LIA-003` | Policy Snapshot unavailable for the given `executed_at` |
| `LIA-004` | ET not found in ledger |
| `LIA-005` | AUTHORIZATION event not found for the referenced ET |
| `LIA-006` | Ledger write failure during LIABILITY_RECORD emission |
| `LIA-007` | LIABILITY_RECORD in transitional state: ET consumed, emission in progress |
| `LIA-008` | Duplicate liability_id: a LIABILITY_RECORD already exists for this et_id |

---

## 13. Conformance

An implementation conforms to ACP-LIA-1.0 if it:

1. Emits exactly one `LIABILITY_RECORD` per ET consumed with a final result.
2. Constructs `delegation_chain` exclusively from Audit Ledger data.
3. Applies the §6 assignment rules in the specified order.
4. Includes a valid `policy_snapshot_ref` in every LIABILITY_RECORD.
5. Persists the event as an append-only entry in the Audit Ledger (ACP-LEDGER-1.0).
6. Exposes the three endpoints in §9 with the specified schemas.
7. Emits the event with `chain_incomplete: true` when the chain is not reconstructible (never omits the record).
8. Guarantees idempotency by `liability_id` during emission.
