# ACP-HIST-1.0
## History Query API Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-LEDGER-1.1, ACP-ITA-1.0, ACP-SIGN-1.0
**Required-by:** ACP-REP-1.2 (historical event query for ERS)

---

## 1. Scope

This document defines the query layer over the ACP Audit Ledger. It specifies filtered and paginated endpoints for programmatic access to event history, the portable export format for sharing audit trail segments between institutions, and the integrity contract that every response must include.

ACP-LEDGER-1.1 defines structure and storage. ACP-HIST-1.0 defines access.

---

## 2. Definitions

**HistoryQuery:** A filtered request for ledger events with pagination and scope parameters.

**Cursor:** An opaque token representing the pagination position. Encapsulates the `sequence` of the last returned event.

**ExportBundle:** A signed, self-verifiable collection of ledger events designed to be shared between institutions as a portable audit unit.

**chain_valid:** A boolean field present in every response indicating whether the hash chain of the returned segment was verified by the responding server.

**Verifiable segment:** A contiguous subset of the ledger that includes sufficient information to verify its integrity independently.

---

## 3. Authorization Model

Queries require standard ACP authentication per ACP-API-1.0.

| Role | Scope |
|------|-------|
| `SYSTEM` | May query all events from their institution |
| `SUPERVISOR` | May query events from agents under their supervision |
| `AGENT` | May query only their own events |
| `EXTERNAL_AUDITOR` | May query events explicitly shared via ExportBundle |

Cross-institutional queries (institution B querying institution A's events) MUST be performed via ExportBundle signed by institution A, not via direct access to A's ledger.

---

## 4. Main Endpoint — `GET /acp/v1/audit/query`

Paginated, filtered query of the institutional ledger.

### Query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string (multi) | Filter by event type. Accepts multiple comma-separated values |
| `agent_id` | string | Filter by AgentID (exact match) |
| `institution_id` | string | Filter by event-issuing institution |
| `capability` | string | Filter by ACP capability (prefix allowed: `acp:cap:financial.*`) |
| `resource` | string | Filter by resource (exact match) |
| `decision` | string | Filter by decision: `APPROVED`, `DENIED`, `ESCALATED` (only in AUTHORIZATION and ESCALATION_RESOLVED events) |
| `from_ts` | int64 | UNIX timestamp range start (inclusive) |
| `to_ts` | int64 | UNIX timestamp range end (inclusive) |
| `from_seq` | int64 | Minimum sequence (inclusive). Alternative to `from_ts` |
| `to_seq` | int64 | Maximum sequence (inclusive). Alternative to `to_ts` |
| `cursor` | string | Pagination token from previous response |
| `limit` | int | Maximum events to return. Default: 20. Maximum: 100 |
| `verify_chain` | bool | If `true`, server verifies chain integrity before responding. Default: `false` |

`from_ts`/`to_ts` and `from_seq`/`to_seq` cannot be combined in the same request.

### Response 200

```json
{
  "ver": "1.0",
  "institution_id": "org.example.banking",
  "events": [
    {
      "ver": "1.0",
      "event_id": "<uuid>",
      "event_type": "AUTHORIZATION",
      "sequence": 1547,
      "timestamp": 1718920000,
      "institution_id": "org.example.banking",
      "prev_hash": "<sha256_base64url>",
      "payload": {},
      "hash": "<sha256_base64url>",
      "sig": "<institutional_signature>"
    }
  ],
  "pagination": {
    "cursor": "<opaque_base64url_cursor>",
    "has_more": true,
    "returned_count": 20,
    "total_count": null
  },
  "integrity": {
    "chain_valid": true,
    "verified_from_seq": 1547,
    "verified_to_seq": 1566,
    "policy_context": "v1.1"
  }
}
```

`total_count` is always `null` — the ledger is append-only and exact counting requires a full scan. Clients MUST NOT assume `null` means zero.

`policy_context` is `"v1.1"` if all events in the segment include `policy_snapshot_ref`. If some don't, it is `"mixed"`. If none do, it is `"legacy"`.

`chain_valid` is `null` when `verify_chain` was `false`. It is `true` or `false` when `verify_chain` was `true`.

### Cursor

The cursor is `base64url(JSON({seq: N, ts: T}))` where N is the sequence of the last returned event and T is its timestamp. It is opaque to the client — its internal format MUST NOT be relied upon by client implementations.

The cursor expires after 24 hours. An expired cursor returns HIST-E005.

### Errors

| Code | HTTP | Condition |
|------|------|-----------|
| HIST-E001 | 400 | Invalid or incompatible filter parameters |
| HIST-E002 | 400 | `limit` out of range (< 1 or > 100) |
| HIST-E003 | 400 | Simultaneous `ts` and `seq` combination |
| HIST-E004 | 403 | Insufficient role for requested scope |
| HIST-E005 | 400 | Expired or invalid cursor |
| HIST-E006 | 500 | Chain verification failure during `verify_chain: true` |

---

## 5. Single Event Endpoint — `GET /acp/v1/audit/events/{event_id}`

Returns a single event by its `event_id` (UUID v4).

### Response 200

```json
{
  "ver": "1.0",
  "event": {
    "ver": "1.0",
    "event_id": "<uuid>",
    "event_type": "LIABILITY_RECORD",
    "sequence": 1548,
    "timestamp": 1718920010,
    "institution_id": "org.example.banking",
    "prev_hash": "<sha256_base64url>",
    "payload": {},
    "hash": "<sha256_base64url>",
    "sig": "<institutional_signature>"
  },
  "integrity": {
    "hash_valid": true,
    "sig_valid": true
  }
}
```

`hash_valid` and `sig_valid` are always verified in this endpoint (no toggle).

### Errors

| Code | HTTP | Condition |
|------|------|-----------|
| HIST-E010 | 404 | `event_id` not found |
| HIST-E011 | 403 | No permission to view this event |

---

## 6. Agent History Endpoint — `GET /acp/v1/audit/agents/{agent_id}/history`

Consolidated view of a specific agent's activity. Returns only event types relevant to the agent's trajectory.

### Query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `from_ts` | int64 | Start timestamp |
| `to_ts` | int64 | End timestamp |
| `cursor` | string | Pagination token |
| `limit` | int | Default: 20. Maximum: 100 |
| `include_types` | string (multi) | Subset of event types to include. Default: all agent-relevant types |

### Event types included by default

`AUTHORIZATION`, `RISK_EVALUATION`, `REVOCATION`, `TOKEN_ISSUED`, `EXECUTION_TOKEN_ISSUED`, `EXECUTION_TOKEN_CONSUMED`, `LIABILITY_RECORD`, `REPUTATION_UPDATED`, `AGENT_STATE_CHANGE`, `ESCALATION_CREATED`, `ESCALATION_RESOLVED`

### Response 200

```json
{
  "ver": "1.0",
  "agent_id": "<AgentID>",
  "institution_id": "org.example.banking",
  "events": [],
  "summary": {
    "total_authorizations": 142,
    "approved": 138,
    "denied": 3,
    "escalated": 1,
    "executions_successful": 135,
    "executions_failed": 3,
    "current_rep_score": 82,
    "first_event_ts": 1710000000,
    "last_event_ts": 1718920000
  },
  "pagination": {
    "cursor": "<opaque_cursor>",
    "has_more": false,
    "returned_count": 142
  },
  "integrity": {
    "chain_valid": null
  }
}
```

`summary` reflects the calculated state at query time across all agent events, not only those returned in the current page.

---

## 7. Portable Export — `POST /acp/v1/audit/export`

Generates a signed ExportBundle: a self-verifiable ledger segment designed to be shared with third parties (external institutions, auditors, regulators).

### Request body

```json
{
  "scope": {
    "from_ts": 1718000000,
    "to_ts": 1718999999,
    "agent_id": "<optional_AgentID>",
    "event_types": ["AUTHORIZATION", "LIABILITY_RECORD", "REPUTATION_UPDATED"]
  },
  "format": "full | hashes_only",
  "include_anchor": true,
  "ttl_seconds": 86400
}
```

`format`:
- `full` — complete events with payload, hash, and sig
- `hashes_only` — only `event_id`, `sequence`, `hash`, and `sig` per event (for verification without payload exposure)

`include_anchor` — if `true`, includes the event immediately before the range to anchor chain verification without requiring the complete ledger.

`ttl_seconds` — bundle validity period. Default: 86400 (24h). Maximum: 604800 (7 days).

### Response 200 — ExportBundle

```json
{
  "ver": "1.0",
  "bundle_id": "<uuid>",
  "issuer": "org.example.banking",
  "issued_at": 1718920000,
  "expires_at": 1719006400,
  "scope": {
    "from_ts": 1718000000,
    "to_ts": 1718999999,
    "agent_id": "<AgentID>",
    "event_types": ["AUTHORIZATION", "LIABILITY_RECORD", "REPUTATION_UPDATED"]
  },
  "format": "full",
  "anchor_event": {
    "event_id": "<uuid>",
    "sequence": 1540,
    "hash": "<sha256_base64url>"
  },
  "events": [],
  "event_count": 28,
  "chain_valid": true,
  "bundle_hash": "<sha256_base64url_of_bundle_without_bundle_sig>",
  "bundle_sig": "<institutional_signature_over_bundle_hash>"
}
```

`bundle_sig` is `base64url(Sign(institutional_sk, SHA-256(JCS(bundle without bundle_sig))))`.

### ExportBundle verification by the recipient

```
1. Obtain issuer pk via ACP-ITA-1.0: GET /ita/v1/institutions/{issuer}
2. Verify bundle_sig with issuer pk
3. Verify bundle.expires_at > now()
4. Verify chain from anchor_event:
   a. first event: E.prev_hash MUST match anchor_event.hash
   b. verify internal chain per ACP-LEDGER-1.1 §7
5. Verify individual sig of each event with issuer pk
```

A recipient can verify the bundle without access to the issuer's original ledger.

### Errors

| Code | HTTP | Condition |
|------|------|-----------|
| HIST-E020 | 400 | Invalid export range (`from_ts` ≥ `to_ts`) |
| HIST-E021 | 400 | `ttl_seconds` out of range |
| HIST-E022 | 403 | Insufficient role to export |
| HIST-E023 | 422 | Scope produces zero events — empty bundle not allowed |
| HIST-E024 | 500 | Error signing institutional bundle |

---

## 8. Interaction with ACP-REP-1.2

The ACP-REP-1.2 ERS engine queries `REPUTATION_UPDATED` events from the ledger using `GET /acp/v1/audit/query` with `event_type=REPUTATION_UPDATED&agent_id={id}`. The response format defined in this document is the contract that ACP-REP-1.2 consumes.

For cross-institutional reputation, the destination institution may request an ExportBundle filtered by `event_types=["REPUTATION_UPDATED","LIABILITY_RECORD"]` from the origin institution as evidence to bootstrap external ERS.

---

## 9. Retention and Coverage

Queries cover all events within ACP-LEDGER-1.1's active retention period (90 days in hot storage). Events archived in cold storage (between 90 days and 7 years) SHOULD be available with additional latency declared in the `X-ACP-Archive-Latency-Seconds` header.

If a queried segment includes archived events, the response includes:

```json
"integrity": {
  "chain_valid": true,
  "archive_segments": true,
  "archive_retrieval_latency_seconds": 3600
}
```

---

## 10. General Errors

| Code | HTTP | Condition |
|------|------|-----------|
| HIST-E030 | 401 | No valid ACP authentication |
| HIST-E031 | 429 | Rate limit exceeded |
| HIST-E032 | 503 | Ledger temporarily unavailable |

Default rate limit: 60 rpm per caller for `/audit/query` and `/audit/agents/*/history`. 10 rpm for `/audit/export`.

---

## 11. Conformance

An implementation is ACP-HIST-1.0 conformant if it:

- Exposes `GET /acp/v1/audit/query` with all parameters from §4
- Implements cursor-based pagination with 24h expiration
- Returns `chain_valid` in all responses when `verify_chain: true`
- Exposes `GET /acp/v1/audit/events/{event_id}` with hash and sig verification
- Exposes `GET /acp/v1/audit/agents/{agent_id}/history` with computed summary
- Exposes `POST /acp/v1/audit/export` generating independently-verifiable signed ExportBundle
- Implements role-based authorization model from §3
- Respects rate limits from §10
- Supports archived event coverage per §9
