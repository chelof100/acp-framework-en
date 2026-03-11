# ACP-API-1.0
## HTTP API Formal Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-HP-1.0, ACP-RISK-1.0, ACP-REV-1.0, ACP-CAP-REG-1.0
**Required-by:** ACP-EXEC-1.0, ACP-LEDGER-1.2

---

## 1. Scope

This document specifies the complete HTTP API of the ACP system: endpoints, request/response schemas, status codes, error contracts, authentication, and behavior under anomalous conditions.

---

## 2. General Principles

**2.1 Base protocol**
HTTPS mandatory. HTTP without TLS MUST NOT be accepted outside of explicit local development. Minimum TLS: 1.2. TLS 1.3 SHOULD be used in B2B environments.

**2.2 Format**
All bodies MUST be JSON. Header `Content-Type: application/json` MUST be present in requests with a body.

**2.3 Authentication**
Every endpoint except `/acp/v1/health` and `POST /acp/v1/handshake/challenge` MUST require two headers:
```http
Authorization: ACP-Agent <base64url_encoded_capability_token>
X-ACP-PoP: <base64url_encoded_pop_token>
```
The server MUST verify the Proof-of-Possession per ACP-HP-1.0 §10 before validating the CT. If the PoP fails, the CT is not processed. Only after the PoP is valid does CT validation proceed per ACP-CT-1.0 §6.

**2.4 Request ID**
Every request MUST include:
```http
X-ACP-Request-ID: <uuid>
```
The server MUST include this value in the response.

**2.5 Versioning**
The server MUST include in every response:
```http
X-ACP-Version: 1.0
```

**2.6 Timestamps**
JSON bodies: Unix timestamp in seconds. Headers: RFC 7231.

---

## 3. Base Response Structure

**Successful response:**
```json
{
  "acp_version": "1.0",
  "request_id": "<uuid>",
  "timestamp": 1718920000,
  "data": {},
  "sig": "<base64url_institutional_signature>"
}
```

The `sig` field MUST cover: `acp_version`, `request_id`, `timestamp`, `data`. Per ACP-SIGN-1.0.

**Error response:**
```json
{
  "acp_version": "1.0",
  "request_id": "<uuid>",
  "timestamp": 1718920000,
  "error": {
    "code": "<ACP_code>",
    "message": "<description>",
    "detail": {}
  }
}
```

Error responses MUST NOT include a `sig` field.

---

## 4. Endpoints — Agent Registry

### `POST /acp/v1/agents`
Registers a new agent. **Required capability:** `acp:cap:agent.register`

**Request body:**
```json
{
  "agent_id": "<AgentID>",
  "public_key": "<base64url_pk>",
  "institution_id": "org.example.banking",
  "autonomy_level": 2,
  "authority_domain": "financial",
  "metadata": {
    "name": "payment-agent-01",
    "version": "1.0.0"
  },
  "sig": "<requester_signature>"
}
```

**MUST validations:**
```
agent_id == base58(SHA-256(decode_base64url(public_key)))
autonomy_level ∈ {0,1,2,3,4}
authority_domain ∈ domains registered in ACP-CAP-REG-1.0
sig valid per ACP-SIGN-1.0
agent_id not previously existing
```

**Response 201:** `data.agent_id`, `data.status: "active"`, `data.registered_at`

**Errors:** AGENT-001 to AGENT-004, SIGN-003, AUTH-001, AUTH-002

---

### `GET /acp/v1/agents/{agent_id}`
Agent status. **Required capability:** `acp:cap:agent.read`

**Response 200 data:**
```json
{
  "agent_id": "<AgentID>",
  "status": "active",
  "autonomy_level": 2,
  "authority_domain": "financial",
  "registered_at": 1718900000,
  "last_active_at": 1718919000,
  "trust_score": null
}
```

`trust_score` is a reserved field for ACP-REP-1.1. In v1.0 the server MAY return null.

---

### `POST /acp/v1/agents/{agent_id}/state`
Modifies agent state.

**Valid states in v1.0:** `active`, `restricted`, `suspended`, `revoked`.
The `under_review` state does not exist in v1.0. An escalation is an authorization event, not an agent state.

**Allowed transitions:**
```
active      → restricted   (agent.modify)
active      → suspended    (agent.suspend)
active      → revoked      (agent.revoke)
restricted  → active       (agent.modify)
restricted  → suspended    (agent.suspend)
restricted  → revoked      (agent.revoke)
suspended   → active       (agent.modify)
suspended   → revoked      (agent.revoke)
revoked     → *            NEVER — irreversible
```

---

## 5. Endpoints — Authorization

### `POST /acp/v1/authorize`
Central authorization evaluation.

**Request body:**
```json
{
  "request_id": "uuid",
  "agent_id": "<AgentID>",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "action_parameters": {
    "amount": 1500.00,
    "currency": "USD"
  },
  "context": {
    "timestamp": 1718920000,
    "ip_type": "corporate",
    "geo": "AR",
    "channel": "internal_api",
    "hour_of_day": 14,
    "day_of_week": 2
  },
  "sig": "<agent_signature>"
}
```

**Internal processing MUST (in order):**
```
1.   Validate request signature
2.   Verify agent state != revoked, suspended
2.5  If autonomy_level == 0 → DENIED immediately AUTH-008
3.   Verify Capability Token from Authorization header
4.   Verify requested capability ∈ token
5.   Verify resource covered by token
6.   Register CT nonce in 5-min window — if already seen → AUTH-007
7.   Execute ACP-RISK-1.0 → RS
8.   Apply thresholds per autonomy_level
9.   Generate AuthorizationDecision
10.  Record in Audit Ledger
11.  Return response
```

**Response APPROVED:**
```json
{
  "decision": "APPROVED",
  "risk_score": 28,
  "risk_eval_id": "<uuid>",
  "valid_until": 1718920300,
  "execution_token": { }
}
```

**Response DENIED:**
```json
{
  "decision": "DENIED",
  "risk_score": 82,
  "reason_code": "RISK-005",
  "retry_allowed": false
}
```

**Response ESCALATED:**
```json
{
  "decision": "ESCALATED",
  "risk_score": 55,
  "escalation_id": "<uuid>",
  "escalated_to": "<AgentID_or_queue>",
  "expires_at": 1718923600
}
```

An ESCALATED decision MUST generate an entry in the review queue. The action MUST NOT be executed until explicit resolution.

---

### `POST /acp/v1/authorize/escalations/{escalation_id}/resolve`
Resolves an escalation. **Required capability:** `acp:cap:agent.modify` with autonomy_level ≥ 3.

**Request body:** `resolution: "APPROVED" | "DENIED"`, `resolved_by`, `sig`.

---

## 6. Endpoints — Capability Tokens

### `POST /acp/v1/tokens`
Issues a new CT. **Required capability:** `acp:cap:agent.delegate`

---

## 7. Endpoints — Audit

### `POST /acp/v1/audit/query`
Queries the Audit Ledger. **Required capability:** `acp:cap:audit.query`

Response includes `chain_valid: true | false`.

### `GET /acp/v1/audit/verify/{event_id}`
Verifies the integrity of an event. **Required capability:** `acp:cap:audit.verify`

---

## 8. Endpoints — Execution Tokens

### `POST /acp/v1/exec-tokens/{et_id}/consume`
Reports ET consumption by the target system. Per ACP-EXEC-1.0 §9.1.

### `GET /acp/v1/exec-tokens/{et_id}/status`
Status of an ET.

**Response 200 data:**
```json
{
  "et_id": "<uuid>",
  "state": "issued | used | expired",
  "expires_at": 1718920300,
  "consumed_at": null
}
```

---

## 9. Endpoint — Health

### `GET /acp/v1/health`
Does not require authentication.

**Response 200:**
```json
{
  "acp_version": "1.0",
  "status": "operational | degraded | unavailable",
  "timestamp": 1718920000,
  "components": {
    "policy_engine": "operational",
    "audit_ledger": "operational",
    "agent_registry": "operational",
    "rev_endpoint": "operational"
  }
}
```

---

## 10. Behavior Under Anomalous Conditions

| Condition | MUST Behavior |
|-----------|---------------|
| Expired authentication token | 401 AUTH-001 |
| Revoked token | 401 AUTH-006 |
| Agent Registry unavailable | 503 SYS-001 — do not process |
| Policy Engine unavailable | 503 SYS-002 — do not process |
| Audit Ledger unavailable | 503 SYS-003 — do not process |
| External Rev endpoint unavailable | Apply ACP-REV-1.0 §5 offline policy |
| Rev endpoint returns invalid signature | 403 REV-E002 — DENIED |
| Malformed request body | 400 SYS-004 |
| Duplicate request_id within 5-min window | 400 AUTH-004 |
| Rate limit exceeded | 429 with Retry-After |
| Internal timeout > 5 seconds | 504 SYS-005 |
| Unregistered core capability | 403 CAP-002 — DENIED immediately |
| Unknown extended capability | 200 ESCALATED reason CAP-003 |

**Critical principle:** Upon any internal component failure, ACP MUST fail closed. A request that cannot be fully evaluated MUST be denied, never approved by default.

---

## 11. Rate Limiting

Per `agent_id`:

| Endpoint | Reference limit |
|----------|----------------|
| POST /authorize | 100 req/min |
| POST /tokens | 20 req/min |
| POST /agents | 5 req/min |
| POST /audit/query | 30 req/min |

Headers in 429 response:
```http
Retry-After: 30
X-ACP-RateLimit-Limit: 100
X-ACP-RateLimit-Remaining: 0
X-ACP-RateLimit-Reset: 1718920060
```

---

## 12. Consolidated Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| HP-004 | 400 | X-ACP-PoP header absent |
| HP-007 | 401 | Challenge not found, expired, or already consumed |
| HP-009 | 401 | Invalid PoP signature |
| HP-010 | 401 | agent_id in PoP does not match CT sub |
| HP-014 | 400 | request_body_hash does not match |
| AUTH-001 | 401 | Token absent or expired |
| AUTH-002 | 403 | Insufficient capability |
| AUTH-003 | 403 | Insufficient capability for state transition |
| AUTH-004 | 400 | Duplicate request_id |
| AUTH-005 | 403 | Agent suspended or revoked |
| AUTH-006 | 401 | Token revoked |
| AUTH-007 | 401 | Token nonce reused — possible replay |
| AUTH-008 | 403 | Agent has no execution autonomy (level 0) |
| AGENT-001 | 400 | agent_id does not derive from public_key |
| AGENT-002 | 400 | autonomy_level out of range |
| AGENT-003 | 400 | authority_domain not registered |
| AGENT-004 | 409 | agent_id already registered |
| AGENT-005 | 404 | agent_id not found |
| STATE-001 | 400 | Invalid state transition |
| STATE-002 | 400 | Attempted transition from revoked |
| AUDIT-001 | 500 | Invalid hash chain |
| SYS-001 | 503 | Agent Registry unavailable |
| SYS-002 | 503 | Policy Engine unavailable |
| SYS-003 | 503 | Audit Ledger unavailable |
| SYS-004 | 400 | Malformed request body |
| SYS-005 | 504 | Internal timeout |

---

## 13. Conformance

An implementation is ACP-API-1.0 conformant if it:

- Implements all endpoints from §4 to §9
- Uses the base response structure from §3 with correct signature coverage
- Implements CT-based authentication on all endpoints except /health
- Signs all successful responses with the institutional key
- Fails closed upon internal component failures
- Implements rate limiting per agent_id
- Implements nonce anti-replay validation (5-min window)
- Verifies X-ACP-PoP per ACP-HP-1.0 §10 before processing CT
- Rejects requests without X-ACP-PoP on authenticated endpoints with HP-004
- Produces the error codes from §12
- Includes `X-ACP-Request-ID` in all responses
