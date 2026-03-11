# ACP-REV-1.0
## Revocation Protocol Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0
**Required-by:** ACP-API-1.0, ACP-LEDGER-1.2

---

## 1. Scope

This document defines the revocation mechanisms for Capability Tokens and agents, the status query protocol, offline behavior, and transitive revocation in delegation chains.

---

## 2. Definitions

**agent_id:** Agent identifier. MUST comply with ACP-CT-1.0 §3.2 format.

**token_id:** Unique identifier of a token. Corresponds to the `nonce` field of the Capability Token.

**Transitive revocation:** When a token T0 is revoked, all tokens T1 where `parent_chain` contains T0 are automatically invalid.

---

## 3. Revocation Mechanisms

ACP defines two mechanisms. Each token MUST specify which one it uses in the `rev` field.

### Mechanism A — Endpoint (online)

Real-time query to the revocation server.

**Request:**
```http
GET /acp/v1/rev/check?token_id=<nonce>
Authorization: ACP-Agent <token>
```

**Response 200:**
```json
{
  "token_id": "<nonce>",
  "status": "active",
  "checked_at": 1718920000,
  "sig": "<institutional_signature>"
}
```

`status` MUST be `"active"` or `"revoked"`.

**HTTP Codes:**

| HTTP | Condition |
|------|-----------|
| 200 | Successful response — check status field |
| 401 | Not authenticated |
| 403 | No permission to query |
| 404 | token_id not found — treat as revoked |
| 429 | Rate limit exceeded |
| 503 | Service unavailable — apply offline policy |

### Mechanism B — CRL (offline-capable)

Downloadable signed Certificate Revocation List.

**CRL Structure:**
```json
{
  "ver": "1.0",
  "issuer": "org.example.banking",
  "issued_at": 1718920000,
  "next_update": 1718923600,
  "revoked": [
    {
      "token_id": "<nonce>",
      "revoked_at": 1718910000,
      "reason_code": "REV-003"
    }
  ],
  "sig": "<institutional_signature>"
}
```

The CRL MUST be signed per ACP-SIGN-1.0. The verifier MUST validate the signature before using the CRL.

**Update frequency:**

| Context | Maximum frequency |
|---------|------------------|
| Critical financial | 1 hour |
| General enterprise | 6 hours |
| Development | 24 hours |

---

## 4. Caching

For Mechanism A, the verifier MAY cache responses:

| Capability | Maximum TTL |
|------------|------------|
| financial.payment, financial.transfer | 60 seconds |
| infrastructure.* | 120 seconds |
| *.read | 300 seconds |
| others | 180 seconds |

---

## 5. Offline Policy

When the verification mechanism is unavailable:

| Condition | Decision |
|-----------|----------|
| Cached response within TTL | Use cache |
| Valid CRL (next_update > now) | Use local CRL |
| CRL expired < 1 hour ago | ESCALATED |
| CRL expired ≥ 1 hour ago | DENIED |
| No cache or CRL | DENIED |

There are no more permissive exceptions to this policy. DENIED is the safe default behavior.

---

## 6. Transitive Revocation

When T0 is revoked:

```
For every token T1 where T1.parent_chain contains T0:
  T1 is automatically invalid
```

The system MUST implement this propagation. A verifier that finds `parent_hash` in a token MUST verify the parent token's status.

**Agent revocation:**

When agent A is revoked:
- All tokens where A is `iss` are revoked
- All tokens where A is `sub` are revoked
- Transitive revocation applies to all derived tokens

---

## 7. Revocation Issuance

```http
POST /acp/v1/rev/revoke
Authorization: ACP-Agent <token>
```

```json
{
  "token_id": "<nonce>",
  "reason_code": "REV-003",
  "revoked_by": "<AgentID>",
  "revoke_descendants": true,
  "sig": "<authorizer_signature>"
}
```

`revoke_descendants: true` MUST trigger transitive revocation of all derived tokens.

---

## 8. Reason Codes

| Code | Description |
|------|-------------|
| REV-001 | Early expiration requested by issuer |
| REV-002 | Subject's private key compromise |
| REV-003 | Policy violation detected |
| REV-004 | Agent decommissioned |
| REV-005 | Revocation by administrative order |
| REV-006 | Parent token revoked (transitive revocation) |
| REV-007 | Expiration due to inactivity |
| REV-008 | Emergency revocation due to institutional compromise |

---

## 9. Security

- All communications MUST use HTTPS
- Endpoint responses MUST be signed per ACP-SIGN-1.0
- The verifier MUST validate the signature before trusting the status
- mTLS SHOULD be used in B2B environments
- Rate limiting MUST be implemented on the verification endpoint

---

## 10. Errors

| Code | Condition |
|------|-----------|
| REV-E001 | token_id not found — treat as revoked |
| REV-E002 | Invalid response signature |
| REV-E003 | CRL with invalid signature |
| REV-E004 | Expired CRL |
| REV-E005 | No verification mechanism available — DENIED |
| REV-E006 | No permission to issue revocation |
| REV-E007 | Invalid reason code |

---

## 11. Conformance

An implementation is ACP-REV-1.0 conformant if it:

- Implements at least one of the two mechanisms (A or B)
- Validates response signatures before use
- Implements transitive revocation correctly
- Applies offline policy without more permissive exceptions
- Produces the defined reason codes and error codes
