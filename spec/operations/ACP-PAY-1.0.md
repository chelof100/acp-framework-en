# ACP-PAY-1.0
## Payment Extension — Verifiable Payment Settlement

**Status:** Draft
**Version:** 1.0
**Type:** Protocol Extension
**Depends-on:** ACP-CT-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.2
**Conformance-level:** L2+ (requires ACP-EXEC-1.0 and ACP-LEDGER-1.2)
**Related:** ACP-AGS-1.0 (L6 — Economic Layer)

---

## Abstract

ACP-PAY-1.0 defines a mechanism to link capability-based authorization with verifiable economic settlement. It integrates settlement proof within the capability model without modifying the ACP core, and records the `PAYMENT_VERIFIED` event in the audit ledger.

---

## 1. Introduction

Some resources require verifiable payment before granting access. ACP-PAY integrates settlement proof within the capability model without modifying the ACP core.

An agent wishing to access a payment-gated resource MUST:
1. Obtain a capability with an embedded `payment_condition`
2. Complete settlement via the corresponding payment mechanism
3. Attach `settlement_proof` to the capability token
4. Present the `ACP-PAY-Token` to the Resource Server
5. The Resource Server records a `PAYMENT_VERIFIED` event in ACP-LEDGER-1.2

---

## 2. Terminology

Interpretation conformant with IETF RFC 2119 (MUST, SHOULD, MAY, MUST NOT).

| Term | Definition |
|---|---|
| `payment_condition` | Economic condition embedded in a capability |
| `settlement_proof` | Cryptographic evidence of successful settlement |
| `proof_id` | Unique identifier for the settlement_proof |
| `ACP-PAY-Token` | Capability token extended with a payment condition |
| `Resource Server` | Server that validates capabilities and payment proofs |

---

## 3. Extended Capability Format

### 3.1 payment_condition

```json
{
  "amount": "<decimal>",
  "currency": "<ISO-4217 | crypto-ticker>",
  "settlement_proof": "<ProofReference>",
  "expiration": "<ISO-8601 timestamp>"
}
```

### 3.2 ACP-PAY-Token

```json
{
  "capability_claim": {
    "capability_id": "<CapabilityID>",
    "holder": "<AgentID>",
    "issuer": "<AgentID>",
    "resource": "<URI>",
    "action": "<action>",
    "constraints": {}
  },
  "payment_condition": {
    "amount": "100.00",
    "currency": "USD",
    "settlement_proof": "proof_9f4a2b1c",
    "expiration": "2025-12-31T23:59:59Z"
  },
  "proof": "<JWS-signature>",
  "multi_signature": ["<sig1>", "<sig2>"]
}
```

The presence of `payment_condition` indicates that access to the resource is conditioned on verifiable settlement.

---

## 4. Settlement Proof

### 4.1 Requirements

`settlement_proof` MUST demonstrate:
- Valid transfer to the correct recipient
- Absence of double spend
- Sufficient confirmation per the payment mechanism

### 4.2 Supported types

| Type | Description |
|---|---|
| `on-chain` | Proof on a public or permissioned blockchain |
| `off-chain-channel` | Lightning/similar payment channel proof |
| `corporate-ledger` | Signed entry in a corporate ledger |

ACP-PAY does not impose a specific network. The Resource Server MUST support at least one type.

### 4.3 settlement_proof structure

```json
{
  "proof_id": "<UUID>",
  "type": "on-chain | off-chain-channel | corporate-ledger",
  "amount": "100.00",
  "currency": "USD",
  "recipient": "<AgentID | wallet-address>",
  "timestamp": "<ISO-8601>",
  "confirmation_data": "<type-specific>",
  "signature": "<JWS>"
}
```

---

## 5. API Endpoints

### 5.1 POST /acp/v1/payment/verify

Verifies an `ACP-PAY-Token` and emits the `PAYMENT_VERIFIED` event in the ledger upon successful verification.

**Request:**
```http
POST /acp/v1/payment/verify
Content-Type: application/json
Authorization: Bearer <token>

{
  "pay_token": {
    "capability_claim": { ... },
    "payment_condition": {
      "amount": "100.00",
      "currency": "USD",
      "settlement_proof": "proof_9f4a2b1c",
      "expiration": "2025-12-31T23:59:59Z"
    },
    "proof": "<JWS>",
    "multi_signature": []
  }
}
```

**Response 200 OK:**
```json
{
  "status": "verified",
  "proof_id": "proof_9f4a2b1c",
  "ledger_event_id": "evt_abc123",
  "verified_at": "2025-06-15T10:30:00Z"
}
```

**Response errors:** see §6.

### 5.2 GET /acp/v1/payment/{proof_id}

Retrieves the status and metadata of a previously verified settlement_proof.

**Request:**
```http
GET /acp/v1/payment/proof_9f4a2b1c
Authorization: Bearer <token>
```

**Response 200 OK:**
```json
{
  "proof_id": "proof_9f4a2b1c",
  "status": "verified | pending | rejected | expired",
  "type": "on-chain",
  "amount": "100.00",
  "currency": "USD",
  "recipient": "agent:org.example/payment-receiver",
  "timestamp": "2025-06-15T10:29:55Z",
  "verified_at": "2025-06-15T10:30:00Z",
  "ledger_event_id": "evt_abc123",
  "expiration": "2025-12-31T23:59:59Z"
}
```

**Response 404:** proof_id not found.

---

## 6. Error Codes

| Code | HTTP | Description |
|---|---|---|
| `PAY-001` | 400 | Malformed `payment_condition` or missing fields |
| `PAY-002` | 402 | Invalid or unverifiable settlement proof |
| `PAY-003` | 402 | Insufficient amount (amount < required) |
| `PAY-004` | 410 | Payment condition expired (`expiration` in the past) |
| `PAY-005` | 409 | Double-spend detected: proof_id already used |
| `PAY-006` | 503 | Payment verification system unavailable |

**Error format:**
```json
{
  "error": "PAY-003",
  "message": "Payment amount 50.00 USD is below required 100.00 USD",
  "required_amount": "100.00",
  "provided_amount": "50.00",
  "currency": "USD"
}
```

---

## 7. Verification Requirements

A Resource Server MUST:
1. Verify the base capability (ACP-CT-1.0 §4)
2. Verify `settlement_proof` against the declared mechanism
3. Confirm `amount` ≥ minimum required amount for the resource
4. Confirm `expiration` has not passed
5. Verify absence of double-spend (proof_id not reused)
6. Emit `PAYMENT_VERIFIED` event in ACP-LEDGER-1.2 (§8)

---

## 8. LEDGER-1.2 Integration

### 8.1 New event: PAYMENT_VERIFIED

After successful verification, the Resource Server MUST record:

```json
{
  "event_id": "<UUID>",
  "event_type": "PAYMENT_VERIFIED",
  "timestamp": "<ISO-8601>",
  "agent_id": "<AgentID>",
  "institution_id": "<InstitutionID>",
  "proof_id": "proof_9f4a2b1c",
  "amount": "100.00",
  "currency": "USD",
  "resource": "<URI>",
  "capability_id": "<CapabilityID>",
  "prev_hash": "<SHA-256 of previous event>",
  "signature": "<JWS of the Resource Server>"
}
```

### 8.2 Audit chain

The `PAYMENT_VERIFIED` event is chained in the ACP-LEDGER-1.2 hash-chained ledger. The `prev_hash` field MUST correspond to the hash of the last event recorded by the same institution.

---

## 9. Conformance

### 9.1 Minimum required level

ACP-PAY-1.0 requires **Conformance Level L2+**:
- L1: ACP-CT-1.0 (Capability Token)
- L2: ACP-EXEC-1.0 (Execution Token)
- L2+PAY: ACP-PAY-1.0 (this document) + ACP-LEDGER-1.2

### 9.2 Conformance declaration

A conformant implementation MUST declare:
```
Conforms-to: ACP-PAY-1.0
Conformance-level: L2+
Settlement-types: [on-chain | off-chain-channel | corporate-ledger]
```

### 9.3 Mandatory requirements

| Requirement | MUST / SHOULD |
|---|---|
| Verify base capability before payment | MUST |
| Reject reused proof_ids | MUST |
| Reject tokens with past expiration | MUST |
| Emit PAYMENT_VERIFIED in LEDGER-1.2 | MUST |
| Support at least one settlement type | MUST |
| Return PAY-00x error per specific failure | MUST |
| Support GET /acp/v1/payment/{proof_id} | MUST |

---

## 10. Security Considerations

### 10.1 Mitigated threats

| Threat | Mitigation |
|---|---|
| Access without payment | Mandatory pre-access verification (§7) |
| Reuse of expired proof | Expiration validation (PAY-004) |
| Amount manipulation | Amount ≥ required check (PAY-003) |
| Double-spend | Unique proof_id detection (PAY-005) |
| Proof forgery | JWS signature by Resource Server in LEDGER-1.2 |

### 10.2 Security dependencies

The system inherits the security of the underlying ledger used for `settlement_proof`. Implementations SHOULD use irreversible confirmation mechanisms when amounts exceed institution-defined thresholds.

---

## 11. IANA Considerations

None in this version.

---

## 12. Normative References

- RFC 2119 — Key words for use in RFCs (IETF)
- ACP-CT-1.0 — Capability Token
- ACP-EXEC-1.0 — Execution Token
- ACP-LEDGER-1.2 — Hash-chained Audit Ledger
- ACP-AGS-1.0 — Agent Governance Stack (L6 Economic Layer)
