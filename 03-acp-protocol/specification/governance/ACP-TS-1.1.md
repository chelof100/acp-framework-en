# ACP-TS-1.1 — Conformance Test Suite

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1 |
| **Type** | Test Suite Specification |
| **Depends-on** | ACP-CONF-1.1, ACP-LEDGER-1.2 |
| **Required-by** | ACR-1.0 |
| **Date** | 2026-03-10 |

---

## 1. Scope

This test suite covers conformance verification of ACP implementations at levels L1 through L5, as defined in ACP-CONF-1.1.

Each level is cumulative: an implementation declaring L3 conformance must pass all test cases for L1, L2, and L3.

The tests in this suite are the authoritative source for determining whether an implementation meets a given conformance level. The reference tool for running this suite is `acr` (ACP Compliance Runner), defined in ACR-1.0.

---

## 2. Test Case Format

Each test case follows the structure below:

```json
{
  "test_id": "TS-L1-001",
  "level": "L1",
  "description": "Short description of the test case",
  "preconditions": ["List of required prior conditions"],
  "input": { "field": "input value" },
  "expected_result": { "field": "expected value" },
  "pass_criteria": "Boolean condition or description of pass criterion"
}
```

| Field | Type | Description |
|---|---|---|
| `test_id` | string | Unique identifier. Format: `TS-L{N}-{NNN}` |
| `level` | enum | Conformance level: L1, L2, L3, L4, L5 |
| `description` | string | Human-readable description of the behavior under test |
| `preconditions` | array | Required system state before executing the test |
| `input` | object | Input data or actions to the system under test |
| `expected_result` | object | Expected output from the system |
| `pass_criteria` | string | Precise criterion to determine PASS |

---

## 3. L1 Test Cases — Core

### TS-L1-001: AgentRegistration Validation

```json
{
  "test_id": "TS-L1-001",
  "level": "L1",
  "description": "Agent registration must include all required fields and be rejected if any are missing",
  "preconditions": ["ACP node operational", "Registration endpoint available"],
  "input": {
    "event": "AGENT_REGISTERED",
    "payload": {
      "agent_id": "agent-test-001",
      "capabilities": [],
      "public_key": null
    }
  },
  "expected_result": {
    "status": "rejected",
    "error_code": "ACP-001",
    "message": "public_key is required"
  },
  "pass_criteria": "System rejects registration with error ACP-001 when public_key is null"
}
```

### TS-L1-002: Capability Token Format

```json
{
  "test_id": "TS-L1-002",
  "level": "L1",
  "description": "Issued capability token must conform to the format defined in ACP-CONF-1.1 §4",
  "preconditions": ["Agent registered with valid agent_id"],
  "input": {
    "action": "request_capability_token",
    "agent_id": "agent-test-001",
    "capability": "READ_LEDGER"
  },
  "expected_result": {
    "token_format": "JWT",
    "required_claims": ["sub", "cap", "iat", "exp", "iss"],
    "signature_algorithm": "ES256"
  },
  "pass_criteria": "Issued token is an ES256 JWT with all required claims present and not expired"
}
```

### TS-L1-003: Message Signature Verification

```json
{
  "test_id": "TS-L1-003",
  "level": "L1",
  "description": "Messages with invalid signatures must be rejected",
  "preconditions": ["Agent registered", "Known key pair"],
  "input": {
    "message": {
      "agent_id": "agent-test-001",
      "action": "EXECUTE",
      "signature": "invalid-signature-base64"
    }
  },
  "expected_result": {
    "status": "rejected",
    "error_code": "ACP-003"
  },
  "pass_criteria": "System rejects the message with error ACP-003 when signature does not verify against the registered public key"
}
```

### TS-L1-004: Anti-Replay — ACP-006

```json
{
  "test_id": "TS-L1-004",
  "level": "L1",
  "description": "A message with an already-used nonce must be rejected (anti-replay protection)",
  "preconditions": ["Agent registered", "Message M1 already processed with nonce='nonce-abc-123'"],
  "input": {
    "message": {
      "agent_id": "agent-test-001",
      "nonce": "nonce-abc-123",
      "timestamp": "2026-03-10T10:00:00Z",
      "signature": "<valid-signature>"
    }
  },
  "expected_result": {
    "status": "rejected",
    "error_code": "ACP-006"
  },
  "pass_criteria": "System rejects the duplicate message with error ACP-006"
}
```

### TS-L1-005: Fail-Closed Behavior

```json
{
  "test_id": "TS-L1-005",
  "level": "L1",
  "description": "On indeterminate verification error, the system must deny the operation (fail-closed)",
  "preconditions": ["Key verification service unreachable"],
  "input": {
    "message": {
      "agent_id": "agent-test-001",
      "action": "EXECUTE",
      "signature": "<valid-signature>"
    }
  },
  "expected_result": {
    "status": "denied",
    "error_code": "ACP-000",
    "action_taken": "none"
  },
  "pass_criteria": "System denies the operation and takes no action when it cannot verify the signature"
}
```

---

## 4. L2 Test Cases — Execution

### TS-L2-001: Execution Token Lifecycle

```json
{
  "test_id": "TS-L2-001",
  "level": "L2",
  "description": "An execution token must transition through states: issued → consumed, and must not be reusable",
  "preconditions": ["Agent with EXECUTE capability", "Execution token ET-001 issued"],
  "input": {
    "action": "consume_exec_token",
    "token_id": "ET-001",
    "agent_id": "agent-test-001"
  },
  "expected_result": {
    "first_consume": { "status": "accepted", "token_state": "consumed" },
    "second_consume": { "status": "rejected", "error_code": "ACP-010" }
  },
  "pass_criteria": "First consume is accepted; second consume of the same token is rejected with ACP-010"
}
```

### TS-L2-002: Exec-Token Consume Endpoint

```json
{
  "test_id": "TS-L2-002",
  "level": "L2",
  "description": "The execution token consume endpoint must respond with the correct schema",
  "preconditions": ["Execution token ET-002 in state issued"],
  "input": {
    "method": "POST",
    "endpoint": "/v1/exec-tokens/ET-002/consume",
    "body": { "agent_id": "agent-test-001", "signature": "<valid-signature>" }
  },
  "expected_result": {
    "http_status": 200,
    "body": {
      "token_id": "ET-002",
      "status": "consumed",
      "consumed_at": "<ISO8601>",
      "agent_id": "agent-test-001"
    }
  },
  "pass_criteria": "HTTP 200 response with body including token_id, status=consumed, consumed_at, and agent_id"
}
```

### TS-L2-003: Risk Threshold Enforcement

```json
{
  "test_id": "TS-L2-003",
  "level": "L2",
  "description": "An execution exceeding the configured risk_threshold must be blocked",
  "preconditions": ["risk_threshold configured at 0.7", "Agent with risk_score=0.85"],
  "input": {
    "action": "request_execution",
    "agent_id": "agent-test-001",
    "operation": "DELETE_RECORDS",
    "risk_score": 0.85
  },
  "expected_result": {
    "status": "blocked",
    "error_code": "ACP-020",
    "reason": "risk_score exceeds risk_threshold"
  },
  "pass_criteria": "Execution is blocked with error ACP-020 when risk_score > risk_threshold"
}
```

---

## 5. L3 Test Cases — Reputation

### TS-L3-001: REPUTATION_UPDATED Event Format

```json
{
  "test_id": "TS-L3-001",
  "level": "L3",
  "description": "The REPUTATION_UPDATED event must include all required fields as defined in ACP-LEDGER-1.2",
  "preconditions": ["Agent registered", "Reputation event triggered"],
  "input": {
    "trigger": "execution_completed",
    "agent_id": "agent-test-001",
    "outcome": "success"
  },
  "expected_result": {
    "event_type": "REPUTATION_UPDATED",
    "required_fields": ["agent_id", "previous_score", "new_score", "delta", "reason", "timestamp", "ledger_tx_id"]
  },
  "pass_criteria": "Emitted event contains all required fields with correct types"
}
```

### TS-L3-002: Reputation Score Range

```json
{
  "test_id": "TS-L3-002",
  "level": "L3",
  "description": "Reputation score must remain within the range [0.0, 1.0] under all conditions",
  "preconditions": ["Agent with score=0.05"],
  "input": {
    "action": "apply_penalty",
    "agent_id": "agent-test-001",
    "penalty": 0.5
  },
  "expected_result": {
    "new_score": 0.0,
    "clamped": true
  },
  "pass_criteria": "Resulting score is 0.0 (not negative); system applies clamping at lower bound"
}
```

### TS-L3-003: REP-1.2 Integration

```json
{
  "test_id": "TS-L3-003",
  "level": "L3",
  "description": "Reputation events must be traceable in the ledger per REP-1.2",
  "preconditions": ["Ledger operational", "REPUTATION_UPDATED event generated with tx_id=TX-REP-001"],
  "input": {
    "query": "get_ledger_entry",
    "tx_id": "TX-REP-001"
  },
  "expected_result": {
    "found": true,
    "event_type": "REPUTATION_UPDATED",
    "immutable": true
  },
  "pass_criteria": "Event is retrievable from the ledger, immutable, and linked to the correct agent_id"
}
```

---

## 6. L4 Test Cases — Liability

### TS-L4-001: resolver_type Field in ESCALATION_RESOLVED

```json
{
  "test_id": "TS-L4-001",
  "level": "L4",
  "description": "The ESCALATION_RESOLVED event must include the resolver_type field with a valid value",
  "preconditions": ["Escalation ESC-001 open"],
  "input": {
    "action": "resolve_escalation",
    "escalation_id": "ESC-001",
    "resolver": "human-operator-42"
  },
  "expected_result": {
    "event_type": "ESCALATION_RESOLVED",
    "resolver_type": "human",
    "valid_values": ["human", "automated", "council"]
  },
  "pass_criteria": "Event contains resolver_type with one of the valid values"
}
```

### TS-L4-002: LIA-1.0 Traceability

```json
{
  "test_id": "TS-L4-002",
  "level": "L4",
  "description": "Every executed action must have a traceable liability chain per LIA-1.0",
  "preconditions": ["Action ACT-001 executed by agent-test-001"],
  "input": {
    "query": "get_liability_chain",
    "action_id": "ACT-001"
  },
  "expected_result": {
    "chain": [
      { "role": "initiator", "entity_id": "agent-test-001", "entity_type": "agent" },
      { "role": "authorizer", "entity_id": "user-007", "entity_type": "human" }
    ]
  },
  "pass_criteria": "Chain contains at least one initiator and is complete back to a human or system root"
}
```

### TS-L4-003: Liability Chain Reconstruction

```json
{
  "test_id": "TS-L4-003",
  "level": "L4",
  "description": "The system must be able to reconstruct the full liability chain for a given action",
  "preconditions": ["Sequence of 3 delegated agents: A→B→C executing ACT-002"],
  "input": {
    "query": "reconstruct_liability_chain",
    "action_id": "ACT-002"
  },
  "expected_result": {
    "chain_length": 3,
    "all_links_present": true,
    "root_authority": "user-007"
  },
  "pass_criteria": "Reconstructed chain contains all 3 links in correct order with root_authority identified"
}
```

---

## 7. L5 Test Cases — Payment

### TS-L5-001: ACP-PAY-Token Verification

```json
{
  "test_id": "TS-L5-001",
  "level": "L5",
  "description": "An ACP-PAY-Token must be cryptographically verifiable before processing payment",
  "preconditions": ["PAY-Token PT-001 issued by authorized issuer"],
  "input": {
    "action": "verify_pay_token",
    "token_id": "PT-001",
    "signature": "<valid-issuer-signature>"
  },
  "expected_result": {
    "valid": true,
    "issuer_verified": true,
    "not_expired": true,
    "not_spent": true
  },
  "pass_criteria": "Token passes all checks: signature, issuer, expiration, and unspent state"
}
```

### TS-L5-002: Double-Spend Detection — PAY-005

```json
{
  "test_id": "TS-L5-002",
  "level": "L5",
  "description": "An attempt to use the same PAY-Token twice must be rejected with PAY-005",
  "preconditions": ["PAY-Token PT-002 already used in transaction TX-001"],
  "input": {
    "action": "process_payment",
    "token_id": "PT-002",
    "amount": 10.00,
    "recipient": "agent-test-002"
  },
  "expected_result": {
    "status": "rejected",
    "error_code": "PAY-005",
    "reason": "token_already_spent"
  },
  "pass_criteria": "System rejects the second token use with error PAY-005 and does not process the payment"
}
```

### TS-L5-003: PAYMENT_VERIFIED Ledger Event

```json
{
  "test_id": "TS-L5-003",
  "level": "L5",
  "description": "Every successfully processed payment must generate a PAYMENT_VERIFIED event in the ledger",
  "preconditions": ["PAY-Token PT-003 valid and unspent"],
  "input": {
    "action": "process_payment",
    "token_id": "PT-003",
    "amount": 5.00,
    "recipient": "agent-test-002"
  },
  "expected_result": {
    "payment_status": "processed",
    "ledger_event": {
      "event_type": "PAYMENT_VERIFIED",
      "required_fields": ["token_id", "amount", "sender", "recipient", "timestamp", "ledger_tx_id"]
    }
  },
  "pass_criteria": "PAYMENT_VERIFIED event is generated with all required fields and is immutable in the ledger"
}
```

---

## 8. Result Format

Each test execution produces a result in the following JSON format:

```json
{
  "test_id": "TS-L1-001",
  "level": "L1",
  "status": "pass",
  "duration_ms": 142,
  "error_code": null,
  "details": {
    "actual_result": { "status": "rejected", "error_code": "ACP-001" },
    "pass_criteria_met": true,
    "notes": "Correct behavior: registration rejected due to null public_key"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `test_id` | string | Identifier of the executed test case |
| `level` | enum | Conformance level: L1–L5 |
| `status` | enum | `pass`, `fail`, or `skip` |
| `duration_ms` | integer | Execution duration in milliseconds |
| `error_code` | string\|null | Error code if `status=fail`; null otherwise |
| `details` | object | Actual result, pass criteria status, additional notes |

The test runner MUST emit results in this format. Output in any other format is not conformant with this specification.

---

## 9. Reference Tool

The reference tool for running this suite is `acr` — ACP Compliance Runner, defined in **ACR-1.0**.

The `acr` runner is the canonical implementation of the test executor. Any alternative tool claiming to run this suite MUST:

1. Accept as input a set of test cases in the format of §2.
2. Produce results in the exact format of §8.
3. Return exit code `0` if all tests for the requested level pass, and `1` otherwise.
4. Support per-level execution (`--level L1`, `--level L2`, etc.) and full execution (`--level all`).

Reference: see ACR-1.0 for installation, usage, and runner extension details.

---

## 10. Conformance Requirements

An ACP implementation is considered **conformant at level Lx** if and only if **all test cases for levels L1 through Lx inclusive** produce a `pass` result.

| Declared Level | Tests that must pass |
|---|---|
| L1 | TS-L1-001 … TS-L1-005 |
| L2 | TS-L1-001 … TS-L1-005 + TS-L2-001 … TS-L2-003 |
| L3 | L1 + L2 + TS-L3-001 … TS-L3-003 |
| L4 | L1 + L2 + L3 + TS-L4-001 … TS-L4-003 |
| L5 | L1 + L2 + L3 + L4 + TS-L5-001 … TS-L5-003 |

A `skip` result on any test required for the declared level is treated as `fail` for certification purposes.

Implementations may report partial conformance (e.g., "L3 conformant, L4 tests pending") provided all tests for the declared level and all preceding levels have passed.
