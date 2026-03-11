# ACP-MESSAGES-1.0
## Formal Message Specification

**Status:** Normative
**Version:** 1.0
**Type:** Core Protocol Specification
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0
**Required-by:** ACP-CONF-1.1 (L1 — Core Conformance)

> This specification is **normative**. All ACP v1.x implementations MUST comply with the format, signature, and anti-replay requirements defined here.

---

## 1. General Principles

All messages must be serializable as JSON.

All messages must include protocol_version.

All messages must include a unique message_id.

All messages must include timestamp in ISO 8601 UTC format.

All critical messages must be digitally signed.

Mandatory base format:

{
  "protocol_version": "1.0",
  "message_id": "uuid",
  "timestamp": "ISO-8601-UTC",
  "type": "MESSAGE_TYPE",
  "payload": { },
  "signature": "base64_signature"
}
2. Mandatory Message Types

ACP v1.0 defines 5 fundamental messages:

AgentRegistration

ActionRequest

AuthorizationDecision

AgentStateChange

AuditQuery

3. AgentRegistration
Purpose

Register an agent in the Agent Identity Registry.

Mandatory Payload
{
  "agent_id": "string",
  "public_key": "string",
  "institution_id": "string",
  "autonomy_level": "integer",
  "authority_domain": "string"
}
Rules

agent_id must be unique.

public_key must comply with the declared cryptographic standard.

Registration must generate an event in the Action Ledger.

Cannot be overwritten without prior revocation.

4. ActionRequest
Purpose

Request authorization to execute a critical action.

Mandatory Payload
{
  "request_id": "uuid",
  "agent_id": "string",
  "action_type": "string",
  "target_resource": "string",
  "action_parameters": { },
  "context": {
    "ip": "string",
    "geo": "string",
    "device_id": "string"
  }
}
Rules

Must be signed by the agent's private key.

request_id must be unique.

Cannot be executed without an explicit AuthorizationDecision.

5. AuthorizationDecision
Purpose

Issue a formal decision from the ACP system.

Mandatory Payload
{
  "request_id": "uuid",
  "agent_id": "string",
  "decision": "APPROVED | DENIED | ESCALATED",
  "risk_score": "integer",
  "reason_code": "string",
  "policy_reference": "string"
}
Rules

Must be signed by the ACP institutional key.

Must be recorded in the Action Ledger.

Only APPROVED permits execution.

6. AgentStateChange
Purpose

Modify the operational state of an agent.

Mandatory Payload
{
  "agent_id": "string",
  "previous_state": "string",
  "new_state": "string",
  "reason_code": "string",
  "authorized_by": "string"
}
Valid states

active

restricted

suspended

revoked

Critical rule

If state = suspended or revoked
→ all future ActionRequests must automatically receive DENIED.

7. AuditQuery
Purpose

Enable structured auditing.

Mandatory Payload
{
  "query_id": "uuid",
  "agent_id": "string",
  "time_range": {
    "from": "ISO-8601",
    "to": "ISO-8601"
  }
}
Response must include

Ordered list of events

Verifiable chained hash

Institutional signature

8. Mandatory Digital Signature

Minimum rules:

ActionRequest → signed by agent

AuthorizationDecision → signed by ACP Authority

AgentStateChange → signed by Control Authority

AuditResponse → signed by institution

Without a valid signature → message is invalid.

9. Standard Error Codes

ACP v1.0 must support at least:

ACP-001 Invalid Signature

ACP-002 Agent Suspended

ACP-003 Permission Denied

ACP-004 Risk Threshold Exceeded

ACP-005 Invalid Message Format

ACP-006 Replay Detected

ACP-007 Unknown Agent

10. Replay Protection

Every ActionRequest must include:

Unique request_id

Validated timestamp

Configurable maximum window (e.g., 30s)

If reuse of request_id is detected → ACP-006.

11. Versioning

The field:

"protocol_version": "1.0"

Is mandatory.

Incompatible changes must increment the major version.

12. Critical Protocol Properties

An ACP v1.0 implementation must guarantee:

Determinism in evaluation.

Cryptographic integrity.

Non-repudiation.

Complete traceability.

Fail-closed by default.

13. Result

ACP now has:

Minimal architecture

Mandatory components

Formal flow

Message model

Error codes

Signing rules

Anti-replay rules

This now resembles a real protocol.
