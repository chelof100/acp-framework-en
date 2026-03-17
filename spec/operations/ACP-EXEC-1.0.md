# ACP-EXEC-1.0
## Execution Token Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0
**Required-by:** ACP-LEDGER-1.3, ACP-CONF-1.2
**Integration note:** Execution Tokens are issued via the ACP HTTP API (ACP-API-1.0 §6). ACP-API-1.0 is an operational transport layer; it is not required for ET issuance and validation logic to be correct.

---

## 1. Scope

This document defines the Execution Token (ET), its structure, lifecycle, issuance, validation, and invalidation. The ET is the artifact that proves to the target system that a specific action was authorized by ACP and may be executed exactly once.

The target system does not need to know the full ACP protocol to validate an ET. It only needs the ACP institutional public key (obtained via ACP-ITA-1.0) and this document.

---

## 2. Definitions

**Execution Token (ET):** Single-use cryptographic artifact that authorizes the execution of a specific instance of an ACP-authorized action.

**Target System:** System, API, or service that receives and validates the ET before executing the action.

**Execution window:** The ET's validity period. Maximum 300 seconds (5 minutes).

**Consumption:** The act of presenting the ET to the target system. Irreversible.

---

## 3. Design Principles

```
1. An ET authorizes exactly one action, once, within a short window
2. The target system validates with a single cryptographic operation
3. No delegation
4. No renewal
5. No intermediate states
6. Lifecycle exactly: issued → used → expired
```

---

## 4. Execution Token Structure

```json
{
  "ver": "1.0",
  "et_id": "<uuid_v4>",
  "agent_id": "<AgentID>",
  "authorization_id": "<request_id_of_APPROVED_decision>",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "action_parameters_hash": "<SHA-256_base64url_of_JCS(action_parameters)>",
  "issued_at": 1718920000,
  "expires_at": 1718920300,
  "used": false,
  "sig": "<base64url_ACP_institutional_signature>"
}
```

---

## 5. Field Specification

**5.1 `et_id`** — UUID v4 CSPRNG. MUST be globally unique. This is the consumption identifier.

**5.2 `agent_id`** — MUST match the agent_id of the AuthorizationDecision that originated the ET.

**5.3 `authorization_id`** — MUST be the `request_id` of the APPROVED AuthorizationDecision. Enables direct traceability to the Audit Ledger.

**5.4 `capability`** — MUST be identical to the capability field of the original ActionRequest.

**5.5 `resource`** — MUST be identical to the resource field of the original ActionRequest. The target system MUST verify that it matches the resource being operated upon.

**5.6 `action_parameters_hash`** — MUST be `base64url(SHA-256(JCS(action_parameters)))`. The target system MAY verify this hash. If it verifies and it does not match, it MUST reject.

**5.7 `expires_at`** — MUST be `issued_at + N`, where N MUST NOT exceed 300 seconds.

Recommended windows per capability:

| Capability | Window |
|-----------|---------|
| financial.payment, financial.transfer | 60s |
| infrastructure.delete | 30s |
| infrastructure.deploy | 120s |
| *.read | 300s |
| others | 120s |

**5.8 `used`** — MUST be `false` in the issued ET. The consumption state lives in the target system's registry, not in the token.

**5.9 `sig`** — Signature of the ACP institution per ACP-SIGN-1.0. The target system validates with the ACP institutional pk from ACP-ITA-1.0.

---

## 6. Lifecycle

```
┌─────────┐
│  ISSUED │
└────┬────┘
     │
┌────┴──────────────────┐
│                       │
presented           expires_at
to target           reached
│                       │
┌─▼──────┐        ┌──────▼──────┐
│  USED  │        │   EXPIRED   │
└────────┘        └─────────────┘
```

From USED and EXPIRED there are no possible transitions.

---

## 7. Issuance

The ET is issued exclusively as part of an APPROVED AuthorizationDecision:

```
POST /acp/v1/authorize → APPROVED → ET included in response
POST /acp/v1/authorize/escalations/{id}/resolve → APPROVED → ET included
```

**Process:**
```
1. Generate et_id UUID v4
2. Copy agent_id, capability, resource from the ActionRequest
3. Calculate action_parameters_hash = base64url(SHA-256(JCS(action_parameters)))
4. issued_at = current timestamp
5. expires_at = issued_at + configured_window
6. used = false
7. Build object without sig
8. Sign per ACP-SIGN-1.0
9. Register in internal ET Registry
10. Include in response
```

---

## 8. Validation by the Target System

MUST steps in exact order:

```
Step 1: Verify ver == "1.0"
Step 2: Verify sig with ACP institutional pk (ACP-SIGN-1.0)
Step 3: Verify expires_at > current_timestamp
Step 4: Verify agent_id matches the agent presenting the ET
Step 5: Verify capability is the requested action
Step 6: Verify resource matches the target resource
Step 7: Verify et_id is NOT in the local registry of consumed ETs
Step 8: If verifying action_parameters → compute hash and compare
Step 9: Record et_id as USED with timestamp
Step 10: Execute action
```

Steps 1–9 MUST be completed before step 10. A failure at any step MUST cancel execution.

**Step 7 is critical.** The target system MUST maintain a local registry of consumed et_ids. The registry MUST persist for at least `expires_at + 60 seconds`.

---

## 9. ET Registry

The ACP system MUST maintain:

```json
{
  "et_id": "<uuid>",
  "authorization_id": "<uuid>",
  "agent_id": "<AgentID>",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "issued_at": 1718920000,
  "expires_at": 1718920300,
  "state": "issued | used | expired",
  "consumed_at": null,
  "consumed_by_system": null
}
```

**Consumption report (SHOULD):**
```http
POST /acp/v1/exec-tokens/{et_id}/consume
```

```json
{
  "et_id": "<uuid>",
  "consumed_at": 1718920150,
  "execution_result": "success | failure | unknown",
  "sig": "<target_system_signature>"
}
```

SHOULD and not MUST because the target system may be external and not ACP-conformant.

**Cleanup:** The system MAY clean up USED or EXPIRED entries after 30 days. MUST move to the Audit Ledger before cleanup.

---

## 10. Behavior Under Anomalous Conditions

| Condition | Behavior |
|-----------|----------|
| Expired ET | Reject EXEC-003 |
| ET already consumed | Reject EXEC-004 |
| Invalid signature | Reject EXEC-002 |
| agent_id does not match | Reject EXEC-005 |
| resource does not match | Reject EXEC-006 |
| action_parameters_hash does not match | Reject EXEC-007 |
| et_id not found | Reject EXEC-008 |
| ACP system unavailable to report consumption | Continue — record locally, synchronize later |

The last case is the only one where the target system may proceed without confirmation from the ACP system. This is intentional — ACP availability MUST NOT be a single point of failure for execution.

---

## 11. Errors

| Code | Condition |
|------|-----------|
| EXEC-001 | Unsupported version |
| EXEC-002 | Invalid signature |
| EXEC-003 | Expired ET |
| EXEC-004 | ET already consumed |
| EXEC-005 | agent_id does not match |
| EXEC-006 | resource does not match |
| EXEC-007 | action_parameters_hash does not match |
| EXEC-008 | et_id not found in registry |
| EXEC-009 | Target system not authorized to consume ET |

---

## 12. Conformance

An implementation is ACP-EXEC-1.0 conformant if it:

- Issues ETs exclusively as a result of an APPROVED AuthorizationDecision
- Signs ETs with the ACP institutional key per ACP-SIGN-1.0
- Maintains an ET Registry with the states from §9
- Implements the consumption endpoint POST /acp/v1/exec-tokens/{et_id}/consume
- Applies a maximum execution window of 300 seconds
- Rejects consumed or expired ETs without exception
- Produces the error codes from §11
