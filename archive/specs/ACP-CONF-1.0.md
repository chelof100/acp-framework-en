# ACP-CONF-1.0
## Conformance Specification

> **SUPERSEDED** — This document defines the conformance levels for ACP v1.0 (L1–L3).
> It has been superseded by **ACP-CONF-1.2** (current active version).
> New implementations MUST use ACP-CONF-1.2.
> This document is maintained for historical reference of ACP v1.0.

**Status:** Superseded
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-CAP-REG-1.0, ACP-HP-1.0, ACP-RISK-1.0, ACP-REV-1.0, ACP-ITA-1.0, ACP-API-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.0
**Blocks:** none — terminal document of the v1.0 specification
**Superseded-by:** ACP-CONF-1.2

---

## 1. Scope

This document defines the ACP protocol conformance levels, the minimum requirements per level, the conformance verification process, and the interoperability conditions between implementations.

An implementation that declares ACP conformance MUST satisfy all requirements of the declared level. There is no partial conformance within a level.

---

## 2. Conformance Levels

```
Level 1 — CORE
  Documents: ACP-SIGN-1.0, ACP-CT-1.0, ACP-CAP-REG-1.0, ACP-HP-1.0
  Use case: token verification with proof of key possession

Level 2 — SECURITY
  Documents: Level 1 + ACP-RISK-1.0, ACP-REV-1.0, ACP-ITA-1.0
  Use case: token issuing system with risk evaluation

Level 3 — FULL
  Documents: Level 2 + ACP-API-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.0
  Use case: complete ACP system with API, execution, and auditing
```

---

## 3. Requirements — Level 1 (CORE)

### ACP-SIGN-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L1-SIGN-001 | Canonicalization uses exact JCS (RFC 8785) | Test vector §6 |
| L1-SIGN-002 | Hash uses SHA-256 over JCS output in UTF-8 | Test vector §6 |
| L1-SIGN-003 | Signature uses Ed25519 (RFC 8032) | Interop test |
| L1-SIGN-004 | Signature encoded in base64url without padding | Output inspection |
| L1-SIGN-005 | Verification precedes all semantic validation | Flow test |
| L1-SIGN-006 | Object with invalid signature rejected without processing content | Negative test |

### ACP-CT-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L1-CT-001 | AgentID = base58(SHA-256(pk_bytes)) | Test vector |
| L1-CT-002 | Tokens with all MUST fields | Schema inspection |
| L1-CT-003 | Verification in exact order from §6 | Flow test |
| L1-CT-004 | Failure at any step produces immediate rejection | Negative tests |
| L1-CT-005 | Delegation rules from §7 correct | Delegation test |
| L1-CT-006 | max_depth > 8 rejected | Negative test |
| L1-CT-007 | Full chain verified to root | Chain test |

### ACP-CAP-REG-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L1-CAP-001 | Capability format validated | Format tests |
| L1-CAP-002 | All core domains recognized | Coverage test |
| L1-CAP-003 | RS baselines applied exactly | Value test |
| L1-CAP-004 | Unknown extended capability → ESCALATED, not DENIED | Negative test |
| L1-CAP-005 | Mandatory constraints validated | Constraint tests |

### ACP-HP-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L1-HP-001 | POST /handshake/challenge endpoint implemented with §6 structure | API test |
| L1-HP-002 | 128-bit CSPRNG challenges with 30-second window | Inspection |
| L1-HP-003 | PoP verification in exact order from §10 | Flow test |
| L1-HP-004 | Challenge deleted upon consumption — not reusable | Replay test |
| L1-HP-005 | Expired or consumed challenge returns HP-007 without revealing which | Negative test |
| L1-HP-006 | Fail closed when challenge registry unavailable | Failure test |
| L1-HP-007 | X-ACP-PoP required on all authenticated endpoints | Coverage test |
| L1-HP-008 | request_body_hash binds PoP to exact body | Binding test |
| L1-HP-009 | request_method and request_path verified against actual request | Binding test |

---

## 4. Requirements — Level 2 (SECURITY)

Includes all Level 1 requirements plus:

### ACP-RISK-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L2-RISK-001 | Identical RS for the same inputs | Determinism test |
| L2-RISK-002 | All factors B, F_ctx, F_hist, F_res implemented | Coverage test |
| L2-RISK-003 | Correct thresholds per autonomy_level | Threshold test |
| L2-RISK-004 | Autonomy_level 0 → DENIED without executing function | Special test |
| L2-RISK-005 | Evaluation record with complete structure from §10 | Inspection |
| L2-RISK-006 | Incomplete context rejected with RISK-004 | Negative test |

### ACP-REV-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L2-REV-001 | At least one mechanism (A or B) implemented | Declaration |
| L2-REV-002 | Response signature validated before use | Flow test |
| L2-REV-003 | token_id not found → revoked | Negative test |
| L2-REV-004 | Correct transitive revocation | Chain test |
| L2-REV-005 | Offline policy without more permissive exceptions | Availability test |
| L2-REV-006 | Agent revocation invalidates all its tokens | Propagation test |

### ACP-ITA-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L2-ITA-001 | Institutional record with §4 structure | Inspection |
| L2-ITA-002 | GET /institutions/{id} and /key/{key_id} endpoints | API test |
| L2-ITA-003 | proof_of_key_possession validated | Bootstrap test |
| L2-ITA-004 | Rotation with transition ≤ 7 days | Rotation test |
| L2-ITA-005 | Emergency rotation invalidates immediately | Emergency test |
| L2-ITA-006 | Records signed with authority RIK | Signature test |
| L2-ITA-007 | Revoked key → artifact rejection | Negative test |

---

## 5. Requirements — Level 3 (FULL)

Includes all Level 2 requirements plus:

### ACP-API-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L3-API-001 | All endpoints from §4 to §9 implemented | Coverage test |
| L3-API-002 | CT authentication on all except /health | Authentication test |
| L3-API-003 | Response signatures with correct coverage | Signature inspection |
| L3-API-004 | Internal failure → rejection, never approval | Failure test |
| L3-API-005 | Rate limiting per agent_id | Rate limit test |
| L3-API-006 | Anti-replay nonce window of 5 minutes | Replay test |
| L3-API-007 | Autonomy_level 0 → AUTH-008 on /authorize | Special test |
| L3-API-008 | Unknown core capability → 403 CAP-002 | Negative test |
| L3-API-009 | Unknown extended capability → ESCALATED | Negative test |
| L3-API-010 | Rev offline applies ACP-REV-1.0 §5 | Availability test |

### ACP-EXEC-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L3-EXEC-001 | ETs issued only on APPROVED AuthorizationDecision | Flow test |
| L3-EXEC-002 | ETs signed with ACP institutional key | Signature test |
| L3-EXEC-003 | Maximum window of 300 seconds | Expiration test |
| L3-EXEC-004 | Consumed ET not reusable | Replay test |
| L3-EXEC-005 | Expired ET rejected | Negative test |
| L3-EXEC-006 | ET Registry with issued/used/expired states | Inspection |
| L3-EXEC-007 | POST /exec-tokens/{et_id}/consume implemented | API test |

### ACP-LEDGER-1.0

| ID | Requirement | Verification |
|----|-------------|--------------|
| L3-LEDG-001 | All event types from §5 implemented | Coverage test |
| L3-LEDG-002 | Mandatory JCS hash | Test vector |
| L3-LEDG-003 | Genesis with correct prev_hash constant | Bootstrap test |
| L3-LEDG-004 | Monotonic sequence without gaps | Integrity test |
| L3-LEDG-005 | Chain verification from §7 implemented | Verification test |
| L3-LEDG-006 | Corruption reported without silencing | Corruption test |
| L3-LEDG-007 | No modification operations available | Negative test |
| L3-LEDG-008 | chain_valid in query responses | Inspection |
| L3-LEDG-009 | Minimum 7-year retention declared in policy | Declaration |

---

## 6. Interoperability Conditions

### 6.1 L1 Interoperability

```
A can verify tokens from B if:
  - Both implement ACP-CONF-L1
  - A has B's pk (via ITA or out-of-band)
  - B's tokens use algorithms from ACP-SIGN-1.0
  - B's tokens use capabilities from the core registry
```

### 6.2 L2 Interoperability

```
A can delegate to B's agents if:
  - Both implement ACP-CONF-L2
  - Both registered in common ITA or with mutual recognition
  - B's revocation endpoint accessible to A
  - Same set of core domains
```

### 6.3 L3 Interoperability

```
A can audit B's ledger if:
  - B implements ACP-CONF-L3
  - A resolves B's pk via ACP-ITA-1.0
  - B exposes GET /acp/v1/audit/query
  - A implements chain verification from ACP-LEDGER-1.0 §7
```

---

## 7. Conformance Declaration

Must be accessible at `GET https://<contact_endpoint>/acp/v1/conformance` without authentication.

```json
{
  "acp_conformance": {
    "version": "1.0",
    "level": "FULL",
    "documents": {
      "ACP-SIGN-1.0": "compliant",
      "ACP-CT-1.0": "compliant",
      "ACP-CAP-REG-1.0": "compliant",
      "ACP-HP-1.0": "compliant",
      "ACP-RISK-1.0": "compliant",
      "ACP-REV-1.0": { "status": "compliant", "mechanism": "endpoint" },
      "ACP-ITA-1.0": { "status": "compliant", "model": "centralized" },
      "ACP-API-1.0": "compliant",
      "ACP-EXEC-1.0": "compliant",
      "ACP-LEDGER-1.0": "compliant"
    },
    "extensions": [],
    "institution_id": "org.example.banking",
    "contact_endpoint": "https://acp.example-banking.com",
    "declaration_date": 1718920000
  }
}
```

---

## 8. Prohibited Behaviors

An implementation that exhibits any of these behaviors MUST NOT declare conformance at any level.

| ID | Prohibited behavior |
|----|---------------------|
| PROHIB-001 | Approving request when any evaluation component fails |
| PROHIB-002 | Reusing a consumed Execution Token |
| PROHIB-003 | Omitting signature verification on incoming artifact |
| PROHIB-004 | Treating token_id not found as active during revocation |
| PROHIB-005 | Allowing transition from `revoked` state |
| PROHIB-006 | Issuing ET without APPROVED AuthorizationDecision |
| PROHIB-007 | Modifying or deleting Audit Ledger events |
| PROHIB-008 | Silencing corruption detection in ledger |
| PROHIB-009 | Ignoring max_depth in delegation chains |
| PROHIB-010 | Offline policy more permissive than ACP-REV-1.0 §5 |
| PROHIB-011 | Approving requests from agents with autonomy_level 0 |
| PROHIB-012 | Continuing to process an object with an invalid signature |

---

## 9. Extensions

Institutional extensions are conformant if they:
- Are formally documented
- Do not modify the behavior of core documents
- Do not violate any prohibited behavior from §8
- Are declared in the Conformance Declaration

Mandatory namespace: `ext.<institution_id>.<name>`

---

## 10. Future Versions

**Minor version (v1.x):** Adds optional capabilities. Does not break v1.0 conformance.

**Major version (v2.0):** May introduce breaking changes. Requires a new conformance process.

---

## 11. Summary

| Document | L1 CORE | L2 SECURITY | L3 FULL |
|----------|---------|------------|---------|
| ACP-SIGN-1.0 | ✓ | ✓ | ✓ |
| ACP-CT-1.0 | ✓ | ✓ | ✓ |
| ACP-CAP-REG-1.0 | ✓ | ✓ | ✓ |
| ACP-HP-1.0 | ✓ | ✓ | ✓ |
| ACP-RISK-1.0 | — | ✓ | ✓ |
| ACP-REV-1.0 | — | ✓ | ✓ |
| ACP-ITA-1.0 | — | ✓ | ✓ |
| ACP-API-1.0 | — | — | ✓ |
| ACP-EXEC-1.0 | — | — | ✓ |
| ACP-LEDGER-1.0 | — | — | ✓ |
