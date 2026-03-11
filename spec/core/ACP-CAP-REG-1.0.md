# ACP-CAP-REG-1.0
## Capability Type Registry Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-CT-1.0
**Required-by:** ACP-RISK-1.0, ACP-API-1.0

---

## 1. Scope

This document defines the format of capability identifiers, the core domains of protocol v1.0, the risk baselines per capability, the mandatory constraints, and the extension process for institutional capabilities.

---

## 2. Identifier Format

```
acp:cap:<domain>.<action>
```

Rules:
- `acp:cap:` prefix is mandatory
- `domain` and `action`: lowercase alphanumeric, hyphens permitted, no spaces
- Subdomain permitted: `acp:cap:<domain>.<subdomain>.<action>`
- Maximum total length: 128 characters
- Extended capabilities: `acp:cap:ext.<institution_id>.<domain>.<action>`

---

## 3. Core Domains v1.0

The following domains are immutable in v1.0. They cannot be modified by institutions.

### 3.1 `financial`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| financial.read | 0 | — |
| financial.write | 10 | — |
| financial.payment | 35 | max_amount, currency |
| financial.transfer | 40 | max_amount, currency |
| financial.approve | 25 | — |
| financial.cancel | 15 | — |
| financial.report | 5 | — |

### 3.2 `identity`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| identity.read | 0 | — |
| identity.verify | 5 | — |
| identity.create | 20 | — |
| identity.modify | 20 | — |
| identity.revoke | 30 | — |
| identity.delegate | 25 | — |

### 3.3 `infrastructure`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| infrastructure.read | 0 | — |
| infrastructure.deploy | 30 | — |
| infrastructure.modify | 25 | — |
| infrastructure.scale | 20 | — |
| infrastructure.delete | 55 | — |
| infrastructure.restart | 15 | — |
| infrastructure.monitor | 0 | — |

### 3.4 `data`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| data.read | 0 | — |
| data.write | 10 | — |
| data.delete | 30 | — |
| data.export | 25 | destination_domain |
| data.import | 15 | — |
| data.classify | 10 | — |
| data.anonymize | 15 | — |

### 3.5 `communication`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| communication.internal | 0 | — |
| communication.external | 20 | allowed_endpoints |
| communication.broadcast | 25 | — |
| communication.webhook | 15 | allowed_endpoints |
| communication.notify | 5 | — |

### 3.6 `agent`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| agent.register | 20 | — |
| agent.read | 0 | — |
| agent.modify | 25 | — |
| agent.suspend | 30 | — |
| agent.revoke | 40 | — |
| agent.delegate | 20 | — |

### 3.7 `audit`

| Capability | Baseline RS | Mandatory Constraints |
|-----------|-------------|--------------------------|
| audit.read | 5 | — |
| audit.query | 5 | — |
| audit.export | 20 | destination_domain |
| audit.verify | 5 | — |

---

## 4. Extended Capabilities

Institutions may define their own capabilities using the prefix:

```
acp:cap:ext.<institution_id>.<domain>.<action>
```

Example: `acp:cap:ext.org.example.banking.credit.approve`

Rules for extended capabilities:
- May only be used by the institution that defines them
- MUST be registered in the institutional internal directory
- When an external verifier encounters an unknown extended capability, it MUST escalate (not deny)
- The baseline RS for unknown extended capabilities is 40 (escalation threshold)

---

## 5. Constraint Specification

Constraints are additional fields in the `constraints` object of the token.

### 5.1 `max_amount`

Required by: `financial.payment`, `financial.transfer`

```json
"constraints": {
  "max_amount": 1000.00,
  "currency": ["USD", "EUR"]
}
```

- `max_amount`: positive number. The action MUST be rejected if the amount exceeds this value.
- `currency`: array of ISO 4217 codes. The action MUST use one of these currencies.

### 5.2 `destination_domain`

Required by: `data.export`, `audit.export`

```json
"constraints": {
  "destination_domain": ["org.example.partner"]
}
```

Array of institution_ids authorized as destination.

### 5.3 `allowed_endpoints`

Required by: `communication.external`, `communication.webhook`

```json
"constraints": {
  "allowed_endpoints": ["https://api.partner.com", "https://webhook.example.com"]
}
```

Array of authorized URLs or domains.

---

## 6. Capability Validation

Validation process upon receiving a capability identifier:

```
Step 1: Verify "acp:cap:" prefix
Step 2: Verify length ≤ 128 characters
Step 3: Verify valid characters in domain and action
Step 4: If prefix "acp:cap:ext." → extended capability, go to step 7
Step 5: Verify domain ∈ core domains (§3)
Step 6: Verify action ∈ domain actions → if not found: CAP-002
Step 7: Unknown extended capability → baseline RS = 40, ESCALATED
Step 8: Verify mandatory constraints present → if missing: CAP-004
```

---

## 7. Errors

| Code | Condition |
|--------|-----------|
| CAP-001 | Invalid capability format |
| CAP-002 | Core capability not registered |
| CAP-003 | Unknown extended capability (not an error — produces ESCALATED) |
| CAP-004 | Mandatory constraint absent |
| CAP-005 | Constraint value out of range |
| CAP-006 | institution_id in extended capability is invalid |

---

## 8. Conformance

An implementation is ACP-CAP-REG-1.0 conformant if it:

- Validates capability format per §2
- Recognizes all core domains in §3
- Applies the RS baselines defined in §3
- Escalates (does not deny) on unknown extended capabilities
- Validates the presence of mandatory constraints per §5
- Produces the error codes of §7
