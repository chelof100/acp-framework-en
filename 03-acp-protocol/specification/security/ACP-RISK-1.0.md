# ACP-RISK-1.0
## Deterministic Risk Model Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-CAP-REG-1.0
**Required-by:** ACP-API-1.0, ACP-LEDGER-1.0

---

## 1. Scope

This document defines the risk evaluation function Risk(a,c,r,x,h)→[0,100], its factors, decision thresholds, autonomy_level override, and the evaluation record format for auditability.

---

## 2. Definitions

**agent_id (a):** AgentID of the requesting agent. MUST comply with ACP-CT-1.0 §3.2 format.

**capability (c):** Capability identifier per ACP-CAP-REG-1.0.

**resource (r):** Target resource identifier.

**context (x):** Set of observable environment attributes at the time of the request.

**history (h):** Agent activity record in the previous 24-hour window.

**Risk Score (RS):** Integer in [0, 100]. Higher value indicates greater risk.

---

## 3. Risk Function

```
RS = min(100, B(c) + F_ctx(x) + F_hist(h) + F_res(r))
```

where:
- `B(c)` = capability baseline
- `F_ctx(x)` = contextual factor
- `F_hist(h)` = history factor
- `F_res(r)` = resource factor

---

## 4. Capability Baseline B(c)

Values defined in ACP-CAP-REG-1.0 §3. Summary:

| Capability | B(c) |
|------------|------|
| *.read, *.monitor | 0 |
| *.write, *.notify | 5–10 |
| financial.payment | 35 |
| financial.transfer | 40 |
| infrastructure.delete | 55 |
| agent.revoke | 40 |

For unknown extended capabilities: B(c) = 40.

---

## 5. Contextual Factor F_ctx(x)

Sum of applicable factors. Not bounded here — the `min(100,...)` in the main function is the cap.

| Condition | Value |
|-----------|-------|
| Outside institutional operational window | +15 |
| Non-business day (weekend or holiday) | +10 |
| Non-corporate source IP | +20 |
| Geolocation outside institutional domain | +25 |
| Timestamp drift > 300 seconds | +30 |
| No condition applies | 0 |

The institutional operational window is configurable. Default: 08:00–20:00 local institutional time.

---

## 6. History Factor F_hist(h)

Analysis window: previous 24 hours for the same `agent_id`.

| Condition | Value |
|-----------|-------|
| Denial rate > 10% in window | +15 |
| Unresolved escalations in window | +10 |
| Denial in the last 30 minutes | +20 |
| Anomalous request frequency (>3σ from agent baseline) | +15 |
| Requested amount > 80% of agent limit (if applicable) | +20 |
| No prior history for agent | +10 |
| No condition applies | 0 |

---

## 7. Resource Factor F_res(r)

Target resource classification:

| Classification | F_res |
|----------------|-------|
| public | 0 |
| internal | 5 |
| sensitive | 15 |
| critical | 30 |
| restricted | 45 |

The classification of each resource is the institution's responsibility and MUST be recorded in its resource directory. If a resource has no registered classification, it MUST be treated as `sensitive` (F_res = 15).

---

## 8. Decision Thresholds

| RS | Decision |
|----|----------|
| 0 – 39 | APPROVED |
| 40 – 69 | ESCALATED |
| 70 – 100 | DENIED |

---

## 9. Autonomy Level Override

The agent's autonomy_level modifies the effective thresholds:

| Autonomy Level | Description | APPROVED Threshold | ESCALATED Threshold |
|----------------|-------------|-------------------|---------------------|
| 0 | No autonomy | — | DENIED always |
| 1 | Minimal | 0–19 | 20–100 → ESCALATED |
| 2 | Standard | 0–39 | 40–69 → ESCALATED, 70+ → DENIED |
| 3 | Elevated | 0–59 | 60–79 → ESCALATED, 80+ → DENIED |
| 4 | Maximum | 0–79 | 80–89 → ESCALATED, 90+ → DENIED |

Autonomy level 0 MUST produce DENIED for any RS without executing the risk function.

---

## 10. Evaluation Record

Every evaluation MUST produce a record with the following structure for the Audit Ledger:

```json
{
  "eval_id": "<uuid>",
  "request_id": "<uuid>",
  "agent_id": "<AgentID>",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "baseline": 35,
  "f_ctx": 15,
  "f_hist": 0,
  "f_res": 15,
  "rs_final": 65,
  "decision": "ESCALATED",
  "threshold_config": {
    "approved_max": 39,
    "escalated_max": 69,
    "autonomy_level": 2
  },
  "factors_applied": [
    "f_ctx_ip_non_corporate",
    "f_res_sensitive"
  ]
}
```

The `factors_applied` field MUST list exactly the factors that contributed to the score. This allows the calculation to be reproduced from the record.

---

## 11. Extensibility

Institutions MAY add custom factors under the identifier `F_custom_<institution_id>`. These factors:

- MUST be documented internally
- MUST be included in the evaluation record
- MUST NOT modify the core factors defined in §5, §6, §7

---

## 12. Errors

| Code | Condition |
|------|-----------|
| RISK-001 | agent_id not registered |
| RISK-002 | Invalid capability per ACP-CAP-REG-1.0 |
| RISK-003 | Resource without classification (treated as sensitive) |
| RISK-004 | Context with missing required fields |
| RISK-005 | RS ≥ 70 — DENIED |
| RISK-006 | Autonomy level 0 — DENIED without evaluation |

---

## 13. Conformance

An implementation is ACP-RISK-1.0 conformant if it:

- Implements the Risk function with all defined factors
- Produces identical RS values for the same inputs (deterministic function)
- Applies thresholds with autonomy_level override
- Records each evaluation with the complete structure from §10
- Produces DENIED for autonomy_level 0 without executing the function
- Rejects requests with incomplete context (RISK-004)
