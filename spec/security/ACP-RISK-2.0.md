# ACP-RISK-2.0
## Deterministic Risk Model Specification — Anomaly Detection and Cooldown Extension
**Status:** Draft
**Version:** 2.0
**Supersedes:** ACP-RISK-1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-CAP-REG-1.0
**Required-by:** ACP-API-1.0, ACP-LEDGER-1.3
**Date:** 2026-03-22

---

## 1. Scope

This document supersedes ACP-RISK-1.0. It extends the risk evaluation function with:

1. **F_anom** — a deterministic anomaly factor based on three counting rules
2. **Cooldown mechanism** — a temporary block state for agents exhibiting sustained denial patterns
3. **Factor breakdown** — a mandatory extended evaluation record enabling full forensic reproducibility

All additions preserve the core invariant: **deterministic, auditable, reproducible with the same inputs and a signed policy**.

---

## 2. Definitions

Definitions from ACP-RISK-1.0 §2 apply without change. Additional definitions:

**anomaly (a):** Observable behavioral pattern derived from the request stream and audit ledger, evaluated via F_anom.

**pattern_key:** A derived identifier encoding the tuple (agent_id, capability, resource), used for repeat-pattern detection. Computed as:
```
pattern_key = SHA-256(agent_id || "|" || capability || "|" || resource)
```
Truncated to 32 hex characters for storage.

**sliding window:** A time window anchored to the moment of evaluation, not to fixed clock boundaries (e.g., not "this minute" but "the 60 seconds ending now").

**cooldown_period:** A configurable duration during which an agent's requests are automatically DENIED without executing the risk function. Recorded as explicit agent state in the Audit Ledger.

**policy_hash:** SHA-256 of the active signed policy document. MUST be included in every evaluation record.

---

## 3. Risk Function

```
RS = min(100, B(c) + F_ctx(x) + F_hist(h) + F_res(r) + F_anom(a))
```

where:
- `B(c)` = capability baseline (unchanged from ACP-RISK-1.0 §4)
- `F_ctx(x)` = contextual factor (unchanged from ACP-RISK-1.0 §5)
- `F_hist(h)` = history factor (unchanged from ACP-RISK-1.0 §6)
- `F_res(r)` = resource factor (unchanged from ACP-RISK-1.0 §7)
- `F_anom(a)` = **anomaly factor (new in v2.0, defined in §3.1)**

The evaluation MUST check for active cooldown (§3.5) before executing this function. If an agent is in cooldown, the function is not executed.

---

### 3.1 Anomaly Factor F_anom(a)

F_anom is the sum of applicable rule contributions. All rules operate on integer counts derived exclusively from the Audit Ledger. No floating-point arithmetic. No machine learning. No external state.

```
F_anom(a) = Rule1(a) + Rule2(a) + Rule3(a)
```

**Rule 1 — High Request Rate**
```
if count(requests[agent_id], sliding_window=60s) > N → +20
else → 0
```
- `N` is defined in the signed policy (default: 10)
- Window is sliding (anchored to now), not fixed-bucket
- Counts all requests in the Audit Ledger for this agent_id in the window

**Rule 2 — Recent Denials**
```
if count(events[agent_id, decision=DENIED], last_24h) ≥ X → +15
else → 0
```
- `X` is defined in the signed policy (default: 3)
- Includes DENIED events from both autonomy_level override and threshold evaluation
- Window: 24 hours ending at evaluation timestamp

**Rule 3 — Repeated Pattern**
```
pattern_key = SHA-256(agent_id || "|" || capability || "|" || resource)
if count(events[pattern_key], last_5min) ≥ Y → +15
else → 0
```
- `Y` is defined in the signed policy (default: 3)
- Window: sliding 5 minutes ending at evaluation timestamp
- No fuzzy matching. No semantic equivalence. No ML. Exact hash equality only.

**Maximum contribution:** F_anom ≤ 50 (all three rules triggered simultaneously).

---

### 3.2 Capability Baseline B(c)

Unchanged from ACP-RISK-1.0 §4.

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

### 3.3 Contextual Factor F_ctx(x)

Unchanged from ACP-RISK-1.0 §5.

| Condition | Value |
|-----------|-------|
| Outside institutional operational window | +15 |
| Non-business day (weekend or holiday) | +10 |
| Non-corporate source IP | +20 |
| Geolocation outside institutional domain | +25 |
| Timestamp drift > 300 seconds | +30 |
| No condition applies | 0 |

---

### 3.4 History Factor F_hist(h) and Resource Factor F_res(r)

Unchanged from ACP-RISK-1.0 §6 and §7 respectively.

---

### 3.5 Cooldown Mechanism

The Decision Engine MUST evaluate cooldown state before executing the risk function.

**Trigger condition:**
```
if count(events[agent_id, decision=DENIED], last_10min) ≥ 3:
    → enter COOLDOWN state for cooldown_period (policy-defined, default: 5 min)
```

**During cooldown:**
- All requests from the agent_id → DENIED automatically
- The risk function is NOT executed
- The decision = "DENIED" with reason = "COOLDOWN_ACTIVE"
- A DECISION event is recorded in the Audit Ledger with cooldown metadata

**Cooldown agent state record** (appended to Audit Ledger on entry):
```json
{
  "event_type": "AGENT_STATE_CHANGE",
  "agent_id": "A1",
  "previous_status": "ACTIVE",
  "new_status": "COOLDOWN",
  "until": "2026-03-22T15:30:00Z",
  "triggered_by": "3_DENIED_in_10min",
  "policy_hash": "abc123..."
}
```

**Exit from cooldown:**
- Automatic at `until` timestamp
- An AGENT_STATE_CHANGE event with new_status = "ACTIVE" MUST be recorded

**Design rationale:** Cooldown is an explicit, observable agent state. Any audit can reconstruct exactly why and for how long an agent was blocked. This is not a silent throttle — it is a formal state in the governance model.

---

## 4. Decision Thresholds

Unchanged from ACP-RISK-1.0 §8. Applied after F_anom contribution.

| RS | Decision |
|----|----------|
| 0 – 39 | APPROVED |
| 40 – 69 | ESCALATED |
| 70 – 100 | DENIED |

---

## 5. Autonomy Level Override

Unchanged from ACP-RISK-1.0 §9.

| Autonomy Level | Description | APPROVED Threshold | ESCALATED Threshold |
|----------------|-------------|-------------------|---------------------|
| 0 | No autonomy | — | DENIED always |
| 1 | Minimal | 0–19 | 20–100 → ESCALATED |
| 2 | Standard | 0–39 | 40–69 → ESCALATED, 70+ → DENIED |
| 3 | Elevated | 0–59 | 60–79 → ESCALATED, 80+ → DENIED |
| 4 | Maximum | 0–79 | 80–89 → ESCALATED, 90+ → DENIED |

---

## 6. Evaluation Record (Extended)

Every evaluation MUST produce a record with the following structure. The `factors` object (new in v2.0) enables forensic reproducibility: any third party with the Audit Ledger and signed policy can recalculate RS and verify it matches.

```json
{
  "eval_id": "<uuid>",
  "request_id": "<uuid>",
  "agent_id": "acp:agent:org.example:PayAgent-001",
  "capability": "acp:cap:financial.payment",
  "resource": "org.example/accounts/ACC-001",
  "timestamp": "2026-03-22T14:00:00Z",
  "factors": {
    "base": 35,
    "context": 20,
    "history": 0,
    "resource": 15,
    "anomaly": 15
  },
  "rs_raw": 85,
  "rs_final": 85,
  "decision": "DENIED",
  "threshold_config": {
    "approved_max": 39,
    "escalated_max": 69,
    "autonomy_level": 2
  },
  "factors_applied": [
    "f_ctx_ip_non_corporate",
    "f_res_restricted",
    "f_anom_rule2_recent_denials"
  ],
  "anomaly_detail": {
    "rule1_triggered": false,
    "rule1_count": 4,
    "rule1_threshold": 10,
    "rule2_triggered": true,
    "rule2_count": 3,
    "rule2_threshold": 3,
    "rule3_triggered": false,
    "rule3_count": 1,
    "rule3_threshold": 3,
    "pattern_key": "a3f8bc12..."
  },
  "cooldown_active": false,
  "policy_hash": "sha256:d4e5f6..."
}
```

**Notes:**
- `rs_raw` = sum before min(100,...) cap. `rs_final` = effective RS after cap.
- `anomaly_detail` MUST be present on every evaluation (even when no anomaly rule triggers), to enable verification that rules were evaluated correctly.
- `cooldown_active` MUST be `true` when the record is generated due to cooldown (in which case factors, rs_raw, rs_final, and threshold_config MUST be omitted or null — the function was not executed).
- `policy_hash` MUST reference the signed policy version active at evaluation time.

---

## 7. Extensibility

Unchanged from ACP-RISK-1.0 §11. Institutions MAY add custom anomaly rules as `F_anom_custom_<institution_id>`. These:

- MUST be deterministic (integer inputs → integer output)
- MUST be documented in the signed policy
- MUST appear in `factors_applied` and `anomaly_detail`
- MUST NOT replace or modify Rules 1–3

---

## 8. Errors

Extends ACP-RISK-1.0 §12.

| Code | Condition |
|------|-----------|
| RISK-001 | agent_id not registered |
| RISK-002 | Invalid capability per ACP-CAP-REG-1.0 |
| RISK-003 | Resource without classification (treated as sensitive) |
| RISK-004 | Context with missing required fields |
| RISK-005 | RS ≥ 70 — DENIED |
| RISK-006 | Autonomy level 0 — DENIED without evaluation |
| RISK-007 | Agent in COOLDOWN state — DENIED without risk function execution |
| RISK-008 | Audit Ledger unavailable — evaluation MUST be rejected (fail-closed) |
| RISK-009 | policy_hash mismatch — evaluation MUST be rejected |

**RISK-008 design note:** F_anom depends on the Audit Ledger. If the ledger is unavailable, the anomaly factor cannot be computed. ACP-RISK-2.0 mandates fail-closed: reject the request rather than evaluate without anomaly data.

---

## 9. Migration from ACP-RISK-1.0

Implementations upgrading from v1.0 to v2.0:

1. Add F_anom computation using ledger counts (§3.1)
2. Add cooldown state tracking (§3.5)
3. Extend evaluation records with `factors`, `anomaly_detail`, and `policy_hash` (§6)
4. Update error handling to include RISK-007, RISK-008, RISK-009

Backward compatibility: RS values for requests where F_anom = 0 and no cooldown is active are identical to ACP-RISK-1.0 outputs for the same inputs.

---

## 10. Conformance

An implementation is ACP-RISK-2.0 conformant if it:

- Implements the extended Risk function with all five factors (B, F_ctx, F_hist, F_res, F_anom)
- Implements F_anom using exactly Rules 1–3 with sliding windows (no fixed-bucket approximation)
- Computes pattern_key as SHA-256(agent_id || "|" || capability || "|" || resource)
- Evaluates cooldown state before executing the risk function
- Records AGENT_STATE_CHANGE events on cooldown entry and exit
- Produces DENIED with reason "COOLDOWN_ACTIVE" for all requests during cooldown
- Produces identical RS values for the same inputs and same policy (deterministic)
- Records every evaluation with the complete structure from §6 including anomaly_detail
- Applies fail-closed behavior when the Audit Ledger is unavailable (RISK-008)
- Rejects evaluations when policy_hash cannot be verified (RISK-009)
- Rejects requests with incomplete context (RISK-004)
- Produces DENIED for autonomy_level 0 without executing the function (RISK-006)

---

## Appendix A — Policy Configuration Parameters

The following parameters MUST be defined in the signed policy document referenced by policy_hash:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `risk.anom.rule1.threshold_N` | 10 | Request count threshold for Rule 1 (60s window) |
| `risk.anom.rule2.threshold_X` | 3 | Denial count threshold for Rule 2 (24h window) |
| `risk.anom.rule3.threshold_Y` | 3 | Pattern count threshold for Rule 3 (5min window) |
| `risk.cooldown.trigger_denials` | 3 | Denials in 10 min that trigger cooldown |
| `risk.cooldown.period_seconds` | 300 | Cooldown duration in seconds |

All policy changes MUST produce a new policy_hash. Evaluation records MUST reference the policy_hash active at evaluation time — this allows reconstruction of thresholds used in any historical evaluation.
