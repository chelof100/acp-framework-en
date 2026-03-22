# ACP Payment-Agent Demo

The ACP value proposition in 30 seconds: **a financial agent tries to pay, ACP decides, the log is immutable.**

Specification reference: [arXiv:2603.18829](https://arxiv.org/abs/2603.18829)

---

## What this demo shows

```
PayAgent-001                      ACP (RISK-2.0 engine)           Ledger
──────────────────────────────────────────────────────────────────────────
POST /admission ─────────────────► Evaluate(req, querier)
                                    RS = B + F_ctx + F_hist + F_res + F_anom
                                    decision = threshold(RS, policy)
◄──────────────────────────────── {rs, decision, factors}  ──────► append(event)

  (repeat 3× DENIED in 10min)
                                    ShouldEnterCooldown() → true
                                    querier.SetCooldown(until +5min)

POST /admission ─────────────────► CooldownActive() → true
◄──────────────────────────────── {decision=DENIED, reason=COOLDOWN_ACTIVE}

GET /audit/agent/PayAgent-001 ───► filter ledger by agent_id
◄──────────────────────────────── {events[], cooldown, anomaly_summary}
```

**ACP-RISK-2.0 in action:**
- Every decision includes a full factor breakdown: `{base, context, history, resource, anomaly}`
- Any third party can recompute the score from `policy_hash` + inputs — no black box
- The ledger is append-only; events are never modified after writing
- Cooldown is deterministic: 3 DENIED in 10 min → block 5 min → ledger event

---

## Run

```bash
cd examples/payment-agent
go run .
# Server listening on :8080
```

Optional: `go run . -port 9090`

---

## Quick scenario

### 1. Baseline — low risk, APPROVED

```bash
curl -s -X POST http://localhost:8080/admission \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "acp:agent:org.example:PayAgent-001",
    "capability": "acp:cap:data.read",
    "resource": "org.example/reports/Q1",
    "resource_class": "public"
  }' | jq '{decision, risk_score, factors}'
```

Expected: `decision=APPROVED`, `risk_score=0`, all factors zero.

---

### 2. Payment from outside the corporate network — DENIED

```bash
curl -s -X POST http://localhost:8080/admission \
  -H 'Content-Type: application/json' \
  -d '{
    "capability": "acp:cap:financial.payment",
    "resource": "org.example/accounts/ACC-001",
    "resource_class": "restricted",
    "context": {"external_ip": true}
  }' | jq '{decision, risk_score, factors}'
```

Expected: `decision=DENIED`, `risk_score=100` (35+45+20=100, capped).

---

### 3. F_anom activates — repeated pattern detected

Send the same payment request 3× within a few seconds:

```bash
for i in 1 2 3; do
  curl -s -X POST http://localhost:8080/admission \
    -H 'Content-Type: application/json' \
    -d '{
      "capability": "acp:cap:financial.payment",
      "resource": "org.example/accounts/ACC-001",
      "resource_class": "restricted"
    }' | jq '{decision, risk_score, "anomaly_detail": .anomaly_detail}';
done
```

After 3 repeated DENIED, the cooldown triggers.

---

### 4. Cooldown — DENIED without risk evaluation

```bash
curl -s -X POST http://localhost:8080/admission \
  -H 'Content-Type: application/json' \
  -d '{"capability": "acp:cap:financial.payment", "resource_class": "restricted"}' \
  | jq '{decision, denied_reason}'
```

Expected: `decision=DENIED`, `denied_reason=COOLDOWN_ACTIVE`.

---

### 5. Audit trail — immutable log

```bash
curl -s http://localhost:8080/audit/agent/acp:agent:org.example:PayAgent-001 | jq '{total_count, cooldown, "anomaly_summary": .anomaly_summary}'
```

```bash
curl -s http://localhost:8080/ledger | jq '{total_events, append_only}'
```

---

## Policy (ACP-RISK-2.0 defaults)

| Parameter | Value | Description |
|---|---|---|
| `autonomy_level` | 2 | L2: APPROVED ≤39 / ESCALATED 40–69 / DENIED ≥70 |
| `approved_max` | 39 | RS threshold for autonomous approval |
| `escalated_max` | 69 | RS threshold for escalation (vs. denial) |
| `anomaly_rule1_n` | 10 | Rule 1: requests/60s > 10 → +20 |
| `anomaly_rule2_x` | 3 | Rule 2: denials/24h ≥ 3 → +15 |
| `anomaly_rule3_y` | 3 | Rule 3: pattern hits/5min ≥ 3 → +15 |
| `cooldown_denials` | 3 | Denials in 10min to trigger cooldown |
| `cooldown_period` | 300s | Cooldown duration |

---

## Risk score table

| Capability | Resource class | RS | Decision |
|---|---|---|---|
| `data.read` | public | 0 | APPROVED |
| `data.write` | public | 10 | APPROVED |
| `financial.payment` | public | 35 | APPROVED |
| `financial.payment` | sensitive | 50 | ESCALATED |
| `financial.payment` | restricted | 80 | DENIED |
| `financial.payment` | restricted + external_ip | 100 (capped) | DENIED |

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/admission` | Evaluate admission request (ACP-RISK-2.0) |
| `GET` | `/audit/agent/{id}` | Agent decision timeline (API endpoint 18) |
| `GET` | `/ledger` | Full append-only audit log |
| `GET` | `/health` | Server status |
