# ACP Sequence Test Vectors

Stateful, multi-step test cases for the ACP-RISK-2.0 execution contract.

These vectors test behaviors that require state accumulation across requests —
cooldown activation, F_anom Rule 3 pattern detection, threshold boundaries,
and privilege jumps. They cannot be validated with single-shot test runners.

## Format

Each file is a `TestCase` JSON object:

```json
{
  "id": "SEQ-XXX-001",
  "description": "...",
  "steps": [
    {
      "agent_id": "...",
      "capability": "acp:cap:...",
      "resource": "...",
      "resource_class": "public|sensitive|restricted",
      "context": { "external_ip": false, "off_hours": false, ... },
      "history": { "denial_rate_high": false, ... },
      "expected": {
        "decision": "APPROVED|ESCALATED|DENIED",
        "risk_score": 0,
        "denied_reason": "COOLDOWN_ACTIVE"
      }
    }
  ]
}
```

## Vectors

| ID | File | Steps | What it tests |
|----|------|-------|---------------|
| SEQ-COOLDOWN-001 | cooldown.json | 4 | 3×DENIED → cooldown; step 4 blocked |
| SEQ-FANOM-RULE3-001 | f_anom_rule3.json | 4 | Pattern accumulation → APPROVED→ESCALATED at step 4 |
| SEQ-BENIGN-001 | benign_flow.json | 3 | No false positives under repeated read |
| SEQ-BOUNDARY-001 | boundary.json | 3 | Exact thresholds: RS=35/40/70 |
| SEQ-PRIVJUMP-001 | privilege_jump.json | 2 | Low→high privilege jump caught by RS formula |

## Running

Use the ACR-1.0 sequence compliance runner:

```bash
cd compliance/runner
go run . --mode library --dir ../test-vectors/sequence
```

All 5 vectors: **5/5 PASS | CONFORMANT**

## Execution Contract

The runner implements the ACP-RISK-2.0 execution contract (§4):

```
1. Evaluate(req, querier)     — stateless, reads querier
2. AddRequest(agentID, now)   — always
3. AddPattern(patKey, now)    — always (feeds F_anom Rule 3)
4. AddDenial(agentID, now)    — only if DENIED
5. SetCooldown(agentID, exp)  — only if ShouldEnterCooldown
```
