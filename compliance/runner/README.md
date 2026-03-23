# ACR-1.0 Sequence Compliance Runner

Validates ACP-RISK-2.0 implementations against stateful, multi-step test sequences.

ACP is not just a decision engine — it is the combination of a stateless evaluation function,
a state model, and an execution contract that governs how state evolves across requests.
This runner implements that contract, making the system testable and verifiable by third parties.

## Modes

| Mode | Description |
|------|-------------|
| `library` | Direct call to `pkg/risk.Evaluate()` — no network, deterministic, CI-ready |
| `http` | POST JSON to an external ACP server — interoperability validation |

## Usage

```bash
# Library mode (default — runs against the Go reference implementation)
go run . --mode library --dir ../test-vectors/sequence

# HTTP mode (validate an external server)
go run . --mode http --url http://localhost:8080 --dir ../test-vectors/sequence

# With report output and strict exit code
go run . --mode library --dir ../test-vectors/sequence --out report.json --strict
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `library` | `library` or `http` |
| `--url` | `http://localhost:8080` | Base URL for HTTP mode |
| `--dir` | `testcases` | Directory containing `.json` test case files |
| `--out` | `""` | Write JSON report to this file (empty = skip) |
| `--strict` | `false` | Exit 1 if any test case fails |

## Execution Contract (ACP-RISK-2.0 §4)

The runner implements the execution contract defined by ACP-RISK-2.0.
Steps must execute in this order on every request:

```
1. Evaluate(req, querier)      — stateless; reads querier state
2. AddRequest(agentID, now)    — always; records request timestamp
3. AddPattern(patKey, now)     — always; feeds F_anom Rule 3
4. AddDenial(agentID, now)     — only if DENIED
5. SetCooldown(agentID, exp)   — only if ShouldEnterCooldown returns true
```

**Critical timing fact:** `AddPattern()` runs *after* `Evaluate()`, so the pattern count
visible to step N's evaluation is N-1. F_anom Rule 3 (count ≥ 3) therefore first
triggers on step 4, not step 3. Test vectors are designed accordingly.

## Test Cases

Test case files are JSON objects with `id`, `description`, and `steps`:

```json
{
  "id": "SEQ-EXAMPLE-001",
  "description": "Human-readable description",
  "steps": [
    {
      "agent_id": "agent-A",
      "capability": "acp:cap:data.read",
      "resource": "public-bucket",
      "resource_class": "public",
      "context": { "external_ip": false, "off_hours": false },
      "history": { "denial_rate_high": false, "recent_denial": false },
      "expected": {
        "decision": "APPROVED",
        "risk_score": 0
      }
    }
  ]
}
```

The `expected.denied_reason` field is optional and only checked when present
(use `"COOLDOWN_ACTIVE"` for cooldown assertions).

### Bundled sequence vectors

| ID | Steps | Behavior tested |
|----|-------|-----------------|
| `SEQ-BENIGN-001` | 3 | No false positives under repeated benign reads |
| `SEQ-BOUNDARY-001` | 3 | Exact decision thresholds: RS = 0 / 25 / 35 / 40 / 70 |
| `SEQ-PRIVJUMP-001` | 2 | Low→high privilege jump caught immediately |
| `SEQ-FANOM-RULE3-001` | 4 | Pattern accumulation → APPROVED→ESCALATED at step 4 |
| `SEQ-COOLDOWN-001` | 4 | 3×DENIED → cooldown; step 4 blocked with `COOLDOWN_ACTIVE` |

All 5/5 pass against the Go reference implementation in library mode.

## Adding New Vectors

1. Create a `.json` file in `../test-vectors/sequence/` (canonical) or `testcases/` (local).
2. Set a unique `id` (format: `SEQ-<SCENARIO>-<NNN>`).
3. Define `steps` with `expected.decision` and `expected.risk_score` per step.
4. Run `go run . --mode library --dir ../test-vectors/sequence --strict` to validate.

## Architecture

```
compliance/runner/
├── main.go       — entry point; dispatches by mode
├── cli.go        — Config struct, parseFlags()
├── backend.go    — Backend interface: Evaluate(RunnerRequest) + Reset()
├── library.go    — LibraryBackend: pkg/risk + full execution contract
├── http.go       — HTTPBackend: POST JSON, Reset is no-op
├── loader.go     — loadTestCases(dir): reads sorted .json files
├── report.go     — runTestCase, validateStep, buildReport, printSummary, writeReport
└── types.go      — RunnerContext, RunnerRequest, Step, TestCase, ACPResponse, Report
```

The runner is a **separate Go module** (`github.com/chelof100/acp-framework/compliance/runner`)
with a `replace` directive pointing to `../../impl/go`, so it uses the local engine
without requiring a published module version.
