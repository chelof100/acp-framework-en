# ACP Compliance Runner — ACR-1.0

**Version:** 1.0
**Compatible with:** ACP-TS-1.1
**Objective:** Execute test vectors and certify conformance L1–L5

## 1. Principles

The runner MUST be:

- Deterministic
- Reproducible
- Language-independent
- Automatable in CI
- Not coupled to any specific implementation

The runner does not implement ACP.
It validates that an implementation does so correctly.

## 2. Integration Model

The runner interacts with the implementation under test (IUT – Implementation Under Test) through a standard interface.

**Mandatory option: CLI Adapter**

The implementation MUST expose a command:

```bash
acp-evaluate < test-vector.json
```

MUST return:

```json
{
  "decision": "VALID",
  "error_code": null
}
```

**The runner:**

1. Loads test vector
2. Validates against JSON Schema
3. Executes IUT
4. Compares output with `expected`
5. Records result

## 3. Runner Architecture

```
ACP Compliance Runner
│
├── Loader
├── Schema Validator
├── Context Injector
├── Execution Engine
├── Comparator
├── Report Generator
└── Certification Engine
```

## 4. Execution Flow

For each test vector:

1. Validate JSON against schema
2. Verify layer/level consistency
3. Serialize canonical JSON
4. Send to IUT
5. Parse response
6. Compare with `expected`
7. Record PASS / FAIL

## 5. Official Runner CLI

```bash
acp-runner run \
  --impl ./acp-evaluate \
  --suite ./test-suite \
  --level L4 \
  --report report.json
```

**Options:**

| Flag | Description |
|------|-------------|
| `--impl` | Path to IUT executable |
| `--suite` | Test suite directory |
| `--level` | L1–L5 |
| `--layer` | Run specific layer |
| `--strict` | Fail if there are warnings |
| `--performance` | Run benchmarks |

## 6. Comparison Engine

**Strict comparison:**

```
expected.decision == actual.decision
expected.error_code == actual.error_code
```

Any difference → FAIL.

No tolerance.

## 7. Global Result

**Final output:**

```json
{
  "implementation": "acp-go-impl",
  "implementation_version": "0.9.3",
  "acp_version": "1.1",
  "tested_level": "L4",
  "test_suite_hash": "sha256:abc123...",
  "total_tests": 124,
  "passed": 124,
  "failed": 0,
  "failed_tests": [],
  "timestamp": "2026-02-25T10:22:00Z",
  "status": "CONFORMANT"
}
```

If `failed > 0` → `status = NON_CONFORMANT`

## 8. Performance Mode

In performance mode:

```bash
acp-runner run --performance
```

Executes:

- 10k consecutive validations
- Measures average latency
- Measures p95
- Measures throughput
- Measures memory usage

**Result:**

```json
{
  "latency_avg_ms": 2.8,
  "latency_p95_ms": 4.1,
  "throughput_per_sec": 12400,
  "memory_mb": 32
}
```

Does not affect functional conformance, but is required for public certification.

## 9. Automatic Certification

If:

- 100% mandatory tests PASS
- No schema errors
- No crashes
- Minimum performance met

The runner generates:

```json
{
  "protocol": "ACP",
  "version": "1.1",
  "level": "L4",
  "certification_id": "ACP-CERT-2026-0007",
  "test_suite_hash": "...",
  "runner_version": "1.0",
  "issued_at": "2026-02-25"
}
```

Digitally signed by the ACP Certification Authority (governance entity to be defined by the community — see ACP-CERT-1.0 §7).

## 10. Runner Security Rules

The runner MUST:

- Execute IUT in sandbox
- Limit time per test (e.g., 2s timeout)
- Detect crashes
- Detect invalid JSON outputs
- Detect disallowed additional output

If IUT prints logs mixed with JSON → FAIL.

## 11. CI/CD Mode

**GitHub Actions example:**

```yaml
- name: Run ACP Compliance
  run: |
    acp-runner run \
      --impl ./bin/acp-evaluate \
      --suite ./test-suite \
      --level L4
```

If `status != CONFORMANT` → pipeline fails.

## 12. Runner Versioning

- ACP-CR-1.x compatible with ACP-TS-1.1
- New major version if protocol changes
- Runner never modifies historical test suite

## 13. Strategic Result

With this, ACP obtains:

- ✔ Objective verification
- ✔ Reproducible certification
- ✔ Automatic CI integration
- ✔ Solid defense under academic review
- ✔ Real foundation for enterprise adoption
