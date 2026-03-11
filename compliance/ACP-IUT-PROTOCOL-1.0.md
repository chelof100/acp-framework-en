# ACP IUT Protocol — ACP-IUT-PROTOCOL-1.0

**Official Runner ↔ Implementation Under Test Protocol**

**Status:** Normative
**Compatible with:** ACR-1.0 / ACP-TS-1.1

## 1. Communication Channel

**Mandatory mode:**

| Channel | Usage |
|---------|-------|
| Input | STDIN |
| Output | STDOUT |
| Errors | STDERR |

- Format: JSON UTF-8
- Single JSON object per execution
- No logs on STDOUT
- Any extra text on STDOUT → automatic FAIL

## 2. Input to the IUT

The runner sends exactly the complete test vector:

```json
{
  "meta": {...},
  "input": {...},
  "context": {...},
  "expected": {...}
}
```

**Rules:**

- Canonicalized
- No modifications
- No fields removed
- The IUT MUST ignore `expected`

## 3. Mandatory IUT Output

**Strict format:**

```json
{
  "decision": "VALID",
  "error_code": null
}
```

**Formal response schema:**

```json
{
  "type": "object",
  "required": ["decision", "error_code"],
  "additionalProperties": false,
  "properties": {
    "decision": {
      "type": "string",
      "enum": [
        "VALID",
        "REJECT",
        "ACCESS_GRANTED",
        "ACCESS_DENIED"
      ]
    },
    "error_code": {
      "type": ["string", "null"]
    }
  }
}
```

**Failure conditions:**

| Condition | Result |
|-----------|--------|
| Missing fields | FAIL |
| Extra fields | FAIL |
| Invalid JSON | FAIL |
| Timeout | FAIL |
| Exit code ≠ 0 | FAIL |

## 4. Exit Codes

The IUT MUST use:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Evaluation completed correctly |
| ≠ 0 | Internal error |

If exit ≠ 0 → Runner marks FAIL even if JSON appears valid.

## 5. Timeout

Maximum time per test:

- Default: 2000 ms
- Configurable

If timeout is exceeded → FAIL + CRASH flag.

## 6. Optional Batch Mode (Not Required)

For performance mode, the IUT may support:

```
acp-evaluate --batch
```

**Input:**

```json
{
  "batch": [
    { "...test_vector_1..." },
    { "...test_vector_2..." }
  ]
}
```

**Output:**

```json
{
  "results": [
    { "decision": "...", "error_code": "..." },
    { "decision": "...", "error_code": "..." }
  ]
}
```

If implemented, it MUST be declared in the manifest.

## 7. Implementation Manifest

The IUT MUST expose:

```
acp-evaluate --manifest
```

**Output:**

```json
{
  "implementation_name": "acp-go-impl",
  "implementation_version": "0.9.3",
  "supported_acp_version": "1.1",
  "max_conformance_level": "L4",
  "supports_batch": true
}
```

The runner uses this to validate consistency.

## 8. Protocol Security

**Mandatory:**

- No execution of external code from input
- No writes outside sandbox
- No network calls during evaluation
- Full determinism

If network activity is detected → FAIL in strict mode.
