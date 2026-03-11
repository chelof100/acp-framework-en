JSON Formal Schema for Test Vectors

Applies to: ACP-TS-1.1
Draft: 2020-12

1. Main Schema
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://acp.foundation/schemas/acp-test-vector-1.0.json",
  "title": "ACP Test Vector",
  "type": "object",
  "required": ["meta", "input", "context", "expected"],
  "additionalProperties": false,

  "properties": {

    "meta": {
      "type": "object",
      "required": [
        "id",
        "acp_version",
        "layer",
        "conformance_level",
        "description",
        "severity"
      ],
      "additionalProperties": false,
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^TS-[A-Z]+(-NEG)?-[0-9]+$"
        },
        "acp_version": {
          "type": "string",
          "enum": ["1.0", "1.1"]
        },
        "layer": {
          "type": "string",
          "enum": ["CORE", "ITA", "CONF", "PAY", "REP", "D"]
        },
        "conformance_level": {
          "type": "string",
          "enum": ["L1", "L2", "L3", "L4", "L5"]
        },
        "description": {
          "type": "string",
          "minLength": 10
        },
        "severity": {
          "type": "string",
          "enum": ["mandatory", "optional"]
        }
      }
    },

    "input": {
      "type": "object",
      "minProperties": 1
    },

    "context": {
      "type": "object",
      "required": ["current_time"],
      "additionalProperties": false,
      "properties": {

        "current_time": {
          "type": "integer",
          "minimum": 0
        },

        "revocation_list": {
          "type": "array",
          "items": { "type": "string" }
        },

        "trusted_issuers": {
          "type": "array",
          "items": { "type": "string" }
        },

        "reputation_scores": {
          "type": "object",
          "additionalProperties": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
          }
        },

        "payment_tokens": {
          "type": "array",
          "items": { "type": "string" }
        },

        "delegation_chain_depth": {
          "type": "integer",
          "minimum": 0
        }
      }
    },

    "expected": {
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
          "type": ["string", "null"],
          "enum": [
            null,
            "EXPIRED",
            "INVALID_SIGNATURE",
            "REVOKED",
            "UNTRUSTED_ISSUER",
            "PAYMENT_REQUIRED",
            "PAYMENT_REPLAY",
            "LOW_REPUTATION",
            "INTEGRITY_FAILURE",
            "DELEGATION_DEPTH",
            "MALFORMED_INPUT"
          ]
        }
      }
    }
  }
}
2. Normative Rules Outside the Schema

The JSON Schema validates structure.
But ACP requires additional rules:

2.1 Mandatory Canonicalization

Before signing or verifying:

UTF-8

Lexicographic key ordering

No extra whitespace

No undefined fields

No comments

If not compliant → immediate FAIL.

2.2 Level/Layer Consistency Rule

Implementations MUST verify:

Level	Permitted layers
L1	CORE
L2	CORE, ITA
L3	CORE, ITA, CONF
L4	CORE, ITA, CONF, PAY, REP
L5	All

A test with layer=PAY and level=L2 is invalid.

This is not covered by the JSON Schema.
The runner MUST validate it.

2.3 Temporal Determinism

All temporal logic uses context.current_time.

Using the system clock is prohibited.

3. Controlled Extensibility

If ACP 1.2 adds new error codes:

A new schema is published

New $id

New major schema version

Not modified retroactively.

4. CI Validation

In the official repository:

ajv validate -s acp-test-vector-1.0.json -d test-suite/**/*.json

If it fails → PR rejected.

5. Schema Version Hash

Each release MUST publish:

SHA256(acp-test-vector-1.0.json)

So that certifications indicate which version they validated against.
