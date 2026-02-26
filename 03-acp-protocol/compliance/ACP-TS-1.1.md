ACP-TS-1.1
Normative Test Vector Format

Status: Normative
Applies to: ACP v1.0 / v1.1
Required for certification

This document defines the official format that every implementation MUST use to validate compliance against ACP.

No ambiguity. No creative freedom.

1. Design Principles

An ACP test vector MUST be:

Deterministic

Reproducible

Language-agnostic

Machine-executable

Versioned

2. General Test Vector Structure

Required format: canonicalized JSON UTF-8.

Structure:

{
  "meta": {},
  "input": {},
  "context": {},
  "expected": {}
}
3. meta Section

Describes the test.

{
  "meta": {
    "id": "TS-CORE-01",
    "acp_version": "1.1",
    "layer": "CORE",
    "conformance_level": "L1",
    "description": "Valid canonical capability",
    "severity": "mandatory"
  }
}

Required fields:

Field	Type	Description
id	string	Unique identifier
acp_version	string	1.0 or 1.1
layer	enum	CORE / ITA / CONF / PAY / REP / D
conformance_level	enum	L1-L5
severity	enum	mandatory / optional
4. input Section

Contains the object to evaluate.

CORE example:

{
  "input": {
    "capability": {
      "id": "cap-001",
      "subject": "did:example:alice",
      "action": "read",
      "resource": "doc-123",
      "expiry": 1893456000,
      "issuer": "did:example:authority",
      "signature": "BASE64_SIGNATURE"
    }
  }
}
5. context Section

Defines the deterministic environment.

Example:

{
  "context": {
    "current_time": 1700000000,
    "revocation_list": [],
    "trusted_issuers": [
      "did:example:authority"
    ],
    "reputation_scores": {
      "did:example:alice": 0.82
    },
    "payment_tokens": []
  }
}

Key rule:
The real system clock is never used. Always use context.current_time.

6. expected Section

Defines the required outcome.

Format:

{
  "expected": {
    "decision": "VALID",
    "error_code": null
  }
}

Possible decision values:

VALID

REJECT

ACCESS_GRANTED

ACCESS_DENIED

Possible error_code values:

EXPIRED

INVALID_SIGNATURE

REVOKED

UNTRUSTED_ISSUER

PAYMENT_REQUIRED

PAYMENT_REPLAY

LOW_REPUTATION

INTEGRITY_FAILURE

DELEGATION_DEPTH

MALFORMED_INPUT

7. Canonicalization Rules (Critical)

Before verifying a signature:

Lexicographic key ordering

UTF-8

No extra whitespace

No additional fields

If an implementation does not comply with this → automatic FAIL.

8. Mandatory Negative Test Vector

Example:

{
  "meta": {
    "id": "TS-CORE-NEG-01",
    "acp_version": "1.1",
    "layer": "CORE",
    "conformance_level": "L1",
    "description": "Missing expiry field",
    "severity": "mandatory"
  },
  "input": {
    "capability": {
      "id": "cap-002",
      "subject": "did:example:alice"
    }
  },
  "context": {
    "current_time": 1700000000
  },
  "expected": {
    "decision": "REJECT",
    "error_code": "MALFORMED_INPUT"
  }
}

Every implementation MUST:

Detect the missing field

Not crash

Return the correct code

9. Test Suite Signature

To prevent tampering:

Each version of the suite has a SHA-256 hash

Published in the official repository

Certification requires declaring the hash used

10. Execution Result

The implementation MUST generate:

{
  "implementation": "acp-go-impl",
  "version": "0.9.3",
  "tested_against": "ACP-TS-1.1",
  "test_suite_hash": "sha256:abc123...",
  "total_tests": 124,
  "passed": 124,
  "failed": 0,
  "conformance_level": "L4"
}

If failed > 0 → not conformant.
