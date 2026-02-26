# ACP Test Vectors

This directory contains official test vectors for ACP conformance testing, following the format defined in [`../compliance/ACP-TS-1.1.md`](../compliance/ACP-TS-1.1.md).

---

## Format

Each vector is a JSON file with four sections:

```json
{
  "meta":     { "id", "acp_version", "layer", "conformance_level", "description", "severity" },
  "input":    { ... object to evaluate ... },
  "context":  { "current_time", "revocation_list", "trusted_issuers", ... },
  "expected": { "decision", "error_code" }
}
```

All vectors use `context.current_time` — **never system time**.

Fixed reference timestamp used across all vectors: `1700000000` (2023-11-14T22:13:20Z).

---

## Test Key (for positive test cases)

Positive test vectors require a real Ed25519 signature over the canonicalized input.
The signatures in this directory are **placeholders** (`PLACEHOLDER:*`).

When a reference implementation is available, signatures will be replaced with actual values generated using the following test key pair:

```
# TEST KEY — DO NOT USE IN PRODUCTION
Private: d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f4475584
Public:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511
DID:     did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2
```

Negative test vectors with `INVALID_SIGNATURE` use `aGVsbG8gd29ybGQ=` (base64 of "hello world") as a deliberately wrong signature.

---

## Coverage

| File | Layer | Level | Type | Description |
|---|---|---|---|---|
| TS-CORE-POS-001 | CORE | L1 | Positive | Valid canonical capability |
| TS-CORE-POS-002 | CORE | L1 | Positive | Valid capability — expiry far future |
| TS-CORE-NEG-001 | CORE | L1 | Negative | Expired token |
| TS-CORE-NEG-002 | CORE | L1 | Negative | Missing expiry field |
| TS-CORE-NEG-003 | CORE | L1 | Negative | Missing nonce field |
| TS-CORE-NEG-004 | CORE | L1 | Negative | Invalid signature |
| TS-CORE-NEG-005 | CORE | L1 | Negative | Revoked token (jti in revocation list) |
| TS-CORE-NEG-006 | CORE | L1 | Negative | Untrusted issuer |
| TS-DCMA-POS-001 | CORE | L2 | Positive | Valid single-hop delegation chain |
| TS-DCMA-NEG-001 | CORE | L2 | Negative | Privilege escalation attempt |
| TS-DCMA-NEG-002 | CORE | L2 | Negative | Revoked delegator — chain invalid |
| TS-DCMA-NEG-003 | CORE | L2 | Negative | Delegation depth exceeded |

---

## Naming Convention

```
TS-{LAYER}-{POS|NEG}-{NNN}-{description}.json
```

---

## Validation

Vectors MUST validate against `../compliance/ACP-TS-SCHEMA-1.0.md`.

To run the compliance suite against an implementation: see `../compliance/ACR-1.0.md`.
