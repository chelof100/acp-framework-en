ACP Test Suite & Compliance Specification

Status: Draft
Version: 1.0
Applies to: ACP v1.0 and v1.1

1. Objective

Define:

How to validate that an implementation complies with ACP.

What minimum test cases it MUST pass.

How to certify L1 → L5.

How to automate verification.

Without this, ACP is only a theoretical specification.

2. Conformance Model

ACP defines cumulative levels (see ACP-CONF-1.1 for normative definition):

Level	Name	        Requires
L1	CORE	        SIGN + CT + CAP-REG + HP
L2	SECURITY	L1 + RISK + REV + ITA-1.0
L3	FULL	        L2 + API + EXEC + LEDGER
L4	EXTENDED	L3 + PAY + REP + ITA-1.1
L5	DECENTRALIZED	L4 + ACP-D + ITA-1.1 BFT

An implementer declares:

{
  "acp_version": "1.1",
  "conformance_level": "L4"
}

The suite validates that it actually complies.

3. Test Suite Structure

Expected directory layout:

acp-test-suite/
 ├── core/
 ├── ita/
 ├── dcma/
 ├── pay/
 ├── rep/
 ├── operations/
 ├── integration/
 ├── negative/
 └── performance/

Each module contains:

test vector JSON

expected result

failure mode

rationale

4. CORE — Test Vectors

> **Editorial note:** The input examples in this section use a simplified, illustrative format.
> The normative and deterministic format for implementations is defined in **ACP-TS-1.1**
> (`{meta, input, context, expected}` with a fixed `context.current_time`).
> Production test vectors are located in `/test-vectors/` (ACP-TS-1.1 format).

TS-CORE-01

Canonical Capability Validation

Input:

{
  "id": "cap-001",
  "subject": "did:example:alice",
  "action": "read",
  "resource": "doc-123",
  "expiry": 1893456000,
  "issuer": "did:example:authority",
  "signature": "<valid_signature>"
}

Expected:

VALID
TS-CORE-02

Expired Capability

expiry < current_time

Expected:

REJECT: EXPIRED
TS-CORE-03

Invalid Signature

Expected:

REJECT: INVALID_SIGNATURE
TS-CORE-04

Revoked Capability

If present in revocation list:

REJECT: REVOKED
5. ITA — Identity & Trust
TS-ITA-01

Valid DID resolution

Expected:

IDENTITY_RESOLVED
TS-ITA-02

Trust anchor mismatch

Expected:

REJECT: UNTRUSTED_ISSUER
6. Operations — L3 (API, EXEC, LEDGER)
TS-OPS-01

Execution Token issued only after AuthorizationDecision APPROVED

Expected:

ET_ISSUED
TS-OPS-02

Execution Token consumed — reuse attempt

Expected:

REJECT: ET_ALREADY_USED
TS-OPS-03

Audit Ledger — attempt to modify an existing event

Expected:

REJECT: LEDGER_IMMUTABLE
7. PAY — Payment Layer
TS-PAY-01

Payment required, token present

Expected:

PAYMENT_VALID
TS-PAY-02

Payment required, token missing

Expected:

REJECT: PAYMENT_REQUIRED
TS-PAY-03

Payment replay attempt

Expected:

REJECT: PAYMENT_REPLAY
8. REP — Reputation Layer
TS-REP-01

Reputation above threshold

Expected:

ACCESS_GRANTED
TS-REP-02

Reputation below threshold

Expected:

REJECT: LOW_REPUTATION
9. ACP-D — Distributed Mode (L5)
TS-D-01

Cross-domain delegation

Expected:

DELEGATION_CHAIN_VALID
TS-D-02

Delegation depth exceeded

Expected:

REJECT: DELEGATION_DEPTH
10. Negative Testing (Mandatory)

All levels MUST pass:

malformed JSON

missing fields

future-issued capability

duplicate ID reuse

signature over modified payload

11. Integration Scenarios
Scenario 1 — Full L4 Flow

Identity verified (ITA)

Capability validated (CORE)

Payment verified (PAY)

Reputation checked (REP)

Access granted

Expected:

ACCESS_GRANTED
Scenario 2 — Economic Attack

Valid capability

Payment replayed

Reputation manipulated

Expected:

ACCESS_DENIED
12. Performance Benchmarks

Implementations are required to publish:

Metric	Target
Capability validation latency	< 5 ms
Signature verification	< 3 ms
Payment token verification	< 5 ms
Throughput	≥ 10k validations/sec
Memory footprint	< 50MB baseline

Measured on:

CPU: x86_64

RAM: 16GB

Linux kernel 5+

13. Conformance Certification

A system MAY declare:

ACP v1.1 - Conformant L4

only if:

Passes 100% of the mandatory test suite for that level

Passes 100% of negative tests

Publishes a reproducible benchmark

14. Compliance Badge Schema

Verifiable certification:

{
  "protocol": "ACP",
  "version": "1.1",
  "level": "L4",
  "test_suite_hash": "sha256:....",
  "certified_on": "2026-02-25",
  "issuer": "ACP-CA"
}
15. Direct Impact

With this:

✔ ACP is no longer just a specification
✔ Implementers can validate compliance
✔ Formal certification is enabled
✔ Credible presentation before IEEE / NDSS becomes possible
