0 — Objective

Moving from:

"Secure under cryptographic model"

to:

"Resilient in a hostile distributed environment"

1 — Issuer Hardening (Critical Point)

The issuer is the heart of the system.
If it falls, everything falls.

1.1 Key Protection

The issuer MUST:

Run in HSM or secure enclave

Not expose the private key in application memory

Use isolated signing by process

Recommended:

Delegated signing via isolated module

Threshold signatures (e.g., 2-of-3)

1.2 Key Rotation

Define:

Key epoch = k_t

Token MUST include:

key_id

Verifier MUST:

Maintain list of active keys

Reject expired keys

Recommended rotation window:

30–90 days in critical production

1.3 Forward Containment

If key k_t is compromised:

MUST NOT allow signing tokens with exp > epoch_end

Mitigation:

Issuer MUST enforce exp ≤ epoch_expiration

2 — Verifier Hardening

This is where most implementations fail.

2.1 Atomic Verification

MUST guarantee:

Verify(token) AND Execute(resource)

as an indivisible operation.

If there is a delay:

Revalidate before execution.

2.2 Anti-Replay Protection

Verifier MUST:

Maintain distributed nonce cache

TTL = exp - now

In cluster:

Consistent cache

Or derive nonce as deterministic function of request_id

2.3 Deterministic Canonicalization

Before hashing:

JSON MUST be canonicalized

Fields ordered

No ambiguous whitespace

Strict UTF-8 encoding

Without this, the cryptographic model is irrelevant.

2.4 Anti-Downgrade

Verifier MUST:

Reject policy_version < min_supported

And that variable MUST NOT be dynamically configurable per request.

3 — Context Binding Hardening

Context_hash MUST include:

resource_id

HTTP method

environment_id

tenant_id

policy_version

optional security level

If any field is missing → possible lateral escalation.

4 — Lateral Movement Reduction

Recommended design:

Short TTL (5–15 min)

Tokens non-reusable across different endpoints

Strict subject binding

Ideal:

subject = cryptographic identity (mTLS cert fingerprint)

Not just a string.

5 — Side Channel Protection

Verifier MUST:

Use constant-time comparison

Unify error messages

Not reveal whether failure was due to:

Signature

Expiration

Policy

Subject mismatch

Single response:

403 Forbidden

No detail.

6 — Controlled Revocation

ACP favors short expiration, but in real systems you need revocation.

Options:

A) Short-lived tokens

Simple. Scalable.

B) Revocation list

MUST be signed and cached.

C) Online introspection

Reduces autonomy. Increases latency.

Practical recommendation:

Short TTL + revocation only for critical incidents.

7 — Distributed Trust Model

In multi-service systems:

Each service verifies token

None trusts another

There is no "implicit delegation"

Key rule:

No service may execute capability it cannot verify itself.

8 — Cryptographically Verifiable Audit

Each token issuance MUST be logged as:

H(token) stored in append-only log

Ideal:

Signed log

Or periodically anchored on public blockchain
(if you want to go to the extreme)

This prevents silent malicious issuance.

9 — Operational Security

Not cryptography, but critical:

Monitoring of issuance rate

Alerts for anomalous spikes

Detection of abnormal usage patterns

If a service starts using 10x more tokens → something is wrong.

10 — Resulting Maturity Level

After hardening:

| Area | Level |
|---|---|
| Forgery | Very high |
| Escalation | Very low |
| Replay | Controlled |
| Lateral movement | Limited |
| Issuer compromise | Contained |
| Downgrade | Blocked |
| Operational | Monitorable |
