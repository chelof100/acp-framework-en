A Cryptographically Verifiable Authorization Architecture
Abstract

Authorization by Cryptographic Capability (ACP) is an authorization architecture that models access rights as explicit cryptographic artifacts rather than implicit permissions derived from roles or centralized policy evaluation. ACP binds authorization to context, enforces temporal validity, and enables local verification through standard cryptographic primitives. This paper formalizes the doctrinal foundations, technical specification, cryptographic construction, adversarial model, and system-level guarantees of ACP.

1. Introduction

Authorization systems traditionally rely on role assignments, access control lists, or centralized policy engines. These approaches suffer from structural weaknesses:

Implicit privilege inheritance

Accumulated permissions over time

Contextual ambiguity

Limited formal verifiability

ACP proposes a different paradigm:

Authorization is an explicit, cryptographically verifiable object.

Each operation requires a signed capability describing exactly what is allowed, under which context, and for how long.

This document presents the doctrinal foundation and technical construction of ACP.

2. Foundational Doctrine of ACP

ACP is built upon three structural principles. These principles define the logical and security boundaries of the system.

2.1 Pillar I — Principle of Explicit Authorization
Statement

No action within the system is valid without explicit cryptographic authorization specific to that action.

Formally:

Execute(op) ⇒ ∃ Capability(op)

Where Capability(op) is a cryptographically verifiable token authorizing operation op.

Conceptual Implication

Traditional authorization attaches permissions to identities. ACP attaches authorization to operations.

RBAC model:

User ∈ Role ⇒ Permission

ACP model:

Operation ⇒ Requires Capability

Authorization is no longer inferred from membership but demonstrated via evidence.

Security Invariant
¬Capability(op) ⇒ ¬Execute(op)

No execution occurs without explicit authorization.

2.2 Pillar II — Strict Contextual Binding
Statement

Every capability MUST be cryptographically bound to the precise execution context for which it was issued.

Context Definition

The execution context includes:

Resource identifier

Operation or method

Environment identifier

Tenant identifier

Policy version

Optional fields may include security level or cryptographic subject identity.

Formalization

Let:

context_hash = H(context)

The capability signs this hash as part of its payload.

Under collision resistance and deterministic serialization:

context₁ ≠ context₂ ⇒ H(context₁) ≠ H(context₂)
Security Invariant
Valid(T, C₁) ∧ C₁ ≠ C₂ ⇒ Invalid(T, C₂)

A capability valid in one context cannot be reused in another.

2.3 Pillar III — Cryptographic Verifiability
Statement

Authorization validity MUST be verifiable locally through standard cryptographic primitives without requiring centralized policy evaluation.

Reduction Principle

Security of ACP reduces to the security of:

Digital signature scheme (EUF-CMA secure)

Collision-resistant hash function

Sufficiently random nonce generation

Formally:

Security(ACP) ≤ Security(Signature)

Given correct implementation constraints.

Deterministic Verification

Verification requires only:

Public key

Token

Deterministic decoding

No dynamic global policy lookup is required.

Security Invariant
Verify(pk, T) = true
is necessary for execution.
2.4 Structural Interdependence

The three pillars are mutually dependent:

Without explicit authorization → privilege inference reappears.

Without contextual binding → lateral reuse becomes possible.

Without cryptographic verifiability → authorization depends on mutable state.

Together they establish ACP as a capability-based authorization model grounded in cryptographic evidence.

3. System Architecture

ACP consists of:

Issuer

Verifier

Client

Resource

The Issuer signs capabilities.
The Verifier validates tokens locally before execution.
Each service verifies independently.

4. Capability Token Construction
4.1 Token Payload
m = Encode(
    subject,
    resource,
    context_hash,
    exp,
    nonce,
    policy_version,
    key_id
)
4.2 Signature
T = Sign_sk(m)

Recommended primitives:

Ed25519

SHA-256

CSPRNG ≥ 128-bit entropy

5. Security Model

Let:

T = Sign_skI(m)

The system is secure if:

Pr[Forge ∨ Escalate ∨ Replay ∨ Rebind] ≤ ε

Where ε is negligible under standard cryptographic assumptions.

6. Security Reduction

If an adversary can forge a valid ACP token, then the adversary can forge a signature under the underlying signature scheme.

Therefore:

ACP is existentially unforgeable under chosen-message attack assuming the signature scheme is secure.

The reduction is tight under perfect oracle simulation.

7. Adversarial Analysis

Evaluated threats include:

Token forgery

Replay attacks

Privilege escalation

Confused deputy

Policy downgrade

Lateral movement

Issuer compromise

Mitigations rely on nonce tracking, strict context binding, policy version enforcement, and key rotation.

8. Distributed System Considerations

Critical invariants:

NoEscalation:

Execute(op) ⇒ ∃ valid token

NoReplay:

Nonce used ≤ 1 time

Atomicity:

Execute ⇒ Verify in same transition

Operational constraints include:

Linearizable NonceStore

Bounded clock drift

Key retention ≥ maximum token TTL

9. Comparison with Existing Models

ACP differs from RBAC and policy-evaluation systems by:

Eliminating implicit permission inheritance

Binding authorization to context

Enabling formal cryptographic reduction

ACP is compatible with zero-trust philosophies but provides a concrete enforcement mechanism.

10. Conclusion

ACP reframes authorization as explicit cryptographic evidence rather than implicit policy derivation. By grounding authorization in signed capabilities with strict contextual binding and local verification, ACP enables formal security reasoning and scalable distributed enforcement.
