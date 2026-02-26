Abstract

This paper introduces the foundational doctrine of Authorization by Cryptographic Capability (ACP), structured around three core principles: Explicit Authorization, Contextual Binding, and Cryptographic Verifiability. These pillars redefine authorization as an explicit, cryptographically verifiable artifact rather than an implicit system property derived from roles or policy evaluation. The doctrine establishes the conceptual and formal basis for building authorization systems that are mathematically analyzable, context-restricted, and operationally deterministic.

1. Introduction

Modern authorization mechanisms rely predominantly on role-based or policy-evaluation models. While widely adopted, such systems exhibit structural limitations:

Implicit privilege inheritance

Privilege aggregation over time

Context ambiguity

Weak formal analyzability

ACP proposes a structural shift:

Authorization is not inferred. It is presented as explicit cryptographic evidence.

This paper formalizes the doctrinal foundation of ACP through three pillars that jointly redefine how authorization is modeled.

2. Pillar I — Principle of Explicit Authorization
2.1 Statement

No action within the system is valid without explicit cryptographic authorization specific to that action.

Formally:

Execute(op) ⇒ ∃ Capability(op)

Where Capability(op) is a cryptographically verifiable token authorizing operation op.

2.2 Conceptual Shift

Traditional systems attach permissions to identities. ACP attaches authorization to operations.

In RBAC-like systems:

User ∈ Role ⇒ Permission

In ACP:

Operation ⇒ Requires Capability

Authorization is decoupled from identity inheritance and bound directly to execution.

2.3 Security Consequences

This principle eliminates:

Implicit privilege escalation

Transitive permission inheritance

Authorization ambiguity

Security reasoning becomes local and operation-specific.

2.4 Invariant
¬Capability(op) ⇒ ¬Execute(op)

There are no exceptions.

3. Pillar II — Strict Contextual Binding
3.1 Statement

Every capability MUST be cryptographically bound to the precise context in which it is intended to be executed.

3.2 Definition of Context

Context minimally includes:

Resource identifier

Operation/method

Environment identifier

Tenant identifier

Policy version

Optionally:

Security level

Subject cryptographic identity

3.3 Formalization

Let:

context_hash = H(context)

The capability signs this hash.

Security requires:

context₁ ≠ context₂ ⇒ H(context₁) ≠ H(context₂)

under collision-resistant hash assumptions and deterministic serialization.

3.4 Implications

A capability valid in context C₁ does not imply validity in C₂.

This prevents:

Lateral reuse

Cross-environment replay

Policy downgrade exploitation

Endpoint substitution

3.5 Invariant
Valid(T, C₁) ∧ C₁ ≠ C₂ ⇒ Invalid(T, C₂)
4. Pillar III — Cryptographic Verifiability
4.1 Statement

Authorization validity MUST be locally verifiable using standard cryptographic primitives without requiring dynamic global policy evaluation.

4.2 Reduction Principle

Security of ACP reduces to:

EUF-CMA security of digital signatures

Collision resistance of hash functions

Entropy guarantees of nonces

Formally:

Security(ACP) ≤ Security(Signature)

Given correct implementation constraints.

4.3 Local Determinism

Verification requires:

Public key

Token

Deterministic decoding

No central lookup is required for validity assessment.

4.4 Invariant
Verify(pk, T) = true
is necessary for execution.
5. Joint Structural Implications

Together, the three pillars establish:

Authorization is explicit (Pillar I).

Authorization is context-bound (Pillar II).

Authorization is cryptographically verifiable (Pillar III).

This produces a system where:

Escalation requires explicit issuance.

Context migration invalidates capability.

Security reasoning reduces to primitive hardness assumptions.

6. Comparison to Conventional Models
Property	RBAC	Policy Engines	ACP
Implicit permissions	Yes	Yes	No
Context binding	Weak	Partial	Strong
Cryptographic reduction	No	No	Yes
Formal invariants	Hard	Hard	Explicit

ACP does not replace identity systems.
It replaces implicit authorization semantics.

7. Discussion

The doctrine shifts the unit of authorization from "who you are" to "what explicit evidence you present."

This has implications for:

Distributed systems

Microservice security

Zero-trust architectures

Formal verification environments

The pillars are mutually dependent. Removing any one of them collapses the model:

Without explicitness → reintroduces implicit privilege.

Without contextual binding → enables reuse.

Without cryptographic verifiability → depends on policy state.

8. Conclusion

The foundational doctrine of ACP establishes authorization as a verifiable, contextual, and explicit artifact.

This doctrinal framework enables formal reduction proofs, adversarial analysis, and distributed enforcement models that are difficult to achieve under traditional role-based paradigms.
