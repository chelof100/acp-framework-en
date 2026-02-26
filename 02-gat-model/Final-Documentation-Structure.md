01 — Vision & Position Paper

Conceptual foundation and motivation.

02 — ACP Technical RFC v0.2

Normative specification (MUST, SHOULD, etc.).

03 — Capability Token Cryptographic Schema

Formal token design and primitives.

04 — Mathematical Security Model

Abstract formalization.

05 — Security Proof by Reduction

Reduction to EUF-CMA.

06 — Formal Adversarial Analysis

Structured red team.

07 — Systemic Hardening

Operational hardening.

08 — Formal Distributed Model (TLA+ style)

States, transitions, invariants.

09 — Comparative Document: ACP vs RBAC vs Zero Trust

Comparative analytical framework.

We will go through them one by one.

We start with:

📄 Document 01
ACP — Vision & Position Paper

Delivered now complete and ready to save as:

01_ACP_Vision_Position_Paper.md
ACP — Authorization by Cryptographic Capability
Position Paper
1. Introduction

The dominant current authorization models are based on roles, access control lists, or centralized dynamic policy evaluation. These approaches present structural problems:

Implicit authorization.

Privilege overlap.

Global state dependency.

Difficulty in formally reasoning about security.

ACP proposes a different approach:

Authorization is an explicit, verifiable, and portable cryptographic object.

The question is not "does it have permission?", but:

"does it possess a valid signed capability?"

2. Fundamental Principle

An action is only valid if a cryptographic token exists that:

Describes the resource exactly.

Describes the context.

Is signed by a trusted issuer.

Has not expired.

Has not been reused.

No implicit authorization exists.
No automatic inheritance exists.
No contextual extension exists.

3. Central Hypothesis

If every action requires a cryptographically verifiable and context-bound capability, then:

The escalation surface is reduced.

The model is formalizable.

Security depends on well-studied primitives.

4. Conceptual Differentiation

ACP is not:

A role system.

A list system.

A central authorization proxy.

ACP is a signed capability-based system.

5. Desired Properties

No escalation without explicit issuance.

Mandatory context binding.

Strict temporality.

Independence between services.

Local verification.

6. Scope of Application

ACP is designed for:

Distributed systems.

Microservices.

Cloud infrastructure.

Multi-tenant environments.

Critical APIs.

7. Conclusion

ACP proposes that authorization cease to be implicit logic and become explicit cryptographic evidence.

Security is not inferred.
It is verified.

📄 01_ACP_Vision_Position_Paper.md
ACP — Authorization by Cryptographic Capability
Position Paper
1. Introduction

Traditional authorization systems are based on roles (RBAC), attributes (ABAC), or centralized dynamic validations. These models share structural problems:

Implicit authorization.

Accidental privilege expansion.

Global state dependency.

Difficulty of mathematical formalization.

ACP proposes an alternative model:

Authorization is an explicit cryptographic object.

Every action requires a verifiable and signed capability.

2. Central Principle

An operation is valid if and only if a cryptographic token exists that:

Describes the resource.

Describes the context.

Is signed by a trusted issuer.

Has not expired.

Has not been reused.

3. Hypothesis

If all authorization is explicit and cryptographically verifiable:

No implicit escalation exists.

Security is reducible to formal primitives.

The system is mathematically audited.

4. Key Properties

No-escalation by construction.

Mandatory context binding.

Strict temporality.

Decentralized verification.

Autonomous tokens.

5. Conclusion

ACP converts authorization into portable cryptographic evidence.
Trust is reduced to signatures and deterministic verification.

📄 02_RFC_ACP_v0.2.md
RFC ACP v0.2
Authorization by Cryptographic Capability
1. Terminology

The words MUST, MUST NOT, SHOULD, MAY shall be interpreted as in RFC 2119.

2. Token Structure

The Capability Token MUST contain:

subject

resource

context_hash

exp

nonce

policy_version

key_id

signature

3. Issuance

The Issuer:

MUST sign the full payload.

MUST validate policy_version.

MUST ensure exp ≤ key_epoch_end.

MUST generate nonce with entropy ≥ 128 bits.

4. Verification

The Verifier:

MUST validate signature.

MUST validate expiration.

MUST validate policy_version ≥ min_supported.

MUST validate subject binding.

MUST verify that nonce has not been used.

MUST execute operation only if all validations are true.

5. Canonicalization

The payload MUST:

Use UTF-8 encoding.

Be deterministically serialized.

Have fixed field order.

6. Anti-Replay

Verifier MUST maintain a consistent NonceStore.

7. Key Rotation

Verifier MUST accept active keys.
Retention window MUST ≥ maximum TTL.

📄 03_Capability_Token_Cryptographic_Spec.md
Cryptographic Specification of ACP Token
1. Primitives

Digital signature: Ed25519

Hash: SHA-256

RNG: CSPRNG ≥ 128 bits

2. Payload
m = Encode(
    subject,
    resource,
    context_hash,
    exp,
    nonce,
    policy_version,
    key_id
)

Token:

T = Sign_sk(m)
3. Context Hash
context_hash = SHA256(
    resource_id ||
    http_method ||
    environment_id ||
    tenant_id ||
    policy_version
)
4. Security

Security depends on:

EUF-CMA of the signature.

Hash collision resistance.

Nonce entropy.

📄 04_ACP_Mathematical_Security_Model.md
Mathematical Security Model

Definitions:

I: Issuer

V: Verifier

S: Subject

T: Token

Token:

T = Sign_skI(m)

Security property:

Pr[Forge ∨ Escalate ∨ Replay ∨ Rebind] ≤ ε

ε is negligible if:

Signature is EUF-CMA secure.

Hash is collision-resistant.

Nonce is unique.

📄 05_ACP_Security_Reduction.md
Security Reduction to EUF-CMA
Theorem

If there exists adversary A that forges ACP with advantage ε,
then there exists adversary B that breaks EUF-CMA with advantage ≥ ε.

Idea

B uses A as a subroutine.

Simulates signing oracle.

Receives forgery.

Forwards it as a signature forgery.

Tight reduction.

Conclusion:

ACP is as secure as the underlying signature.

📄 06_ACP_Formal_Adversarial_Analysis.md
Formal Adversarial Analysis
Evaluated Threats

Forgery → mitigated by signature.

Replay → mitigated by nonce cache.

Privilege escalation → impossible without issuer.

Confused deputy → mitigated by subject binding.

Policy downgrade → mitigated by min_policy.

Context swap → mitigated by context_hash.

Lateral movement → mitigated by short TTL.

Issuer compromise → critical risk.

Key leakage → requires rotation.

Side-channel → requires constant-time verification.

📄 07_ACP_System_Hardening.md
System Hardening
Issuer

MUST use HSM or enclave.

SHOULD use threshold signatures.

MUST rotate keys periodically.

Verifier

MUST verify atomically.

MUST use constant-time comparison.

MUST unify error messages.

MUST maintain consistent NonceStore.

Operational

Monitor issuance rate.

Detect anomalies.

Signed append-only log.

📄 08_ACP_Distributed_Formal_Model.md
Distributed System Model
State

issued_tokens

nonce_cache

valid_keys

current_time

Invariants

NoEscalation:

Execute(op) ⇒ ∃ valid token

NoReplay:

Each nonce is used ≤ 1 time

Atomicity:

Execute ⇒ Verify in the same step

KeySafety:

RetentionWindow ≥ MaxTTL
Identified Risks

Race condition in NonceStore.

Clock drift.

Premature key rotation.

Non-atomic verification.

📄 09_ACP_vs_RBAC_vs_ZeroTrust.md
Comparative Analysis
ACP vs RBAC

RBAC:

Role-based.

Implicit permissions.

Difficult to audit formally.

ACP:

Explicit authorization.

No automatic inheritance.

Mathematically formalizable.

ACP vs Zero Trust

Zero Trust:

Continuous verification philosophy.

Can use RBAC internally.

ACP:

Concrete mechanism.

Based on signed tokens.

Compatible with Zero Trust.

ACP Advantages

Clear reduction to cryptographic primitives.

Strict context binding.

Elimination of implicit permissions.

Formally verifiable model.
