Adaptive Capability Protocol — Unified Architecture

Version 1.0
Status: Candidate Standard

1. Scope

This document consolidates:

ACP 1.0 (Core Capability Model)

ACP-D 1.0 (Decentralized Model)

ACP-ITA 1.1 (Trust Anchor Governance)

ACP-PAY 1.0 (Payment Binding)

ACP-REP 1.1 (Reputation Layer)

Defines the comprehensive architecture of the ACP ecosystem.

2. Design Principles

ACP is based on five principles:

Explicit capabilities

Mandatory cryptographic verification

Byzantine fault tolerance

Extensible modularity

Minimization of implicit trust

3. Layered Architecture

ACP is organized into five layers:

Layer 1 — Identity Layer

Based on DIDs compatible with the World Wide Web Consortium model.

Defines:

Subject identifiers

Authority identifiers

Verifier identifiers

Layer 2 — Capability Layer (ACP Core)

Defines:

Cap = (subject, resource, action_set, constraints, expiry)

Capabilities MUST:

Be signed

Have expiration

Have a unique identifier (jti)

Have an anti-replay nonce

Layer 3 — Consensus & Governance (ACP-D + ACP-ITA)

Byzantine model:

n ≥ 3f + 1
Token valid if ≥ 2f+1 signatures

ACP-ITA defines:

Authority registry

Admission

Removal

Key rotation

The Trust Registry is the root of trust for the system.

Layer 4 — Economic Binding (ACP-PAY)

Optional.

Adds:

payment_condition

A resource may require:

Verifiable prior payment

Micropayment per access

Economic SLA

Layer 5 — Adaptive Security (ACP-REP)

Each entity has:

ReputationScore ∈ [0,1]

Used to:

Adjust expirations

Increase dynamic quorum

Activate auditing

4. System Roles

Subject

Authority Node

Resource Server

Revocation Network

Governance Participants

5. Token Taxonomy

ACP defines three types:

ACP-CAP (centralized)

ACP-D-CAP (decentralized)

ACP-PAY-CAP (economic)

All share a base structure:

header
claim
proof
signature_set
6. Security Model

The system is secure if:

≤ f Byzantine authorities

Hash is collision-resistant

Signatures are non-forgeable

Revocation is consistent

Fails if ≥ 2f+1 authorities collude.

7. Failure Domains
Domain	Mitigation
Compromised issuer	Eliminated in ACP-D
Partial collusion	Tolerated up to f
Replay	nonce + expiration
Escalation	Explicit capability
Slow capture	ACP-REP
8. Formal Guarantees

ACP guarantees:

No unilateral capability creation

No escalation without quorum

No validity after revocation

Security under Byzantine model

9. Interoperability

ACP can be integrated with:

DID infrastructure

Zero-Trust systems

Permissioned blockchains

Legacy enterprise infrastructure

10. Extensibility Model

New extensions MUST:

Not break Byzantine invariants

Not introduce a central issuer

Maintain cryptographic verifiability

11. Reference Implementation Guidance

Recommended languages:

Rust (core)

Go (network layer)

WASM (client proof)

Cryptography:

BLS12-381

Ed25519

SHA-256
