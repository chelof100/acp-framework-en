Normative Technical Specification
Status: Proposed Standard

1. Introduction

ACP-D defines a decentralized cryptographic authorization system based on:

Decentralized Identifiers (DID)

Verifiable Credentials

Cryptographically derived capability tokens

Verification without a central issuer

The protocol eliminates the single point of failure present in architectures with a central issuer.

2. Normative Terminology

The words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY are interpreted per IETF RFC 2119.

3. General Architecture

ACP-D consists of four roles:

Subject

Resource Server (Verifier)

Authority Set (decentralized quorum)

Revocation Network

There is no single issuer.

4. Identity
4.1 Identifiers

Every participant MUST possess a DID conformant with the World Wide Web Consortium (W3C DID Core) model.

Format:

did:acpd:<method-specific-id>

5. Decentralized Capability Model

An ACP-D Capability is defined as:

Cap = (subject, resource, action_set, constraints, expiry)

A token is valid if:

The Subject holds a valid credential.

The credential was issued by an authority that is a member of the quorum.

The consensus policy is satisfied.

A valid cryptographic proof is presented.

6. ACP-D Token Structure
ACP-D-Token = {
    header,
    capability_claim,
    zk_proof,
    multi_signature
}

6.1 Header
{
  "alg": "BLS12-381",
  "typ": "ACP-D-CAP",
  "ver": "1.0"
}

6.2 Capability Claim
{
  sub: DID,
  res: ResourceID,
  act: [Action],
  ctx: ContextObject,
  exp: Timestamp,
  jti: UniqueID
}

7. Multi-Authority Signature
7.1 Quorum Requirement

Let:

n = total number of authorities

f = maximum number of tolerable Byzantine nodes

The system MUST satisfy:

n ≥ 3f + 1

A token is valid if at least t signatures are present:

t ≥ 2f + 1

7.2 Algorithm

The protocol SHOULD use:

BLS12-381 threshold signature
or

Aggregated Multi-Ed25519

The aggregated signature MUST be verified against the authorized public set.

8. Credential Possession Proof

The Subject MUST generate a cryptographic proof demonstrating:

It holds a valid credential.

The credential contains authorization for the requested capability.

It is not revoked.

The protocol SHOULD use:

zk-SNARK

zk-STARK

Bulletproofs

The proof MUST be non-interactive.

9. Decentralized Revocation
9.1 Model

The network maintains a Merkle Tree of revocations.

Each revocation block MUST include:

{
  revoked_token_id,
  timestamp,
  revocation_reason,
  authority_signature
}

9.2 Validation

The Verifier MUST:

Verify Merkle proof of non-inclusion.

Verify revocation block signature.

Confirm the block belongs to a valid chain.

10. Authorization Flow
Step 1: Request

Subject requests capability.

Step 2: Proof generation

Subject generates zk_proof.

Step 3: Signature collection

Authorities sign under quorum policy.

Step 4: Presentation

Subject presents ACP-D-Token to the Resource Server.

Step 5: Verification

The Verifier MUST:

Verify multi_signature

Verify zk_proof

Verify expiry

Verify non-revocation

Evaluate constraints

If all validations pass → access granted.

11. Security Model

ACP-D is secure if:

The fraction of Byzantine nodes < 1/3.

The underlying cryptography is secure.

A majority of private keys is not compromised.

Resists:

Partial authority compromise

Limited collusion

Token forgery

Replay (with nonce and expiration)

Privilege escalation

12. Considered Attacks
12.1 Authority Compromise

If f authorities are compromised:

They cannot generate a valid token without quorum.

12.2 Verifier + Authority Collusion

Mitigated by:

Independent validation

Public audit

Verifiable registry

12.3 Replay Attack

Mitigated by:

Mandatory nonce

Short exp

Optional distributed registry

13. Implementation Considerations
13.1 Recommended Languages

Rust

Go

TypeScript (client layer only)

13.2 Cryptographic Libraries

blst (BLS12-381)

arkworks

dalek (Ed25519)

14. Interoperability

ACP-D MAY integrate with:

DID identity systems

SSI infrastructures

Permissioned blockchain systems

Legacy Web2 systems via gateway

15. Future Extensions

Post-Quantum support (Dilithium)

Publicly verifiable Proof-of-Validation

ZK audit of verifiers

Cryptographic capability delegation

Technical Conclusion

ACP-D eliminates the central issuer.

Authority is distributed under a Byzantine fault-tolerant model.

Authorization transitions from a unilateral signature to a verifiable cryptographic consensus.

This makes access control:

Verifiable

Distributed

Auditable

Resistant to partial collusion
