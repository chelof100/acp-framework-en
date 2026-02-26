ACP Conformance Specification

Version: 1.1
Status: Standards Track
Updated: 2026-02-25 (corrective revision — profile model replaced by level model)

---

1. Scope

This document defines the conformance requirements for implementations of the ACP (Agent Control Protocol) version 1.1 protocol.

It establishes:

- Cumulative conformance levels
- Mandatory minimum requirements per level
- Interoperability rules
- Validation criteria

An implementation MUST explicitly declare the conformance level it supports.

---

2. Terminology

The words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT and MAY are to be interpreted as described in IETF RFC 2119.

---

3. Level Model

ACP 1.1 defines five cumulative conformance levels:

| Level | Name          | Required layers                          |
|-------|---------------|------------------------------------------|
| L1    | CORE          | SIGN + CT + CAP-REG + HP                 |
| L2    | SECURITY      | L1 + RISK + REV + ITA-1.0               |
| L3    | FULL          | L2 + API + EXEC + LEDGER                 |
| L4    | EXTENDED      | L3 + PAY + REP + ITA-1.1                 |
| L5    | DECENTRALIZED | L4 + ACP-D + ITA-1.1 BFT                 |

Levels are cumulative. An implementation that declares level Lk MUST satisfy all requirements of levels Li where i ≤ k.

An implementation MAY support multiple levels, but MUST declare the maximum level it supports.

---

4. L1 — CORE (Mandatory for all ACP implementations)

An L1-conformant implementation MUST:

4.1 Identity Layer

- Support unique identifiers (DID or equivalent)
- Validate Subject identity before issuance

4.2 Capability Structure

Each token MUST contain:

- header
- claim
- signature

The claim MUST include:

- sub
- resource
- action_set
- exp
- jti (unique identifier)
- nonce (minimum 128 random bits)

4.3 Signature

- The signature MUST be cryptographically verifiable.
- The algorithm MUST be Ed25519 or equivalent with security ≥ 128 bits.
- The signature MUST cover the complete header + claim.

4.4 Expiration

- Tokens MUST have mandatory expiration.
- The verifier MUST reject expired tokens.

4.5 Anti-Replay

The verifier MUST:

- Validate nonce
- Detect reuse of jti or nonce within the validity period

4.6 Basic Revocation

An L1 implementation MUST support at least one of:

- Signed revocation list
- Revoked token database

The verifier MUST check revocation status before granting access.

---

5. L2 — SECURITY (L1 + Trust Anchor + Risk + Revocation)

An L2-conformant implementation MUST satisfy L1 and additionally:

5.1 Trust Registry (ACP-ITA-1.0)

- Maintain a registry of trusted authorities
- Register public_key per authority
- Register status per authority: active / suspended / revoked

5.2 Authority Admission

A new authority MUST require a quorum defined by institutional policy.

5.3 Key Rotation

Rotation MUST:

- Be signed by the previous key
- Be recorded in the Trust Registry
- Be verifiable by any verifier

5.4 Authority Removal

A removed authority MUST:

- Not be able to issue valid tokens
- Not be accepted in subsequent verifications

5.5 Risk Scoring (ACP-RISK-1.0)

- Calculate a risk score per action request
- Block actions that exceed the configured risk threshold

5.6 Advanced Revocation (ACP-REV-1.0)

- Support individual token revocation by jti
- Support issuer-based revocation (revoke all tokens from an authority)

---

6. L3 — FULL (L2 + API + Execution + Ledger)

An L3-conformant implementation MUST satisfy L2 and additionally:

6.1 HTTP API (ACP-API-1.0)

- Expose the endpoints defined in ACP-API-1.0
- Authenticate all incoming calls via a valid Capability Token
- Return normalized error codes per ACP-API-1.0

6.2 Execution Tokens (ACP-EXEC-1.0)

- Issue single-use Execution Tokens with TTL ≤ 300s
- Invalidate an Execution Token immediately after its first use
- Reject reuse of Execution Tokens

6.3 Audit Ledger (ACP-LEDGER-1.0)

- Maintain an append-only ledger of all executed actions
- Chain entries via hash of the previous record
- Guarantee verifiable tamper-evidence

---

7. L4 — EXTENDED (L3 + Payment + Reputation + ITA-1.1)

An L4-conformant implementation MUST satisfy L3 and additionally:

7.1 Payment Extension (ACP-PAY-1.0)

If payment_condition is present in the token:

The verifier MUST:

- Validate settlement_proof
- Validate amount ≥ required
- Validate payment non-expiration

An implementation MAY operate without payment condition if the resource does not require it.

7.2 Reputation Extension (ACP-REP-1.1)

The implementation MUST:

- Maintain ReputationScore ∈ [0,1] per agent
- Update reputation after verifiable events
- Allow real-time reputation queries

The reputation calculation MUST be deterministic.

7.3 BFT Trust Anchor (ACP-ITA-1.1)

The implementation MUST:

- Operate the Trust Anchor as a BFT quorum with n ≥ 3f+1 nodes
- Require threshold t ≥ 2f+1 for issuance decisions
- Tolerate f Byzantine nodes without compromising quorum integrity

---

8. L5 — DECENTRALIZED (L4 + ACP-D)

An L5-conformant implementation MUST satisfy L4 and additionally satisfy the ACP-D specification defined in `../decentralized/ACP-D-Specification.md`.

This includes:

- DID-based identity (no central issuer)
- Verifiable Credentials for capabilities
- Distributed BFT consensus without a single control point

---

9. Interoperability

To interoperate, two implementations MUST:

- Declare the same minimum conformance level
- Support at least one common signature algorithm
- Use the agreed canonical serialization format (JCS)

---

10. Token Versioning

Each token MUST include:

```json
{
  "ver": "1.1",
  "conformance_level": "L1|L2|L3|L4|L5"
}
```

A verifier MUST reject tokens with an unsupported version.

A verifier MUST reject tokens whose conformance_level declares capabilities not supported by the verifier.

---

11. Compliance Validation

An ACP-conformant implementation MUST:

- Pass all official test vectors for the declared level (ACP-TS-1.1)
- Reject all invalid tokens defined in the suite
- Produce deterministic reproducible signatures

ACP certification requires successful execution of the official compliance runner (ACR-1.0) for the declared level.

---

12. Non-Conformance

An implementation is NOT conformant if it:

- Omits token expiration
- Omits nonce
- Allows tokens without a valid signature
- Ignores revocation
- Does not declare the supported conformance level
- Declares a level without satisfying all requirements of lower levels

---

13. Security Considerations

Conformance does NOT guarantee security if:

- Private keys are compromised
- Revocation is not updated with timely propagation
- Nonce is not verified correctly
- The BFT quorum (L4/L5) operates with fewer nodes than required

---

14. Implementation Claim Format

A conformant implementation SHOULD declare:

```
ACP Implementation:
  Version: 1.1
  Conformance-Level: L3
  Algorithms: Ed25519, SHA-256
  Compliance-Suite: Passed ACP-TS-1.1
```

---

Appendix A — Mapping from Previous Profiles (Informative)

Version 1.0 of this specification defined conformance profiles. That model is entirely replaced by the level model. The following table is informative and MUST NOT be used in certification declarations:

| Profile (deprecated) | Equivalent level |
|----------------------|-----------------|
| Core                 | L1              |
| Governance           | L2              |
| Extended             | L4              |
| Full v1.1            | L4              |
