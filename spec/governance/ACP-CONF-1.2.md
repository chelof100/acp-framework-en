ACP Conformance Specification

Version: 1.2
Status: Standards Track
Updated: 2026-03-12
Supersedes: ACP-CONF-1.1
Depends-on: ACP-SIGN-1.0, ACP-CT-1.0, ACP-CAP-REG-1.0, ACP-HP-1.0,
            ACP-AGENT-1.0, ACP-DCMA-1.0, ACP-MESSAGES-1.0,
            ACP-RISK-1.0, ACP-REV-1.0, ACP-ITA-1.1,
            ACP-API-1.0, ACP-EXEC-1.0, ACP-LEDGER-1.3,
            ACP-PROVENANCE-1.0, ACP-POLICY-CTX-1.0, ACP-PSN-1.0,
            ACP-PAY-1.0, ACP-REP-1.2, ACP-REP-PORTABILITY-1.0,
            ACP-GOV-EVENTS-1.0, ACP-LIA-1.0, ACP-HIST-1.0,
            ACP-NOTIFY-1.0, ACP-DISC-1.0, ACP-BULK-1.0, ACP-CROSS-ORG-1.0,
            ACP-DCMA-1.0
Required-by: —

---

1. Scope

This document defines the conformance requirements for implementations of the
ACP (Agent Control Protocol) version 1.2 protocol.

It establishes:

- Cumulative conformance levels
- Mandatory minimum requirements per level
- Interoperability rules
- Validation criteria

ACP-CONF-1.2 supersedes ACP-CONF-1.1. It restores this specification as the
sole normative source for level requirements, incorporating all protocol
specifications introduced since CONF-1.1 was written (P4 specifications:
PROVENANCE, POLICY-CTX, PSN, GOV-EVENTS, and extended L4 governance specs).
It also corrects the L1 definition (adds AGENT, DCMA, MESSAGES), fixes the
L4 reputation reference (REP-1.1 → REP-1.2), and updates the L3 ledger
reference (LEDGER-1.2 → LEDGER-1.3).

An implementation MUST explicitly declare the conformance level it supports.

---

2. Terminology

The words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT and MAY are to
be interpreted as described in IETF RFC 2119.

---

3. Level Model

ACP 1.2 defines five cumulative conformance levels:

| Level | Name          | Required layers                                                  |
|-------|---------------|------------------------------------------------------------------|
| L1    | CORE          | SIGN + CT + CAP-REG + HP + AGENT + DCMA + MESSAGES              |
| L2    | SECURITY      | L1 + RISK + REV + ITA-1.0                                       |
| L3    | FULL          | L2 + API + EXEC + LEDGER + PROVENANCE + POLICY-CTX + PSN        |
| L4    | EXTENDED      | L3 + PAY + REP-1.2 + ITA-1.1 + GOV-EVENTS + LIA + HIST +       |
|       |               | NOTIFY + DISC + BULK + CROSS-ORG + REP-PORTABILITY              |
| L5    | DECENTRALIZED | L4 + ACP-D + ITA-1.1 BFT                                        |

Levels are cumulative. An implementation that declares level Lk MUST satisfy
all requirements of levels Li where i ≤ k.

An implementation MAY support multiple levels, but MUST declare the maximum
level it supports.

---

4. L1 — CORE (Mandatory for all ACP implementations)

An L1-conformant implementation MUST satisfy sections 4.1 through 4.9.

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

4.7 Agent Registration (ACP-AGENT-1.0)

- Each agent MUST be registered in the Agent Registry before receiving
  Capability Tokens.
- Registration MUST produce a unique agent_id.
- Agent records MUST include: agent_id, public_key, status, created_at,
  and issuing_authority.
- The verifier MUST validate that agent_id exists and status is active
  before granting access.
- A token issued to an unregistered or inactive agent MUST be rejected.

4.8 Delegation Chains (ACP-DCMA-1.0)

- Delegation chains MUST be validated end-to-end before a delegated token
  is accepted.
- Each link in the chain MUST be signed by the delegating authority.
- Chain depth MUST NOT exceed the max_delegation_depth specified in the
  root token.
- Circular delegations MUST be detected and rejected.
- A verifier MUST reject a token whose delegation chain contains an
  expired, revoked, or invalid link.

4.9 Message Format (ACP-MESSAGES-1.0)

- All protocol messages MUST conform to the canonical schema defined in
  ACP-MESSAGES-1.0.
- The message version field MUST be validated before processing.
- Implementations MUST declare whether they operate in strict mode
  (unknown fields rejected) or lenient mode (unknown fields ignored).
- Messages that fail schema validation MUST be rejected with the
  appropriate ACP-MESSAGES error code.

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

6. L3 — FULL (L2 + API + Execution + Ledger + Provenance + Policy + PSN)

An L3-conformant implementation MUST satisfy L2 and additionally:

6.1 HTTP API (ACP-API-1.0)

- Expose the endpoints defined in ACP-API-1.0
- Authenticate all incoming calls via a valid Capability Token
- Return normalized error codes per ACP-API-1.0

6.2 Execution Tokens (ACP-EXEC-1.0)

- Issue single-use Execution Tokens with TTL ≤ 300s
- Invalidate an Execution Token immediately after its first use
- Reject reuse of Execution Tokens

6.3 Audit Ledger (ACP-LEDGER-1.3)

- Maintain an append-only ledger of all executed actions
- Chain entries via hash of the previous record
- Guarantee verifiable tamper-evidence
- Every ledger entry MUST carry a valid institutional signature (sig MUST
  be present and non-empty; see ACP-LEDGER-1.3 §4.4)

6.4 Provenance (ACP-PROVENANCE-1.0)

- Generate a signed provenance artefact for each executed action.
- Each artefact MUST include: action_id, agent_id, capability_token_jti,
  timestamp, resource, and inputs_hash.
- Artefacts MUST be stored in the audit ledger and be retrievable by
  action_id.
- A verifier MUST be able to reconstruct the full provenance chain for
  any completed action.

6.5 Policy Context (ACP-POLICY-CTX-1.0)

- Capture a policy snapshot at the time of each authorization decision.
- The snapshot MUST include: policy_version, effective_date, and the set
  of applicable rules evaluated for the decision.
- The snapshot MUST be linked to the authorization record via the token jti.
- Policy snapshots MUST be immutable once created.

6.6 Process-Session Node (ACP-PSN-1.0)

- Create a PSN record for each execution session.
- The PSN MUST include: session_id, agent_id, started_at, and
  ledger_ref (hash of the first ledger event in the session).
- The PSN MUST be finalized with ended_at and final_ledger_ref on session
  close.
- PSN records MUST be stored in the audit ledger and be queryable by
  session_id.

---

7. L4 — EXTENDED (L3 + Payment + Reputation + Federation + Governance)

An L4-conformant implementation MUST satisfy L3 and additionally:

7.1 Payment Extension (ACP-PAY-1.0)

If payment_condition is present in the token:

The verifier MUST:

- Validate settlement_proof
- Validate amount ≥ required
- Validate payment non-expiration

An implementation MAY operate without payment condition if the resource
does not require it.

7.2 Reputation Extension (ACP-REP-1.2)

The implementation MUST:

- Maintain ReputationScore ∈ [0,1] per agent
- Update reputation after verifiable events
- Allow real-time reputation queries

The reputation calculation MUST be deterministic.

7.3 Federation Trust (ACP-ITA-1.1)

The implementation MUST:

- Operate the Federation Trust Anchor per ACP-ITA-1.1
- Require threshold t ≥ 2f+1 for issuance decisions
- Tolerate f Byzantine nodes without compromising quorum integrity

7.4 Governance Event Stream (ACP-GOV-EVENTS-1.0)

The implementation MUST:

- Emit a structured governance event for every authorization decision.
- Each event MUST include: event_id, timestamp, actor, action, resource,
  decision (granted / denied / escalated), and rationale_code.
- Events MUST be signed by the institutional key.
- Events MUST be queryable via the audit API with filtering by actor,
  resource, and time range.

7.5 Liability Tracking (ACP-LIA-1.0)

The implementation MUST:

- Create a liability record for each executed action.
- Each record MUST reference the originating Capability Token jti.
- Liability records MUST be immutable once created.
- Records MUST be queryable by agent_id and by token jti.

7.6 Audit History (ACP-HIST-1.0)

The implementation MUST:

- Maintain a queryable audit history per agent.
- History MUST be append-only.
- Retention MUST be ≥ 90 days unless institutional policy requires longer.
- History MUST support pagination and time-range queries.

7.7 Notifications (ACP-NOTIFY-1.0)

The implementation MUST:

- Emit notifications on configurable event triggers (at minimum: token
  issuance, revocation, and execution completion).
- Notification delivery MUST be acknowledged by the recipient endpoint.
- Failed deliveries MUST be retried with exponential backoff per
  ACP-NOTIFY-1.0.

7.8 Discovery (ACP-DISC-1.0)

The implementation MUST:

- Expose a discovery endpoint for agent and capability registration.
- Discovery records MUST include: agent_id, available_capabilities,
  status, and updated_at.
- Discovery MUST support pagination.
- Discovery endpoint MUST be authenticated via Capability Token.

7.9 Bulk Operations (ACP-BULK-1.0)

The implementation MUST:

- Support batch authorization requests up to the limits defined in
  ACP-BULK-1.0.
- Each item in a batch MUST be evaluated independently.
- Partial success MUST be supported: the response MUST include per-item
  status for every item in the batch.

7.10 Cross-Organization (ACP-CROSS-ORG-1.0)

The implementation MUST:

- Support cross-organizational capability delegation.
- Cross-org tokens MUST include org_id in the claim.
- The verifier MUST validate cross-org trust anchors per ACP-ITA-1.1
  before accepting cross-org tokens.

7.11 Reputation Portability (ACP-REP-PORTABILITY-1.0)

The implementation MUST:

- Support export of signed reputation records per agent.
- Exported records MUST be signed by the originating institution's key.
- An importing institution MUST verify the origin signature before
  incorporating a portable reputation record.

---

8. L5 — DECENTRALIZED (L4 + ACP-D)

An L5-conformant implementation MUST satisfy L4 and additionally satisfy the
ACP-D specification defined in `../decentralized/ACP-D-Specification.md`.

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
  "ver": "1.2",
  "conformance_level": "L1|L2|L3|L4|L5"
}
```

A verifier MUST reject tokens with an unsupported version.

A verifier MUST reject tokens whose conformance_level declares capabilities
not supported by the verifier.

---

11. Compliance Validation

An ACP-conformant implementation MUST:

- Pass all official test vectors for the declared level (ACP-TS-1.1)
- Reject all invalid tokens defined in the suite
- Produce deterministic reproducible signatures

ACP certification requires successful execution of the official compliance
runner (ACR-1.0) for the declared level.

---

12. Non-Conformance

An implementation is NOT conformant if it:

- Omits token expiration
- Omits nonce
- Allows tokens without a valid signature
- Ignores revocation
- Does not declare the supported conformance level
- Declares a level without satisfying all requirements of lower levels
- Issues tokens to unregistered agents (violates §4.7)
- Accepts delegated tokens without validating the full chain (violates §4.8)
- Stores ledger events without institutional signature (violates §6.3)

---

13. Security Considerations

Conformance does NOT guarantee security if:

- Private keys are compromised
- Revocation is not updated with timely propagation
- Nonce is not verified correctly
- The BFT quorum (L4/L5) operates with fewer nodes than required
- Cross-org trust anchors are not independently validated

---

14. Implementation Claim Format

A conformant implementation SHOULD declare:

```
ACP Implementation:
  Version: 1.2
  Conformance-Level: L3
  Algorithms: Ed25519, SHA-256
  Compliance-Suite: Passed ACP-TS-1.1
```

---

Appendix A — Mapping from CONF-1.1 (Informative)

The following table maps CONF-1.1 level definitions to their CONF-1.2
equivalents. This table is informative and MUST NOT be used in certification
declarations.

| CONF-1.1 level definition          | Status in CONF-1.2                     |
|------------------------------------|----------------------------------------|
| L1: SIGN+CT+CAP-REG+HP             | Expanded: + AGENT + DCMA + MESSAGES    |
| L2: L1+RISK+REV+ITA-1.0           | Unchanged                              |
| L3: L2+API+EXEC+LEDGER-1.2        | Expanded: + PROVENANCE + POLICY-CTX + PSN; LEDGER updated to 1.3 |
| L4: L3+PAY+REP-1.1+ITA-1.1       | REP corrected to 1.2; + 8 governance specs |
| L5: L4+ACP-D+ITA-1.1 BFT         | Unchanged                              |

---

Appendix B — Mapping from Previous Profiles (Informative)

Version 1.0 of this specification defined conformance profiles. That model
was replaced by the level model in CONF-1.1. The following table is
informative and MUST NOT be used in certification declarations:

| Profile (deprecated) | Equivalent level |
|----------------------|-----------------|
| Core                 | L1              |
| Governance           | L2              |
| Extended             | L4              |
| Full v1.1            | L4              |
