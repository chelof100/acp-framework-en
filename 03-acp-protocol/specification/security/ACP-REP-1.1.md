Adaptive Capability Protocol — Reputation Extension
Internet-Draft

Status: Standards Track

Abstract

ACP-REP-1.1 introduces a quantifiable reputation model for authorities, verifiers, and subjects within the ACP ecosystem.

1. Introduction

Byzantine tolerance defines a theoretical bound. ACP-REP adds an adaptive layer that reduces risk before that bound is reached.

2. Terminology

Interpretation per IETF RFC 2119.

3. Reputation Model

Each entity has:

ReputationScore ∈ [0,1]

4. Update Function

After each verifiable event:

score' = α·score + β·event_metric

Where:

α ∈ (0,1)

β ∈ (0,1)

α + β ≤ 1

5. Event Metrics

event_metric MAY include:

Invalid signature detected

Late signature

Malformed token

Incorrect revocation

Passed audit

6. Usage in Policy

An ACP system MAY:

Require minimum reputation

Reduce expiration for low reputation

Dynamically increase quorum requirements

7. Authority Governance

If:

ReputationScore < threshold

The following are triggered:

Automatic audit

Temporary restriction

Possible removal process (ACP-ITA)

8. Security Considerations

Mitigates:

Slow system degradation

Opportunistic attacks

Progressive collusion

Reputation manipulation MUST be avoided through:

Verifiable proofs

Public event registry

Penalties for false reports

9. IANA Considerations

No assignments required.

10. Normative References

RFC 2119

Byzantine systems research

Reputation systems literature
