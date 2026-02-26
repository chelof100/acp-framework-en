Adaptive Capability Protocol — Payment Extension
Internet-Draft

Status: Experimental

Abstract

ACP-PAY-1.0 defines a mechanism to link capability-based authorization with verifiable economic settlement.

1. Introduction

Some resources require verifiable payment before granting access. ACP-PAY integrates settlement proof within the capability model without modifying the ACP core.

2. Terminology

Interpretation conformant with IETF RFC 2119.

3. Extended Capability Format

Added:

payment_condition = {
    amount,
    currency,
    settlement_proof,
    expiration
}

The complete capability:

ACP-PAY-Token = {
    capability_claim,
    payment_condition,
    proof,
    multi_signature
}

4. Settlement Proof

settlement_proof MUST demonstrate:

Valid transfer

No double spend

Sufficient confirmation

Can be:

On-chain proof

Off-chain channel

Signed corporate ledger

ACP-PAY does not impose a specific network.

5. Verification Requirements

A Resource Server MUST:

Verify base capability

Verify settlement_proof

Confirm amount >= required

Confirm payment has not expired

6. Security Considerations

Mitigates:

Access without payment

Reuse of expired proof

Amount manipulation

The system depends on the security of the underlying ledger.

7. IANA Considerations

Not applicable.

8. Normative References

RFC 2119

Digital Payment Verification literature
