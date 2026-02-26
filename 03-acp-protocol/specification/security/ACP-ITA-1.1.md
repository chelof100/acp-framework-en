Adaptive Capability Protocol — Identity Trust Anchor
Internet-Draft

Status: Standards Track

Abstract

This document defines ACP-ITA-1.1, the trust anchor extension for the ACP ecosystem. It specifies the admission, rotation, and removal model for authorities in Byzantine fault-tolerant environments.

1. Introduction

ACP-D assumes a set of trusted authorities that sign capabilities under a Byzantine model. Without a formal governance mechanism, the system lacks a verifiable root of trust.

ACP-ITA defines:

Authority registry

Admission process

Removal process

Key rotation

Protection against quorum capture

2. Terminology

The words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT and MAY are to be interpreted as described in IETF RFC 2119.

3. System Model

Let:

n = total number of authorities

f = maximum number of tolerable Byzantine nodes

The following MUST hold:

n ≥ 3f + 1

4. Trust Registry

Every authority MUST be registered in the Trust Registry:

TrustRegistryEntry = {
    authority_id,
    public_key,
    admission_signatures,
    activation_epoch,
    status
}

The registry MUST be:

Verifiable

Signed by quorum

Public or audit-able

5. Admission Protocol

A new authority is valid if it:

Presents a public key

Obtains ≥ 2f+1 signatures from active authorities

Waits for activation_delay

Formally:

Authority_Valid(a) ⇔
    Cardinality(signatures(a)) ≥ 2f + 1

An authority MUST NOT activate immediately after being signed.

6. Removal Protocol

An authority MAY be removed if:

Cryptographic evidence of misbehavior exists

A vote of ≥ 2f+1 is obtained

The removal MUST be recorded in the Trust Registry with verifiable proof.

7. Key Rotation

An authority rotating its key MUST:

Sign the new key with the previous key

Obtain confirmation from ≥ 2f+1 authorities

Publish a verifiable transition

The system MUST reject unregistered keys.

8. Security Considerations

ACP-ITA protects against:

Unilateral authority insertion

Silent key substitution

Progressive quorum capture

If ≥ 2f+1 authorities collude, the model fails by definition of the Byzantine system.

9. IANA Considerations

No IANA assignments are required.

10. Normative References

RFC 2119

Byzantine Fault Tolerance literature

Threshold Signature research
