# ACP Certification — ACP-CERT-1.0

**Objective:**
Allow an implementation to publish verifiable and auditable conformance.

## 1. Certification Model

**Process:**

1. Implementor runs the official runner
2. Generates `report.json`
3. Submits report + binary hash to the ACP Certification Authority (see §7 — Governance)
4. Reproducibility is verified
5. Signed certificate is issued

## 2. Certification Identifier

**Format:**

```
ACP-CERT-YYYY-NNNN
```

**Example:**

```
ACP-CERT-2026-0007
```

## 3. Official Certificate (JSON Format)

```json
{
  "certification_id": "ACP-CERT-2026-0007",
  "protocol": "ACP",
  "acp_version": "1.1",
  "conformance_level": "L4",
  "implementation_name": "acp-go-impl",
  "implementation_version": "0.9.3",
  "binary_hash": "sha256:...",
  "test_suite_hash": "sha256:...",
  "runner_version": "1.0",
  "total_tests": 124,
  "passed": 124,
  "performance": {
    "latency_avg_ms": 2.8,
    "throughput_per_sec": 12400
  },
  "issued_at": "2026-02-25T12:00:00Z",
  "issuer": "ACP-CA",
  "signature": "BASE64_SIGNATURE"
}
```

Signed with the official private key.

## 4. Public Verification

Anyone can:

- Download the certificate
- Verify the signature
- Reproduce the test suite
- Compare the binary hash

If they do not match → certification is invalid.

## 5. Public Badge

Verifiable SVG format:

```
ACP v1.1 — L4 Certified
ACP-CERT-2026-0007
```

The badge includes:

- QR code linking to the certificate
- Short hash
- Date

## 6. Revocation

If discovered:

- Critical bug
- Falsification
- Severe incompatibility

A revocation list is published:

```json
{
  "revoked_certifications": [
    {
      "certification_id": "ACP-CERT-2026-0007",
      "reason": "Critical validation flaw",
      "revoked_at": "2026-04-10"
    }
  ]
}
```

Consumers must verify against this list.

## 7. Governance Model

> **Design note:** The ACP Certification Authority ("ACP-CA") is a placeholder.
> The design direction is **decentralized**: no single entity should control
> the issuance of certifications. TraslaIA is not positioned as a permanent authority.
> The definitive structure is a governance decision open to the community.

**Design direction — decentralized:**

Certification MUST NOT depend on a single central entity.

**Target model:** multi-sig on-chain — n of m independent organizations co-sign each certificate. A single organization cannot issue unilaterally.

In the ACP-D variant (L5): the ACP-CA can be implemented as a smart contract or BFT protocol where the quorum of signers is verifiable on-chain, eliminating the need to trust any individual entity.

**Evaluated options (from most to least centralized):**

| Option | Notes |
|--------|-------|
| Non-profit foundation — single legal entity | Less decentralized |
| Independent technical committee (e.g., W3C Working Group) | More distributed, still centralized |
| Institutional multi-sig (n of m co-signers) | ✅ Preferred direction for v2.x |
| BFT on-chain with verifiable quorum | ✅ Final architectural goal (ACP-D) |

Current state (v1.x): placeholder "ACP-CA" — resolution pending community governance.

## 8. Strategic Impact

With this, ACP has:

- ✔ Formal technical interface
- ✔ Reproducible runner
- ✔ Auditable certification
- ✔ Public revocation
- ✔ Solid foundation for IEEE S&P / NDSS
