# ACP-SIGN-2.0
## Post-Quantum Hybrid Signing Specification
**Status:** Draft
**Version:** 2.0
**Replaces:** ACP-SIGN-1.0 (backward-compatible — see §11)
**Depends-on:** RFC 8785 (JCS), RFC 8032 (Ed25519), NIST FIPS 204 (ML-DSA / Dilithium), RFC 4648 (base64url)
**Required-by:** ACP-CT-1.0, ACP-LEDGER-1.3, ACP-RISK-2.0, ACP-API-1.0
**Implementation note:** No Go implementation in v1.16. Reference library: `github.com/cloudflare/circl/sign/dilithium`. Go implementation target: v1.17.

---

## 1. Scope

This document specifies the **post-quantum hybrid signing scheme** for ACP artifacts. It extends ACP-SIGN-1.0 with support for ML-DSA-65 (Module Lattice Digital Signature Algorithm, NIST FIPS 204) alongside the existing Ed25519 scheme, enabling a structured migration to post-quantum cryptography without breaking existing deployments.

The design principle is **crypto-agility by design**: ACP defines the migration path explicitly, with each deployment advancing through three transition modes at its own pace according to a configurable policy.

**This specification does not invalidate ACP-SIGN-1.0.** All existing ACP-SIGN-1.0 artifacts remain valid. Implementations MUST continue to accept them per the backward-compatibility rules in §11.

---

## 2. Threat Model and Motivation

**2.1 The harvest-now / decrypt-later threat**

An adversary with access to recorded Ed25519-signed ACP artifacts today could, upon acquiring a sufficiently powerful quantum computer, forge signatures retroactively, invalidating audit trails and capability tokens. The timeline for cryptographically relevant quantum computers is uncertain but credible within a 10–15 year horizon.

**2.2 NIST standardization**

NIST finalized ML-DSA (Module Lattice-based Digital Signature Algorithm) in FIPS 204 (August 2024), based on the CRYSTALS-Dilithium submission. ML-DSA-65 (Security Category 3, equivalent to AES-192) is selected for ACP because it offers the best balance between signature size, key size, and security margin for institutional deployments.

**2.3 ACP-specific requirements**

| Requirement | Rationale |
|---|---|
| Backward compatibility | Existing deployments cannot be required to upgrade atomically |
| Auditability | Hybrid artifacts must be unambiguously verifiable by any third party |
| Determinism | Same inputs must always produce same verifiable result |
| No key sprawl | Key material for both algorithms is registered once per agent |

---

## 3. Algorithm Parameters

**3.1 Classical component (unchanged from ACP-SIGN-1.0)**

| Property | Value |
|---|---|
| Algorithm | Ed25519 (RFC 8032) |
| Private key | 32 bytes |
| Public key | 32 bytes |
| Signature | 64 bytes |
| Encoding | base64url without padding (86 characters) |

**3.2 Post-quantum component (new in v2.0)**

| Property | Value |
|---|---|
| Algorithm | ML-DSA-65 (NIST FIPS 204, formerly CRYSTALS-Dilithium3) |
| Security category | NIST Category 3 (≥ AES-192 quantum security) |
| Private key | 4000 bytes |
| Public key | 1952 bytes |
| Signature | 3309 bytes |
| Encoding | base64url without padding |
| Reference library | `github.com/cloudflare/circl/sign/dilithium` (mode `Dilithium3`) |

**3.3 Hash**

SHA-256 (FIPS 180-4) for the pre-signature digest, applied to the JCS-canonicalized payload. Both signature components sign the same digest.

---

## 4. Transition Modes

A deployment operates in exactly one of three transition modes, declared in its ACP policy configuration.

| Mode | Identifier | Classic sig | PQC sig | Verification requirement |
|---|---|---|---|---|
| Classic-only | `CLASSIC_ONLY` | Required | Absent | Ed25519 MUST verify |
| Hybrid | `HYBRID` | Required | Required | BOTH MUST verify |
| PQC-only | `PQC_ONLY` | Absent | Required | ML-DSA-65 MUST verify |

**4.1 Default mode**

Unless otherwise configured, deployments operate in `CLASSIC_ONLY` mode. This is identical to ACP-SIGN-1.0 behavior.

**4.2 Mode progression**

Deployments advance through modes in order: `CLASSIC_ONLY` → `HYBRID` → `PQC_ONLY`. Reversal is not permitted once PQC keys are registered and active.

**4.3 Policy declaration**

The active transition mode is declared in the institutional policy configuration:

```json
{
  "acp_sign_mode": "HYBRID",
  "pqc_required": false,
  "pqc_required_after": "2027-01-01T00:00:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `acp_sign_mode` | string | Active mode: `CLASSIC_ONLY`, `HYBRID`, or `PQC_ONLY` |
| `pqc_required` | boolean | If true, rejects artifacts missing `pqc_sig` regardless of mode |
| `pqc_required_after` | string (ISO 8601) | Date after which `pqc_required` is automatically enforced |

---

## 5. Wire Format

**5.1 Classic-only artifacts (ACP-SIGN-1.0 format, unchanged)**

```json
{
  "ver": "1.0",
  "...",
  "sig": "<base64url_ed25519_signature>"
}
```

**5.2 Hybrid artifacts (ACP-SIGN-2.0)**

```json
{
  "ver": "1.0",
  "...",
  "ed25519_sig": "<base64url_ed25519_signature_86_chars>",
  "pqc_sig": "<base64url_mldsa65_signature_4412_chars>",
  "pqc_alg": "ML-DSA-65"
}
```

| Field | Required | Description |
|---|---|---|
| `ed25519_sig` | In `HYBRID` and `CLASSIC_ONLY` | Ed25519 signature over JCS digest. Replaces `sig` in v2.0 hybrid artifacts. |
| `pqc_sig` | In `HYBRID` and `PQC_ONLY` | ML-DSA-65 signature over the same JCS digest. base64url without padding. |
| `pqc_alg` | When `pqc_sig` present | Algorithm identifier. MUST be `"ML-DSA-65"` in v2.0. Reserved for future algorithms. |

**5.3 Coexistence with the `sig` field**

To maintain backward compatibility, implementations producing hybrid artifacts MUST:
- Set `ed25519_sig` (not `sig`) for the classical component
- Set `pqc_sig` + `pqc_alg` for the PQC component
- Leave `sig` absent (avoiding ambiguity with ACP-SIGN-1.0 verifiers)

ACP-SIGN-1.0 verifiers encountering `ed25519_sig` instead of `sig` MUST treat the artifact as an unknown version and reject it with SIGN-010, unless they have been upgraded to ACP-SIGN-2.0.

---

## 6. Public Key Registration

**6.1 Extended agent record**

Agents operating in `HYBRID` or `PQC_ONLY` mode MUST register their ML-DSA-65 public key alongside their Ed25519 key:

```json
{
  "agent_id": "acp:agent:org.example:agent-001",
  "public_key": "<base64url_ed25519_public_key_32_bytes>",
  "pqc_public_key": "<base64url_mldsa65_public_key_2592_chars>",
  "pqc_alg": "ML-DSA-65"
}
```

**6.2 Retrieval**

Verifiers obtain PQC public keys via the agent registry:

```
GET /acp/v1/agents/{agent_id}
→ response.pqc_public_key (when present)
```

**6.3 Institutional key**

For artifacts signed by the institutional ACP system (API responses, ledger events), the PQC public key is declared in the ITA trust anchor per ACP-ITA-1.1. Institutions MUST publish their PQC public key in the ITA document before activating `HYBRID` mode.

---

## 7. Signing Procedure

**7.1 Classic-only mode (ACP-SIGN-1.0 compatible)**

```
Given: JSON object O, Ed25519 private key sk_ed

1. Verify O does not contain "sig", "ed25519_sig", or "pqc_sig"
2. canonical_bytes = JCS(O)
3. h = SHA-256(canonical_bytes)
4. sig_bytes = Ed25519_Sign(sk_ed, h)
5. O["sig"] = base64url(sig_bytes)
6. Return O
```

**7.2 Hybrid mode**

```
Given: JSON object O, Ed25519 private key sk_ed, ML-DSA-65 private key sk_pqc

1. Verify O does not contain "sig", "ed25519_sig", or "pqc_sig"
2. canonical_bytes = JCS(O)
3. h = SHA-256(canonical_bytes)
4. ed_sig_bytes   = Ed25519_Sign(sk_ed, h)        [64 bytes]
5. pqc_sig_bytes  = MLDSA65_Sign(sk_pqc, h)       [3309 bytes]
6. O["ed25519_sig"] = base64url(ed_sig_bytes)
7. O["pqc_sig"]     = base64url(pqc_sig_bytes)
8. O["pqc_alg"]     = "ML-DSA-65"
9. Return O
```

**7.3 PQC-only mode**

```
Given: JSON object O, ML-DSA-65 private key sk_pqc

1. Verify O does not contain "sig", "ed25519_sig", or "pqc_sig"
2. canonical_bytes = JCS(O)
3. h = SHA-256(canonical_bytes)
4. pqc_sig_bytes  = MLDSA65_Sign(sk_pqc, h)
5. O["pqc_sig"]     = base64url(pqc_sig_bytes)
6. O["pqc_alg"]     = "ML-DSA-65"
7. Return O
```

**Important:** The digest `h` is always SHA-256 of the JCS-canonicalized payload with ALL signature fields absent. Both signature algorithms sign the same digest over the same canonical form.

---

## 8. Verification Procedure

**8.1 Mode determination**

Verifiers determine the artifact's signature mode by inspecting which fields are present:

| Fields present | Inferred mode |
|---|---|
| `sig` only | `CLASSIC_ONLY` (ACP-SIGN-1.0 format) |
| `ed25519_sig` only | Reject — incomplete hybrid artifact (SIGN-012) |
| `pqc_sig` only | `PQC_ONLY` |
| `ed25519_sig` + `pqc_sig` | `HYBRID` |
| Neither | Reject — no signature found (SIGN-007) |

**8.2 Classic-only verification (ACP-SIGN-1.0 compatible)**

```
Given: O with field "sig", Ed25519 public key pk_ed

1. sig_bytes = base64url_decode(O["sig"])     — must be 64 bytes (SIGN-005)
2. O_plain   = copy of O without "sig"
3. h         = SHA-256(JCS(O_plain))
4. result    = Ed25519_Verify(pk_ed, h, sig_bytes)
5. If false  → reject SIGN-003
```

**8.3 Hybrid verification**

```
Given: O with "ed25519_sig" and "pqc_sig", public keys pk_ed + pk_pqc

1. ed_bytes  = base64url_decode(O["ed25519_sig"])  — must be 64 bytes (SIGN-005)
2. pqc_bytes = base64url_decode(O["pqc_sig"])      — must be 3309 bytes (SIGN-013)
3. O_plain   = copy of O without "ed25519_sig", "pqc_sig", "pqc_alg"
4. h         = SHA-256(JCS(O_plain))
5. ed_ok     = Ed25519_Verify(pk_ed, h, ed_bytes)
6. pqc_ok    = MLDSA65_Verify(pk_pqc, h, pqc_bytes)
7. If NOT (ed_ok AND pqc_ok) → reject SIGN-003
   (both components MUST verify in HYBRID mode)
```

**8.4 PQC-only verification**

```
Given: O with "pqc_sig", ML-DSA-65 public key pk_pqc

1. pqc_bytes = base64url_decode(O["pqc_sig"])      — must be 3309 bytes (SIGN-013)
2. O_plain   = copy of O without "pqc_sig", "pqc_alg"
3. h         = SHA-256(JCS(O_plain))
4. result    = MLDSA65_Verify(pk_pqc, h, pqc_bytes)
5. If false  → reject SIGN-003
```

**8.5 Policy enforcement**

After signature verification, verifiers MUST check mode compliance against the active policy:

```
active_mode = policy.acp_sign_mode

If active_mode == "HYBRID" and artifact_mode != "HYBRID":
  → reject SIGN-014 (mode mismatch)

If policy.pqc_required == true and pqc_sig absent:
  → reject SIGN-015 (PQC signature required)

If now >= policy.pqc_required_after and pqc_sig absent:
  → reject SIGN-015 (PQC signature required — deadline exceeded)
```

---

## 9. Conformance Levels

| Level | Requirement |
|---|---|
| **L1** | Implements ACP-SIGN-1.0 only (`CLASSIC_ONLY`). Can read and verify ACP-SIGN-1.0 artifacts. |
| **L2** | Implements ACP-SIGN-2.0 `HYBRID` mode. Can produce and verify hybrid artifacts. Registers PQC public keys. |
| **L3** | Implements all three modes. Enforces `pqc_required_after` deadline. Manages PQC key lifecycle. |

All existing ACP v1.x deployments are implicitly L1. Upgrading to L2 requires registering ML-DSA-65 keys and updating the signing pipeline.

---

## 10. Errors

| Code | Condition |
|---|---|
| SIGN-001 | Signature field present before signing — object already signed or corrupted |
| SIGN-002 | JCS failed — object contains non-serializable types |
| SIGN-003 | Signature verification failed (Ed25519 or ML-DSA-65) |
| SIGN-004 | Public key not found for issuer |
| SIGN-005 | Ed25519 signature wrong length — expected 64 bytes |
| SIGN-006 | base64url decode failed |
| SIGN-007 | No signature field found in object that requires a signature |
| SIGN-008 | (Reserved) |
| SIGN-009 | (Reserved) |
| SIGN-010 | Unknown signature format — `ed25519_sig` present but verifier only supports ACP-SIGN-1.0 |
| SIGN-011 | `pqc_alg` value not supported (only `"ML-DSA-65"` is valid in v2.0) |
| SIGN-012 | Incomplete hybrid artifact — `ed25519_sig` present without `pqc_sig` |
| SIGN-013 | ML-DSA-65 signature wrong length — expected 3309 bytes |
| SIGN-014 | Signature mode mismatch — artifact mode does not match active policy mode |
| SIGN-015 | PQC signature required but absent — `pqc_required` enforced |

---

## 11. Backward Compatibility and Migration Guide

**11.1 ACP-SIGN-1.0 artifacts remain valid**

Artifacts signed with ACP-SIGN-1.0 (using the `sig` field) remain valid indefinitely in deployments operating in `CLASSIC_ONLY` mode. No re-signing is required.

**11.2 Migration path**

```
Phase 1 — Register PQC keys (no traffic impact):
  → Register ml-dsa-65 key pair for each agent and institution
  → Add pqc_public_key to agent records in the registry
  → Add institutional PQC key to ITA document

Phase 2 — Enable HYBRID mode:
  → Set acp_sign_mode = "HYBRID" in policy
  → Update signing pipeline to produce both ed25519_sig and pqc_sig
  → Verify all verifiers are ACP-SIGN-2.0 L2 compliant

Phase 3 — Set PQC deadline:
  → Set pqc_required_after = "<target_date>"
  → Monitor: any artifact missing pqc_sig after that date is rejected

Phase 4 (optional, v1.17+) — PQC-only:
  → Set acp_sign_mode = "PQC_ONLY"
  → Classical key material may be retired
```

**11.3 Interoperability window**

During the migration period (Phase 1–2), verifiers MUST accept both ACP-SIGN-1.0 artifacts (`sig` field) and ACP-SIGN-2.0 hybrid artifacts (`ed25519_sig` + `pqc_sig`). This window is expected to span at minimum 12 months to allow all deployed agents to upgrade.

**11.4 No mixed `sig` / `ed25519_sig`**

An artifact MUST NOT contain both `sig` (ACP-SIGN-1.0 classical field) and `ed25519_sig` simultaneously. The presence of both is an error (SIGN-001). Upgrading means replacing `sig` with `ed25519_sig` + `pqc_sig`.

---

## 12. Security Considerations

**12.1 Key generation**

ML-DSA-65 key pairs MUST be generated using a cryptographically secure random number generator. The reference implementation `cloudflare/circl` provides a FIPS 204-compliant key generation function.

**12.2 Side-channel considerations**

ML-DSA-65 signing is not constant-time in all implementations. Implementations operating in security-sensitive environments MUST use libraries with documented side-channel countermeasures.

**12.3 Signature size impact**

Hybrid artifacts are substantially larger than ACP-SIGN-1.0 artifacts due to the 3309-byte ML-DSA-65 signature. Storage and bandwidth requirements increase accordingly. Implementations SHOULD plan for a ~50× increase in signature field size when moving to hybrid mode.

**12.4 Algorithm agility**

The `pqc_alg` field is reserved for future algorithm substitution. In v2.0, only `"ML-DSA-65"` is valid. Future specifications may add `"SLH-DSA-128s"` (NIST FIPS 205, SPHINCS+) or other NIST-standardized schemes. The `pqc_alg` field enables verifiers to route to the correct verification logic without structural changes.

---

## Appendix A — Reference Implementations

| Language | Library | ML-DSA-65 Mode |
|---|---|---|
| Go | `github.com/cloudflare/circl/sign/dilithium` | `dilithium.Mode3` (Dilithium3 = ML-DSA-65) |
| Python | `pyca/cryptography` (≥ 43.0) | `dilithium3` |
| Rust | `pqcrypto-dilithium` | `dilithium3` |
| JavaScript | `@noble/post-quantum` | `ml_dsa_65` |

> **Note:** Ensure the library implements NIST FIPS 204 (final), not the earlier CRYSTALS-Dilithium round-3 specification. Key and signature sizes differ between versions.

---

## Appendix B — Worked Example (Hybrid Mode)

```
Input JSON object (before signing):
{
  "ver": "1.0",
  "iss": "did:key:z6MkekQTaq7vjX7Vdy6pxabbjgkauuzprRGbBWNAXDs1NZdQ",
  "sub": "acp:agent:org.example:agent-001",
  "iat": 1700000000
}

Step 1 — JCS canonicalization:
{"iat":1700000000,"iss":"did:key:z6MkekQTaq7vjX7Vdy6pxabbjgkauuzprRGbBWNAXDs1NZdQ","sub":"acp:agent:org.example:agent-001","ver":"1.0"}

Step 2 — SHA-256 digest:
h = SHA-256(canonical_bytes)  [32 bytes]

Step 3 — Ed25519 sign with sk_ed:
ed_sig = Ed25519_Sign(sk_ed, h)  [64 bytes → 86 base64url chars]

Step 4 — ML-DSA-65 sign with sk_pqc:
pqc_sig = MLDSA65_Sign(sk_pqc, h)  [3309 bytes → 4412 base64url chars]

Step 5 — Output hybrid artifact:
{
  "ver": "1.0",
  "iss": "did:key:z6MkekQTaq7vjX7Vdy6pxabbjgkauuzprRGbBWNAXDs1NZdQ",
  "sub": "acp:agent:org.example:agent-001",
  "iat": 1700000000,
  "ed25519_sig": "<86 base64url chars>",
  "pqc_sig":     "<4412 base64url chars>",
  "pqc_alg":     "ML-DSA-65"
}
```

Both `ed25519_sig` and `pqc_sig` are computed over the same digest `h`, which was computed from the object without any signature fields.

---

## Appendix C — Why ML-DSA-65 (not ML-DSA-44 or ML-DSA-87)

| Parameter set | NIST category | Public key | Signature | ACP rationale |
|---|---|---|---|---|
| ML-DSA-44 | 2 (≈ AES-128) | 1312 bytes | 2420 bytes | Insufficient margin for institutional infrastructure |
| **ML-DSA-65** | **3 (≈ AES-192)** | **1952 bytes** | **3309 bytes** | ✅ Recommended — balanced security/size for enterprise |
| ML-DSA-87 | 5 (≈ AES-256) | 2592 bytes | 4627 bytes | Excessive overhead; reserved for highest-sensitivity contexts |

ACP selects ML-DSA-65 as the mandatory parameter set. Implementations MUST NOT substitute ML-DSA-44 or ML-DSA-87 without an explicit policy declaration, as this would break interoperability.
