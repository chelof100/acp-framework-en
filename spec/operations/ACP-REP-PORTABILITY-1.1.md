# ACP-REP-PORTABILITY-1.1 — Signed Reputation Snapshot

**Version:** 1.1
**Status:** Active
**Supersedes:** ACP-REP-PORTABILITY-1.0 (archived)
**Dependencies:** ACP-SIGN-1.0, ACP-REP-1.2
**Implements:** ACP-CONF-1.2 Conformance Level L4
**Related:** ACP-CROSS-ORG-1.1, ACP-REP-1.2

---

## §1 Overview

ACP-REP-PORTABILITY-1.1 defines the `ReputationSnapshot`: a compact, cryptographically signed record that carries an agent's reputation score across organizational boundaries. Unlike the bilateral attestation protocol of v1.0, this specification focuses on the **snapshot object itself** — its structure, signing procedure, validation algorithm, and expiration semantics — enabling any verifier to independently validate a snapshot without trusting an intermediary.

A `ReputationSnapshot` is issued by a scoring institution (the **issuer**), signed with Ed25519 over a JCS-canonical payload, and carries a mandatory expiration timestamp (`valid_until`). Verifiers check the signature and, for v1.1 snapshots, enforce expiration. Snapshots issued under v1.0 remain valid without expiration enforcement (§12).

---

## §2 Scope

This document defines:

- The `ReputationSnapshot` object and its fields
- The signing procedure (JCS + SHA-256 + Ed25519)
- The validation algorithm, including backward compatibility with v1.0
- Divergence semantics for cross-organizational score comparison
- Error codes and warning codes
- Extensibility rules

This document does **not** define:

- The internal scoring engine or EWA formula (see ACP-REP-1.2)
- The bilateral attestation request protocol (see ACP-REP-PORTABILITY-1.0, archived)
- Transport-level protocols for snapshot exchange
- Cross-org key discovery or federation (see ACP-CROSS-ORG-1.1)
- A confidence field or probabilistic bounds (deferred to extensibility, §14)
- Demo multi-org workflows (see GAP-14)

---

## §3 Data Model

### 3.1 ReputationSnapshot

```json
{
  "ver": "1.1",
  "rep_id": "3f7a1c9e-0b2d-4e8a-a5f6-1234567890ab",
  "subject_id": "agent.example.payments",
  "issuer": "inst-alpha",
  "score": 0.82,
  "scale": "0-1",
  "model_id": "risk-v3",
  "evaluated_at": 1741200000,
  "valid_until": 1741203600,
  "signature": "Ed25519-base64url..."
}
```

### 3.2 signableReputation (canonical payload)

The signing payload is the snapshot without the `signature` field:

```json
{
  "ver": "1.1",
  "rep_id": "3f7a1c9e-0b2d-4e8a-a5f6-1234567890ab",
  "subject_id": "agent.example.payments",
  "issuer": "inst-alpha",
  "score": 0.82,
  "scale": "0-1",
  "model_id": "risk-v3",
  "evaluated_at": 1741200000,
  "valid_until": 1741203600
}
```

Canonicalization MUST use JCS (RFC 8785). Implementations MUST NOT use `json.Marshal` directly as the canonical form — field ordering is not guaranteed by standard JSON libraries and differs across languages.

---

## §4 Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | ✓ | Spec version. MUST be `"1.0"` or `"1.1"`. |
| `rep_id` | string (UUID v4) | ✓ | Unique identifier for this snapshot. Issuers MUST NOT reuse `rep_id` values. |
| `subject_id` | string | ✓ | ACP agent identifier for the subject of this reputation score. |
| `issuer` | string | ✓ | Identifier of the institution issuing this snapshot. MUST NOT be empty. |
| `score` | float64 | ✓ | Reputation score. MUST be within the bounds defined by `scale`. |
| `scale` | string | ✓ (v1.1) | Score range. Supported values: `"0-1"` (score ∈ [0.0, 1.0]) or `"0-100"` (score ∈ [0.0, 100.0]). |
| `model_id` | string | ✓ (v1.1) | Identifier of the scoring model used. Opaque to the verifier; used for audit and traceability. |
| `evaluated_at` | int64 | ✓ | Unix timestamp (seconds) when the score was computed. |
| `valid_until` | int64 | ✓ (v1.1) | Unix timestamp (seconds) after which this snapshot is expired. MUST be ≥ `evaluated_at`. |
| `signature` | string | ✓ | Ed25519 signature over the JCS-canonical `signableReputation`, base64url-encoded (no padding). |

**v1.0 fields:** `ver`, `rep_id`, `subject_id`, `issuer`, `score`, `evaluated_at`, `signature`. Fields `scale`, `model_id`, and `valid_until` are absent in v1.0 snapshots.

---

## §5 Invariants

These invariants MUST hold for a snapshot to be considered valid.

| § | Invariant | Applies to | Error |
|---|-----------|------------|-------|
| 5.1 | `evaluated_at ≤ valid_until` | v1.1 only | REP-001 |
| 5.2 | `now ≤ valid_until` | v1.1 only | REP-011 |
| 5.3 | `score` within bounds of `scale` | v1.1 only | REP-002 |
| 5.4 | `issuer` is not empty | all versions | REP-004 |
| 5.5 | `signature` is cryptographically valid | all versions | REP-010 |

**Note on 5.3 scale bounds:**
- `scale = "0-1"`: score MUST satisfy `0.0 ≤ score ≤ 1.0`
- `scale = "0-100"`: score MUST satisfy `0.0 ≤ score ≤ 100.0`
- Any other `scale` value is rejected with REP-002

---

## §6 Validation Algorithm

```
ValidateReputationSnapshot(rep, now):
  1. Verify rep.ver ∈ {"1.0", "1.1"}
       → if unknown version, return error (unsupported version)
  2. Verify rep.issuer ≠ ""
       → REP-004 if empty
  3. Verify rep.evaluated_at ≤ rep.valid_until  [v1.1 only]
       → REP-001 if violated
  4. If rep.ver == "1.1":
       Verify now.Unix() ≤ rep.valid_until
       → REP-011 if expired
  5. If rep.ver == "1.1":
       Verify rep.score within bounds of rep.scale
       → REP-002 if out of bounds or unknown scale
  6. Verify rep.signature ≠ ""
       → REP-010 if empty
  7. Return VALID

VerifySig(rep, pubKey):
  1. Construct signableReputation (all fields except signature)
  2. canonical = JCS(json.Marshal(signableReputation))
  3. digest = SHA-256(canonical)
  4. sigBytes = base64url_decode(rep.signature)
  5. Verify Ed25519(pubKey, digest, sigBytes)
       → REP-010 if verification fails
  6. Return VALID
```

**Design note:** `Validate()` and `VerifySig()` are intentionally separate operations. `Validate()` checks structural invariants without requiring the issuer's public key. `VerifySig()` is called separately when the verifier has the issuer's public key. This separation allows lightweight structural validation at ingestion time and full cryptographic validation when the key is available.

---

## §7 Divergence Semantics

When a verifier receives snapshots of the same `subject_id` from multiple issuers, it MAY compute divergence to detect scoring inconsistencies.

### 7.1 ComputeDivergence

```
ComputeDivergence(a, b) → float64:
  return |a.score - b.score|
```

Both snapshots MUST use the same `scale`. Comparing snapshots with different scales is undefined behavior and MUST NOT be performed.

### 7.2 CheckDivergence

```
CheckDivergence(a, b, threshold) → (exceeded bool, divergence float64):
  div = ComputeDivergence(a, b)
  return (div > threshold), div
```

### 7.3 Warning REP-WARN-002

If `CheckDivergence` returns `exceeded = true`, the verifier SHOULD emit warning `REP-WARN-002` (divergence detected). This is a non-blocking warning — the verifier continues processing. The policy decision of whether to accept, reject, or escalate is left to the verifier's business logic.

Recommended default threshold: `0.30` for `scale="0-1"`, `30.0` for `scale="0-100"`.

---

## §8 Cross-Org Integration

ACP-REP-PORTABILITY-1.1 is designed to operate within the cross-organizational trust model defined in ACP-CROSS-ORG-1.1. Typical usage:

1. **Issuance:** The home institution scores the agent and calls `Capture()` to produce a signed `ReputationSnapshot`. The snapshot is delivered to the agent or a designated endpoint.
2. **Presentation:** The agent presents the snapshot to a foreign institution as part of an authorization or onboarding flow.
3. **Verification:** The foreign institution calls `ValidateReputationSnapshot(rep, now)` and `VerifySig(rep, issuerPubKey)`. The issuer's public key is resolved via ACP-CROSS-ORG-1.1 key discovery (or a pre-shared trust anchor).
4. **Divergence check (optional):** If the foreign institution has its own score for the agent, it MAY call `CheckDivergence` and emit REP-WARN-002 if the threshold is exceeded.

The foreign institution's **policy decision** (whether to grant access based on a given score) is out of scope. The verifier applies its own threshold — this is intentional institutional sovereignty. ACP does not mandate what score value constitutes "good enough."

---

## §9 Error Codes

| Code | Description | HTTP (if applicable) |
|------|-------------|----------------------|
| REP-001 | `evaluated_at > valid_until`: temporal order violated | 422 |
| REP-002 | Score out of scale bounds, or unsupported scale value | 422 |
| REP-004 | `issuer` field is missing or empty | 422 |
| REP-010 | Signature invalid (bad bytes, empty, or verification failed) | 422 |
| REP-011 | Snapshot expired: `now > valid_until` (v1.1 only) | 410 |

---

## §10 Warning Codes

Warning codes are non-blocking. Implementations SHOULD log them and MAY surface them to policy decision points.

| Code | Description |
|------|-------------|
| REP-WARN-002 | Divergence detected: score difference between two snapshots exceeds threshold |

---

## §11 Versioning

| Ver | `valid_until` | `scale` | `model_id` | Expiration enforced |
|-----|--------------|---------|------------|---------------------|
| 1.0 | absent | absent | absent | No |
| 1.1 | required | required | required | Yes |

Version is determined by the `ver` field in the snapshot. An implementation that encounters an unknown version MUST reject the snapshot with an unsupported version error (not a REP-00x code — this is a structural error before invariant checks begin).

---

## §12 Backward Compatibility

A v1.1 validator MUST accept v1.0 snapshots with the following adjustments:

- **Expiration NOT enforced:** Invariant 5.2 (`now ≤ valid_until`) is skipped for v1.0 snapshots. `valid_until` is absent and defaults to `MaxInt64` (never expires in the validator).
- **Invariant 5.1** (`evaluated_at ≤ valid_until`) is skipped for v1.0 snapshots.
- **Invariant 5.3** (score bounds) is skipped for v1.0 snapshots — `scale` is absent.
- **Signature verification** applies to all versions using the same JCS + SHA-256 + Ed25519 procedure.
- **Issuer check** (invariant 5.4) applies to all versions.

This ensures that a v1.0 snapshot remains valid indefinitely from the verifier's perspective — the issuer institution retains control over v1.0 snapshot lifecycle.

---

## §13 Security

### 13.1 Signing

The signing procedure is:

```
1. raw     = json.Marshal(signableReputation)
2. canonical = jcs.Transform(raw)          // JCS RFC 8785
3. digest  = sha256.Sum256(canonical)
4. sig     = ed25519.Sign(privKey, digest[:])
5. snapshot.Signature = base64url_encode(sig)  // no padding (RawURLEncoding)
```

Implementations MUST use JCS (RFC 8785) for canonicalization. Using `json.Marshal` directly as the canonical form is **not permitted** — key ordering differs across language implementations and will produce verification failures in cross-org deployments.

The digest (SHA-256 of canonical) is what is signed, not the canonical bytes directly. This is consistent with the ACP signing convention used in ACP-POLICY-CTX-1.1 and ACP-CROSS-ORG-1.1.

### 13.2 `valid_until` authority

The issuer has exclusive authority over `valid_until`. The verifier:
- MUST NOT extend `valid_until` beyond what the issuer set
- MUST NOT reduce `valid_until` to force earlier expiration
- MUST reject expired snapshots (v1.1) with REP-011

This is a deliberate departure from ACP-POLICY-CTX-1.1's `effectiveMax` model. In POLICY-CTX, verifiers may reduce `delta_max` because they have operational context about acceptable freshness. In REP-PORT, the issuer has full authority over score lifetime — the verifier's role is to apply its own acceptance threshold (what score value is acceptable), not to alter the temporal bounds.

### 13.3 Replay protection

`rep_id` (UUID v4) MUST be treated as a one-time identifier. Implementations that require replay protection MUST maintain a nonce registry and reject snapshots whose `rep_id` has been seen, subject to `valid_until` as the registry TTL.

### 13.4 Key management

Issuers MUST use dedicated Ed25519 signing keys for reputation snapshots. Key rotation is out of scope — implementations SHOULD follow ACP-SIGN-1.0 key management guidelines.

---

## §14 Extensibility

Future versions MAY add fields to `ReputationSnapshot`. A v1.1 validator encountering unknown fields MUST ignore them (permissive unknown field policy). This enables forward compatibility with v1.2+ snapshots in environments that have not yet upgraded.

Fields explicitly deferred from v1.1:

| Field | Deferral reason |
|-------|-----------------|
| `confidence` | Requires probabilistic scoring model — future work |
| `verifier_override_until` | Not applicable — issuer has full authority (§13.2) |

---

## §15 Design Principles

**Issuer sovereignty:** The issuer defines the score, the scale, the model, and the validity window. Verifiers accept or reject based on their own thresholds — they do not alter the issuer's assertions.

**Minimal payload:** A `ReputationSnapshot` carries only what is needed for verification. Internal scoring history, event logs, and behavioral records are never exported.

**Deterministic signing:** JCS canonicalization guarantees that two implementations (Go, Python, TypeScript) signing the same snapshot produce identical payloads and therefore identical signatures. Cross-org interoperability depends on this property.

**Separation of concerns:** Structural validation (`Validate`) and cryptographic verification (`VerifySig`) are separate operations. This allows lightweight ingestion-time checks without requiring key material.

**Backward compatibility:** v1.0 snapshots continue to validate without modification. The upgrade path from v1.0 to v1.1 is additive (new required fields in new snapshots only).
