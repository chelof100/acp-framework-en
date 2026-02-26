# ACP-ITA-1.0
## Institutional Trust Anchor Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0
**Required-by:** ACP-LEDGER-1.0, ACP-CONF-1.0

---

## 1. Scope

This document defines how institutions are registered in ACP, how the Root Institutional Key (RIK) is established and managed, how external verifiers resolve institutional keys, and how trust is established between institutions in B2B environments.

---

## 2. Definitions

**Institutional Trust Anchor (ITA):** Authoritative record that binds an `institution_id` to an externally verifiable Ed25519 public key.

**Root Institutional Key (RIK):** Ed25519 key pair of the institution. The public key is registered in the ITA. The private key MUST be held in the institutional HSM and MUST never leave it.

**Key Rotation:** Process of replacing the RIK with verifiable continuity of trust.

**Cross-Institutional Verification:** Ability of institution B to verify ACP artifacts issued by institution A using only the public ITA.

---

## 3. Trust Model

```
         ITA Registry
         (authoritative)
               │
    ┌──────────┴──────────┐
    │                     │
Institution A         Institution B
RIK_A (pk_A)          RIK_B (pk_B)
    │                     │
    ├─ Capability Tokens   ├─ Capability Tokens
    ├─ Execution Tokens    ├─ Execution Tokens
    ├─ Ledger Events       ├─ Ledger Events
    └─ API Responses       └─ API Responses
```

---

## 4. Institutional Record Structure

```json
{
  "ver": "1.0",
  "institution_id": "org.example.banking",
  "display_name": "Example Banking Corp",
  "public_key": "<base64url_ed25519_public_key_32_bytes>",
  "key_id": "<SHA-256_base64url_of_public_key>",
  "registered_at": 1718900000,
  "status": "active",
  "contact_endpoint": "https://acp.example-banking.com",
  "prev_key_id": null,
  "rotation_ref": null,
  "sig": "<record_signature_by_ITA_authority>"
}
```

---

## 5. Field Specification

**5.1 `institution_id`**
Format: `<tld>.<domain>.<optional_subdomain>`. MUST be unique. Alphanumeric characters and dots. Maximum length: 128 characters.

**5.2 `public_key`**
MUST be a 32-byte Ed25519 public key in base64url without padding.

**5.3 `key_id`**
MUST be `base64url(SHA-256(decode_base64url(public_key)))`.

**5.4 `status`**
MUST be one of: `active`, `rotating`, `revoked`.

- `active` — current key
- `rotating` — rotation in progress, both keys valid during transition
- `revoked` — key compromised, all artifacts signed with it are invalid

**5.5 `contact_endpoint`**
Base URL of the institutional ACP system. MUST be HTTPS.

**5.6 `prev_key_id`**
`key_id` of the previous key. Null for initial records.

**5.7 `sig`**
Signature of the ITA authority over all fields except `sig`, per ACP-SIGN-1.0.

---

## 6. ITA Registry API

### `GET /ita/v1/institutions/{institution_id}`

Returns the institutional record. **Does not require authentication.**

**Response 200:**
```json
{
  "ver": "1.0",
  "institution_id": "org.example.banking",
  "public_key": "<base64url_pk>",
  "key_id": "<key_id>",
  "status": "active",
  "contact_endpoint": "https://acp.example-banking.com",
  "sig": "<ITA_authority_signature>"
}
```

### `GET /ita/v1/institutions/{institution_id}/key/{key_id}`

Returns a specific key by key_id. Useful during rotation.

**Response 200:**
```json
{
  "institution_id": "org.example.banking",
  "key_id": "<key_id>",
  "public_key": "<base64url_pk>",
  "status": "active | rotating | revoked",
  "valid_from": 1718900000,
  "valid_until": null,
  "sig": "<ITA_authority_signature>"
}
```

`valid_until` is null while the key is active.

### `POST /ita/v1/institutions`

Registers a new institution. Requires out-of-band authentication with the ITA authority.

**Request body:**
```json
{
  "institution_id": "org.example.banking",
  "display_name": "Example Banking Corp",
  "public_key": "<base64url_pk>",
  "contact_endpoint": "https://acp.example-banking.com",
  "proof_of_key_possession": "<signature_over_institution_id_with_institutional_sk>"
}
```

`proof_of_key_possession` MUST be `base64url(Sign(institutional_sk, SHA-256(institution_id_bytes)))`.

---

## 7. Key Resolution for Verification

```
1. Extract institution_id from artifact
2. GET /ita/v1/institutions/{institution_id}
3. Verify record sig with ITA authority pk
4. Verify status == "active" or "rotating"
5. If status == "revoked" → reject artifact
6. Extract public_key and verify artifact signature
```

**Caching:** Recommended TTL 3600s. Maximum TTL 86400s. During `rotating`: maximum TTL 300s.

---

## 8. Key Rotation

### Normal process (3 phases)

**Phase 1 — Preparation:**
- Institution generates new key pair in HSM
- Submits new public_key with proof_of_possession to ITA authority
- Authority updates status to `rotating`, records `prev_key_id`

**Phase 2 — Transition (maximum 7 days):**
- New artifacts signed with new key
- Artifacts with previous key remain valid
- Verifiers obtain both keys during transition

**Phase 3 — Completion:**
- Institution confirms no active artifacts with previous key
- ITA authority updates to `active` with new key
- `prev_key_id` remains for historical traceability

### Emergency rotation (key compromise)

```
1. Institution notifies ITA authority
2. Authority marks current key as "revoked" with valid_until = now
3. All artifacts signed with that key are immediately invalid
4. Institution initiates registration with new key
5. No transition period
```

Emergency rotation invalidates all CTs, ETs, and ledger events signed with the compromised key. This is correct and expected behavior.

---

## 9. key_id Inclusion in Artifacts

To support efficient resolution during rotation:

In Capability Tokens (optional field):
```json
"iss_key_id": "<key_id>"
```

In ledger events (optional field):
```json
"signing_key_id": "<key_id>"
```

When present, the verifier SHOULD use `GET /ita/v1/institutions/{institution_id}/key/{key_id}` directly.

---

## 10. Bootstrap

The ITA authority's public key MUST be distributed via out-of-band channel. Recommended mechanisms: signed official documentation, DNS with DNSSEC, TLS certificate of the ITA endpoint.

Bootstrap is the only point where ACP depends on an external mechanism. Once the verifier has the ITA authority's key, all subsequent verification is autonomous.

---

## 11. Operational Models

**Model A — Centralized:** A single entity operates the ITA Registry. Simple to implement. Single point of trust.

**Model B — Federated:** Multiple ITA authorities with mutual recognition. No single point of trust. Requires an inter-authority recognition protocol.

The specification defines the interface without prescribing the model. Each B2B deployment chooses the model. The verification mechanisms are identical in both.

---

## 12. Errors

| Code | Condition |
|------|-----------|
| ITA-001 | institution_id not registered |
| ITA-002 | Institution revoked |
| ITA-003 | key_id not found for institution |
| ITA-004 | Invalid proof_of_key_possession |
| ITA-005 | institution_id already registered |
| ITA-006 | ITA record signature invalid |
| ITA-007 | Key in revoked state — artifact invalid |

---

## 13. Conformance

An implementation is ACP-ITA-1.0 conformant if it:

- Maintains institutional record with structure from §4
- Exposes endpoints from §6
- Implements proof_of_key_possession at initial registration
- Implements rotation with maximum transition period of 7 days
- Implements emergency rotation with immediate invalidation
- Signs all records with the ITA authority's RIK
- Allows resolution by key_id during rotation
