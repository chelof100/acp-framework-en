# ACP-ITA-1.1
## Inter-Authority Federation Specification
**Status:** Draft
**Version:** 1.1
**Depends-on:** ACP-ITA-1.0, ACP-SIGN-1.0
**Required-by:** ACP-LEDGER-1.1 (cross-institutional verification), ACP-REP-1.2 (cross-institutional ERS)
**Changelog:** v1.1 — Adds mutual recognition protocol between independent ITA authorities (Federated Model B defined in ACP-ITA-1.0 §11). Supersedes previous BFT draft.

---

## 1. Scope

ACP-ITA-1.0 defines the centralized model (Model A): a single ITA authority registers institutions. This document defines Federated Model B: multiple independently-operated ITA authorities that mutually recognize each other, enabling cross-authority verification without a single point of trust.

ACP-ITA-1.1 specifies:
- FederationRecord structure: the bilaterally signed mutual recognition agreement
- Federation establishment protocol
- Cross-authority resolution algorithm for ACP artifacts
- Revocation propagation between federated authorities
- Authority discovery for a given `institution_id`

---

## 2. Definitions

**Authority (ITA Authority):** Entity operating an ITA Registry per ACP-ITA-1.0. Identified by `authority_id` (format: `ita.<domain>`).

**FederationRecord:** A bilaterally signed document expressing that two authorities mutually recognize each other as trustworthy for ACP verification purposes.

**FederationRegistry:** A public endpoint of an authority listing all its active federation relationships.

**Cross-Authority Resolution:** The process by which institution B (under ITA_B) verifies artifacts issued by institution A (under ITA_A) using the ITA_A ↔ ITA_B federation.

**Authority Root Key (ARK):** Ed25519 key pair of the ITA authority. Analogous to the institutional RIK but for the authority itself. Used to sign FederationRecords and institutional registry entries.

---

## 3. Federated Trust Model

```
        ITA_A                        ITA_B
    (authority_a)               (authority_b)
         │                            │
         │    FederationRecord        │
         │◄──────────────────────────►│
         │    (bilateral, signed)     │
         │                            │
    ┌────┴────┐                  ┌────┴────┐
    │  Inst A │                  │  Inst B │
    │ (org.a) │                  │ (org.b) │
    └─────────┘                  └─────────┘
         │                            │
         └──── ACP artifacts ─────────►│
              (verifiable via
               cross-auth resolution)
```

Federation is bilateral: ITA_A recognizes ITA_B and vice versa in the same FederationRecord. Unidirectional federation does not exist.

Federation depth is 1 hop: ITA_A may federate with ITA_B and with ITA_C, but ITA_B and ITA_C are not transitively recognized as a result. Each pair requires its own FederationRecord.

---

## 4. FederationRecord Structure

```json
{
  "ver": "1.1",
  "federation_id": "<uuid_v4>",
  "authority_a": {
    "authority_id": "ita.example-a.com",
    "display_name": "Authority A",
    "registry_endpoint": "https://ita.example-a.com",
    "public_key": "<base64url_ed25519_pk_32_bytes>",
    "key_id": "<SHA-256_base64url_of_public_key>"
  },
  "authority_b": {
    "authority_id": "ita.example-b.com",
    "display_name": "Authority B",
    "registry_endpoint": "https://ita.example-b.com",
    "public_key": "<base64url_ed25519_pk_32_bytes>",
    "key_id": "<SHA-256_base64url_of_public_key>"
  },
  "established_at": 1718900000,
  "valid_until": null,
  "scope": {
    "capabilities": ["*"],
    "event_types": ["*"],
    "restrictions": null
  },
  "sig_a": "<authority_a_signature_over_record_without_sig_b>",
  "sig_b": "<authority_b_signature_over_record_without_sig_a>"
}
```

`valid_until` is null for indefinite federations. When present, the federation expires automatically and all artifacts issued before expiration remain verifiable until their own `exp`.

`scope.capabilities` limits which ACP capabilities are recognized cross-authority. `["*"]` means unrestricted.

`sig_a` covers all fields except `sig_a` and `sig_b`. Same for `sig_b`. Both signatures MUST be present for the record to be valid.

---

## 5. Federation Establishment Protocol

### Phase 1 — Proposal (out of band)

Authorities contact each other through an out-of-band channel (email, legal agreement, admin portal) and agree to federate. The out-of-band mechanism is not specified by ACP.

### Phase 2 — Bilateral signing

```
1. ITA_A constructs FederationRecord with all fields except sig_a and sig_b
2. ITA_A signs: sig_a = Sign(ark_a, SHA-256(JCS(record_without_both_sigs)))
3. ITA_A sends the record with sig_a to ITA_B
4. ITA_B verifies sig_a with pk_a obtained out of band
5. ITA_B signs: sig_b = Sign(ark_b, SHA-256(JCS(record_without_both_sigs)))
6. ITA_B publishes the complete record (with sig_a and sig_b) in its FederationRegistry
7. ITA_A does the same
```

Both authorities MUST publish the same FederationRecord. A verifier obtaining the record from either party can verify both signatures.

### Phase 3 — Activation

The federation is active when the FederationRecord is published by both parties. There is no transition period.

---

## 6. FederationRegistry API

### `GET /ita/v1/federation`

Lists all active federations for this authority. **No authentication required.**

**Response 200:**
```json
{
  "ver": "1.1",
  "authority_id": "ita.example-a.com",
  "federations": [
    {
      "federation_id": "<uuid>",
      "peer_authority_id": "ita.example-b.com",
      "peer_display_name": "Authority B",
      "peer_registry_endpoint": "https://ita.example-b.com",
      "established_at": 1718900000,
      "valid_until": null,
      "status": "active"
    }
  ]
}
```

### `GET /ita/v1/federation/{federation_id}`

Returns the complete FederationRecord with both signatures.

**Response 200:** Complete FederationRecord per §4.

### `GET /ita/v1/federation/resolve/{institution_id}`

Given an `institution_id`, returns which authority governs that institution, searching the local registry and federated peers.

**Response 200:**
```json
{
  "institution_id": "org.example.banking",
  "governing_authority": "ita.example-a.com",
  "resolution_path": "direct | federated",
  "federation_id": "<uuid_or_null_if_direct>",
  "institution_record": {},
  "verified_at": 1718920000
}
```

`resolution_path: "direct"` — the institution is in the local registry.
`resolution_path: "federated"` — the institution was found in a federated peer.

The server MUST verify the signature of the returned institutional record before including it in the response.

**Errors:**

| Code | HTTP | Condition |
|------|------|-----------|
| ITA-F001 | 404 | institution_id not found in any federated registry |
| ITA-F002 | 502 | Peer federation registry not responding (timeout) |

When ITA-F002, the response SHOULD include which peers were attempted and which failed:
```json
{
  "error": "ITA-F002",
  "peers_attempted": ["ita.example-b.com"],
  "peers_failed": ["ita.example-b.com"]
}
```

---

## 7. Revocation Notification — `POST /ita/v1/revocation-notify`

When an institution under ITA_A is revoked, ITA_A MUST notify all its federated peers.

### Request body (sent by ITA_A to ITA_B)

```json
{
  "ver": "1.1",
  "notification_id": "<uuid>",
  "federation_id": "<uuid>",
  "notifying_authority": "ita.example-a.com",
  "event": "institution_revoked | institution_key_revoked",
  "institution_id": "org.example.banking",
  "key_id": "<affected_key_id_or_null_if_institution_revoked>",
  "revoked_at": 1718920000,
  "reason_code": "ITA-F010",
  "sig": "<authority_a_signature>"
}
```

`sig` covers all fields except `sig`.

ITA_B MUST verify `sig` with ITA_A's pk from the FederationRecord before processing the notification.

### Response 200

```json
{
  "notification_id": "<uuid>",
  "accepted": true,
  "invalidated_cache_entries": 3
}
```

ITA_B MUST immediately invalidate its local cache of the revoked institution or key. Artifacts signed with the revoked key are invalid from `revoked_at`.

---

## 8. Cross-Authority Resolution Algorithm

When institution B (under ITA_B) verifies an ACP artifact issued by institution A (under ITA_A):

```
1. Extract institution_id from artifact → "org.example.banking"
2. GET /ita/v1/institutions/org.example.banking at ITA_B → 404 (not in ITA_B)
3. GET /ita/v1/federation/resolve/org.example.banking at ITA_B
   → governing_authority: "ita.example-a.com", resolution_path: "federated"
4. Obtain FederationRecord ITA_A ↔ ITA_B:
   GET /ita/v1/federation/{federation_id} at ITA_B or ITA_A
5. Verify both FederationRecord signatures with pk of ITA_A and ITA_B
   (ITA_B pk known locally; ITA_A pk is in FederationRecord)
6. Verify FederationRecord.status == "active"
7. Obtain institutional record from ITA_A:
   GET /ita/v1/institutions/org.example.banking at ITA_A
8. Verify institutional record signature with ITA_A pk (from FederationRecord)
9. Extract institutional public_key and verify artifact signature
```

A verifier can perform this process without trusting ITA_A directly — it trusts ITA_B's signature on the FederationRecord, which in turn includes ITA_A's pk.

**Caching:** FederationRecords may be cached up to 3600s. Institutional records obtained via federation have maximum TTL 300s (same as during rotation in ITA-1.0).

---

## 9. Impact on ACP-REP-1.2

`REPUTATION_UPDATED` events emitted by institution A (under ITA_A) and used by institution B (under ITA_B) to compute cross-institutional ERS MUST be verified via the §8 algorithm before being treated as `context: "cross_institutional"` (weight 1.0 in ERS).

Events not verifiable via cross-authority resolution (federation unavailable, invalid signature) MUST be discarded from the ERS calculation.

---

## 10. Federation Termination

A federation may be terminated by mutual agreement or unilaterally.

### Mutual termination

Both authorities remove the FederationRecord from their FederationRegistries simultaneously.

### Unilateral termination

An authority may mark the federation as `status: "terminating"` in its own registry, establishing a 7-day grace period. During that period:
- No new cross-authority artifacts are accepted
- Artifacts issued before `terminating_at` remain verifiable until their own `exp`

When the grace period expires, status transitions to `"terminated"`. Artifacts issued after `terminating_at` are invalid.

The other authority MUST be notified via `POST /ita/v1/revocation-notify` with `event: "federation_terminating"`.

---

## 11. General Federation Errors

| Code | HTTP | Condition |
|------|------|-----------|
| ITA-F010 | — | Institution revoked by its governing authority |
| ITA-F011 | 400 | FederationRecord with invalid signature |
| ITA-F012 | 400 | FederationRecord expired |
| ITA-F013 | 403 | Federation terminated — cross-authority resolution unavailable |
| ITA-F014 | 400 | Revocation notification with invalid signature |
| ITA-F015 | 409 | Federation already exists between these two authorities |
| ITA-F016 | 400 | Federation depth exceeded (max 1 direct hop) |

---

## 12. Security Considerations

**FederationRecord capture:** An attacker who compromises ITA_A's ARK can establish fraudulent federations. The ARK MUST be kept in an HSM with strictly limited access.

**Ambiguous institution_id resolution:** If the same `institution_id` appears under two different authorities, the verifier MUST reject both and report ITA-F001. `institution_id` values must be globally unique.

**Authority pk bootstrap:** An ITA authority's pk (its public ARK) MUST be obtained out of band the first time. Recommended mechanisms: DNSSEC, TLS certificate of the ITA endpoint, officially signed documentation. Once obtained, all subsequent verifications are autonomous.

**Late revocation:** Between ITA_A revoking an institution and the notification reaching ITA_B, a time window exists where ITA_B still accepts artifacts from the revoked institution. This window is acceptable given the threat model and is mitigated by a low TTL (300s) for federated institutional records.

---

## 13. Conformance

An implementation is ACP-ITA-1.1 conformant if it:

- Implements FederationRecord per §4 with dual signature
- Implements establishment protocol from §5
- Exposes `GET /ita/v1/federation`, `GET /ita/v1/federation/{id}`, `GET /ita/v1/federation/resolve/{institution_id}`
- Exposes `POST /ita/v1/revocation-notify` and propagates revocations to peers
- Implements cross-authority resolution algorithm from §8
- Limits federation to 1 hop (non-transitive)
- Invalidates local cache on revocation notification
- Keeps ARK in HSM and never exposes it via API
