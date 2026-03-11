# ACP-PSN-EXPORT — Policy Snapshot Cross-Institution Export

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0 |
| **Type** | Protocol Extension |
| **Depends-on** | ACP-PSN-1.0, ACP-SIGN-1.0, ACP-LEDGER-1.2 |
| **Date** | 2026-03-10 |

---

## 1. Purpose

This document specifies the mechanism for exporting Policy Snapshots (PSN) between participating institutions in the ACP federation, in a signed and verifiable format.

PSN export allows an institution to share a verified policy state with another institution, guaranteeing:

- **Authenticity**: the snapshot originates from the declared source institution.
- **Integrity**: the content was not modified in transit.
- **Freshness**: the snapshot was exported within a valid time window.
- **Traceability**: the event is recorded in the ledger of both institutions.

This mechanism is required for cross-institution audit scenarios, federated agent onboarding, and policy synchronization between ACP nodes belonging to different organizations.

---

## 2. Export Format

A Policy Snapshot export is encapsulated in a **signed export envelope** with the following structure:

```json
{
  "export_id": "exp-uuid-7f3a1b",
  "snapshot_id": "psn-uuid-4d2e9c",
  "source_institution": "inst-uuid-acme",
  "target_institution": "inst-uuid-globalbank",
  "exported_at": "2026-03-10T14:00:00Z",
  "snapshot_content": {
    "snapshot_id": "psn-uuid-4d2e9c",
    "institution_id": "inst-uuid-acme",
    "policy_version": "3.1.2",
    "effective_at": "2026-03-01T00:00:00Z",
    "rules": [ "..." ],
    "content_hash": "sha256:abc123..."
  },
  "signature": "<compact JWS — signed by source_institution>"
}
```

### 2.1 Envelope fields

| Field | Type | Description |
|---|---|---|
| `export_id` | UUID | Unique identifier for this export. Single-use per source/target pair. |
| `snapshot_id` | UUID | Reference to the exported snapshot (ACP-PSN-1.0). |
| `source_institution` | UUID | Institution that generates and signs the envelope. |
| `target_institution` | UUID | Destination institution for the envelope. |
| `exported_at` | ISO 8601 | Timestamp when the envelope was generated. |
| `snapshot_content` | Object | Full snapshot body per ACP-PSN-1.0. |
| `signature` | JWS | JWS (JSON Web Signature) of the full envelope by `source_institution`. |

### 2.2 Signature algorithm

The JWS signature MUST use the `ES256` algorithm with the private key registered for `source_institution` in the ACP key directory. The signed payload is the full envelope object excluding the `signature` field.

---

## 3. Export Endpoint

### 3.1 Request

```
GET /acp/v1/policy-snapshots/{snapshot_id}/export?target_institution={inst_id}
```

| Parameter | Location | Required | Description |
|---|---|---|---|
| `snapshot_id` | Path | Yes | ID of the snapshot to export |
| `target_institution` | Query | Yes | ID of the destination institution |

**Required headers:**
```
Authorization: Bearer <source_institution token>
Content-Type: application/json
```

### 3.2 Successful response

```
HTTP 200 OK
Content-Type: application/json
```

Body: the signed export envelope per §2.

### 3.3 Server behavior

Upon receiving the request, the ACP server of `source_institution` MUST:

1. Verify that `snapshot_id` exists and belongs to the authenticated institution.
2. Verify that `target_institution` is in the trust federation (ACP-ITA-1.1).
3. Verify that no prior export of this snapshot to `target_institution` exists (single-use).
4. Construct the export envelope with the fields from §2.
5. Sign the envelope with the institutional private key.
6. Record the event in the ledger (§6).
7. Return the signed envelope.

---

## 4. Receiving Institution Validation

Upon receiving an export envelope, the receiving institution MUST validate the following in order:

### 4.1 JWS signature verification

- Obtain the public key of `source_institution` from the ACP key directory.
- Verify the JWS signature of the full envelope (excluding the `signature` field).
- If verification fails: reject with error `PSN-EXP-003`.

### 4.2 Content hash verification

- Compute the SHA-256 hash of `snapshot_content` serialized canonically.
- Compare against `snapshot_content.content_hash`.
- If they do not match: reject with error `PSN-EXP-003`.

### 4.3 Time window verification

- Compute `now() - exported_at`.
- If the result exceeds 24 hours: reject with error `PSN-EXP-004`.

### 4.4 Federation verification

- Confirm that `source_institution` appears in the federated institution registry (ACP-ITA-1.1).
- If not federated: reject with error `PSN-EXP-002`.

### 4.5 Acceptance

Only after passing all validations above MAY the receiving institution import the snapshot into its local storage and record the import event (§7).

---

## 5. Error Codes

| Code | HTTP | Description |
|---|---|---|
| `PSN-EXP-001` | 404 | Snapshot not found or does not belong to the authenticated institution |
| `PSN-EXP-002` | 403 | Target institution is not federated (not present in ACP-ITA-1.1) |
| `PSN-EXP-003` | 422 | Signature or hash verification failed |
| `PSN-EXP-004` | 410 | Snapshot expired for export (24h window exceeded) |
| `PSN-EXP-005` | 409 | This snapshot was already previously exported to this target institution |

---

## 6. Ledger Integration

### 6.1 Event at source institution

Upon completing a successful export, `source_institution` MUST record the following event in ACP-LEDGER-1.2:

```json
{
  "event_type": "POLICY_SNAPSHOT_EXPORTED",
  "event_id": "evt-uuid-...",
  "timestamp": "2026-03-10T14:00:00Z",
  "snapshot_id": "psn-uuid-4d2e9c",
  "source_institution": "inst-uuid-acme",
  "target_institution": "inst-uuid-globalbank",
  "export_id": "exp-uuid-7f3a1b",
  "prev_hash": "<hash of the previous event in the chain>",
  "signature": "<institutional signature of the event>"
}
```

### 6.2 Event fields

| Field | Description |
|---|---|
| `event_type` | Fixed value: `POLICY_SNAPSHOT_EXPORTED` |
| `snapshot_id` | ID of the exported snapshot |
| `source_institution` | ID of the exporting institution |
| `target_institution` | ID of the receiving institution |
| `export_id` | Unique ID of the generated export envelope |
| `prev_hash` | Hash of the last event in the ledger chain (chaining) |
| `signature` | Institutional signature of the full event |

---

## 7. Security

### 7.1 Single-use exports

Each export envelope is single-use per `(snapshot_id, target_institution)` pair. If `source_institution` attempts to export the same snapshot to the same target institution again, the server MUST return `PSN-EXP-005`.

### 7.2 Import recording

The receiving institution MUST record in its own ledger the `POLICY_SNAPSHOT_IMPORTED` event upon accepting an envelope:

```json
{
  "event_type": "POLICY_SNAPSHOT_IMPORTED",
  "snapshot_id": "psn-uuid-4d2e9c",
  "source_institution": "inst-uuid-acme",
  "export_id": "exp-uuid-7f3a1b",
  "imported_at": "2026-03-10T14:02:00Z",
  "prev_hash": "<hash of the previous event in the receiving institution ledger>",
  "signature": "<receiving institution signature>"
}
```

### 7.3 No envelope reuse

The receiving institution MUST reject any envelope whose `export_id` is already recorded in its local ledger, even if the signature is valid.

### 7.4 Secure transmission

Export envelopes MUST be transmitted exclusively over TLS 1.2 or higher. The content is additionally protected by the JWS signature, but transport security is mandatory.
