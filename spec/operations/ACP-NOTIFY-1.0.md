# ACP-NOTIFY-1.0 — Push Notifications / Webhooks

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0 |
| **Type** | Protocol Extension |
| **Depends-on** | ACP-LEDGER-1.2, ACP-SIGN-1.0 |
| **Date** | 2026-03-10 |

---

## 1. Purpose

This document specifies the push notification system for ACP ledger events via HTTP webhooks.

Push notifications allow external systems (dashboards, audit systems, secondary agents, third-party integrations) to receive real-time alerts when relevant events occur in the ACP ledger, without needing to perform active polling.

Primary use cases include:

- Monitoring systems that need to react to new agent registrations.
- Audit platforms that must process each verified payment event.
- Escalation systems that respond to dispute resolutions.
- Reputation dashboards that update metrics in real time.

---

## 2. Subscription API

### 2.1 Create subscription

```
POST /acp/v1/webhooks
```

**Request body:**

```json
{
  "webhook_url": "https://my-system.com/acp/events",
  "events": ["AGENT_REGISTERED", "PAYMENT_VERIFIED", "*"],
  "secret": "s3cr3t-hmac-key-here",
  "institution_id": "inst-uuid-acme"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `webhook_url` | String (URL) | Yes | HTTPS URL where events will be delivered. MUST use HTTPS. |
| `events` | Array[String] | Yes | List of event types to receive. `"*"` subscribes to all. |
| `secret` | String | Yes | Shared secret key for HMAC-SHA256. Minimum 32 characters. |
| `institution_id` | UUID | Yes | Institution to which the subscription belongs. |

**Successful response (201 Created):**

```json
{
  "webhook_id": "wh-uuid-...",
  "webhook_url": "https://my-system.com/acp/events",
  "events": ["AGENT_REGISTERED", "PAYMENT_VERIFIED"],
  "institution_id": "inst-uuid-acme",
  "status": "active",
  "created_at": "2026-03-10T14:00:00Z"
}
```

### 2.2 Get subscription details

```
GET /acp/v1/webhooks/{webhook_id}
```

Returns the subscription object. The `secret` field is NEVER included in the response.

**Response (200 OK):**

```json
{
  "webhook_id": "wh-uuid-...",
  "webhook_url": "https://my-system.com/acp/events",
  "events": ["AGENT_REGISTERED", "PAYMENT_VERIFIED"],
  "institution_id": "inst-uuid-acme",
  "status": "active",
  "created_at": "2026-03-10T14:00:00Z",
  "last_delivered_at": "2026-03-10T15:30:00Z",
  "failure_count": 0
}
```

### 2.3 Delete subscription

```
DELETE /acp/v1/webhooks/{webhook_id}
```

**Response (204 No Content)**

Deleted subscriptions receive no further deliveries. Events queued for retry are discarded.

---

## 3. Webhook Payload

Each event delivery sent to `webhook_url` has the following format:

```json
{
  "webhook_id": "wh-uuid-...",
  "event_type": "AGENT_REGISTERED",
  "event_id": "evt-uuid-...",
  "timestamp": "2026-03-10T15:30:00Z",
  "institution_id": "inst-uuid-acme",
  "data": {
    "agent_id": "agt-uuid-...",
    "agent_type": "financial",
    "registered_by": "usr-uuid-...",
    "capabilities": ["acp:cap:financial.payment"]
  },
  "signature": "sha256=abc123def456..."
}
```

### 3.1 Payload fields

| Field | Type | Description |
|---|---|---|
| `webhook_id` | UUID | ID of the subscription originating this delivery |
| `event_type` | String | Event type (e.g. `AGENT_REGISTERED`) |
| `event_id` | UUID | Unique ID of the event in the ACP ledger |
| `timestamp` | ISO 8601 | Timestamp of the original ledger event |
| `institution_id` | UUID | Institution that originated the event |
| `data` | Object | Event-type-specific payload |
| `signature` | String | HMAC-SHA256 of the payload (see §4) |

### 3.2 `data` field per event type

The `data` field varies by `event_type`. Specific fields for each event follow the structure defined in ACP-LEDGER-1.2 for that event type.

---

## 4. Authentication and Verification

### 4.1 Signature header

Each webhook delivery MUST include the header:

```
X-ACP-Signature: sha256=<hmac_hex>
```

Where `<hmac_hex>` is the HMAC-SHA256 of the full payload body (as a UTF-8 string), computed using the subscription `secret` as the key.

### 4.2 HMAC computation

```
signature = HMAC-SHA256(secret, raw_body_utf8)
header_value = "sha256=" + hex(signature)
```

### 4.3 Receiver verification

The receiving system MUST:

1. Read the request body as raw bytes (do not parse JSON first).
2. Compute `HMAC-SHA256(secret, raw_body)`.
3. Compare the result with the value in `X-ACP-Signature` using constant-time comparison (to prevent timing attacks).
4. Reject the delivery if signatures do not match (return HTTP 401).

### 4.4 Replay protection

The receiver SHOULD verify that `event_id` was not previously processed, by storing received IDs for the past 24 hours.

---

## 5. Retry Policy

### 5.1 Retry condition

ACP-NOTIFY retries delivery when the receiver endpoint responds with a non-2xx HTTP status, or when the connection fails (timeout, network error).

### 5.2 Retry schedule

| Attempt | Wait before attempt |
|---|---|
| Initial attempt | Immediate |
| Retry 1 | 5 seconds |
| Retry 2 | 30 seconds |
| Retry 3 | 5 minutes |

After 3 failed retries (4 total attempts), the webhook is marked with `status: "failed"`.

### 5.3 Failed webhook

When a webhook reaches `status: "failed"`:

- The administrator of the subscribing institution receives a notification via the configured admin channel.
- No further delivery attempts are made for that webhook.
- New events are NOT queued for that webhook.
- The webhook can be reactivated via `PUT /acp/v1/webhooks/{webhook_id}/reactivate`.

### 5.4 Per-attempt timeout

Each delivery attempt has a 10-second timeout. If the receiver does not respond within that window, the attempt is considered failed.

---

## 6. Event Filtering

### 6.1 Subscribe to all events

```json
{ "events": ["*"] }
```

The `"*"` wildcard subscribes to all current and future event types. Use with caution in high-activity environments.

### 6.2 Subscribe to specific events

```json
{
  "events": [
    "AGENT_REGISTERED",
    "PAYMENT_VERIFIED",
    "ESCALATION_RESOLVED",
    "REPUTATION_UPDATED"
  ]
}
```

### 6.3 Event type catalog

| Event type | Description |
|---|---|
| `AGENT_REGISTERED` | A new agent was registered in the system |
| `AGENT_DEREGISTERED` | An agent was deregistered |
| `CAPABILITY_GRANTED` | A capability was granted to an agent |
| `CAPABILITY_REVOKED` | A capability was revoked |
| `PAYMENT_VERIFIED` | A payment was verified in the ledger |
| `PAYMENT_DISPUTED` | A payment was disputed |
| `ESCALATION_CREATED` | A new escalation was created |
| `ESCALATION_RESOLVED` | An escalation was resolved |
| `REPUTATION_UPDATED` | An agent's reputation score was updated |
| `POLICY_SNAPSHOT_EXPORTED` | A policy snapshot was exported (ACP-PSN-EXPORT) |
| `INSTITUTION_FEDERATED` | A new institution joined the federation |

### 6.4 Updating filters

Event filters of an existing subscription can be updated via:

```
PATCH /acp/v1/webhooks/{webhook_id}
```

With body `{ "events": [...] }`.

---

## 7. Security

### 7.1 HTTPS required

The `webhook_url` field MUST begin with `https://`. The ACP server MUST reject with HTTP 422 any attempt to create a subscription with a non-HTTPS URL.

### 7.2 Minimum TLS version

Outbound connections from the ACP server to `webhook_url` MUST use TLS 1.2 at minimum. TLS 1.3 is recommended.

### 7.3 Secret rotation

The HMAC secret can be rotated without interrupting the subscription:

```
PUT /acp/v1/webhooks/{webhook_id}/rotate-secret
```

**Body:**
```json
{ "new_secret": "new-secret-here" }
```

During rotation, there is a 5-minute grace window in which the ACP server accepts signatures computed with either the old or new secret, to prevent event loss during the changeover.

### 7.4 Secret confidentiality

The `secret` field is NEVER included in API responses (GET, LIST). It is only transmitted at creation time (POST) and rotation (PUT).

### 7.5 Access control

Only the institution that owns a subscription (`institution_id`) may read, modify, or delete that webhook. The authentication token MUST belong to that institution.
