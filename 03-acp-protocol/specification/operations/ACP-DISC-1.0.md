# ACP-DISC-1.0 — Agent Discovery

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0 |
| **Type** | Protocol Extension |
| **Depends-on** | ACP-AGS-1.0, ACP-CT-1.0, ACP-LEDGER-1.2 |
| **Date** | 2026-03-10 |

---

## 1. Purpose

This document specifies the ACP agent discovery mechanism via a public capability registry.

Agent discovery allows institutions and external systems to find agents by their publicly advertised capabilities, without needing to know the target agent's `agent_id` in advance.

Discovery is **opt-in** and operates independently from the capability grant system (ACP-CT-1.0):

- **ACP-CT-1.0** controls which capabilities an agent is authorized to use (grants).
- **ACP-DISC-1.0** controls which capabilities an agent publicly advertises to be found.

An agent may have capabilities granted in ACP-CT-1.0 without exposing them in the discovery registry, and conversely, an agent may only advertise a capability in discovery if it also has that capability granted.

---

## 2. Discovery Registry

### 2.1 Principles

- The discovery registry is **opt-in**: agents do not appear in the registry until their institution explicitly registers them.
- Capabilities advertised in discovery MUST be registered in ACP-CAP-REG-1.0.
- The discovery registry does not grant or revoke capabilities; that function belongs exclusively to ACP-CT-1.0.
- The institution is responsible for validating agent identity before registering it.

### 2.2 Lifecycle

```
Not registered → Registered (active) → Updated → Expired / Deregistered
```

Discovery entries have an expiration date (`expires_at`). Institutions MUST renew entries before expiration if the agent remains active.

---

## 3. API Endpoints

### 3.1 Register agent for discovery

```
POST /acp/v1/discovery/register
```

**Request body:**

```json
{
  "agent_id": "agt-uuid-...",
  "public_capabilities": [
    "acp:cap:financial.payment",
    "acp:cap:financial.transfer"
  ],
  "institution_id": "inst-uuid-acme",
  "contact_endpoint": "https://agents.acme.com/acp/agt-uuid-..."
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | UUID | Yes | ID of the agent to register. MUST exist in ACP-AGS-1.0. |
| `public_capabilities` | Array[String] | Yes | Public capabilities to advertise. MUST exist in ACP-CAP-REG-1.0. |
| `institution_id` | UUID | Yes | Institution responsible for the agent. |
| `contact_endpoint` | URL | No | Contact endpoint for interacting with the agent (HTTPS). |

**Successful response (201 Created):**

```json
{
  "agent_id": "agt-uuid-...",
  "institution_id": "inst-uuid-acme",
  "public_capabilities": ["acp:cap:financial.payment", "acp:cap:financial.transfer"],
  "contact_endpoint": "https://agents.acme.com/acp/agt-uuid-...",
  "registered_at": "2026-03-10T14:00:00Z",
  "expires_at": "2027-03-10T14:00:00Z"
}
```

If the agent was already registered, the existing entry is **overwritten** with the new data (idempotent).

### 3.2 Query agents by capability

```
GET /acp/v1/discovery/agents?capability={cap_id}&institution={inst_id}
```

| Parameter | Location | Required | Description |
|---|---|---|---|
| `capability` | Query | No | Filter by capability (e.g. `acp:cap:financial.payment`) |
| `institution` | Query | No | Filter by institution |
| `page` | Query | No | Page number (pagination, default 1) |
| `per_page` | Query | No | Results per page (default 20, max 100) |

**Response (200 OK):**

```json
{
  "total": 42,
  "page": 1,
  "per_page": 20,
  "results": [
    {
      "agent_id": "agt-uuid-...",
      "institution_id": "inst-uuid-acme",
      "public_capabilities": ["acp:cap:financial.payment"],
      "contact_endpoint": "https://agents.acme.com/acp/agt-uuid-...",
      "registered_at": "2026-03-10T14:00:00Z",
      "expires_at": "2027-03-10T14:00:00Z"
    }
  ]
}
```

### 3.3 Get agent discovery profile

```
GET /acp/v1/discovery/agents/{agent_id}
```

**Response (200 OK):** The agent's discovery entry per §4 format.

**Response (404 Not Found):** If the agent is not registered in the discovery registry.

### 3.4 Deregister agent from discovery

```
DELETE /acp/v1/discovery/agents/{agent_id}
```

Requires authentication from the agent's owning institution.

**Response (204 No Content)**

The agent ceases to appear in search results immediately.

---

## 4. Discovery Entry Format

```json
{
  "agent_id": "agt-uuid-...",
  "institution_id": "inst-uuid-acme",
  "public_capabilities": [
    "acp:cap:financial.payment",
    "acp:cap:financial.transfer"
  ],
  "contact_endpoint": "https://agents.acme.com/acp/agt-uuid-...",
  "registered_at": "2026-03-10T14:00:00Z",
  "expires_at": "2027-03-10T14:00:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `agent_id` | UUID | Agent identifier. May be pseudonymous per institutional policy (§5). |
| `institution_id` | UUID | Institution responsible for the entry. |
| `public_capabilities` | Array[String] | Publicly advertised capabilities. |
| `contact_endpoint` | URL | HTTPS endpoint for contacting the agent. Optional. |
| `registered_at` | ISO 8601 | Timestamp of creation or last update of the entry. |
| `expires_at` | ISO 8601 | Expiration timestamp. Maximum 1 year from `registered_at`. |

---

## 5. Privacy

### 5.1 Institutional granularity

The institution controls which capabilities of each agent are publicly discoverable. An institution may register only a subset of an agent's actual capabilities.

### 5.2 Pseudonymous identity by default

By default, the `agent_id` in the discovery registry is the same UUID assigned in ACP-AGS-1.0, which does not reveal personal information about the agent or its operator.

Institutions may opt into full disclosure by setting `discovery_full_disclosure: true` in their institutional configuration. In that case, the discovery profile may include additional fields such as agent name or description.

### 5.3 Optional contact endpoint

The institution MAY register the agent without a `contact_endpoint` if it does not wish to expose a direct contact point. In that case, contact is made through the institutional endpoint.

---

## 6. ACP-CAP-REG-1.0 Integration

Every capability listed in `public_capabilities` MUST be registered and active in ACP-CAP-REG-1.0. The ACP server MUST validate this during registration.

If a capability is removed from ACP-CAP-REG-1.0, discovery entries referencing it MUST be automatically updated to remove it. If after the update the `public_capabilities` array becomes empty, the discovery entry is marked as `status: inactive`.

---

## 7. ACP-AGS-1.0 Integration

Discovery is part of the **L3 layer (Capability Registry)** in the agent governance architecture (ACP-AGS-1.0).

Per ACP-AGS §4 (Coordination):

- The discovery registry is consulted as part of the capability discovery process in the inter-agent coordination flow.
- Discovery entries are read-only for systems external to the owning institution.
- Federated discovery (across institutions) follows ACP-ITA-1.1 rules to determine which registries from other institutions are visible.

---

## 8. Anti-abuse

### 8.1 Query rate limiting

The `GET /acp/v1/discovery/agents` endpoint is subject to rate limiting:

- **Unauthenticated**: 60 queries per minute per IP.
- **With institution token**: 600 queries per minute per institution.

When the limit is exceeded: HTTP 429 with `Retry-After` header.

### 8.2 Pre-registration validation

The institution MUST verify that the provided `agent_id` exists in ACP-AGS-1.0 and belongs to that institution before registering it. The ACP server validates this automatically.

### 8.3 Duplicate registration overwrite

If an `agent_id` is registered that already exists in the discovery registry under the same institution, the existing entry is **completely overwritten** with the new data. No duplicate entries are created.

### 8.4 Automatic expiration

Expired entries (`expires_at` in the past) are automatically excluded from search results. They are not physically deleted until 30 days after expiration, to facilitate audits.
