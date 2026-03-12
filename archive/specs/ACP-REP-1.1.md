# ACP-REP-1.1
## Reputation Extension — Complete Specification

**Status:** Superseded
**Superseded-by:** ACP-REP-1.2
**Version:** 1.1
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-REV-1.0, ACP-HP-1.0
**Required-by:** ACP-CONF-1.1 (Level 2 — Security Conformance)

> ⚠️ **DEPRECATED** — This document has been superseded by **ACP-REP-1.2**.
> New implementations MUST use ACP-REP-1.2.
> This document is maintained for historical reference.

---

## Abstract

ACP-REP-1.1 introduces a quantifiable reputation model for agents within the ACP ecosystem. It defines the mathematical scoring model, the agent state machine, the event taxonomy, the query API, the storage model, and explicit boundaries between v1 scope (this specification) and v2 (future work).

Reputation in ACP is not an ornament — it is the mechanism that transforms the protocol from a static verification system into an adaptive trust system. A cryptographically valid token issued by a BANNED agent MUST be rejected. An agent with a consistent history of correct behavior SHOULD receive more permissive policies.

---

## 1. Design Decisions — Rationale

This section documents the architectural decisions made and the reasoning behind each one. Read before implementing.

### 1.1 Reputation per institution, not global

Each institution maintains its own reputation registry for the agents it operates. An agent may have high reputation at Institution A and null reputation at Institution B.

**Why:** The ACP protocol is grounded in institutional sovereignty. A global reputation would require a central authority to maintain it — which contradicts ACP-ITA and the GAT model. The same capability token is signed by the institution, not a global body. Reputation must follow the same sovereignty principle.

**Left for v2:** Inter-institutional reputation federation (an institution can query an agent's history at another institution, subject to bilateral agreements). See §12.1.

### 1.2 Event issuer: server only (v1)

In v1, only the ACP server can record reputation events. Events are produced automatically as a side effect of verification operations.

**Why:** If any verifier can report events about an agent, the Sybil problem opens up: a malicious actor can create multiple fake verifiers to degrade a competitor agent's reputation. Solving this requires cryptographic staking or verifiable evidence proofs — mechanisms that exceed v1 scope.

**Left for v2:** External verifiers that can emit signed events with cryptographic proof of evidence + staking mechanism with penalties for false reports. See §12.2.

### 1.3 Cold start: score `null`

A newly registered agent does not have score `0.0` — it has score `null`. These are semantically different:

- `null` = no history
- `0.0` = history with minimum reputation

**Why:** A `0.0` score for new agents blocks adoption — no legitimate agent could operate until it accumulates enough positive history. A `1.0` score is insecure — it allows malicious agents to operate with maximum trust just by registering. `null` delegates the decision to institutional policy, where it belongs.

**Cold start policy per institution:** Each institution defines what to do with a history-less agent:
- A financial institution may require an onboarding process before allowing operation
- A low-risk institution may treat `null` as `0.5` (moderate initial trust)
- A development institution may treat `null` as `ACTIVE` without restrictions

The cold start policy MUST be explicit and documented by the institution. There is no global default.

### 1.4 Private score — authenticated access via ACP-HP-1.0

An agent's reputation score is private. It is not public data. Access to the reputation API requires ACP-HP-1.0 authentication.

**Access model:**

| Actor | Can query the score | Condition |
|---|---|---|
| The agent itself | ✅ | Always, with ACP-HP-1.0 auth |
| The managing institution | ✅ | Always, with institutional credentials |
| Another institution | ⚠️ | Only with federation enabled (v2) |
| The general public | ❌ | Never |

**Events are auditable:** The event registry (with cryptographic signature per event) can be audited by the agent and the institution. The calculated score is internal to the institution.

**Left for v2:** Exploration of a portable external score (separate from internal institutional score) managed by a decentralized oracle. See §12.3.

### 1.5 Dual model: continuous score + state machine

The reputation system has two orthogonal layers:

1. **Continuous score** `[0.0, 1.0]`: measures the agent's behavioral history over time. Updated with each verifiable event.
2. **State machine**: captures categorical events that are not representable in a continuum (e.g.: a compromised key is not "a bit compromised").

Both layers affect access decisions. An agent with score `0.9` but in `BANNED` state is rejected.

---

## 2. Mathematical Model

### 2.1 ReputationScore

```
ReputationScore ∈ [0.0, 1.0]  ∪  {null}

null  = no history (cold start)
0.0   = minimum observable reputation
1.0   = maximum observable reputation
```

### 2.2 Update function

After each verifiable event:

```
score' = α · score + β · event_metric
```

**Parameters:**

| Parameter | Default | Allowed range | Description |
|---|---|---|---|
| α | 0.90 | [0.70, 0.99] | Memory / decay factor |
| β | 0.10 | [0.01, 0.30] | Learning rate for new events |
| Constraint | — | α + β ≤ 1 | Always |

α and β values are configurable per institution within the allowed range. Defaults MUST be used if the institution does not configure its own values.

**Interpretation of α:** Controls how quickly the system "forgets" prior history. A high α (0.99) gives much weight to the past — useful in financial contexts where history matters. A low α (0.70) gives more weight to recent behavior — useful in contexts where faster recovery is desired.

### 2.3 Event taxonomy and event_metric

The `event_metric` values are **fixed in this specification** and are not configurable per institution. Uniformity ensures cross-implementation conformance.

**Positive events:**

| Event | event_metric | Description |
|---|---|---|
| `REP_EVT_VERIFY_OK` | +0.05 | Successful ACP-HP-1.0 verification |
| `REP_EVT_AUDIT_PASS` | +0.10 | Formal audit passed |

**Negative events:**

| Event | event_metric | Description |
|---|---|---|
| `REP_EVT_SIG_LATE` | −0.05 | Signature produced outside the time window |
| `REP_EVT_TOKEN_MALFORMED` | −0.10 | Token with invalid format (missing fields, wrong types) |
| `REP_EVT_REV_INVALID` | −0.20 | Revocation attempt without authorization or malformed |
| `REP_EVT_SIG_INVALID` | −0.30 | Invalid Ed25519 signature detected |
| `REP_EVT_POLICY_VIOLATION` | −0.40 | Institutional policy violation detected |

### 2.4 Asymmetry is an intentional security property

> **Note for implementers and protocol readers:**
>
> The difference between positive values (+0.05, +0.10) and negative values (−0.30, −0.40) **is not a calibration error** — it is a deliberate design decision with direct security consequences.
>
> **Example with defaults (α=0.90, β=0.10), initial score 0.80:**
>
> After an invalid signature (`REP_EVT_SIG_INVALID`, −0.30):
> ```
> score' = 0.90 × 0.80 + 0.10 × (−0.30) = 0.720 − 0.030 = 0.690
> ```
>
> To recover those ~0.030 points via successful verifications (+0.05 each):
> ```
> score' = 0.90 × score + 0.10 × 0.05 = 0.90 × score + 0.005
> ```
> An agent needs approximately **6 successful verifications** to recover the impact of a single invalid signature.
>
> **Why this is correct:** An agent that produces invalid signatures is a red flag, whether from key compromise or malicious behavior. The protocol must make recovering reputation after this event require sustained demonstration of correct behavior. If positive and negative events were symmetric, an agent could alternate malicious and correct behavior without net consequences — which would eliminate the value of the system.
>
> The asymmetry also disincentivizes probe attacks: attempting an invalid signature to test system limits has a significant reputational cost that is not easily recovered.

---

## 3. Agent State Machine

### 3.1 States

| State | Semantics | Can operate? |
|---|---|---|
| `ACTIVE` | Normal operation | ✅ If score ≥ institutional threshold |
| `PROBATION` | Low score, under surveillance | ⚠️ With restrictions (shorter token durations, limited capabilities) |
| `SUSPENDED` | Temporarily barred | ❌ No |
| `BANNED` | Permanently barred | ❌ No, never |

### 3.2 Transitions

```
ACTIVE ────────────► PROBATION   [automatic: score < probation_threshold]
PROBATION ─────────► ACTIVE      [automatic: score ≥ active_threshold]
PROBATION ─────────► SUSPENDED   [automatic: score < suspend_threshold]
                                        [manual: institutional decision]
SUSPENDED ─────────► ACTIVE      [manual: institutional review ONLY]
ANY ────────────────► BANNED      [manual: institutional order]
                                        [automatic: trigger REV-002 (key compromised)]
BANNED ────────────► (none)      [PERMANENT — no exit transition]
```

**Critical rule:** The `SUSPENDED → ACTIVE` transition is NEVER automatic. It requires explicit institutional review and decision. This prevents a suspended agent from accumulating positive events in the background to self-rehabilitate.

**Critical rule:** The `BANNED` state is terminal and irreversible. A banned agent cannot recover operation under any algorithmic condition. If the institution determines it was an error, a new agent identity must be created.

### 3.3 Default thresholds

| Threshold | Default | Configurable per institution |
|---|---|---|
| `probation_threshold` | 0.40 | ✅ Yes |
| `active_threshold` | 0.50 | ✅ Yes (MUST be > probation_threshold) |
| `suspend_threshold` | 0.20 | ✅ Yes |

The hysteresis between `probation_threshold` (0.40) and `active_threshold` (0.50) is intentional — it prevents rapid oscillation between `ACTIVE` and `PROBATION` when the score is on the boundary.

### 3.4 Score during non-ACTIVE states

The score **continues to be calculated** even when the agent is in `PROBATION`, `SUSPENDED`, or `BANNED`. The historical record is valuable for auditing. However:

- In `SUSPENDED` and `BANNED`: the score does not affect access decisions — the state takes precedence.
- In `PROBATION`: the score does affect decisions — it determines whether the agent rises to `ACTIVE` or drops to `SUSPENDED`.

---

## 4. API

All endpoints require ACP-HP-1.0 authentication. Responses are signed per ACP-SIGN-1.0.

### 4.1 Reputation query

```http
GET /acp/v1/rep/{agent_id}
Authorization: ACP-Agent <token>
X-ACP-Agent-ID: <AgentID>
```

**Response 200:**
```json
{
  "agent_id": "<AgentID>",
  "score": 0.847,
  "state": "ACTIVE",
  "event_count": 142,
  "last_event_at": 1718920000,
  "checked_at": 1718921000,
  "sig": "<institutional_signature>"
}
```

`score` is `null` if the agent has no history (cold start).

**HTTP codes:**

| HTTP | Condition |
|---|---|
| 200 | Success |
| 401 | Not authenticated |
| 403 | No permission (only the agent and institution may query) |
| 404 | AgentID not found |
| 429 | Rate limit exceeded |

### 4.2 Event history

```http
GET /acp/v1/rep/{agent_id}/events?limit=50&offset=0
Authorization: ACP-Agent <token>
X-ACP-Agent-ID: <AgentID>
```

**Response 200:**
```json
{
  "agent_id": "<AgentID>",
  "events": [
    {
      "event_id": "<uuid>",
      "event_type": "REP_EVT_VERIFY_OK",
      "event_metric": 0.05,
      "score_before": 0.842,
      "score_after": 0.847,
      "recorded_at": 1718920000,
      "sig": "<event_signature>"
    }
  ],
  "total": 142,
  "sig": "<institutional_signature>"
}
```

Each event has an individual signature. An auditor can independently verify the event chain regardless of the calculated score.

### 4.3 State update (institutional only)

```http
POST /acp/v1/rep/{agent_id}/state
Authorization: ACP-Institution <token>
```

```json
{
  "new_state": "SUSPENDED",
  "reason": "Investigation for policy violation REV-003",
  "authorized_by": "<institutional_AgentID>",
  "sig": "<authorizer_signature>"
}
```

This endpoint is NOT available to agents — only to institutional credentials with scope `acp:rep:admin`.

---

## 5. Storage Model

### 5.1 Durability requirement (normative)

An ACP-REP-1.1 conformant implementation MUST guarantee that reputation records (scores, events, states) survive server restarts. The reference implementation MUST include at least one conformant persistent storage implementation.

### 5.2 ReputationStore interface

```go
type ReputationStore interface {
    // GetRecord returns the agent's complete record, or nil if it doesn't exist (cold start).
    GetRecord(agentID string) (*ReputationRecord, error)

    // RecordEvent records an event and updates the score.
    RecordEvent(agentID string, event ReputationEvent) error

    // GetState returns the agent's current state.
    GetState(agentID string) (AgentState, error)

    // SetState updates the agent's state with reason and authorizer signature.
    SetState(agentID string, state AgentState, reason, authorizedBy string) error

    // GetEvents returns the paginated event history.
    GetEvents(agentID string, limit, offset int) ([]ReputationEvent, int, error)
}
```

### 5.3 Reference implementations

| Implementation | Persistent | Conformant for production? | Use |
|---|---|---|---|
| `InMemoryReputationStore` | ❌ No | ❌ No | Testing / local development |
| `FileReputationStore` (SQLite or JSON) | ✅ Yes | ✅ Yes | Demo, reference, small instances |

`InMemoryReputationStore` MUST include a visible warning at server startup:

```
[WARN] ACP-REP: using InMemoryReputationStore — reputation data will NOT survive restarts.
[WARN] This implementation is NOT conformant for production use.
[WARN] Configure a persistent store (FileReputationStore or external DB) for production.
```

The same design pattern already exists in the codebase with `RevocationChecker` (`NoOpRevocationChecker` / `HTTPRevocationChecker` / `InMemoryRevocationChecker`).

---

## 6. Configuration

```go
type ReputationConfig struct {
    // Alpha: memory / decay factor. Default: 0.90
    Alpha float64 // range [0.70, 0.99]

    // Beta: learning rate. Default: 0.10
    Beta float64 // range [0.01, 0.30]

    // ProbationThreshold: score below which the agent enters PROBATION.
    // Default: 0.40
    ProbationThreshold float64

    // ActiveThreshold: score above which a PROBATION agent returns to ACTIVE.
    // MUST be > ProbationThreshold to avoid oscillation. Default: 0.50
    ActiveThreshold float64

    // SuspendThreshold: score below which a PROBATION agent is SUSPENDED.
    // Default: 0.20
    SuspendThreshold float64

    // ColdStartPolicy: policy when score is null.
    // "deny" | "allow_with_restrictions" | "allow"
    ColdStartPolicy string

    // ColdStartInitialScore: initial score for ColdStartPolicy "allow_with_restrictions".
    // If nil, score remains null until the first event.
    ColdStartInitialScore *float64
}
```

---

## 7. Integration with ACP-REV-1.0

ACP-REP-1.1 depends on ACP-REV-1.0. The `REP_EVT_REV_INVALID` event can only be recorded if the revocation system is operational.

Revocation of an agent (`REV-002`, `REV-004`) MUST automatically trigger a transition to `BANNED` state.

---

## 8. Security

### 8.1 Asymmetry as an anti-abuse mechanism

See §2.4. The asymmetry between positive and negative events is the first line of defense against using the reputation system as an attack vector.

### 8.2 Anti-gaming

- Events are only recordable by the server (v1) — prevents insertion of fake events
- Each event has an individual signature — prevents retroactive modification of history
- The `SUSPENDED → ACTIVE` transition is manual — prevents algorithmic self-rehabilitation
- `BANNED` is terminal — prevents malicious actors from rehabilitating by accumulating positive events

### 8.3 Rate limiting

The `GET /acp/v1/rep/{agent_id}` endpoint MUST have rate limiting to prevent enumeration of foreign agents' scores.

---

## 9. Errors

| Code | Condition |
|---|---|
| `REP-E001` | AgentID not registered |
| `REP-E002` | Score null — agent with no history (cold start) |
| `REP-E003` | BANNED state — operation permanently denied |
| `REP-E004` | SUSPENDED state — operation temporarily denied |
| `REP-E005` | α/β parameters out of allowed range |
| `REP-E006` | No permission to query this agent's reputation |
| `REP-E007` | No permission to modify state (requires institutional credential) |

---

## 10. Conformance

An implementation is ACP-REP-1.1 conformant if:

- [ ] Implements the mathematical model with the fixed `event_metric` values from §2.3
- [ ] Implements the state machine from §3 with all defined transitions
- [ ] Guarantees that reputation records survive restarts (§5.1)
- [ ] Exposes the endpoints from §4 with ACP-HP-1.0 authentication
- [ ] Uses the defaults from §6 if the institution does not configure its own values
- [ ] Produces the error codes from §9
- [ ] Integrates with ACP-REV-1.0 for the `BANNED` trigger on revocation (§7)

---

## 11. IANA Considerations

No IANA assignments required.

---

## 12. v2 Roadmap — Future Work

This section documents features deliberately excluded from v1 scope with the rationale for why they are v2 and not v1.

### 12.1 Inter-institutional reputation federation

**Description:** Institution B can query an agent's reputation history at Institution A, subject to bilaterally signed agreements.

**Why v2:** Requires an inter-institutional reputation data exchange protocol, inter-institutional trust agreements, and possibly a "reputation attestation" format signed by the originating institution. Exceeds the v1 reference server scope.

**Future design impact:** v1 data structures must be designed so that adding this field is possible without breaking changes.

### 12.2 External verifiers with staking

**Description:** Any participating verifier can emit reputation events signed with cryptographic proof of evidence. A staking mechanism penalizes false reports.

**Why v2:** The Sybil problem in open reputation systems is a non-trivial problem. The staking solution requires a consensus mechanism, a value token, and a dispute process — all outside v1 scope. If implemented without these safeguards, the system would be trivially attackable.

### 12.3 Internal vs external score — Decentralized oracle

**Description:** When an agent crosses the boundaries of its home institution to interact with the external ecosystem, its internal score is not necessarily portable or known. The proposal distinguishes:

- **Internal score:** the agent's reputation within its home institution. Rich, detailed, contextual.
- **External score:** the agent's reputation in the global ACP ecosystem. Sparse, privacy-preserving, portable.

A decentralized oracle (analogous to price oracles in DeFi, but for reputation) could aggregate attestations from multiple institutions to produce an external score without revealing detailed internal history.

**Why v2:** Requires design of its own sub-protocol (`ACP-REP-ORACLE`), privacy mechanisms (zk-proofs of minimum reputation without revealing the exact score), and oracle governance. It is an open problem in the distributed reputation systems literature.

**Design note:** An agent with high internal score entering the external ecosystem for the first time will have external score `null`. This is correct — the external score starts building from external interactions, not from internal history. The internal/external distinction is fundamental to respecting institutional sovereignty.

---

## 13. Normative References

- RFC 2119 — Key words for use in RFCs
- ACP-SIGN-1.0 — Ed25519 + JCS canonicalization
- ACP-CT-1.0 — Capability Token format
- ACP-REV-1.0 — Revocation Protocol
- ACP-HP-1.0 — HTTP Protocol + ACP-HP-1.0 authentication
- Byzantine systems research — EigenTrust, HistoryNet
- Reputation systems literature — Mui et al., Jøsang et al.
