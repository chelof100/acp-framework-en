# ACP-REP-1.2
## Reputation & Trust Layer — Full Specification

**Status:** Stable
**Version:** 1.2
**Supersedes:** ACP-REP-1.1
**Depends-on:** ACP-SIGN-1.0, ACP-CT-1.0, ACP-REV-1.0, ACP-HP-1.0, ACP-LEDGER-1.2, ACP-LIA-1.0
**Required-by:** ACP-AGS-1.0 (L7 — Reputation & Trust)

---

## Abstract

ACP-REP-1.2 extends ACP-REP-1.1 with three new mechanisms that close L7 of the Agent Governance Stack:

1. **ExternalReputationScore** — formal external reputation score computed from `REPUTATION_UPDATED` events in ACP-LEDGER-1.2, portable across institutions under controlled conditions.
2. **Dual Trust Bootstrap** — mechanism by which a new agent can initialize its external reputation from a signed attestation of its internal institutional reputation.
3. **Reputation Decay** — temporal degradation of the external score on inactivity, preventing dormant agents from retaining privileges indefinitely.

This specification is backwards compatible with ACP-REP-1.1. Every ACP-REP-1.2 conformant implementation automatically implements ACP-REP-1.1.

---

## Part I — Inheritance from ACP-REP-1.1

ACP-REP-1.2 incorporates by reference the entirety of ACP-REP-1.1. The following sections of the prior specification remain unchanged:

| Section (REP-1.1) | Content | Status in REP-1.2 |
|---|---|---|
| §1 — Design decisions | Per-institution reputation, server-only emitter, null cold start, private score, dual model | ✅ Unchanged |
| §2 — Mathematical model | score' = α·score + β·event_metric, parameters, fixed event_metrics | ✅ Unchanged |
| §3 — State machine | ACTIVE/PROBATION/SUSPENDED/BANNED + transitions | ✅ Unchanged |
| §4 — API v1.1 | GET /rep/{id}, GET /rep/{id}/events, POST /rep/{id}/state | ✅ Unchanged, extended in §6 |
| §5 — Storage | ReputationStore interface, InMemoryStore, FileStore | ✅ Unchanged, extended in §10 |
| §6 — Configuration | ReputationConfig, α, β, thresholds | ✅ Unchanged, extended in §11 |
| §7 — REV-1.0 integration | BANNED trigger via revocation | ✅ Unchanged |
| §8 — Security | Asymmetry, anti-gaming, rate limiting | ✅ Unchanged, extended in §12 |
| §9 — Errors | REP-E001 to REP-E007 | ✅ Unchanged, extended in §13 |
| §10 — Conformance | REP-1.1 checklist | Replaced by §14 |

---

## Part II — v1.2 Extensions

---

## 1. Dual Trust Model

ACP-REP-1.2 formalizes the distinction between two reputation dimensions that coexist in the ACP ecosystem:

### 1.1 Definitions

**InternalTrustScore (ITS):** The reputation score as defined in ACP-REP-1.1. It is the score calculated by the institution operating the agent, based on events recorded within its own ledger. It is private, institutional, and contextual.

**ExternalReputationScore (ERS):** The agent's reputation score in the external ecosystem. It is built from `REPUTATION_UPDATED` events in ACP-LEDGER-1.2 and reflects the agent's behavior in cross-institutional interactions. It is portable (within conditions defined in §3) and verifiably computable.

### 1.2 Orthogonality

The two scores are orthogonal dimensions — an agent can have:

| ITS | ERS | Interpretation |
|---|---|---|
| High (0.9) | null | Agent with long internal history, new to the external ecosystem |
| null | High (0.8) | Internally new agent, established reputation in another context |
| High (0.9) | High (0.8) | Agent consolidated in both dimensions |
| Low (0.2) | High (0.8) | Agent with recent internal issues, positive external track record |

**Precedence rule:** When both scores exist and are contradictory, the institution's policy determines which carries more weight in the authorization decision. If the institution does not configure a precedence policy, the state machine state (§3 of REP-1.1) takes absolute precedence: a BANNED agent is rejected regardless of ERS.

### 1.3 Separation of responsibilities

| Responsible | Domain |
|---|---|
| Operating institution | ITS — computes and custodies the internal score |
| ACP-LEDGER-1.2 | Recording of `REPUTATION_UPDATED` events |
| ERS engine (§2) | Computation of ExternalReputationScore from LEDGER |
| Institution | Policy for using ITS vs ERS in authorization decisions |

---

## 2. ExternalReputationScore (ERS)

### 2.1 Formal definition

```
ERS ∈ [0.0, 1.0]  ∪  {null}

null  = no external activity recorded
0.0   = minimum observable external score
1.0   = maximum observable external score
```

ERS is computed from the set of `REPUTATION_UPDATED` events in ACP-LEDGER-1.2 where `agent_id` matches the evaluated agent.

### 2.2 Structure of REPUTATION_UPDATED event

The `REPUTATION_UPDATED` event (defined in ACP-LEDGER-1.2) carries:

```json
{
  "event_type": "REPUTATION_UPDATED",
  "payload": {
    "agent_id": "<AgentID>",
    "score_before": 0.842,
    "score_after": 0.851,
    "delta": 0.009,
    "trigger_event_id": "<uuid>",
    "trigger_event_type": "EXECUTION_TOKEN_CONSUMED",
    "evaluation_context": "cross_institutional",
    "institution_id": "org.example.banking",
    "timestamp": 1718920000
  }
}
```

**Field `evaluation_context`:** Enum distinguishing the event's origin:
- `internal` — event generated by activity within the institution
- `cross_institutional` — event generated by interaction with another institution
- `bootstrap` — event generated by the Dual Trust Bootstrap mechanism (§3)

### 2.3 ERS computation function

ERS is computed with a **weighted moving average** over the most recent `REPUTATION_UPDATED` events, weighted by time and context:

```
ERS = Σ(w_i · delta_i) / Σ(w_i)
```

Where for each event i:

```
w_i = w_context(context_i) · w_time(age_i)

w_context:
  "internal"            → 0.5
  "cross_institutional" → 1.0
  "bootstrap"           → 0.3

w_time(age):
  age = now - timestamp_i  (in seconds)
  w_time = exp(-λ · age / DECAY_WINDOW)
```

**ERS parameters:**

| Parameter | Default | Configurable | Description |
|---|---|---|---|
| `ers_window_events` | 100 | ✅ | Max historical events to consider |
| `ers_lambda` | 0.5 | ✅ [0.1, 2.0] | Temporal decay factor |
| `ers_decay_window` | 2592000 (30 days) | ✅ | Reference time window in seconds |

### 2.4 Computation base score

ERS does not start from zero. The base score of each computation anchors on the last evaluation's score:

```
If ERS_previous exists:
    ERS_new = α_ext · ERS_previous + (1 - α_ext) · ERS_incremental

If ERS_previous == null (external cold start):
    ERS_new = ERS_bootstrap (§3) if exists, else null until min_events accumulate
```

**Parameter `alpha_ext`:** Memory factor for the external score. Default: 0.85. Range: [0.70, 0.98].

**Parameter `ers_min_events`:** Minimum number of events before ERS is non-null (without active bootstrap). Default: 3.

### 2.5 ERS as field in API responses

ERS is exposed as an additional field in existing reputation endpoints and in the new fast score endpoint (§6):

```json
{
  "agent_id": "<AgentID>",
  "internal_score": 0.847,
  "external_score": 0.731,
  "state": "ACTIVE",
  "event_count": 142,
  "last_event_at": 1718920000,
  "checked_at": 1718921000,
  "sig": "<institutional_signature>"
}
```

The `score` field from REP-1.1 is maintained as an alias for `internal_score` for backwards compatibility.

---

## 3. Dual Trust Bootstrap

### 3.1 The external cold start problem

A new agent operating outside its home institution for the first time has ERS = null. Without a bootstrap mechanism, the agent is at a disadvantage compared to agents with external history — not because of their behavior, but due to lack of prior external exposure.

The Dual Trust Bootstrap allows the agent's home institution to **vouch for** the agent in the external ecosystem, using its internal history as a proxy for initial trustworthiness.

### 3.2 Bootstrap flow

```
1. Institution generates a TrustAttestation for the agent
2. TrustAttestation is signed with the institutional key
3. TrustAttestation is recorded as REPUTATION_UPDATED event
   with evaluation_context = "bootstrap"
4. ERS engine initializes the agent's external score with
   bootstrap_value derived from the attestation
```

### 3.3 TrustAttestation structure

```json
{
  "attestation_id": "<uuid_v4>",
  "attestation_type": "trust_bootstrap",
  "agent_id": "<AgentID>",
  "issuing_institution": "org.example.banking",
  "internal_score": 0.847,
  "agent_state": "ACTIVE",
  "event_count": 142,
  "operating_since": 1714320000,
  "bootstrap_value": 0.45,
  "bootstrap_confidence": 0.3,
  "valid_until": 1774320000,
  "sig": "<institutional_Ed25519_signature>"
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `attestation_id` | uuid | Unique identifier of the attestation |
| `attestation_type` | string | Always `"trust_bootstrap"` in this context |
| `agent_id` | AgentID | Vouched agent |
| `issuing_institution` | string | Vouching institution (MUST be a registered ITA per ACP-ITA-1.0) |
| `internal_score` | float64 | Agent's ITS at the time of attestation |
| `agent_state` | AgentState | Agent's state in the REP-1.1 state machine |
| `event_count` | int | Number of reputation events that generated the ITS |
| `operating_since` | unix timestamp | Date of agent's first reputation event |
| `bootstrap_value` | float64 | Proposed initial ERS value. See §3.4 for computation. |
| `bootstrap_confidence` | float64 | Weight of bootstrap event in ERS computation. Fixed: 0.3 |
| `valid_until` | unix timestamp | Attestation expiration. Max: now + 180 days |
| `sig` | string | Institution's Ed25519 signature (over JCS of attestation without sig) |

### 3.4 bootstrap_value computation

The `bootstrap_value` is NOT the ITS directly. A discount factor is applied:

```
bootstrap_value = internal_score · discount_factor

discount_factor:
  event_count < 10:   0.30  (very short history, high uncertainty)
  event_count 10–49:  0.45
  event_count 50–199: 0.55
  event_count ≥ 200:  0.65  (maximum discount_factor)
```

**Rationale:** ITS is a contextual institutional score. Transferring it directly to the external ecosystem would allow institutions to artificially inflate their agents' ERS. The discount ensures that:
1. Bootstrap is a starting point, not a consolidated score.
2. An agent must demonstrate external behavior to raise their ERS above the bootstrap level.
3. The discount grows with internal history to incentivize institutions to develop agents with track records.

### 3.5 Conditions for issuing a TrustAttestation

The institution MUST verify before issuing:

1. `agent_state == ACTIVE` — agents in PROBATION, SUSPENDED or BANNED are not vouched for.
2. `internal_score ≥ 0.50` — agents with ITS below the minimum trust threshold are not vouched for.
3. `event_count ≥ 5` — minimum verifiable history is required.
4. The issuing institution MUST be registered as a valid ITA (ACP-ITA-1.0).

### 3.6 One attestation per agent per institution

An institution MUST issue only one active attestation per agent. If a new attestation is issued (renewal), the previous one becomes invalid and the previous `attestation_id` is recorded in the ledger as `ATTESTATION_REVOKED`.

### 3.7 Bootstrap degradation

The bootstrap event has weight `bootstrap_confidence = 0.3` (fixed). As the agent accumulates `cross_institutional` events, the bootstrap weight naturally dilutes in the ERS computation until it becomes irrelevant. Bootstrap does not block or distort the score long-term.

---

## 4. Reputation Decay

### 4.1 Definition

Reputation decay is the degradation of the ExternalReputationScore on inactivity. An agent that records no external reputation events for a configurable period sees its ERS gradually decrease.

**Rationale:** An agent that accumulated high ERS two years ago and has not operated since should not retain those privileges indefinitely. The world changes, policies change, and old history is less predictive than recent behavior.

### 4.2 Decay function

Decay is applied to ERS as a multiplicative factor in each score computation:

```
If last_external_event_age > decay_start_days:
    decay_factor = exp(-λ_decay · (last_external_event_age - decay_start_days) / decay_half_life)
    ERS_effective = ERS_raw · decay_factor
Else:
    ERS_effective = ERS_raw
```

**Decay parameters:**

| Parameter | Default | Configurable | Description |
|---|---|---|---|
| `decay_enabled` | `true` | ✅ | Enable/disable decay |
| `decay_start_days` | 90 | ✅ [30, 365] | Inactivity days before decay starts |
| `decay_half_life_days` | 180 | ✅ [60, 730] | Days to halve ERS |
| `decay_floor` | 0.10 | ✅ [0.0, 0.40] | ERS minimum by decay (does not decay to zero) |

**Numerical example (defaults):**

An agent with ERS = 0.80 that does not operate for 270 days (90-day grace period + 180-day half-life):
```
decay_factor = exp(-0.693 · 180/180) = exp(-0.693) = 0.50
ERS_effective = 0.80 · 0.50 = 0.40
```
If inactivity continues for another 180 days (450 total days since last activity):
```
decay_factor = exp(-0.693 · 360/180) = exp(-1.386) = 0.25
ERS_effective = max(0.80 · 0.25, 0.10) = max(0.20, 0.10) = 0.20
```

### 4.3 Decay and ITS

Decay applies **exclusively to ERS**. ITS (ACP-REP-1.1) has its own implicit memory mechanism (parameter α). ITS does not decay via this mechanism — institutions may implement their own internal decay if they require it, but that is not normative in this spec.

### 4.4 Post-decay reactivation

When an inactive agent resumes external operation, decay stops and the score begins recovering with new `REPUTATION_UPDATED` events. There is no additional penalty for the inactivity period — decay is the sufficient mechanism.

### 4.5 Decay state visibility

Score endpoints (§5, §6) MUST include the `decay_state` field in the response:

```json
{
  "external_score": 0.40,
  "decay_state": {
    "active": true,
    "last_external_event_days_ago": 270,
    "decay_factor": 0.50,
    "raw_score_before_decay": 0.80
  }
}
```

---

## 5. Updated Endpoint GET /acp/v1/rep/{agent_id}

The REP-1.1 endpoint is extended with the new fields. Full response in REP-1.2:

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
  "internal_score": 0.847,
  "external_score": 0.731,
  "state": "ACTIVE",
  "event_count": 142,
  "last_event_at": 1718920000,
  "last_external_event_at": 1718800000,
  "decay_state": {
    "active": false,
    "last_external_event_days_ago": 1,
    "decay_factor": 1.0,
    "raw_score_before_decay": 0.731
  },
  "bootstrap": {
    "active": false,
    "attestation_id": null
  },
  "checked_at": 1718921000,
  "sig": "<institutional_signature>"
}
```

`score` is an alias for `internal_score` for backwards compatibility with REP-1.1.
`external_score` is null if the agent has no external activity (no bootstrap, no cross-institutional events).

---

## 6. New Endpoint: GET /acp/v1/rep/{agent_id}/score

Fast score query endpoint — returns only the numeric values without full history detail. Designed to be invoked in the authorization hot path.

```http
GET /acp/v1/rep/{agent_id}/score
Authorization: ACP-Agent <token>
X-ACP-Agent-ID: <AgentID>
```

**Response 200:**
```json
{
  "agent_id": "<AgentID>",
  "internal_score": 0.847,
  "external_score": 0.731,
  "composite_score": 0.789,
  "state": "ACTIVE",
  "checked_at": 1718921000,
  "sig": "<institutional_signature>"
}
```

**Field `composite_score`:** Weighted score combining ITS and ERS per institutional policy. Computation:

```
composite_score = w_int · internal_score + w_ext · external_score

Where:
  w_int + w_ext = 1.0
  Defaults: w_int = 0.6, w_ext = 0.4
  If external_score == null: composite_score = internal_score (effective w_int = 1.0)
  If internal_score == null: composite_score = external_score (effective w_ext = 1.0)
  If both == null: composite_score = null
```

**Configurable parameters:**

| Parameter | Default | Description |
|---|---|---|
| `composite_weight_internal` | 0.6 | ITS weight in composite |
| `composite_weight_external` | 0.4 | ERS weight in composite |

**HTTP codes:**

| HTTP | Condition |
|---|---|
| 200 | Success |
| 401 | Unauthenticated |
| 403 | No permission |
| 404 | AgentID not found |
| 429 | Rate limit exceeded |

**Rate limiting:** This endpoint is subject to differentiated rate limiting from the full `/rep/{agent_id}` endpoint, given that it is the most frequently invoked. Implementations MUST apply rate limiting per requesting `X-ACP-Agent-ID`.

---

## 7. New Endpoint: POST /acp/v1/rep/{agent_id}/bootstrap

Endpoint for institutions to issue a TrustAttestation and initialize an agent's ERS.

```http
POST /acp/v1/rep/{agent_id}/bootstrap
Authorization: ACP-Institution <token>
```

**Request body:**
```json
{
  "attestation_type": "trust_bootstrap",
  "valid_until": 1774320000,
  "sig": "<institutional_signature_of_attestation>"
}
```

The institution MUST have pre-computed the TrustAttestation per §3.3 and signed it.

**Response 201:**
```json
{
  "attestation_id": "<uuid>",
  "agent_id": "<AgentID>",
  "bootstrap_value": 0.45,
  "bootstrap_confidence": 0.3,
  "external_score_initialized": 0.135,
  "valid_until": 1774320000,
  "ledger_event_id": "<uuid>"
}
```

**`external_score_initialized`:** Effective ERS value after applying bootstrap weight (`bootstrap_value · bootstrap_confidence = 0.45 · 0.3 = 0.135`). This is the initial external score — low by design.

**Server validations:**
1. Verify `agent_state == ACTIVE` in REP-1.1.
2. Verify `internal_score ≥ 0.50`.
3. Verify `event_count ≥ 5`.
4. Verify issuing institution is a valid ITA (ACP-ITA-1.0).
5. Verify no active attestation exists for this agent (unless explicit renewal).
6. Verify `sig` against institutional public key.

**Response 400:** If any validation fails → `REP-E011` with detail.
**Response 409:** If active attestation already exists → `REP-E012`.

---

## 8. Integration with ACP-LEDGER-1.2

### 8.1 Consuming REPUTATION_UPDATED events

The ERS engine consumes `REPUTATION_UPDATED` events from the ledger for ExternalReputationScore computation. The `evaluation_context` field discriminates origin:

```
evaluation_context == "internal"            → contributes to ITS (processed by REP-1.1)
evaluation_context == "cross_institutional" → contributes to ERS (processed by REP-1.2)
evaluation_context == "bootstrap"           → initializes ERS (processed by REP-1.2 §3)
```

### 8.2 Producing REPUTATION_UPDATED events

When the ERS engine updates the ExternalReputationScore, it MUST emit a `REPUTATION_UPDATED` event in the ledger with:

```json
{
  "agent_id": "<AgentID>",
  "score_before": 0.720,
  "score_after": 0.731,
  "delta": 0.011,
  "trigger_event_id": "<uuid_of_triggering_event>",
  "trigger_event_type": "EXECUTION_TOKEN_CONSUMED",
  "evaluation_context": "cross_institutional",
  "institution_id": "org.example.banking",
  "timestamp": 1718920000
}
```

### 8.3 Processing sequence

```
1. ET consumed → EXECUTION_TOKEN_CONSUMED event in ledger
2. ACP-LIA-1.0 emits LIABILITY_RECORD
3. REP-1.1 engine: updates ITS → emits REPUTATION_UPDATED (internal)
4. If cross-institutional interaction:
   REP-1.2 engine: updates ERS → emits REPUTATION_UPDATED (cross_institutional)
5. If decay active: ERS_effective recomputed on next query (lazy evaluation)
```

---

## 9. Integration with ACP-RISK-1.0

When ACP-RISK-1.0 evaluates the risk of a request, it MAY query the `composite_score` via `GET /acp/v1/rep/{agent_id}/score` and incorporate it into the risk score computation.

The integration is optional in v1 — ACP-RISK-1.0 can operate without reputation. However, when ERS is available, it is RECOMMENDED to include it in the agent's historical risk factor.

**Suggested mapping (non-normative):**

```
composite_score ≥ 0.80 → reputational_risk_modifier = −0.05  (reduces risk score)
composite_score 0.50–0.79 → reputational_risk_modifier = 0.00 (neutral)
composite_score < 0.50 → reputational_risk_modifier = +0.10  (increases risk score)
composite_score == null → reputational_risk_modifier = +0.05  (no history = slight risk)
```

---

## 10. ReputationStore Interface — extension

The `ReputationStore` interface from REP-1.1 is extended with methods for managing ERS and attestations:

```go
type ReputationStore interface {
    // --- REP-1.1 inherited ---
    GetRecord(agentID string) (*ReputationRecord, error)
    RecordEvent(agentID string, event ReputationEvent) error
    GetState(agentID string) (AgentState, error)
    SetState(agentID string, state AgentState, reason, authorizedBy string) error
    GetEvents(agentID string, limit, offset int) ([]ReputationEvent, int, error)

    // --- REP-1.2 new ---

    // GetExternalScore returns the effective ERS (with decay applied) for the agent.
    // Returns nil if no external score exists (external cold start).
    GetExternalScore(agentID string) (*ExternalScoreRecord, error)

    // RecordExternalEvent records an external reputation event and updates ERS.
    RecordExternalEvent(agentID string, event ExternalReputationEvent) error

    // GetCompositeScore returns the weighted composite score per configuration.
    GetCompositeScore(agentID string) (*CompositeScoreRecord, error)

    // SaveAttestation persists a TrustAttestation issued by the institution.
    SaveAttestation(attestation TrustAttestation) error

    // GetActiveAttestation returns the agent's active attestation, or nil if none.
    GetActiveAttestation(agentID string) (*TrustAttestation, error)

    // RevokeAttestation marks the attestation as revoked.
    RevokeAttestation(attestationID string) error
}
```

### 10.1 ExternalScoreRecord struct

```go
type ExternalScoreRecord struct {
    AgentID                  string
    RawScore                 *float64   // nil if no ERS
    EffectiveScore           *float64   // nil if no ERS; with decay applied
    LastExternalEventAt      *int64     // unix timestamp
    LastExternalEventDaysAgo int
    DecayActive              bool
    DecayFactor              float64
    BootstrapActive          bool
    AttestationID            *string
    ComputedAt               int64
}
```

### 10.2 CompositeScoreRecord struct

```go
type CompositeScoreRecord struct {
    AgentID         string
    InternalScore   *float64
    ExternalScore   *float64
    CompositeScore  *float64   // nil if both are nil
    State           AgentState
    WeightInternal  float64
    WeightExternal  float64
    CheckedAt       int64
}
```

---

## 11. Configuration — extension

The `ReputationConfig` struct from REP-1.1 is extended:

```go
type ReputationConfig struct {
    // --- REP-1.1 inherited ---
    Alpha              float64
    Beta               float64
    ProbationThreshold float64
    ActiveThreshold    float64
    SuspendThreshold   float64
    ColdStartPolicy    string
    ColdStartInitialScore *float64

    // --- REP-1.2 new ---

    // ERS computation
    ERSWindowEvents  int     // Default: 100
    ERSLambda        float64 // Default: 0.5, range [0.1, 2.0]
    ERSDecayWindow   int     // Default: 2592000 (30 days in seconds)
    AlphaExt         float64 // Default: 0.85, range [0.70, 0.98]
    ERSMinEvents     int     // Default: 3

    // Decay
    DecayEnabled       bool    // Default: true
    DecayStartDays     int     // Default: 90, range [30, 365]
    DecayHalfLifeDays  int     // Default: 180, range [60, 730]
    DecayFloor         float64 // Default: 0.10, range [0.0, 0.40]

    // Composite score
    CompositeWeightInternal float64 // Default: 0.6
    CompositeWeightExternal float64 // Default: 0.4

    // Bootstrap
    BootstrapEnabled    bool // Default: true
    BootstrapMaxAgeDays int  // Default: 180
}
```

---

## 12. Security — extension

### 12.1 Bootstrap inflation prevention

The institution cannot bootstrap an agent to an ERS above `0.65 · 0.30 = 0.195` (maximum bootstrap_value by maximum discount_factor, by maximum bootstrap_confidence). This ceiling guarantees bootstrap never grants an ERS comparable to an agent with real external history.

### 12.2 TrustAttestation validity

A TrustAttestation is automatically invalidated if:
- `valid_until < now`
- The agent enters `SUSPENDED` or `BANNED` state
- The issuing institution loses valid ITA status

A server receiving a token from an agent with an invalid attestation MUST ignore the bootstrap boost and use ERS = null for that agent.

### 12.3 Differentiated rate limiting

| Endpoint | Default rate limit | Per whom |
|---|---|---|
| `GET /rep/{id}` | 60 rpm | Per caller |
| `GET /rep/{id}/score` | 120 rpm | Per caller |
| `POST /rep/{id}/bootstrap` | 5 rpm | Per institution |
| `GET /rep/{id}/events` | 30 rpm | Per caller |

### 12.4 Decay state audit

The decay state MUST be recorded in the ledger as a `REPUTATION_UPDATED` event (with `evaluation_context = "decay"`) at least once every 24 hours when decay is active, so that the degradation history is auditable.

---

## 13. Errors — extension

Errors REP-E001 to REP-E007 from ACP-REP-1.1 are maintained. Added:

| Code | Condition |
|---|---|
| `REP-E008` | ERS not available — agent has no external activity and no bootstrap |
| `REP-E009` | composite_score not computable — both scores are null |
| `REP-E010` | decay_state not computable — missing last_external_event_at |
| `REP-E011` | TrustAttestation rejected — conditions of §3.5 not met |
| `REP-E012` | Active attestation already exists for this agent |
| `REP-E013` | Expired attestation — valid_until < now |
| `REP-E014` | Invalid attestation signature |
| `REP-E015` | Issuing institution is not a valid ITA (ACP-ITA-1.0) |

---

## 14. Conformance

An implementation is **ACP-REP-1.2 conformant** if it meets all requirements of ACP-REP-1.1 AND additionally:

### REP-1.1 inheritance
- [ ] Implements the mathematical model with fixed `event_metric` values
- [ ] Implements the state machine with all defined transitions
- [ ] Guarantees reputation records survive restarts
- [ ] Exposes REP-1.1 endpoints with ACP-HP-1.0 authentication
- [ ] Uses defaults when institution does not configure its own values
- [ ] Produces error codes REP-E001 to REP-E007
- [ ] Integrates with ACP-REV-1.0 for BANNED trigger

### ExternalReputationScore
- [ ] Implements ERS computation per §2.3 with parameters from §2.2
- [ ] Consumes `REPUTATION_UPDATED` events from ACP-LEDGER-1.2
- [ ] Distinguishes `evaluation_context` in event processing
- [ ] Exposes `external_score` in `GET /rep/{agent_id}`
- [ ] Exposes the `last_external_event_at` field

### Score API
- [ ] Implements `GET /acp/v1/rep/{agent_id}/score` with fields from §6
- [ ] Computes `composite_score` per configurable weights
- [ ] Applies differentiated rate limiting per §12.3

### Dual Trust Bootstrap
- [ ] Implements `POST /acp/v1/rep/{agent_id}/bootstrap`
- [ ] Validates conditions of §3.5 before accepting an attestation
- [ ] Computes `bootstrap_value` with discount_factors from §3.4
- [ ] Persists attestation and records event in ledger
- [ ] Automatically invalidates expired attestations or those of suspended agents

### Reputation Decay
- [ ] Implements decay function per §4.2
- [ ] Respects `decay_floor` — ERS never falls to zero by decay
- [ ] Includes `decay_state` in score endpoint responses
- [ ] Records decay events in ledger per §12.4

---

## 15. IANA Considerations

No IANA assignments required.

---

## 16. Normative References

- RFC 2119 — Key words for use in RFCs
- ACP-SIGN-1.0 — Ed25519 + JCS canonicalization
- ACP-CT-1.0 — Capability Token format
- ACP-REV-1.0 — Revocation Protocol
- ACP-HP-1.0 — HTTP Protocol + authentication
- ACP-LEDGER-1.2 — Audit log + REPUTATION_UPDATED events
- ACP-LIA-1.0 — Liability Traceability
- ACP-ITA-1.0 — Institutional Trust Authority
- ACP-REP-1.1 — Base specification (superseded by this document)
- ACP-AGS-1.0 — Agent Governance Stack (L7)
- EigenTrust — Kamvar et al., "The EigenTrust Algorithm for Reputation Management in P2P Networks"
- Reputation decay in distributed systems — Jøsang et al., "A Survey of Trust and Reputation Systems for Online Service Provision"
