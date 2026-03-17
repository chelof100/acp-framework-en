# ACP Admission Flow — The Complete Guide

> **This is the document to start with.** If you want to understand how ACP works end-to-end, read this before any spec.

---

## The Core Idea

ACP is admission control for agent actions.

Before any agent mutates system state — sends a payment, writes a record, calls an API — the action must pass an admission check. The check is deterministic, cryptographic, and institution-enforced. If the check fails, the action does not execute. No exceptions.

The analogy: Kubernetes Admission Controllers intercept API requests before they reach the cluster. ACP intercepts agent actions before they reach the execution layer.

```
                     WITHOUT ACP                          WITH ACP
                ┌─────────────────┐               ┌─────────────────┐
                │                 │               │                 │
  agent ──────► │  target system  │   agent ────► │  ACP admission  │──► DENY
                │  (no gate)      │               │     check       │
                │                 │               │                 │──► ESCALATE
                └─────────────────┘               └────────┬────────┘
                                                           │ ADMIT
                                                           ▼
                                                  ┌─────────────────┐
                                                  │  execution      │
                                                  │  token issued   │
                                                  └────────┬────────┘
                                                           │
                                                           ▼
                                                  ┌─────────────────┐
                                                  │  target system  │
                                                  │  (with proof)   │
                                                  └─────────────────┘
```

---

## The Constitutional Invariant

Every admission check enforces exactly one invariant:

```
Execute(request) ⟹
    ValidIdentity  ∧  ValidCapability  ∧  ValidDelegationChain  ∧  AcceptableRisk
```

**All four conditions must be true simultaneously.** If any one fails, the check returns DENY or ESCALATE — never a partial admit.

---

## The Six-Step Flow

```
agent intent
    ↓
[1] Identity check       →  pkg/agent + pkg/hp       (ACP-AGENT-1.0, ACP-HP-1.0)
    ↓
[2] Capability check     →  pkg/ct + pkg/dcma         (ACP-CT-1.0, ACP-DCMA-1.0)
    ↓
[3] Policy check         →  pkg/risk + pkg/psn        (ACP-RISK-1.0, ACP-PSN-1.0)
    ↓
[4] ADMIT / DENY / ESCALATE
    ↓  (if ADMIT)
[5] Execution token      →  pkg/exec                  (ACP-EXEC-1.0)
    ↓
[6] Ledger record        →  pkg/ledger                (ACP-LEDGER-1.3)
    ↓
system state mutation
```

---

## Step-by-Step Breakdown

### Step 1 — Identity Check (`ACP-AGENT-1.0` + `ACP-HP-1.0`)

**Question:** Is this agent who they claim to be?

The agent holds an Ed25519 key pair. Their identity is the public key, bound to an institutional root. Before processing any request, the agent must prove possession of their private key via the Handshake Protocol (HP):

1. Server issues a one-time challenge nonce
2. Agent signs `Method|Path|Challenge|SHA256(body)` with their private key
3. Server verifies the Proof-of-Possession (PoP) signature

If the signature is invalid or the agent is not registered → **DENY** (`HP-004` / `HP-007`).

```
agent                           ACP server
  │  GET /acp/v1/challenge         │
  │ ──────────────────────────────►│
  │  {"challenge": "nonce..."}     │
  │ ◄──────────────────────────────│
  │                                │
  │  POST /acp/v1/verify           │
  │  Authorization: Bearer {CT}    │
  │  X-ACP-Agent-ID: AGT-001       │
  │  X-ACP-Challenge: nonce...     │
  │  X-ACP-Signature: <Ed25519>    │
  │ ──────────────────────────────►│
  │                                │  verify PoP
  │  {"decision": "APPROVED", ...} │  verify CT sig
  │ ◄──────────────────────────────│
```

**Failure modes:**
- `HP-004`: Agent not registered
- `HP-006`: Expired challenge
- `HP-007`: Invalid PoP signature
- `HP-008`: Capability token expired
- `HP-014`: Capability token signature invalid

---

### Step 2 — Capability Check (`ACP-CT-1.0` + `ACP-DCMA-1.0`)

**Question:** Does the agent hold a valid token for this specific action?

A Capability Token (CT) is a signed JSON object specifying:
- Which agent (`sub`) can do what (`cap`) on which resource (`resource`)
- When it's valid (`iat`, `exp`)
- Who issued it (`iss`) — always an institutional root or delegating agent

```json
{
  "ver": "1.0",
  "iss": "did:acp:institution:bank-a",
  "sub": "AGT-payment-001",
  "cap": ["acp:cap:financial.payment"],
  "resource": "bank://accounts/ACC-001",
  "iat": 1718920000,
  "exp": 1718923600,
  "nonce": "k7hd82ns",
  "sig": "<Ed25519-base64url>"
}
```

**Non-escalation rule (DCMA):** An agent can only delegate capabilities it itself holds. If a planning agent has `acp:cap:data.read`, it cannot delegate `acp:cap:financial.payment` to a sub-agent.

**Failure modes:**
- `HP-008`: Token expired
- `HP-009`: Capability not in token scope
- `HP-010`: Resource mismatch
- `HP-014`: Signature invalid
- `DCMA-003`: Delegation exceeds issuer scope (non-escalation violation)

---

### Step 3 — Policy Check (`ACP-RISK-1.0` + `ACP-PSN-1.0`)

**Question:** Is this action acceptable under the current institutional policy?

The Risk engine scores the action (0–100) based on configurable factors:
- `capability_risk`: inherent risk of the capability type (e.g., financial.payment > data.read)
- `autonomy_risk`: agent autonomy level (level 3 = fully autonomous = higher risk)
- `amount_risk`: for financial operations, scaled by transaction size
- `frequency_risk`: recent action frequency from this agent
- `cross_org_risk`: penalty when action crosses organizational boundaries

Score buckets → decision:

| Score | Decision |
|-------|----------|
| < 30 | `APPROVED` |
| 30–69 | `ESCALATED` (requires human review) |
| ≥ 70 | `DENIED` |

**Policy Snapshots (PSN):** Thresholds are not hardcoded — they come from the institution's active policy snapshot. When institutional policy changes (e.g., stricter limits during a security incident), the institution creates a new snapshot. It activates atomically — all subsequent checks use the new parameters immediately. There is always exactly one `ACTIVE` snapshot.

**Failure modes:**
- `RISK-003`: Risk score exceeds denial threshold
- `RISK-004`: Risk score in escalation range
- `PSN-004`: No active policy snapshot found

---

### Step 4 — Decision: ADMIT / DENY / ESCALATE

After all three checks:

| Outcome | Meaning | Next step |
|---------|---------|-----------|
| `APPROVED` | All checks passed, risk within policy | → Issue execution token (Step 5) |
| `DENIED` | One or more checks failed | → Return error with specific error code |
| `ESCALATED` | Risk score in escalation band | → Notify human reviewer; agent waits |

The `AuthorizationDecision` object in `ACP-HP-1.0 §7`:

```json
{
  "decision": "APPROVED",
  "risk_score": 18,
  "risk_level": "LOW",
  "execution_token": { ... },
  "policy_snapshot_ref": "PSN-2026-003"
}
```

---

### Step 5 — Execution Token (`ACP-EXEC-1.0`)

**What it is:** Cryptographic proof that *this specific action* was authorized, by whom, under which policy, at which timestamp.

The Execution Token (ET) is a single-use, time-bounded signed object:

```json
{
  "et_id": "ET-8821-f9a2",
  "authorization_id": "AUTH-4401",
  "agent_id": "AGT-payment-001",
  "capability": "acp:cap:financial.payment",
  "resource": "bank://accounts/ACC-001",
  "issued_at": 1718920000,
  "expires_at": 1718920300,
  "policy_snapshot_ref": "PSN-2026-003",
  "sig": "<institution-Ed25519>"
}
```

**Double-spend prevention:** Each ET has a unique `et_id`. The target system consumes the ET via `POST /acp/v1/exec-tokens/{et_id}/consume`. Any attempt to replay the same ET returns `EXEC-002` (already consumed).

**Failure modes:**
- `EXEC-001`: Token not found
- `EXEC-002`: Token already consumed
- `EXEC-003`: Token expired (> 300s validity)
- `EXEC-005`: Signature invalid

---

### Step 6 — Ledger Record (`ACP-LEDGER-1.3`)

Every admitted action is appended to the institution's immutable audit ledger — a SHA-256 hash-chained sequence of Ed25519-signed events.

```
genesis event
    │  SHA-256(event[0])
    ▼
event[1]: REGISTRATION  prev_hash=...  sig=<institution>
    │  SHA-256(event[1])
    ▼
event[2]: AUTHORIZATION  prev_hash=...  sig=<institution>
    │  SHA-256(event[2])
    ▼
event[3]: EXECUTION  prev_hash=...  sig=<institution>
```

**Properties:**
- Any tamper invalidates all subsequent hashes — detectable by any third party
- Each event is signed by the institution's root key
- The `policy_snapshot_ref` in AUTHORIZATION/RISK events links to the exact policy in force at decision time

**Failure modes:**
- `LEDGER-002`: Signature invalid on event
- `LEDGER-003`: Hash chain broken
- `LEDGER-004`: Previous hash mismatch
- `LEDGER-012`: Missing institutional signature

---

## The Authority Provenance Object

After execution, ACP produces an **Authority Provenance** artifact (`ACP-PROVENANCE-1.0`) — a retrospective proof of the delegation chain at the exact moment of execution:

```json
{
  "provenance_id": "PROV-9921",
  "execution_id": "ET-8821-f9a2",
  "principal": "did:acp:institution:bank-a",
  "delegator": "did:acp:agent:finance-controller",
  "executor": "AGT-payment-001",
  "delegation_id": "DEL-8821",
  "authority_scope": "financial.payment",
  "valid_until": "2026-12-31T23:59:59Z",
  "policy_ref": "PSN-2026-003",
  "sig": "<institution-Ed25519>"
}
```

This answers definitively: **"Who was accountable for this execution?"**

---

## Multi-Agent Delegation (DCMA)

For pipelines where a human authorizes an agent that delegates to sub-agents:

```
human operator
    │  issues CT: cap=[agent.delegate, data.read]
    ▼
planning agent (AGT-plan-001)
    │  re-delegates: cap=[data.read]  (cannot escalate to agent.delegate)
    ▼
research agent (AGT-research-001)
    │  re-delegates: cap=[data.read]  (further restricted to specific resource)
    ▼
data retrieval tool
```

**Non-escalation property:** Each delegation step can only reduce scope, never expand it. Any attempt to delegate more than you hold → `DCMA-003`.

The full chain is verifiable: if the data tool causes harm, the `PROVENANCE` object traces accountability back to the human operator who authorized the initial delegation.

---

## Cross-Organization Flow

When an agent from Institution A requests admission from Institution B:

```
INSTITUTION A                          INSTITUTION B
┌─────────────────────┐                ┌─────────────────────────────┐
│                     │                │                             │
│  Agent A            │                │  ACP Admission Check        │
│  CT signed by       │  ── request ──►│  1. Verify CT sig against   │
│  Institution A's    │                │     Institution A's pubkey  │
│  root key           │                │  2. Verify delegation chain │
│                     │                │  3. Check risk vs policy    │
└─────────────────────┘                │     of Institution B        │
                                       │  4. Issue ET under B's key  │
                                       └─────────────────────────────┘
```

Institution B does **not** need to trust Institution A's internal systems — only Institution A's published root public key. Trust is derived from cryptographic verification, not bilateral trust agreements.

---

## Conformance Levels — Which Checks Apply

| Level | Checks enforced | What you implement |
|-------|-----------------|-------------------|
| **L1** | Identity + Capability | `pkg/agent`, `pkg/ct`, `pkg/hp`, `pkg/dcma` |
| **L2** | + Policy/Risk | + `pkg/risk`, `pkg/psn` |
| **L3** | + Execution proof + Ledger | + `pkg/exec`, `pkg/ledger`, `pkg/provenance`, `pkg/policyctx` |
| **L4** | + Governance events + Liability | + `pkg/govevents`, `pkg/lia`, `pkg/hist`, + others |

**Minimum viable admission check:** L1 gives you cryptographic identity verification and capability scoping. This alone eliminates impersonation and unauthorized capability escalation.

---

## Implementation — Go Reference

The reference implementation in `impl/go/` implements all L1-L4 checks:

```bash
cd impl/go
go build ./...
go test ./...
```

All packages map directly to the specs above:

```
impl/go/pkg/
├── handshake/   # ACP-HP-1.0   — PoP challenge/verify
├── tokens/      # ACP-CT-1.0   — capability token issuance + verification
├── delegation/  # ACP-DCMA-1.0 — delegation chain validation
├── risk/        # ACP-RISK-1.0 — risk scoring engine
├── psn/         # ACP-PSN-1.0  — policy snapshot management
├── execution/   # ACP-EXEC-1.0 — execution token lifecycle
├── ledger/      # ACP-LEDGER-1.3 — hash-chained audit ledger
├── provenance/  # ACP-PROVENANCE-1.0 — authority provenance
└── policyctx/  # ACP-POLICY-CTX-1.0 — policy context snapshot
```

---

## Implementation — Python SDK

The Python SDK in `impl/python/` provides a client that calls the Go reference server:

```python
from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient

# 1. Generate agent identity (Ed25519 key pair)
agent = AgentIdentity.generate()
signer = ACPSigner(agent)

# 2. Connect to ACP server
client = ACPClient(
    server_url="http://localhost:8080",
    identity=agent,
    signer=signer,
)

# 3. Run admission check
decision = client.authorize(
    request_id="req-001",
    agent_id=agent.agent_id,
    capability="acp:cap:financial.payment",
    resource="bank://accounts/ACC-001",
    action_parameters={"amount": 50000},
)

# 4. Act on decision
if decision["decision"] == "APPROVED":
    et = decision["execution_token"]
    # proceed with execution, pass et_id to target system
    execute_payment(amount=50000, execution_token_id=et["et_id"])
elif decision["decision"] == "ESCALATED":
    notify_human_reviewer(decision["escalation_id"])
else:
    raise RuntimeError(f"Action denied: {decision}")
```

See `impl/python/examples/` for runnable end-to-end examples.

---

## Quick Reference — Error Codes

| Code | Spec | Meaning |
|------|------|---------|
| `HP-004` | ACP-HP-1.0 | Agent not registered |
| `HP-006` | ACP-HP-1.0 | Challenge expired |
| `HP-007` | ACP-HP-1.0 | Invalid PoP signature |
| `HP-008` | ACP-HP-1.0 | Capability token expired |
| `HP-009` | ACP-HP-1.0 | Capability scope mismatch |
| `HP-014` | ACP-HP-1.0 | Token signature invalid |
| `DCMA-003` | ACP-DCMA-1.0 | Non-escalation violation |
| `RISK-003` | ACP-RISK-1.0 | Risk above denial threshold |
| `RISK-004` | ACP-RISK-1.0 | Risk in escalation band |
| `PSN-004` | ACP-PSN-1.0 | No active policy snapshot |
| `EXEC-002` | ACP-EXEC-1.0 | Execution token already consumed |
| `EXEC-003` | ACP-EXEC-1.0 | Execution token expired |
| `LEDGER-003` | ACP-LEDGER-1.3 | Hash chain integrity failure |
| `LEDGER-012` | ACP-LEDGER-1.3 | Missing institutional signature |

---

## Where to Go Next

- **Implement L1:** Start with `spec/core/` — AGENT, CT, HP, DCMA
- **Run the reference server:** `impl/go/` — `go build ./...` then `docker compose up`
- **Try the Python demo:** `impl/python/examples/admission_control_demo.py`
- **Conformance requirements:** `spec/governance/ACP-CONF-1.2.md`
- **Formal domain model:** `ARCHITECTURE.md`
- **Test your implementation:** `compliance/test-vectors/` — 42 signed vectors
