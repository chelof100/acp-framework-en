4. Formal Agent Specification
4.1 Agent Definition

An ACP Agent is an autonomous computational entity capable of:

Making decisions within a defined operational domain.

Executing actions on controlled resources.

Declaring its capability, context, and limits.

Being cryptographically audited.

We formally define an agent as:

𝐴
=
(
𝐼
𝐷
,
𝐶
,
𝑃
,
𝐷
,
𝐿
,
𝑆
)
A=(ID,C,P,D,L,S)

Where:

ID → Unique cryptographic identity.

C → Set of declared capabilities.

P → Active policies.

D → Operational domain.

L → Operational limits.

S → Current verifiable state.

4.2 Agent Identity (ID)

Each agent has a verifiable identity composed of:

Public Key

Agent Fingerprint

Issuer Authority

Trust Level

Version

Minimum format:

{
  "agent_id": "did:acp:org:agent-001",
  "public_key": "base64",
  "issuer": "acp-root-authority",
  "trust_level": "institutional",
  "version": "0.3"
}

The agent_id must be:

Globally unique

Non-reusable

Signed by a valid authority

4.3 Capabilities (C)

A capability is an executable action within a domain.

𝐶
=
{
𝑐
1
,
𝑐
2
,
.
.
.
,
𝑐
𝑛
}
C={c
1
	​

,c
2
	​

,...,c
n
	​

}

Each capability has the structure:

{
  "capability_id": "approve_transaction",
  "domain": "finance.payments",
  "constraints": {
    "max_amount": 100000,
    "currency": ["USD", "EUR"]
  }
}

Rules:

Capabilities are declarative.

They do not imply absolute permission.

They are dynamically evaluated under policies.

4.4 Policies (P)

Policies determine when a capability may be exercised.

Model:

𝐷
𝑒
𝑐
𝑖
𝑠
𝑖
𝑜
𝑛
=
𝑓
(
𝐶
𝑜
𝑛
𝑡
𝑒
𝑥
𝑡
,
𝐶
𝑎
𝑝
𝑎
𝑏
𝑖
𝑙
𝑖
𝑡
𝑦
,
𝑃
𝑜
𝑙
𝑖
𝑐
𝑦
)
Decision=f(Context,Capability,Policy)

Example:

{
  "policy_id": "tx-policy-01",
  "rule": "amount < 100000 AND risk_score < 0.7",
  "effect": "allow"
}

Policy types:

Deterministic

Risk-based

Contextual

Temporal

Multi-factor

4.5 Domain (D)

Defines the operational space of the agent.

Example:

{
  "domain_id": "finance.payments",
  "scope": [
    "transaction.initiate",
    "transaction.approve"
  ]
}

An agent cannot operate outside its declared domain.

4.6 Limits (L)

Limits establish hard constraints:

Maximum transactions per hour

Monetary limit

Validity period

Required supervision level

Example:

{
  "rate_limit": "100/hour",
  "expires_at": "2026-12-31T23:59:59Z",
  "supervision_required": true
}

Limits are non-negotiable at runtime.

4.7 State (S)

Current verifiable state of the agent.

𝑆
=
(
𝑚
𝑜
𝑑
𝑒
,
ℎ
𝑒
𝑎
𝑙
𝑡
ℎ
,
𝑡
𝑟
𝑢
𝑠
𝑡
𝑠
𝑐
𝑜
𝑟
𝑒
,
𝑎
𝑢
𝑑
𝑖
𝑡
ℎ
𝑎
𝑠
ℎ
)
S=(mode,health,trust
s
	​

core,audit
h
	​

ash)

Example:

{
  "mode": "active",
  "health": "ok",
  "trust_score": 0.92,
  "audit_hash": "sha256-abc123"
}
5. Agent Lifecycle
5.1 Registration

Cryptographic identity generation.

Domain declaration.

Capability declaration.

Validation by authority.

Issuance of ACP certificate.

5.2 Activation

An agent is activated only if:

Valid ID

Certificate not revoked

Policies loaded

Limits defined

5.3 Operation Flow

Decision process:

Request → Capability Check → Policy Evaluation →
Limit Verification → Decision → Execution → Audit Log

Formally:

𝐸
𝑥
𝑒
𝑐
𝑢
𝑡
𝑒
(
𝐴
,
𝑎
𝑐
𝑡
𝑖
𝑜
𝑛
)
⇒
𝑉
𝑎
𝑙
𝑖
𝑑
(
𝐼
𝐷
)
∧
𝐴
𝑙
𝑙
𝑜
𝑤
𝑒
𝑑
(
𝐶
,
𝑃
)
∧
𝑊
𝑖
𝑡
ℎ
𝑖
𝑛
(
𝐿
)
Execute(A,action)⇒Valid(ID)∧Allowed(C,P)∧Within(L)
5.4 Suspension

An agent can be:

Suspended due to high risk

Revoked by authority

Self-deactivated due to internal failure

5.5 Revocation

Revocation implies:

Immediate invalidity of the ID

Inclusion in the ACP CRL list

Permanent record in immutable log

6. Trust Model

ACP operates under:

Strong cryptographic identity

Continuous evaluation

Auditable record

Contextual trust, not permanent

There is no static trust.

7. Security Properties

ACP guarantees:

No implicit privilege escalation

Complete auditability

Declarative and verifiable capability

Mandatory contextual evaluation

Separation between identity and authorization

8. Minimal Conformance Requirements

A system complies with ACP if it:

Implements verifiable identity

Evaluates policies dynamically

Records auditable events

Allows effective revocation

Separates capability from authorization
