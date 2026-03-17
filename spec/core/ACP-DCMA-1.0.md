# ACP-DCMA-1.0
## Delegation Chain Model & Attestation

**Status:** Normative
**Version:** 1.0
**Type:** Core Protocol Specification
**Depends-on:** ACP-CT-1.0, ACP-SIGN-1.0
**Required-by:** ACP-CONF-1.2 (L1 — Core Conformance)
**Integration note:** DCMA payloads are included in `AUTHORIZATION` and `LIABILITY_RECORD` ledger events (ACP-LEDGER-1.3 §5.2, §5.12). This is a write-only operational integration; ACP-LEDGER-1.3 is not required for DCMA's formal delegation model to be correct.

> This specification is **normative**. It defines the formal chained delegation model, no-escalation constraints, and transitive revocation. All ACP v1.x implementations that support delegation MUST comply with the formal properties defined here.

---

## 1. Extension of the Formal Space

We add:

𝐷 → set of delegations

𝐼 → set of institutions

An agent now belongs to an institution:

𝑂
𝑤
𝑛
𝑒
𝑟
(
𝑎
)
∈
𝐼
Owner(a)∈I
2. Formal Definition of Delegation

A delegation is a tuple:

𝑑
=
(
𝑎
𝑖
,
𝑎
𝑗
,
𝑐
,
𝜎
,
𝜏
)
d=(a
i
	​

,a
j
	​

,c,σ,τ)

Where:

𝑎
𝑖
a
i
	​

 = delegating agent

𝑎
𝑗
a
j
	​

 = delegated agent

𝑐
c = delegated capability

𝜎
σ = additional constraints

𝜏
τ = temporal validity interval

Interpretation:

Agent
𝑎
𝑖
a
i
	​

 delegates capability
𝑐
c to agent
𝑎
𝑗
a
j
	​

 under constraints
𝜎
σ and time
𝜏
τ.

3. Valid Delegation Predicate
𝑉
𝑎
𝑙
𝑖
𝑑
𝐷
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑖
𝑜
𝑛
(
𝑑
)
ValidDelegation(d)

Is true if:

𝑉
𝑎
𝑙
𝑖
𝑑
𝐼
𝐷
(
𝑎
𝑖
)
ValidID(a
i
	​

)

𝑉
𝑎
𝑙
𝑖
𝑑
𝐼
𝐷
(
𝑎
𝑗
)
ValidID(a
j
	​

)

𝐻
𝑎
𝑠
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
(
𝑎
𝑖
,
𝑐
)
HasCapability(a
i
	​

,c)

Valid cryptographic signature of
𝑎
𝑖
a
i
	​

Current time ∈
𝜏
τ

Constraints
𝜎
σ compatible with original limits

4. Delegated Capability

We define:

𝐷
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑒
𝑑
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
(
𝑎
𝑗
,
𝑐
)
DelegatedCapability(a
j
	​

,c)

True if a valid delegation exists:

∃
𝑑
∈
𝐷
 such that
𝑑
=
(
𝑎
𝑖
,
𝑎
𝑗
,
𝑐
,
𝜎
,
𝜏
)
∧
𝑉
𝑎
𝑙
𝑖
𝑑
𝐷
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑖
𝑜
𝑛
(
𝑑
)
∃d∈D such that d=(a
i
	​

,a
j
	​

,c,σ,τ)∧ValidDelegation(d)

The capability predicate is then redefined as:

𝐻
𝑎
𝑠
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
′
(
𝑎
𝑗
,
𝑐
)

⟺

𝐻
𝑎
𝑠
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
(
𝑎
𝑗
,
𝑐
)
∨
𝐷
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑒
𝑑
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
(
𝑎
𝑗
,
𝑐
)
HasCapability
′
(a
j
	​

,c)⟺HasCapability(a
j
	​

,c)∨DelegatedCapability(a
j
	​

,c)
5. No-Escalation Constraint

Delegation cannot expand privileges.

Formally:

𝐶
𝑜
𝑛
𝑠
𝑡
𝑟
𝑎
𝑖
𝑛
𝑡
𝑠
(
𝑐
𝑑
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑒
𝑑
)
⊆
𝐶
𝑜
𝑛
𝑠
𝑡
𝑟
𝑎
𝑖
𝑛
𝑡
𝑠
(
𝑐
𝑜
𝑟
𝑖
𝑔
𝑖
𝑛
𝑎
𝑙
)
Constraints(c
delegated
	​

)⊆Constraints(c
original
	​

)

And:

𝜎
⊆
𝑂
𝑟
𝑖
𝑔
𝑖
𝑛
𝑎
𝑙
𝐿
𝑖
𝑚
𝑖
𝑡
𝑠
(
𝑎
𝑖
,
𝑐
)
σ⊆OriginalLimits(a
i
	​

,c)

If the delegate attempts to execute outside those constraints:

𝐷
𝑒
𝑐
𝑖
𝑠
𝑖
𝑜
𝑛
(
𝑟
𝑒
𝑞
)
=
𝐷
𝑒
𝑛
𝑖
𝑒
𝑑
Decision(req)=Denied
6. Chained Delegation

Allows controlled transitivity.

Chain:

𝑎
1
→
𝑎
2
→
𝑎
3
a
1
	​

→a
2
	​

→a
3
	​


Is valid if:

Each intermediate delegation is valid.

No cumulative constraint is violated.

Delegation depth ≤ institutional limit.

We define:

𝐷
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑖
𝑜
𝑛
𝐷
𝑒
𝑝
𝑡
ℎ
(
𝑎
𝑘
)
≤
𝛿
𝑚
𝑎
𝑥
DelegationDepth(a
k
	​

)≤δ
max
	​


Where
𝛿
𝑚
𝑎
𝑥
δ
max
	​

 is an institutional parameter.

7. Formal Evaluation with Delegation

The authorization rule is modified:

𝐴
𝑢
𝑡
ℎ
𝑜
𝑟
𝑖
𝑧
𝑒
𝑑
(
𝑟
𝑒
𝑞
)

⟺

𝑉
𝑎
𝑙
𝑖
𝑑
𝐼
𝐷
(
𝑎
)
∧
𝐻
𝑎
𝑠
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
′
(
𝑎
,
𝑐
)
∧
𝑃
𝑜
𝑙
𝑖
𝑐
𝑦
𝑆
𝑎
𝑡
𝑖
𝑠
𝑓
𝑖
𝑒
𝑑
(
.
.
.
)
∧
𝑊
𝑖
𝑡
ℎ
𝑖
𝑛
𝐿
𝑖
𝑚
𝑖
𝑡
𝑠
(
.
.
.
)
∧
𝐴
𝑐
𝑐
𝑒
𝑝
𝑡
𝑎
𝑏
𝑙
𝑒
𝑅
𝑖
𝑠
𝑘
(
.
.
.
)
Authorized(req)⟺ValidID(a)∧HasCapability
′
(a,c)∧PolicySatisfied(...)∧WithinLimits(...)∧AcceptableRisk(...)

The difference lies in
𝐻
𝑎
𝑠
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
′
HasCapability
′
.

8. Accountability Chaining

Each delegation generates a record:

𝑒
𝑑
=
(
𝑎
𝑖
,
𝑎
𝑗
,
𝑐
,
𝜎
,
𝜏
,
ℎ
𝑎
𝑠
ℎ
𝑝
𝑟
𝑒
𝑣
)
e
d
	​

=(a
i
	​

,a
j
	​

,c,σ,τ,hash
prev
	​

)

For an action executed under delegation, the ledger must be able to reconstruct:

𝑎
1
→
𝑎
2
→
.
.
.
→
𝑎
𝑘
a
1
	​

→a
2
	​

→...→a
k
	​


Mandatory property:

𝐸
𝑥
𝑒
𝑐
𝑢
𝑡
𝑖
𝑜
𝑛
(
𝑎
𝑘
,
𝑐
)
⇒
𝑇
𝑟
𝑎
𝑐
𝑒
𝑎
𝑏
𝑙
𝑒
𝐶
ℎ
𝑎
𝑖
𝑛
(
𝑎
1
,
.
.
.
,
𝑎
𝑘
)
Execution(a
k
	​

,c)⇒TraceableChain(a
1
	​

,...,a
k
	​

)

If it cannot be reconstructed → not valid.

9. Transitive Revocation

If:

𝑅
𝑒
𝑣
𝑜
𝑘
𝑒
(
𝑎
𝑖
)
Revoke(a
i
	​

)

Then:

∀
𝑑
 where
𝑑
𝑒
𝑙
𝑒
𝑔
𝑎
𝑡
𝑜
𝑟
=
𝑎
𝑖
⇒
𝐼
𝑛
𝑣
𝑎
𝑙
𝑖
𝑑
(
𝑑
)
∀d where delegator=a
i
	​

⇒Invalid(d)

And recursively:

Every dependent chain becomes invalid.

This prevents zombie delegations.

10. Inter-Institutional Model

For delegation between institutions:

𝑂
𝑤
𝑛
𝑒
𝑟
(
𝑎
𝑖
)
≠
𝑂
𝑤
𝑛
𝑒
𝑟
(
𝑎
𝑗
)
Owner(a
i
	​

)

=Owner(a
j
	​

)

Requires:

TrustAnchor(Owner(a_i), Owner(a_j))

Cross-validation of certificates

Auditable record by both parties

B2B delegation is only valid if both institutions can verify the signature.

11. Security Properties

ACP delegation guarantees:

No privilege escalation.

Propagated revocation.

Complete traceability.

Limited depth.

Mandatory signature at each hop.

12. Structural Difference from RBAC

RBAC allows role assignment.
It does not model:

Delegation with dynamic constraints.

Verifiable chaining.

Formal transitive revocation.

Multi-institutional accountability.

ACP does.

13. Critical Point

ACP now has:

Formal decision model

Identity model

Chained delegation model

Demonstrable security properties

Auditable structure

---

14. Transitive Revocation — Normative Timing

Section 9 defines the formal property of transitive revocation. This section establishes the propagation timing requirements that every conformant implementation MUST satisfy.

14.1 Maximum Propagation

From the moment Revoke(aᵢ) is recorded in the revocation system:

The verifier MUST guarantee that every subsequent verification within τ_propagation ≤ 60 seconds rejects:

- Tokens issued by aᵢ
- Tokens from any delegation chain where aᵢ is a delegator (direct or transitive)

The verifier MUST consult revocation status on every authorization decision, without exception.

14.2 Revocation Status Cache

If the verifier uses a cache of revocation status:

- The cache TTL MUST be ≤ 30 seconds.
- Expired entries MUST be invalidated before the next authorization query.
- The verifier MUST accept forced cache refresh upon any revocation notification received via event channel.

An implementation that does not use a cache MUST query the revocation store in real time on every decision.

14.3 In-Flight Requests

If a revocation occurs while an execution request is in progress:

- The verifier MUST re-evaluate the revocation status of the agent and its delegation chain before issuing the final execution confirmation.
- A request approved before the revocation MUST be denied if the revocation is detected before the final confirmation.
- The system MUST emit a REVOKED error with a reference to the jti of the affected token.

14.4 Atomicity of Revocation

Revoke(aᵢ) has atomic effect on the system state:

- There is no intermediate state where aᵢ is partially revoked.
- All dependent delegations (direct and transitive) become invalid simultaneously from the revocation timestamp.
- The revocation timestamp MUST be recorded with second-level precision and be queryable by auditors.

14.5 Non-Compliance Due to Timing

An implementation is NOT conformant with respect to transitive revocation if it:

- Accepts tokens issued by a revoked agent more than 60 seconds after the revocation timestamp.
- Uses a revocation cache with TTL > 30 seconds.
- Confirms executions without re-evaluating revocation status when the revocation occurred during request processing.
- Does not record the revocation timestamp with second-level precision.
