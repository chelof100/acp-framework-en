1. System Assumptions

ACP operates in an environment where:

Autonomous agents with cryptographic identity exist.

Agents can delegate capabilities.

Multiple institutions exist.

Potentially malicious actors exist.

Partial infrastructure compromise may occur.

We do not assume full trust in:

Individual agents.

Internal infrastructure.

External networks.

2. Attack Surface

Minimum relevant surface:

Agent identity spoofing.

Message tampering.

Authorization engine bypass.

Improper escalation via delegation.

Replay attacks.

Ledger manipulation.

Incomplete revocation.

Agent collusion.

3. Threat Classification

We use structural categories:

S — Spoofing

T — Tampering

R — Repudiation

I — Information Disclosure

D — Denial of Service

E — Elevation of Privilege

4. Formal Analysis by Category
4.1 Spoofing (S)
Threat S1

An attacker attempts to impersonate a valid agent.

Adversarial condition:

ForgeSignature(a)

ACP Mitigation:

ValidID(a)⇒VerifySignature(a)

If signature invalid:

Decision(req) = Denied (ACP-001)

Property guaranteed:
Without valid private key, there is no execution.

4.2 Tampering (T)
Threat T1

Alteration of an AuthorizationDecision in transit.

Mitigation:

Mandatory institutional signature.

Verification before execution.

InvalidSignature⇒Reject
Threat T2

Action Ledger manipulation.

Chained ledger:

hash_n = H(e_n || hash_{n-1})

If:

Tamper(e_k)

Then:

InvalidChain

Audit detects alteration.

4.3 Repudiation (R)
Threat R1

An agent denies having issued an action.

Mitigation:

ActionRequest digitally signed.

Signed(req,a)⇒NonRepudiation
4.4 Information Disclosure (I)

ACP is not a confidentiality protocol, but:

Does not expose private keys.

Does not transmit full capabilities if not required.

Delegations must reveal only the necessary subset.

Partial protection.
Confidentiality depends on transport layer.

4.5 Denial of Service (D)
Threat D1

ActionRequest flood.

Mitigation:

WithinLimits(a,c,t) includes rate limit.

Threat D2

Blocking by mass escalations.

Requires:

Controlled queue

Escalation limit per unit of time

ACP does not eliminate network DoS, but limits logical impact.

4.6 Elevation of Privilege (E)

This is the most critical threat.

Threat E1

An agent executes an undeclared capability.

Formally:

c ∉ Ca

Mitigation:

HasCapability(a,c)

If false → Denied.

Threat E2

Delegation expands privileges.

Attack:

Constraints_delegated ⊃ Constraints_original

Formal mitigation:

Constraints_delegated ⊆ Constraints_original

If not satisfied → Invalid delegation.

Threat E3

Infinite delegation chain.

Mitigation:

DelegationDepth(a_k) ≤ δ_max

Threat E4

Partial revocation not propagated.

Mitigation:

Mandatory transitive revocation.

Revoke(a_i) ⇒ ∀d dependents Invalid(d)

5. Adversarial Model

We define adversary A:

Capabilities:

Intercept messages.

Modify traffic.

Compromise individual agent.

Attempt to forge delegations.

Attempt to manipulate state.

Cannot:

Break standard cryptography.

Modify multiple institutions simultaneously without detection.

Rewrite complete ledger without invalidating hash.

6. Global Security Property

ACP guarantees:

Execute(req) ⇒ ValidID(a) ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk

Any attack must break at least one of those predicates.

7. Comparison with RBAC Under Threat

RBAC under E2:

No formal model of chained delegation exists.

RBAC does not define:

Delegation depth.

Formal transitive constraint.

Mandatory cryptographic registry.

ACP does.

8. Comparison with Zero Trust Under Threat

Zero Trust protects network access.

Does not regulate:

Internal semantic escalation.

Chained logical delegation.

Multi-agent structural accountability.

ACP adds that layer.

9. Residual Risks

ACP does not eliminate:

Total root authority compromise.

Coordinated institutional corruption.

Implementation failures.

Physical attacks.

But reduces:

Silent escalation.

Opaque delegation.

Lack of traceability.

Accountability ambiguity.

10. Technical Conclusion

With:

Formal decision model

Formal chained delegation

Structured threat model

Demonstrable properties

ACP already has:

Sufficient technical foundation for rigorous academic review.
