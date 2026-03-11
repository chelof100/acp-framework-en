1. Formal Space

We define the following sets:

𝐴 → set of agents

𝐶 → set of capabilities

𝑃 → set of policies

𝐿 → set of limits

𝑅 → set of resources

𝑋 → set of contexts

𝐸 → set of events

A requested action is modeled as:

req=(a,c,r,x,t)

Where:

a∈A

c∈C

r∈R

x∈X

t = timestamp

2. Fundamental Predicates

We define the following boolean predicates:

2.1 Valid identity
ValidID(a)

True if:

Valid cryptographic identity

Not revoked

State = active

2.2 Declared capability
HasCapability(a,c)

True if:

c∈C_a

Belongs to the agent's authorized domain

2.3 Policy satisfied
PolicySatisfied(a,c,r,x)

Evaluates declared rules:

Context conditions

Quantitative thresholds

Temporal restrictions

2.4 Limits respected
WithinLimits(a,c,t)

Evaluates:

Rate limits

Cumulative limit

Temporal validity

Required supervision

2.5 Acceptable risk

We define the risk function:

Risk:(a,c,r,x)→[0,1]

And institutional threshold:

θ∈[0,1]

Then:

AcceptableRisk(a,c,r,x)⟺Risk(a,c,r,x)<θ

3. Formal Authorization Rule

Authorization is defined as:

Authorized(req)⟺ValidID(a)∧HasCapability(a,c)∧PolicySatisfied(a,c,r,x)∧WithinLimits(a,c,t)∧AcceptableRisk(a,c,r,x)

If any predicate is false → Denied.

4. Decision States

We define the decision function:

Decision(req)→{Approved,Denied,Escalated}

Formally:

Case 1 — Approved
Authorized(req)=True

Case 2 — Denied

If:

¬ValidID(a)∨¬HasCapability(a,c)∨¬WithinLimits(a,c,t)

Case 3 — Escalated

If:

ValidID(a)∧HasCapability(a,c)∧PolicySatisfied(a,c,r,x)∧WithinLimits(a,c,t)∧Risk(a,c,r,x)≥θ

Escalated implies external intervention.

5. Decision–Execution Separation Property

We define the execution operator:

Execute(req)

Mandatory property:

Execute(req)⇒Decision(req)=Approved

And its counterpart:

Decision(req)≠Approved⇒¬Execute(req)

This guarantees no bypass.

6. No Implicit Escalation Property

For every agent a:

∀c∉C_a⇒¬HasCapability(a,c)

And therefore:

¬HasCapability(a,c)⇒Decision(req)=Denied

There is no automatic inference of capabilities.

7. Formal Traceability

Each decision generates an event:

e=(req,Decision(req),risk_value,hash_prev)

The ledger forms a chain:

hash_n=H(e_n∥hash_{n-1})

Property:

Tamper(e_k)⇒InvalidChain

8. Determinism Property

If:

Same identity

Same context

Same policies

Same state

Same risk function

Then:

Decision(req_1)=Decision(req_2)

This is critical for auditability.

9. Formal Comparison with RBAC

RBAC defines:

Authorized_RBAC(u,r)⟺Role(u)∈PermittedRoles(r)

ACP extends the model by adding:

Dynamic context

Risk function

Cumulative limits

Operational state

It is strictly more expressive.

10. Computational Complexity

The ACP decision is:

O(P+L+R_f)

Where:

P = number of applicable policies

L = number of active limits

R_f = cost of the risk function

MUST remain polynomial for practical viability.

11. Result

ACP now has:

Algebraic model

Defined predicates

Formal risk function

Strict authorization rules

Provable properties

Basis for formal analysis
