0. Attacker Model

We define four profiles:

Actor	Capabilities
A1	Malicious legitimate user
A2	Compromised service
A3	Network observer (partial MITM)
A4	Compromised issuer

ACP is evaluated against each one.

1️⃣ Attack 1: Capability Token Forgery
Objective

Create a valid token without issuer authorization.

Surface
Token = Sign_skIssuer(payload)
Attempt

Alter payload

Change context

Reuse prior signature

Generate fake signature

Analysis

If:

Signature = Ed25519

Private key protected

Verification mandatory on every request

Then:

Forgery requires breaking EUF-CMA

Probability ≈ 2^-128

Result

✔️ Secure under standard cryptographic model
❗ Real risk: poor key management

2️⃣ Attack 2: Replay Attack
Objective

Reuse a valid token outside its temporal context.

Surface

Fields:

nbf
exp
nonce
context_hash
Scenario A: Reuse within valid window

✔️ Permitted if policy allows
Not a failure, it is by design.

Scenario B: Reuse outside context

If:

context_hash = H(resource || method || environment || policy_version)

Then the token:

Cannot move to another endpoint

Cannot change method

Cannot bypass policy

✔️ Mitigated

Scenario C: Distributed replay

If no nonce cache exists → possible concurrent reuse.

Mitigation:

Verifier MUST maintain replay cache for nonce during token validity window.

If not implemented → practical vulnerability.

3️⃣ Attack 3: Privilege Escalation via Token Composition
Objective

Combine two tokens to create greater privilege.

ACP does not allow implicit composition.

Each token:

capability = closed set

Does not exist:

union(tokenA, tokenB)

Without issuer intervention.

✔️ Escalation impossible without issuer.

4️⃣ Attack 4: Confused Deputy

Classic capability system problem.

Scenario

Service A has a token for resource X.
Service B invokes A to obtain access to X indirectly.

If the token:

subject = service A

And verifier requires caller identity match:

✔️ Blocked.

If identity binding is not validated:

❌ Vulnerable.

Required normative:

Verifier MUST validate that caller identity matches token.subject.
5️⃣ Attack 5: Context Manipulation
Objective

Change environment without invalidating token.

Example:

Token issued for staging environment

Used in production

If:

context_hash includes environment_id

✔️ Secure.

If environment is not part of the hash:

❌ Vulnerable.

6️⃣ Attack 6: Policy Downgrade Attack
Scenario

policy_version 5 is strict

policy_version 3 is permissive

If attacker forces verifier to accept old version:

Mitigation:

Verifier MUST reject tokens with policy_version lower than minimum_supported.

Without this → downgrade possible.

7️⃣ Attack 7: Issuer Compromise

This is the critical point.

If issuer is compromised:

Can issue any capability

Can escalate privileges

ACP does not eliminate this risk.

Mitigations:

Key rotation

Threshold signatures

HSM

Separation of duties

The security model assumes:

Issuer trusted and secure

Without that → system falls.

8️⃣ Attack 8: Revocation Problem

Signed tokens are autonomous.

If a token is compromised:

Cannot be revoked without an external list.

Options:

Short expiration windows

Distributed CRL

Online introspection

Trade-off:

More autonomy = less revocation control.

ACP favors short expiration.

9️⃣ Attack 9: Lateral Movement

If compromised service holds a valid token:

Can use it until exp.

ACP limits movement if:

Tokens are scoped

Short TTL

Strict context binding

Without that → lateral movement viable.

🔟 Attack 10: Formal Cryptographic Break

Under assumptions:

Ed25519 secure

SHA-256 collision-resistant

Random nonces

ACP reduces to:

EUF-CMA + collision resistance

If either falls → system falls.

But that applies to any modern system.

🧠 Global Results
Vector	Status
Forgery	Secure
Replay	Secure with nonce cache
Escalation	Secure
Confused deputy	Secure with subject binding
Context swap	Secure with correct context hash
Downgrade	Secure if minimum enforced
Issuer compromise	Critical point
Revocation	Limited
Lateral movement	Controllable with short TTL
🔴 Realistic Conclusion

ACP:

✔️ Is cryptographically sound
✔️ Reduces attack surface compared to traditional RBAC
✔️ Eliminates implicit authorization

But:

❗ Real security depends on strict implementation
❗ Issuer remains the highest risk point
❗ Revocation is not trivial
