# ACP: A Cryptographically Verifiable Capability-Based Authorization Architecture for Autonomous Agent Systems

**Submission Draft — IEEE S&P / NDSS**

**Author:** Marcelo Fernandez
**Affiliation:** TraslaIA
**Contact:** marcelo@traslaia.com

---

## Abstract

We present the Agent Control Protocol (ACP), a capability-based authorization architecture for multi-agent systems operating in institutional environments. ACP replaces implicit permission inference with explicit cryptographic artifacts — Capability Tokens — that bind authorization to identity, resource, context, and time. Each token is signed with Ed25519 by a designated issuer and verified locally by any conformant verifier without requiring centralized policy evaluation at runtime. ACP defines a formal delegation model that enforces strict capability confinement across arbitrary delegation chains and a STRIDE-structured threat model with formal mitigation analysis. We prove that ACP token unforgeability reduces tightly to the EUF-CMA security of Ed25519 and that delegation confinement holds by induction over chain length. We evaluate ACP against ten adversarial attack vectors and compare it structurally with RBAC, Zero Trust, and OAuth-based models. ACP provides a formally verifiable authorization primitive suitable for B2B and inter-institutional autonomous agent deployments.

**Keywords:** capability-based security, authorization, Ed25519, EUF-CMA, autonomous agents, delegation, formal security model, multi-agent systems

---

## 1. Introduction

Authorization systems in distributed environments face a structural challenge: they must enforce access control across trust boundaries, at scale, without requiring all parties to share a common policy engine or synchronize state at access time.

Existing approaches exhibit well-known structural weaknesses:

- **Role-Based Access Control (RBAC):** Permission is inferred from role membership. Role accumulation over time creates implicit privilege inflation. Delegation is opaque and unverifiable.
- **Policy Engines (Zero Trust):** Real-time evaluation is correct but introduces centralized latency, availability dependence, and does not produce cryptographic evidence of authorization.
- **OAuth 2.0 / JWT:** Scopes are coarse-grained, not formally verifiable at the capability level. Tokens carry no resource-contextual binding. Delegation is non-standard and not formally constrained.

The rise of autonomous agents executing operations across institutional boundaries exacerbates these weaknesses. An agent may operate across dozens of services, delegating sub-capabilities to other agents, with no human in the loop for individual authorization decisions. A system designed for human sessions does not map cleanly to this environment.

**ACP proposes a different paradigm:**

Authorization is an explicit, cryptographically verifiable object. No operation executes without a signed Capability Token that encodes exactly what is permitted, for whom, on which resource, under which context, and until when. Verification is local, stateless with respect to policy, and formally reducible to standard cryptographic hardness assumptions.

**Contributions of this paper:**

1. A formal definition of the ACP Capability Token structure and verification semantics (§4).
2. A formal delegation model with proven confinement guarantees (§4.4, §5.2).
3. A security reduction from ACP unforgeability to EUF-CMA security of Ed25519 (§5.1).
4. A STRIDE-structured adversarial analysis covering ten attack vectors (§6).
5. Structural comparison with RBAC, Zero Trust, and OAuth (§7).
6. Discussion of deployment constraints and honest residual risks (§8, §9).

---

## 2. Background

### 2.1 Capability-Based Security

Capability systems originate from work on object-capability models [Saltzer & Schroeder 1975; Miller 2006]. In a capability system, the right to access a resource is represented by an unforgeable token — the capability. Possession of a valid capability is sufficient for access; no additional identity lookup is required.

ACP instantiates the capability model cryptographically. Capabilities are Ed25519-signed JSON objects. Unforgeability follows from the signature scheme rather than from object isolation.

### 2.2 Ed25519 and EUF-CMA Security

Ed25519 [Bernstein et al. 2011] is a deterministic Schnorr-variant signature scheme over Curve25519. It achieves existential unforgeability under chosen-message attack (EUF-CMA) in the standard model. For security parameter λ = 128, no probabilistic polynomial-time (PPT) adversary achieves forgery with non-negligible advantage.

ACP relies on Ed25519 exclusively for token integrity. No additional signature scheme is required.

### 2.3 JSON Canonicalization Scheme

Token signing covers a deterministically serialized form of the payload using JSON Canonicalization Scheme (JCS, RFC 8785). This ensures that signature coverage is unambiguous regardless of field ordering or whitespace in transit representations.

### 2.4 Related Work

**SPIFFE/SVID:** Provides cryptographic workload identity via X.509 SVIDs but does not model capabilities or delegation at the authorization layer.

**UCAN (User-Controlled Authorization Networks):** A capability delegation model based on JWTs with a chained delegation structure. ACP differs in its formal constraint enforcement, STRIDE analysis, and conformance test suite.

**Macaroons:** Attenuation-based tokens. Attenuation is additive (caveats restrict but do not create new authority). ACP models a complementary approach with explicit capability sets and resource scopes.

**Verifiable Credentials (W3C VC):** Identity assertion framework. ACP is an authorization framework. The two are complementary.

---

## 3. System Model

### 3.1 Principals

Let **A** be a finite set of agents. Each agent `a ∈ A` possesses an asymmetric key pair:

```
(pk_a, sk_a) ← KeyGen(1^λ)
```

Agent identity is bound to key material:

```
AgentID_a = base58(SHA-256(pk_a_bytes))
```

where `pk_a_bytes` are the 32 bytes of the Ed25519 public key. This binding ensures that AgentID is non-transferable without knowledge of `sk_a`.

The system includes three logical roles:

- **Issuer (I):** Holds `sk_I`. Issues and signs Capability Tokens.
- **Subject (S):** Holds `sk_S`. Receives tokens. Must prove possession of `sk_S` during the handshake protocol (ACP-HP-1.0).
- **Verifier (V):** Holds `pk_I`. Verifies token integrity and authorization predicate. Executes or rejects the requested operation.

### 3.2 Resources and Capabilities

Let:

- **R** = set of resources, identified by `<institution_domain>/<resource_path>`.
- **O** = set of operations, identified by qualified strings per ACP-CAP-REG-1.0 (e.g., `acp:cap:financial.payment`).

A **capability** is a pair `c = (o, r) ∈ O × R`.

### 3.3 Adversarial Environment

We assume operation in a partially adversarial network where:

- Network traffic may be observed (passive adversary).
- Messages may be replayed.
- Individual agents may be compromised.
- Institutions are assumed honest unless stated otherwise (§9 discusses issuer compromise).

We do **not** assume:

- Trust in individual agents beyond their key material.
- Availability of a global policy oracle at verification time.
- Synchronized clocks beyond a bounded drift of 300 seconds.

---

## 4. The ACP Protocol

### 4.1 Capability Token Structure

An ACP Capability Token `τ` is a JSON object with the following normative fields:

```json
{
  "ver":         "1.0",
  "iss":         "<AgentID_issuer>",
  "sub":         "<AgentID_subject>",
  "cap":         ["acp:cap:financial.payment"],
  "res":         "org.example/accounts/ACC-001",
  "iat":         1718920000,
  "exp":         1718923600,
  "nonce":       "<128bit_CSPRNG_base64url>",
  "deleg":       { "allowed": false, "max_depth": 0 },
  "parent_hash": null,
  "constraints": {},
  "rev":         { "type": "endpoint", "uri": "https://acp.example.com/acp/v1/rev/check" },
  "sig":         "<base64url_Ed25519_signature>"
}
```

**Field semantics:**

| Field | Type | Description |
|---|---|---|
| `ver` | string | Protocol version. MUST be `"1.0"`. |
| `iss` | AgentID | Issuer. Signs the token with `sk_iss`. |
| `sub` | AgentID | Subject. Must prove possession of `sk_sub` in handshake. |
| `cap` | string[] | Non-empty array of authorized capabilities. |
| `res` | string | Resource identifier to which capabilities apply. |
| `iat` | uint64 | Issuance timestamp (Unix seconds). |
| `exp` | uint64 | Expiration timestamp. MUST be > `iat`. |
| `nonce` | string | 128-bit CSPRNG value, base64url. Single-use. |
| `deleg` | object | Delegation permissions: `allowed` (bool), `max_depth` (int ≥ 0). |
| `parent_hash` | string\|null | null for root tokens; `base64url(SHA-256(JCS(parent_without_sig)))` for delegated. |
| `constraints` | object | Additional capability-specific restrictions. |
| `rev` | object | Revocation endpoint or CRL reference. |
| `sig` | string | Ed25519 signature over JCS(token_without_sig). |

### 4.2 Token Issuance

The issuer constructs the payload `m`:

```
m = JCS({ ver, iss, sub, cap, res, iat, exp, nonce, deleg, parent_hash, constraints, rev })
```

and computes:

```
σ = Sign_{sk_iss}(m)
τ = m ∪ { "sig": base64url(σ) }
```

The nonce MUST be generated by a CSPRNG with at least 128 bits of entropy. The issuer MUST record the nonce to prevent reuse.

### 4.3 Verification Procedure

A verifier V with `pk_iss` executes the following steps **in order**, failing immediately on any violation:

```
1.  Assert τ.ver == "1.0"
2.  Assert Verify_{pk_iss}(JCS(τ_without_sig), σ) = 1
3.  Assert t_now ≤ τ.exp
4.  Assert t_now ≥ τ.iat − 300          (clock drift tolerance)
5.  Assert ¬Revoked(τ) via τ.rev
6.  Assert requested_capability ∈ τ.cap
7.  Assert requested_resource ⊆ τ.res
8.  If τ.parent_hash ≠ null: verify parent chain (§4.4)
9.  Assert constraints satisfied per τ.constraints
```

The verifier MUST maintain a **nonce store** covering all nonces seen within the maximum token TTL window to prevent concurrent replay.

**Authorization predicate:**

```
Auth(τ, o, r, t) = 1  iff  steps 1–9 all pass
```

**Security invariant:**

```
Execute(op) ⇒ Auth(τ, op.capability, op.resource, t_now) = 1
```

No execution occurs without a satisfied authorization predicate.

### 4.4 Delegation Model

When subject `S1` of root token `T0` issues a delegated token `T1` for subject `S2`:

**Mandatory constraints:**

```
cap(T1)       ⊆  cap(T0)            — capability confinement
res(T1)       ⊆  res(T0)            — resource confinement
exp(T1)       ≤  exp(T0)            — temporal confinement
max_depth(T1) =  max_depth(T0) − 1  — depth reduction
parent_hash(T1) = base64url(SHA-256(JCS(T0_without_sig)))
```

**Absolute depth limit:** `max_depth` MUST NOT exceed 8 in any token. This limit is non-configurable.

A delegation chain of length n:

```
T0 → T1 → … → Tn
```

is valid if and only if each link satisfies the above constraints and each token individually satisfies the verification procedure of §4.3.

---

## 5. Formal Security Analysis

### 5.1 Theorem 1: Token Unforgeability

**Theorem.** If Ed25519 is EUF-CMA secure, then no PPT adversary `𝒜` can produce a token `τ*` such that `Auth(τ*, ·, ·, ·) = 1` for an honest issuer that never issued `τ*`, except with negligible probability.

**Proof.** We construct a reduction `ℬ` that uses `𝒜` as a subroutine to break EUF-CMA.

*Setup.* `ℬ` receives public key `pk` from the EUF-CMA challenger and delivers it to `𝒜` as the issuer public key.

*Oracle simulation.* When `𝒜` queries the token issuance oracle on message `m`, `ℬ` forwards `m` to the real EUF-CMA signing oracle and returns the signature. The simulation is perfect.

*Forgery extraction.* If `𝒜` outputs `τ* = (m*, σ*)` with `Verify_{pk}(m*, σ*) = 1` and `m*` was never queried to the oracle, then `ℬ` returns `(m*, σ*)` as a valid EUF-CMA forgery.

*Advantage.* Since the simulation is perfect:

```
Adv_{EUF-CMA}(ℬ) = Adv_{ACP}(𝒜)
```

The reduction is tight. If Ed25519 is EUF-CMA secure, `Adv_{ACP}(𝒜)` is negligible. ∎

### 5.2 Theorem 2: Delegation Confinement

**Theorem.** For any valid delegation chain `T0 → T1 → … → Tn`:

```
cap(Tn) ⊆ cap(T0)    and    res(Tn) ⊆ res(T0)
```

**Proof by induction on chain length n.**

*Base case (n = 1).* Verification enforces `cap(T1) ⊆ cap(T0)` and `res(T1) ⊆ res(T0)` directly. ✓

*Inductive step.* Assume `cap(Ti) ⊆ cap(T0)` for some i. The verification procedure requires `cap(Ti+1) ⊆ cap(Ti)`. By transitivity of ⊆: `cap(Ti+1) ⊆ cap(T0)`. ✓

The same argument applies to `res`. Since `max_depth` decrements by 1 at each step and starts at most 8, the chain is finite. ∎

### 5.3 Theorem 3: Replay Resistance

**Theorem.** If the verifier maintains a nonce store covering the maximum token TTL, nonces are generated with ≥ 128 bits of CSPRNG entropy, and the signature scheme is secure, then replay attack on a presented token succeeds with negligible probability.

**Proof sketch.** A replayed token carries an identical nonce. The nonce store rejects it deterministically within the token's validity window. After expiration, the token fails the `t_now ≤ exp` check. For cross-context replay, the `res` and `cap` fields are cryptographically bound by the issuer's signature; altering them invalidates `σ`. ∎

### 5.4 Theorem 4: Authentic Proof of Possession

During the ACP handshake (ACP-HP-1.0), the verifier issues a fresh challenge `c` with `|c| ≥ 128` bits. The subject must compute:

```
σ_c = Sign_{sk_sub}(c)
```

**Theorem.** No PPT adversary without knowledge of `sk_sub` can produce `σ_c` for a fresh challenge with non-negligible probability, under EUF-CMA security of Ed25519. ∎

### 5.5 Security Reduction Summary

ACP security reduces to:

```
Security(ACP) ≤_T  Security(Ed25519_EUF-CMA)
                 +  Security(SHA-256_collision_resistance)
                 +  Correct implementation
                 +  Secure key management
```

No additional cryptographic assumptions are required.

---

## 6. Adversarial Evaluation

We evaluate ACP against ten attack vectors across four attacker profiles:

| Profile | Capabilities |
|---|---|
| A1 | Malicious legitimate user |
| A2 | Compromised service |
| A3 | Network observer (partial MITM) |
| A4 | Compromised issuer |

### 6.1 Token Forgery (A1, A3)

**Objective:** Produce a valid token without issuer authorization.

**Analysis:** Forgery requires producing `σ*` such that `Verify_{pk_iss}(m*, σ*) = 1` for a previously unsigned `m*`. This reduces to breaking EUF-CMA of Ed25519. Probability ≈ 2^{-128} under standard model.

**Result:** ✅ Secure. Residual risk: weak key management practices.

### 6.2 Replay Attack (A1, A2, A3)

**Scenario A — Reuse within valid window, same context:** Permitted by design. Not a security failure.

**Scenario B — Cross-context reuse:** `res` and `cap` are signed. Altering them invalidates `σ`. A token for resource X cannot be used for resource Y. ✅ Secure.

**Scenario C — Concurrent replay within window:** Requires nonce store at verifier. Without it, two requests with identical nonce can succeed concurrently. **Implementation requirement, not a protocol weakness.**

**Result:** ✅ Secure with correct nonce store implementation.

### 6.3 Privilege Escalation via Token Composition (A1, A2)

**Objective:** Combine two tokens to obtain combined capabilities.

ACP tokens are not composable. Authorization is evaluated per-token. There is no union operation across tokens without issuer intervention.

**Result:** ✅ Escalation impossible without issuer.

### 6.4 Confused Deputy (A2)

**Scenario:** Service A holds token with `sub = AgentID_A`. Service B invokes A to indirectly access resource.

If the verifier validates that the caller's proven identity matches `τ.sub`, B cannot present A's token. This requires the verifier to execute the handshake protocol (ACP-HP-1.0) and validate the proof-of-possession response.

**Result:** ✅ Blocked when subject binding is enforced. ⚠️ Vulnerable if verifier skips handshake.

### 6.5 Context Manipulation (A2, A3)

**Scenario:** Token issued for staging environment is used in production.

`res` includes the resource identifier. If the institution encodes environment in the resource path (e.g., `org.example/staging/resource`), context is cryptographically bound. The verifier evaluates whether the requested resource satisfies the token's `res` field.

**Result:** ✅ Secure when resource identifiers encode environment context.

### 6.6 Policy Downgrade (A1, A2)

**Scenario:** Verifier is forced to accept a token with an older, more permissive `policy_version`.

ACP-TS-1.0 requires verifiers to enforce a minimum supported policy version. Tokens with `policy_version` below the minimum MUST be rejected.

**Result:** ✅ Secure if minimum version enforcement is implemented.

### 6.7 Delegation Privilege Escalation (A1, A2)

**Scenario:** Delegating agent attempts to issue a token with `cap(T1) ⊃ cap(T0)`.

The verification procedure at §4.4 enforces `cap(child) ⊆ cap(parent)`. A delegated token with expanded capabilities fails step 6.

**Result:** ✅ Secure by Theorem 2 (Delegation Confinement).

### 6.8 Issuer Compromise (A4)

**Scenario:** `sk_iss` is obtained by adversary.

A compromised issuer can issue arbitrary tokens for any subject and resource. ACP does not eliminate this risk.

**Mitigations:** Key rotation, HSM storage, threshold signing for high-value issuers, short token TTLs to bound damage window.

**Result:** ⚠️ **Critical single point of failure.** ACP security assumes issuer integrity. This is an acknowledged limitation (§9).

### 6.9 Revocation Latency (A1, A2)

**Scenario:** Compromised token is used before revocation propagates.

ACP uses a push-model revocation endpoint (`τ.rev`). Tokens are valid until expiration or until the verifier queries the revocation endpoint and receives a positive result. Between compromise and revocation query, the token remains valid.

**Mitigations:** Short expiration windows (recommended < 1 hour for sensitive capabilities), online revocation queries per request.

**Trade-off:** Shorter TTL increases issuer load. ACP favors short TTL over long-lived tokens.

**Result:** ⚠️ Revocation is bounded by TTL, not instantaneous.

### 6.10 Lateral Movement (A2)

**Scenario:** A compromised service uses its valid token to access other resources.

A token is scoped to `cap` and `res`. A compromised service can use its token but cannot access resources or capabilities not encoded therein. Lateral movement is bounded by token scope and TTL.

**Result:** ✅ Controllable with minimal-scope token issuance and short TTL.

### Summary

| Attack Vector | Status | Condition |
|---|---|---|
| Token forgery | ✅ Secure | EUF-CMA assumption |
| Replay | ✅ Secure | Nonce store required |
| Privilege escalation via composition | ✅ Secure | Protocol design |
| Confused deputy | ✅ Secure | Subject binding enforced |
| Context manipulation | ✅ Secure | Resource path encodes context |
| Policy downgrade | ✅ Secure | Minimum version enforced |
| Delegation escalation | ✅ Secure | Theorem 2 |
| Issuer compromise | ⚠️ Critical | Acknowledged limitation |
| Revocation latency | ⚠️ Bounded | TTL-limited |
| Lateral movement | ✅ Controllable | Scoped tokens + short TTL |

---

## 7. Comparison with Existing Models

### 7.1 ACP vs. RBAC

| Dimension | RBAC | ACP |
|---|---|---|
| Permission model | Role membership → implicit permission | Explicit signed capability per operation |
| Delegation | Opaque, implementation-dependent | Formally constrained, cryptographically chained |
| Temporal bounds | Typically session-scoped | Per-token, cryptographically enforced |
| Verifiability | Policy lookup required | Local cryptographic verification |
| Privilege accumulation | Structural weakness (role explosion) | Not possible (each operation requires own capability) |
| Formal security reduction | None | EUF-CMA (§5.1) |

### 7.2 ACP vs. Zero Trust

Zero Trust is an architectural philosophy: assume breach, verify explicitly, enforce least privilege. ACP is a concrete enforcement mechanism compatible with Zero Trust principles.

Key difference: Zero Trust policy engines produce authorization decisions but not cryptographic evidence of those decisions. ACP tokens are the evidence itself, verifiable offline by any party with the issuer's public key.

| Dimension | Zero Trust | ACP |
|---|---|---|
| Authorization evidence | Decision (yes/no) | Signed cryptographic artifact |
| Verification | Requires policy engine | Local, stateless |
| Offline capability | No | Yes |
| Inter-institutional | Requires federation | Native (public key sharing) |

### 7.3 ACP vs. OAuth 2.0 / JWT

| Dimension | OAuth 2.0 + JWT | ACP |
|---|---|---|
| Scope granularity | Coarse (string scopes) | Fine-grained (structured capabilities) |
| Resource binding | Optional (`aud` claim) | Mandatory (`res` field) |
| Delegation | Non-standard (no formal model) | Formally defined with confinement proof |
| Formal security model | Not provided in RFC | EUF-CMA reduction (§5) |
| Depth limit | Not defined | 8 hops maximum |
| Conformance testing | No standard test suite | ACP-TS-1.0/1.1 test vectors |

---

## 8. Implementation Considerations

### 8.1 Cryptographic Primitives

- **Signature:** Ed25519 (32-byte public key, 64-byte signature).
- **Hash:** SHA-256.
- **Nonce:** CSPRNG ≥ 128 bits, base64url encoded.
- **Serialization for signing:** JCS (RFC 8785) for deterministic JSON canonicalization.

### 8.2 Nonce Store

The verifier MUST maintain a nonce store covering all nonces seen within the maximum expected token TTL window. For distributed verifiers, the nonce store MUST be consistent (linearizable) to prevent concurrent replay across replicas.

Recommended implementation: In-memory hash set with TTL-based expiry for single-node; distributed cache (e.g., Redis with atomic SETNX) for multi-node deployments.

### 8.3 Revocation

ACP-REV-1.0 defines two revocation mechanisms:

- **Endpoint:** Verifier queries `τ.rev.uri` per request. Correct but adds latency.
- **CRL (Certificate Revocation List):** Periodic download. More performant, bounded staleness equal to CRL refresh interval.

Recommended: Endpoint mode for high-security deployments; CRL with short refresh (< 5 min) for high-throughput.

### 8.4 Clock Drift

ACP allows 300 seconds of clock drift tolerance in `iat` validation. This value SHOULD be adjustable by deployment policy but MUST NOT exceed 600 seconds.

### 8.5 Key Management

Issuer private key is the single most critical security asset. Recommended protections:

- Hardware Security Module (HSM) storage.
- Key rotation schedule ≤ 90 days.
- Separation of signing authority from business logic.

---

## 9. Limitations

**L1 — Centralized Issuer Trust.** ACP v1.x relies on a single issuer per token lineage. Issuer compromise invalidates all derived security guarantees. This is the most significant limitation. (See ACP-D for the decentralized extension targeting this problem in v2.0.)

**L2 — Revocation is Not Instantaneous.** Token validity is bounded by `exp`. Between compromise and token expiration, an attacker with a valid token can continue to use it unless the verifier performs online revocation queries per request.

**L3 — Confidentiality Not Provided.** ACP is an authorization protocol. Confidentiality of token contents depends on transport layer (TLS). ACP does not encrypt token payload.

**L4 — Side-Channel Attacks Out of Scope.** The formal security reduction covers cryptographic forgery. Implementation-level attacks (timing, power analysis, memory inspection) are outside scope.

**L5 — Correct Implementation Required.** Delegation confinement and replay resistance depend on correct verifier implementation. A verifier that skips nonce checking or delegation chain validation cannot rely on ACP's security guarantees.

**L6 — Clock Synchronization Dependency.** `iat`/`exp` enforcement requires approximately synchronized clocks. In environments with severe clock drift, the 300-second tolerance may be insufficient.

---

## 10. Conclusion

ACP provides a formally grounded capability-based authorization architecture for autonomous agent systems. By representing authorization as explicit cryptographic artifacts rather than implicit policy derivations, ACP enables:

1. **Local verification** — no runtime dependency on a central policy engine.
2. **Formal security guarantees** — token unforgeability reduces to EUF-CMA of Ed25519; delegation confinement proven by induction.
3. **Inter-institutional deployment** — public key sharing enables cross-boundary verification without federated sessions.
4. **Auditability** — each authorization decision corresponds to a signed artifact that can be logged and verified post-hoc.

ACP does not eliminate all security risks. Issuer compromise and revocation latency are acknowledged limitations with known mitigation strategies. The decentralized extension ACP-D, targeting v2.0, proposes to address issuer centralization through threshold signing and Byzantine fault-tolerant consensus.

The current ACP v1.x specification includes a conformance test suite (ACP-TS-1.0/1.1) with machine-verifiable test vectors, enabling independent validation of implementations. We invite the research community to review and critique the specification.

---

## References

[1] Bernstein, D.J., Duif, N., Lange, T., Schwabe, P., Yang, B.Y. (2011). *High-Speed High-Security Signatures.* CHES 2011.

[2] Saltzer, J.H., Schroeder, M.D. (1975). *The Protection of Information in Computer Systems.* Proceedings of the IEEE.

[3] Miller, M.S. (2006). *Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control.* PhD Thesis, Johns Hopkins University.

[4] Hardt, D. (2012). *The OAuth 2.0 Authorization Framework.* RFC 6749, IETF.

[5] Rose, S., Borchert, O., Mitchell, S., Connelly, S. (2020). *Zero Trust Architecture.* NIST SP 800-207.

[6] Sporny, M., Longley, D., Sabadello, M. (2022). *Decentralized Identifiers (DIDs) v1.0.* W3C Recommendation.

[7] Hildebrand, A., Rundgren, A. (2020). *JSON Canonicalization Scheme (JCS).* RFC 8785, IETF.

[8] Bradner, S. (1997). *Key Words for Use in RFCs to Indicate Requirement Levels.* RFC 2119, IETF.

[9] Fernandez, M. (2025). *Agent Control Protocol (ACP) Specification v1.x.* TraslaIA. https://github.com/chelof100/acp-framework

---

*© 2025 Marcelo Fernandez / TraslaIA. Draft manuscript — not yet peer reviewed.*
