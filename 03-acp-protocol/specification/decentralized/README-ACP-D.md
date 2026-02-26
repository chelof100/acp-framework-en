# ACP-D — Decentralized Version

**Status:** Complete conceptual design — Planned for v2.0
**Dependency:** Requires a mature ecosystem of DIDs, BLS, and ZK-proofs in production

---

## Why ACP-D exists

ACP v1.0 has a critical risk point: the **Central Issuer** (ITA — Institutional Trust Anchor).

If the issuer's root key is compromised, the entire cryptographic authority of the system collapses. The adversarial analysis of v1.0 explicitly identifies this as the only attack vector that cannot be mitigated within the centralized model.

ACP-D eliminates that single point of failure.

---

## Fundamental differences from ACP v1.0

| Aspect | ACP v1.0 (centralized) | ACP-D (decentralized) |
|---|---|---|
| **Identity** | `AgentID = base58(SHA-256(pk))` | DID — Decentralized Identifiers |
| **Credentials** | Capability Token signed by issuer | Verifiable Credentials (VC) |
| **Token issuance** | Central issuer (ITA with HSM) | Distributed quorum (BFT) |
| **Signature** | Individual Ed25519 | BLS12-381 threshold or aggregated Multi-Ed25519 |
| **Proof of possession** | Challenge + Ed25519 signature | zk-SNARK / zk-STARK / Bulletproofs |
| **Revocation** | Centralized CRL + online endpoint | Merkle non-inclusion tree |
| **Root of trust** | Root Institutional Key (RIK) in HSM | No issuer — distributed authority |
| **Fault tolerance** | Depends on issuer availability | BFT: resists compromise of < 1/3 of nodes |

---

## ACP-D Architecture

### Roles

| Role | Function |
|---|---|
| **Subject** | Agent requesting authorization |
| **Resource Server / Verifier** | System that receives and verifies the token |
| **Authority Set** | Set of nodes that issue tokens by quorum |
| **Revocation Network** | Distributed revocation network |

### Quorum requirement

```
Total nodes:       n ≥ 3f + 1
Required signatures: t ≥ 2f + 1
```

Where `f` is the number of Byzantine nodes tolerated.

Minimum safe example: n=4 nodes, t=3 signatures, tolerates f=1 compromised node.

### ACP-D token structure

```json
{
  "header": {
    "alg": "BLS12-381-threshold",
    "typ": "ACP-D-TOKEN",
    "ver": "2.0"
  },
  "capability_claim": {
    "sub": "did:acp:org:agent-001",
    "cap": ["acp:cap:financial.read"],
    "res": ["payments/*"],
    "iat": 1700000000,
    "exp": 1700003600,
    "nonce": "<128-bit CSPRNG>"
  },
  "zk_proof": "<possession proof without revealing private key>",
  "multi_signature": "<t-of-n threshold signature of the Authority Set>"
}
```

---

## ACP-D authorization flow

```
1. Subject requests token from Authority Set
2. Subject generates zk_proof of possession of valid credential
3. Subject collects quorum signatures (≥ t nodes)
4. Subject presents ACP-D-Token to Resource Server
5. Resource Server verifies:
   ├── valid multi_signature (≥ t signatures from known nodes)
   ├── valid zk_proof (without revealing credentials)
   ├── Token not expired
   ├── Non-inclusion in Merkle revocation tree
   └── Capability and resource within declared scope
```

---

## Alternative model: Self-Sovereign Capability

For cases where no Authority Set is available, ACP-D defines an alternative model where the token is a direct ZK proof:

```
cap_token = ZK-Proof(
    "I hold a valid verifiable credential"
    ∧ "that credential grants me capability X"
    ∧ "it is not revoked"
)
```

The Verifier validates the proof without needing to communicate with any issuer.

---

## Required cryptographic primitives

| Component | Primitive | Maturity status (2026) |
|---|---|---|
| Threshold signatures | BLS12-381 | Mature in Ethereum ecosystem |
| ZK possession proofs | zk-SNARK (Groth16) / Bulletproofs | Mature in production |
| ZK non-revocation proofs | Merkle non-inclusion proof | Standard |
| Decentralized identities | W3C DID spec | Approved standard |
| Verifiable credentials | W3C VC Data Model | Approved standard |

---

## Security properties

| Property | Guarantee |
|---|---|
| **Token forgery** | Impossible without compromising ≥ t nodes of the Authority Set |
| **Replay attacks** | Unique nonce + temporal window |
| **Privilege escalation** | Formal confinement — `cap_delegated ⊆ cap_original` |
| **Partial collusion** | Resistant up to f = ⌊(n-1)/3⌋ compromised nodes |
| **Agent privacy** | ZK-proof does not reveal credentials, only possession |
| **Single issuer compromised** | Not applicable — there is no single issuer |

---

## Why ACP-D is v2.0 and not v1.1

ACP-D is not an incremental extension. It is a trust model change:

1. **Operational complexity:** Organizations need to operate a set of Authority Set nodes coordinated with BFT.
2. **ZK-proof overhead:** Proof generation has a non-trivial computational cost.
3. **Required ecosystem:** Requires DID and VC infrastructure that is not yet standard in enterprise environments.
4. **Adoption:** ACP v1.0 is already implementable today with standard cryptography (Ed25519, SHA-256, TLS 1.3).

ACP-D is the correct long-term direction. ACP v1.0 is the adoption path today.

---

## Documents

| Document | Content |
|---|---|
| [ACP-D-Specification.md](ACP-D-Specification.md) | Complete normative technical specification |
| [Architecture-Without-Central-Issuer.md](Architecture-Without-Central-Issuer.md) | DID + VC + Self-Sovereign Capability model |

---

*TraslaIA — Marcelo Fernandez — 2026*
