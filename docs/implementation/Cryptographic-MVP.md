## Objective

Build a minimal operative version of the ACP system that enables:

- Capability Token issuance
- Cryptographic verification
- Contextual validation
- Basic revocation
- Replay prevention

Without dependency on complex infrastructure.

## 1.1 MVP Components

### A. Issuer

Service that:

- Generates Ed25519 key
- Issues signed tokens
- Assigns:
  - subject_id
  - capability_set
  - constraints
  - expiry
  - nonce

### B. Verifier

Service that:

- Verifies signature
- Verifies expiry
- Verifies nonce
- Evaluates constraints
- Queries revocation list

### C. Revocation Store

Simple implementation:

- Hash list of revoked token_id values
- Optional: Bloom filter for efficiency

## 1.2 Token Specification (MVP)

Canonical JSON serialized format:

```json
{
  "iss": "did:acp:issuer01",
  "sub": "did:acp:user123",
  "iat": 1730000000,
  "exp": 1730003600,
  "nonce": "b64_random_128bit",
  "cap": [
    {
      "resource": "db.customer",
      "action": ["read"],
      "constraints": {
        "ip_range": "10.0.0.0/24",
        "mfa": true
      }
    }
  ]
}
```

Signed with:

```
Ed25519
signature = Sign(sk_issuer, hash(canonical_token))
```

## 1.3 Operational Flow

### Issuance

1. Authenticated client
2. Issuer builds payload
3. Signs
4. Returns signed token

### Access

1. Client presents token
2. Verifier:
   - Verifies signature
   - Verifies exp
   - Verifies nonce not used
   - Evaluates constraints
   - Verifies not revoked
3. If all valid → access granted

## 1.4 Reference Code (Pseudo)

### Signing

```python
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder

sk = SigningKey.generate()
signed = sk.sign(token_bytes)
```

### Verification

```python
from nacl.signing import VerifyKey

vk = VerifyKey(pubkey_bytes)
vk.verify(signed_token)
```

## 1.5 MVP Security

Protects against:

- Forgery
- Replay (with nonce store)
- Privilege escalation
- Token forging
- Token tampering

Does not yet protect against:

- Malicious issuer
- Private key compromise
- Verifier collusion
