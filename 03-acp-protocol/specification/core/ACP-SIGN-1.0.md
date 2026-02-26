# ACP-SIGN-1.0
## Serialization and Signing Specification
**Status:** Draft
**Version:** 1.0
**Depends-on:** RFC 8785 (JCS), RFC 8032 (Ed25519)
**Required-by:** ACP-CT-1.0, ACP-REV-1.0, ACP-API-1.0, ACP-LEDGER-1.0, ACP-ITA-1.0

---

## 1. Scope

This document specifies the canonicalization, hashing, and digital signing mechanism for all ACP artifacts. Every document, token, and message that requires a signature in the ACP protocol MUST follow this specification.

---

## 2. Canonicalization

**2.1 Mandatory algorithm**

All serialization for signing MUST use the JSON Canonicalization Scheme (JCS) defined in RFC 8785.

JCS guarantees:
- Deterministic ordering of JSON object keys
- Canonical numeric representation
- Consistent Unicode character escaping
- UTF-8 output without BOM

**2.2 Rationale**

JCS is the only JSON canonicalization standard with verified implementations across multiple languages. It requires no prior schema. It is deterministic across conforming implementations.

**2.3 Reference implementations**

- Python: `jcs` package
- JavaScript/Node: `canonicalize` package
- Go: `go-jose/json`
- Java: `erdtman/java-json-canonicalization`

---

## 3. Signing Procedure

**3.1 Signing an object**

```
Given: JSON object O, private key sk (Ed25519, 32 bytes)

1. Verify that O does not contain field "sig"
2. Serialize: canonical_bytes = JCS(O) in UTF-8
3. Compute digest: h = SHA-256(canonical_bytes)
4. Sign: signature_bytes = Ed25519_Sign(sk, h)  [64 bytes]
5. Encode: sig_value = base64url(signature_bytes) without padding
6. Insert field: O["sig"] = sig_value
7. Return O with sig field
```

**3.2 Signature verification**

```
Given: JSON object O with field "sig", public key pk (Ed25519, 32 bytes)

1. Extract and decode: signature_bytes = base64url_decode(O["sig"])
2. Build O_without_sig = copy of O without field "sig"
3. Serialize: canonical_bytes = JCS(O_without_sig) in UTF-8
4. Compute digest: h = SHA-256(canonical_bytes)
5. Verify: result = Ed25519_Verify(pk, h, signature_bytes)
6. If result == false → reject with SIGN-003
7. Continue with semantic validation only if result == true
```

**3.3 Order of operations**

Signature verification MUST precede all semantic validation. An object with an invalid signature MUST be rejected without processing its content.

---

## 4. Algorithms

**4.1 Hash**

SHA-256 (FIPS 180-4). Output: 32 bytes.

**4.2 Digital signature**

Ed25519 (RFC 8032). Private key: 32 bytes. Public key: 32 bytes. Signature: 64 bytes.

No other signing algorithms are permitted in v1.0.

**4.3 Signature encoding**

base64url without padding (RFC 4648 §5). A 64-byte signature produces exactly 86 base64url characters without padding.

---

## 5. Public Key Identification

**5.1 Derivation from AgentID**

For artifacts signed by agents, the public key is obtained from the agent registry:

```
AgentID → GET /acp/v1/agents/{AgentID} → public_key
```

**5.2 Inline inclusion**

The issuer MAY include the public key in the artifact using the `iss_pk` field:

```json
"iss_pk": "<base64url_ed25519_public_key_32_bytes>"
```

When `iss_pk` is present, the verifier MUST verify that the key matches the one registered for the issuer. It cannot use `iss_pk` as a source of truth without validation.

**5.3 Institutional key**

For artifacts signed by the institutional ACP system (API responses, ledger events), the key is obtained from the ITA per ACP-ITA-1.0.

---

## 6. Test Vectors

**6.1 Input**

```json
{"ver":"1.0","iss":"3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM7Kx3","sub":"4zNBqDrDjYEQscgkXPwumDQUIqGH9HrYQuD2UyRFN8y4","iat":1718920000}
```

**6.2 Expected JCS output**

```
{"iat":1718920000,"iss":"3yMApqCuCjXDWPrbjfR5mjCPTHqFG8Pux1TxQrEM7Kx3","sub":"4zNBqDrDjYEQscgkXPwumDQUIqGH9HrYQuD2UyRFN8y4","ver":"1.0"}
```

Note: JCS sorts keys alphabetically.

**6.3 SHA-256 of JCS output**

```
base64url: <must be computed by implementation and verified against reference vector>
```

Implementations MUST verify their JCS output and hash against these vectors before production use.

---

## 7. Errors

| Code | Condition |
|--------|-----------|
| SIGN-001 | sig field present before signing — object already signed or corrupted |
| SIGN-002 | JCS failed — object contains non-serializable types |
| SIGN-003 | Invalid signature — Ed25519 verification failed |
| SIGN-004 | Public key not found for issuer |
| SIGN-005 | Incorrect signature length — not 64 bytes |
| SIGN-006 | base64url decode failed |
| SIGN-007 | sig field absent in object that requires a signature |

---

## 8. Conformance

An implementation is ACP-SIGN-1.0 conformant if it:

- Uses exact JCS (RFC 8785) for canonicalization
- Uses SHA-256 to hash the canonical output
- Uses Ed25519 (RFC 8032) for signing and verification
- Encodes signatures in base64url without padding
- Verifies signature before any semantic validation
- Rejects objects with invalid signatures without processing content
- Passes the test vectors in section 6
