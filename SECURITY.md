# Security Policy — ACP (Agent Control Protocol)

## Scope

This policy covers security vulnerabilities in the **ACP specification** itself — including cryptographic design flaws, protocol weaknesses, ambiguities that could lead to insecure implementations, and errors in the formal security model.

This policy does **not** cover vulnerabilities in third-party implementations of ACP. For those, contact the respective maintainer directly.

---

## Supported Versions

| Version | Status          | Security fixes |
|---------|-----------------|----------------|
| 1.2.x   | Current         | ✅ Yes          |
| 1.1.x   | Maintenance     | ✅ Critical only |
| 1.0.x   | End of life     | ❌ No           |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Send your report to:

**security contact:** info@traslaia.com
**subject line:** `[ACP SECURITY] <brief description>`

Include in your report:
- Description of the vulnerability
- Which specification document(s) are affected (e.g., `ACP-SIGN-1.0`, `ACP-CT-1.0`)
- Potential impact if the flaw is exploited in an implementation
- Suggested fix or mitigation, if you have one
- Whether you plan to publish the finding (and when)

---

## Response Timeline

| Milestone                          | Target time         |
|------------------------------------|---------------------|
| Acknowledgement of receipt         | Within 5 business days |
| Initial assessment                 | Within 15 business days |
| Fix or mitigation published        | Within 90 days of receipt |
| Public disclosure (coordinated)    | After fix is published, or at 90-day deadline |

We follow a **90-day coordinated disclosure policy**, aligned with industry standard (Google Project Zero). If a fix requires more time due to complexity, we will communicate proactively and coordinate disclosure with the reporter.

---

## What Qualifies as a Vulnerability

Examples of in-scope issues:

- **Cryptographic flaws**: weaknesses in the Ed25519 usage, JCS canonicalization, or nonce handling defined in `ACP-SIGN-1.0`
- **Token forgery**: design flaws in `ACP-CT-1.0` that could allow crafting valid Capability Tokens without a legitimate issuer
- **Privilege escalation**: gaps in `ACP-DCMA-1.0` delegation constraints that allow a delegatee to exceed delegated capabilities
- **Replay attacks**: timing or specification ambiguities in `ACP-EXEC-1.0` or anti-replay mechanisms
- **Revocation bypass**: weaknesses in `ACP-REV-1.0` that allow revoked tokens to be accepted
- **BFT threshold vulnerabilities**: flaws in `ACP-ITA-1.1` quorum logic (n ≥ 3f+1, t ≥ 2f+1)
- **Formal model inconsistencies**: contradictions between the security proofs and the normative specification

Out of scope: typos, minor inconsistencies in non-normative documentation, feature requests.

---

## Attribution

We will credit security researchers in the relevant specification errata or changelog entry, unless you prefer to remain anonymous.

---

## Contact

**Marcelo Fernandez — TraslaIA**
info@traslaia.com
www.traslaia.com
