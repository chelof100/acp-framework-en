# Contributing to ACP — Agent Control Protocol

Thank you for your interest in contributing to ACP.

ACP is a **cryptographic authorization protocol** for autonomous AI agents. Changes to the specification have security implications for every implementation. For this reason, we use a **formal RFC process** for all normative changes.

---

## Types of Contributions

| Type | Process |
|---|---|
| Normative change (spec, formal model, cryptographic design) | RFC required |
| New extension or layer | RFC required |
| Non-normative fix (typo, example clarification, formatting) | Pull Request |
| Test vector addition or correction | Pull Request |
| Translation | Pull Request |
| Security vulnerability | See [SECURITY.md](SECURITY.md) — do NOT open a public issue |

---

## RFC Process — Normative Changes

All changes to documents under `03-acp-protocol/specification/`, `04-formal-analysis/`, and the formal security model require an RFC.

### RFC Lifecycle

```
Draft → Review → Last Call → Accepted → Final
           ↓
        Rejected
```

| Status | Meaning |
|---|---|
| **Draft** | Author is working on the proposal — not yet open for review |
| **Review** | Open for community feedback — anyone can comment |
| **Last Call** | Final 14-day window — no new issues, only show-stoppers |
| **Accepted** | Approved — will be incorporated in the next spec release |
| **Rejected** | Not accepted — reason recorded in the RFC document |
| **Final** | Incorporated into the published specification |

### How to Submit an RFC

1. **Open a GitHub Issue** using the RFC template (`New RFC Proposal`)
   - Describe the problem you're solving
   - Identify which specification documents are affected
   - Assess security impact (none / low / medium / high / critical)

2. **Wait for acknowledgement** — a maintainer will assign an RFC number (`ACP-RFC-NNN`) within 10 business days

3. **Write the RFC document** following the template in [`.github/RFC-TEMPLATE.md`](.github/RFC-TEMPLATE.md)
   - File path: `rfcs/ACP-RFC-NNN-short-title.md`
   - Status: `Draft`

4. **Open a Pull Request** targeting the `rfcs/` directory
   - Do not modify spec documents yet — the RFC must be accepted first

5. **Review period** — at least 21 days in `Review` status before moving to Last Call
   - For changes affecting `ACP-SIGN-1.0`, `ACP-CT-1.0`, or `ACP-ITA-*.md`: minimum 45 days

6. **Last Call** — 14-day final window
   - If no blocking objections: RFC moves to `Accepted`
   - If blocking issue found: RFC returns to `Review`

7. **Incorporate changes** — once `Accepted`, open a separate PR modifying the spec document(s)

### RFC Numbering

RFCs are assigned sequential numbers: `ACP-RFC-001`, `ACP-RFC-002`, etc.
Numbers are assigned by maintainers — do not self-assign.

### RFC Security Review

Any RFC with security impact **medium or higher** must include:
- Threat analysis: how could this change be exploited?
- Formal property impact: does this preserve unforgeability, confinement, replay resistance?
- Migration path: how do existing implementations remain compatible?

---

## Pull Request Process — Non-Normative Changes

For typos, examples, formatting, non-normative documentation, and test vectors:

1. Fork the repository
2. Create a branch: `fix/description` or `docs/description`
3. Make your changes
4. Verify your changes do not modify normative language (MUST, SHALL, MUST NOT, SHOULD)
5. Open a Pull Request with a clear description

PRs for non-normative changes are reviewed within 15 business days.

---

## Test Vectors

Test vectors live in `03-acp-protocol/test-vectors/` and follow the schema defined in [`03-acp-protocol/compliance/ACP-TS-SCHEMA-1.0.md`](03-acp-protocol/compliance/ACP-TS-SCHEMA-1.0.md).

To contribute a test vector:
- Ensure it follows `ACP-TS-1.1` format (deterministic, language-agnostic JSON)
- Include `meta`, `input`, `context`, and `expected` sections
- Verify it validates against `ACP-TS-SCHEMA-1.0`
- Name it following the pattern: `TS-{LAYER}-{NN}-{description}.json`

---

## Normative Language

ACP specifications use RFC 2119 keywords:

- **MUST** / **SHALL** — absolute requirement
- **MUST NOT** / **SHALL NOT** — absolute prohibition
- **SHOULD** — recommended, deviation must be documented
- **MAY** — optional

When proposing changes, be precise about which level of obligation applies.

---

## Commit Message Format

```
type(scope): short description

Types: feat, fix, docs, spec, rfc, test, chore
Scope: sign, ct, cap-reg, hp, ita, rep, pay, dcma, conf, ts, cert, readme
```

Examples:
```
spec(ct): clarify nonce validation window in ACP-CT-1.0
rfc(sign): add ACP-RFC-001 proposal for Ed448 support
test(core): add TS-CORE-NEG-008 for empty capability set
docs(readme): update conformance level table
```

---

## Questions

For general questions about the protocol, open a GitHub Discussion.
For security issues, see [SECURITY.md](SECURITY.md).
For everything else: info@traslaia.com

---

*Maintained by Marcelo Fernandez — TraslaIA*
