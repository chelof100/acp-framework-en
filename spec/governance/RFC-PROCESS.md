# RFC-PROCESS — ACP RFC Process

| Field | Value |
|---|---|
| **Status** | Normative |
| **Version** | 1.0 |
| **Type** | Process Document |
| **Scope** | ACP v1.x change management |
| **Date** | 2026-03-10 |

---

## 1. Purpose

This document defines the formal process for proposing, reviewing, and approving changes to ACP (Agent Control Protocol) specifications.

All normative or informational changes to the ACP v1.x specification body must follow this process. Minor editorial corrections (typos, formatting) may be applied directly by the Editor without requiring a full RFC.

This process ensures that changes receive technical review, that affected parties have the opportunity to participate, and that the decision history is documented in RFC-REGISTRY.md.

---

## 2. RFC Types

### (a) Informational

Does not introduce normative changes to any existing specification. May document best practices, analyses, implementation guides, or design proposals that do not require modifying normative text.

- Does not trigger a version bump in any document.
- Does not require Council vote.
- Requires 2 Reviewer approvals.

### (b) Protocol

Introduces normative changes to an existing specification. May add, modify, or remove behaviors, fields, or requirements in already-published documents.

- May be Breaking or Non-Breaking (see §8).
- Requires 2 Reviewer approvals.
- May escalate to Council vote if consensus is not reached (see §7).

### (c) Extension

Proposes a new specification document not previously part of the ACP normative body. Adds capability to the protocol without directly modifying existing documents, though it may require other documents to reference it.

- Always triggers a minor version bump (see §9).
- Requires 2 Reviewer approvals.
- May escalate to Council vote.

---

## 3. RFC Lifecycle

```
Draft → Review → Accepted
                → Rejected

(if Accepted) → Implemented → Stable
```

| State | Description |
|---|---|
| **Draft** | The Author is writing the RFC. Not yet in formal review. |
| **Review** | The RFC has been submitted for review. The review window is open. |
| **Accepted** | The RFC has received the required approvals or was approved by the Council. |
| **Rejected** | The RFC was rejected via NACK with technical justification, or by Council vote. |
| **Implemented** | The accepted RFC has been incorporated into the specification documents. |
| **Stable** | The implemented RFC has passed an observation period without objections. |

A Rejected RFC may be re-submitted as a new Draft with a new `rfc_id` if the Author addresses the objections raised.

---

## 4. RFC Document Format

Every RFC must be submitted as a Markdown document with the following header fields and sections:

```
rfc_id: RFC-XXXX
title: Descriptive title of the proposed change
type: Informational | Protocol | Extension
author: Name or alias of the author
date: YYYY-MM-DD
```

### Required Sections

| Section | Description |
|---|---|
| **Abstract** | One or two sentence summary of the RFC |
| **Motivation** | Why this change is needed; the problem it solves |
| **Specification** | Precise technical description of the proposed change |
| **Backwards Compatibility** | Impact on existing implementations; whether it is Breaking (see §8) |
| **Security Considerations** | Analysis of the security implications of the change |

Additional sections (Examples, Alternatives Considered, References) are optional but welcome.

---

## 5. Roles

### (a) Author

The person or group who writes and proposes the RFC. Responsible for:
- Keeping the document updated during review.
- Responding to technical comments from Reviewers.
- Deciding whether to withdraw the RFC (transition to Rejected) if objections cannot be resolved.

### (b) Reviewer

Participates in the technical review of the RFC. A minimum of **2 Reviewers** are required per RFC. Their responsibilities:
- Review the proposal within the review window.
- Issue approval (LGTM / ACK) or technical rejection (NACK) with justification.
- A Reviewer may change their vote during the review window.

### (c) Editor

Responsible for the integrity of the ACP specification body. Their responsibilities:
- Verify that the RFC meets the required format before opening review.
- Merge the RFC and apply changes to affected documents once Accepted.
- Update RFC-REGISTRY.md with the outcome.
- Apply minor editorial corrections without an RFC.

### (d) Council

Governance body that votes on controversial RFCs where Reviewers cannot reach consensus. See §7 for voting rules.

---

## 6. Review Process

1. The Author submits the RFC to the Editor with the document in §4 format.
2. The Editor verifies the format and assigns an `rfc_id`. If the format does not comply, it is returned to the Author for correction.
3. The Editor opens formal review: the RFC enters the **Review** state.
4. The **minimum review window is 2 weeks** (14 calendar days) from opening.
5. During the window, any Reviewer may:
   - Issue **ACK** (approval) with or without comments.
   - Issue **NACK** (rejection) with mandatory technical justification.
   - Request changes without issuing a final verdict yet.
6. At the close of the window:
   - **2 or more ACK and 0 NACK** → RFC transitions to **Accepted**.
   - **1 or more NACK** → the Author may respond and reopen discussion, or escalate to the Council (§7).
   - **Fewer than 2 ACK** → the window may be extended at the Editor's discretion, or the RFC transitions to Rejected for lack of review.
7. A NACK without technical justification may be dismissed by the Editor, who must document the reason.

---

## 7. Voting

The Council votes only when Reviewers cannot reach consensus and at least one of the following conditions is met:

- There are 1 or more active NACKs at the close of the review window.
- The RFC modifies elements listed in §8 (Breaking changes).
- The Author explicitly requests escalation to the Council.

### Voting Rules

| Parameter | Value |
|---|---|
| **Minimum quorum** | 3 Council members |
| **Required majority** | Simple majority (more than half of votes cast) |
| **Tie** | RFC transitions to Rejected (a tie is not an approval) |
| **Deadline** | The Council has 2 additional weeks to vote |

Council votes are final. An RFC rejected by the Council may not be reintroduced until the objections documented in the vote record have been addressed.

---

## 8. Breaking Changes

A change is classified as **Breaking** if it modifies any of the following:

- **LEDGER event schemas**: adding required fields, renaming fields, removing fields, or changing types in events defined in ACP-LEDGER-1.x.
- **Capability token format**: changes to required claims, signature algorithm, or token structure as defined in ACP-CONF-1.x.
- **Error codes**: renaming, removing, or changing the meaning of existing error codes (prefixes ACP-NNN, PAY-NNN, etc.).

### Additional Requirements for Breaking Changes

1. The RFC must explicitly classify the change as Breaking in the Backwards Compatibility section.
2. The review window is extended to **6 weeks** (42 calendar days) instead of 2.
3. A **version bump** is required in all affected documents (see §9).
4. The Editor must notify known implementors when opening the review.

---

## 9. Versioning Impact

ACP specification documents follow the `MAJOR.MINOR.PATCH` versioning scheme.

| RFC Type | Version Impact |
|---|---|
| **Informational** | No version change in any document |
| **Protocol — Non-Breaking** | Patch version bump (`X.Y.Z` → `X.Y.Z+1`) in affected documents |
| **Protocol — Breaking** | Minor version bump (`X.Y.Z` → `X.Y+1.0`) in affected documents |
| **Extension** | Minor version bump in the ACP normative body; new document at version `1.0` |

A major version bump (`X.0.0`) requires a special Breaking Protocol RFC that explicitly justifies it, with mandatory Council approval regardless of the outcome of the standard review.

---

## 10. RFC Registry

All RFCs, regardless of their final state, must be registered in:

**`RFC-REGISTRY.md`** — located in the same directory as this document.

The registry includes the following fields for each RFC:

| Field | Description |
|---|---|
| `rfc_id` | Unique identifier assigned by the Editor |
| `title` | RFC title |
| `type` | Informational / Protocol / Extension |
| `author` | Author or authors |
| `date_opened` | Date the review was opened |
| `date_closed` | Date of closure (Accepted / Rejected) |
| `status` | Final state |
| `breaking` | Yes / No |
| `version_impact` | Affected documents and versions |
| `link` | Path to the RFC document |

The Editor is responsible for keeping RFC-REGISTRY.md up to date. No RFC may transition to Implemented without being registered.
