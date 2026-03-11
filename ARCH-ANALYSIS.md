# ACP — System Architect Analysis
**Date:** 2026-03-11
**Scope:** `chelof100/acp-framework-en` — full specification tree
**Analyst:** Claude Sonnet 4.5 (system architect pass)
**Focus:** Protocol integrity · Governance logic · Auditability

---

## 1. Architecture Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — Sovereign AI Architecture  (01-sovereign-architecture/)       │
│  Doctrine: Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧             │
│            ValidDelegationChain ∧ AcceptableRisk                         │
│  Files: 3  │  Not protocol specs — philosophical grounding               │
└─────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 2 — GAT Model  (02-gat-model/)                                   │
│  Reference: AGS 8-layer stack, 3-layer architecture, maturity model,     │
│             roadmap. Positions every spec in the full system.            │
│  Files: 6  (incl. 1 stale planning artifact — see §3.I-9)               │
└─────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 3 — ACP Protocol  (03-acp-protocol/)                              │
│                                                                          │
│  3A CORE (7 specs)            3B OPERATIONS (13 specs)                  │
│  ─────────────────            ───────────────────────                   │
│  SIGN-1.0 ←── crypto base     EXEC-1.0                                  │
│  CT-1.0   ←── cap tokens      LEDGER-1.2 ←── central audit primitive    │
│  CAP-REG  ←── namespace       LIA-1.0                                   │
│  HP-1.0   ←── PoP             PSN-1.0                                   │
│  MESSAGES ←── wire format     HIST-1.0                                  │
│  AGENT    ←── data model      API-1.0                                   │
│  DCMA     ←── delegation      RISK-1.0 (misplaced — see §3.I-3)        │
│                               DISC, BULK, NOTIFY, PAY, PSN-EXPORT       │
│                               CROSS-ORG-1.0 [NEW]                       │
│                                                                          │
│  3C SECURITY (6 specs)        3D GOVERNANCE (5 specs)                   │
│  ──────────────────           ──────────────────────                    │
│  ITA-1.0, ITA-1.1             CONF-1.0 (deprecated)                     │
│  REV-1.0                      CONF-1.1 ←── normative conformance        │
│  REP-1.1 (deprecated)         ACR-1.0, RFC-PROCESS, RFC-REGISTRY        │
│  REP-1.2 ←── stable           (+ ACP-TS-1.1 duplicate — see §3.I-8)    │
│  REP-PORTABILITY-1.0 [NEW]                                              │
│                                                                          │
│  3E COMPLIANCE (5 specs)      3F DECENTRALIZED (3 docs)                 │
│  ─────────────────            ──────────────────                        │
│  TS-1.0 (superseded)          ACP-D-Specification (v2.0 proposed)       │
│  TS-1.1, TS-SCHEMA-1.0        Arch-Without-Central-Issuer               │
│  IUT-PROTOCOL-1.0             README-ACP-D                              │
│  CERT-1.0                                                               │
└─────────────────────────────────────────────────────────────────────────┘
                             │
               ┌─────────────┼──────────────┐
               ▼             ▼              ▼
         LAYER 4           LAYER 5       LAYER 6
    Formal Analysis     Implementation  Publications
    (8 docs — proofs,   (acp-go,       (Whitepaper,
    threat models,       py-sdk,        Academic,
    reduction proofs)    ts-sdk)        IEEE-NDSS)
```

### 1.1 Execution Request Lifecycle

```
Agent → POST /acp/v1/authorize
  │
  ├─ 1. CT verification          (ACP-CT-1.0 + ACP-HP-1.0)
  ├─ 2. Delegation chain check   (ACP-DCMA-1.0)
  ├─ 3. Revocation check         (ACP-REV-1.0)
  ├─ 4. Risk evaluation          (ACP-RISK-1.0) → RISK_EVALUATION event
  ├─ 5. Decision                 → AUTHORIZATION event (ACP-LEDGER-1.2)
  │
  ├─ [PERMIT] → Execution Token issued  (ACP-EXEC-1.0) → ET_ISSUED event
  │               │
  │               ▼
  │    Target System: ET consumed       → ET_CONSUMED event
  │               │
  │               ├─ LIABILITY_RECORD   (ACP-LIA-1.0)
  │               └─ REPUTATION_UPDATED (ACP-REP-1.2)
  │
  ├─ [ESCALATE] → ESCALATION_CREATED event
  └─ [DENY]     → AUTHORIZATION(DENIED) event
```

### 1.2 Conformance Hierarchy (as declared in CONF-1.1)

| Level | Label | Specified Components |
|-------|-------|----------------------|
| L1 | CORE | SIGN + CT + CAP-REG + HP |
| L2 | SECURITY | L1 + RISK + REV + ITA-1.0 |
| L3 | FULL | L2 + API + EXEC + LEDGER |
| L4 | EXTENDED | L3 + PAY + REP + ITA-1.1 |
| L5 | DECENTRALIZED | L4 + ACP-D + ITA-1.1 BFT |

---

## 2. Main Modules — Responsibility Summary

| Module | Tier | Role in System |
|--------|------|---------------|
| **ACP-SIGN-1.0** | Core/Primitive | Cryptographic base. Ed25519 + JCS. Every signed artifact traces here. |
| **ACP-CT-1.0** | Core/Auth | Primary authorization artifact. Carries who, what, on what, until when. |
| **ACP-CAP-REG-1.0** | Core/Namespace | Canonical namespace for capability IDs. Prevents collision, enforces domains. |
| **ACP-HP-1.0** | Core/Security | Proof-of-Possession on every request. Renders stolen CTs non-functional. |
| **ACP-MESSAGES-1.0** | Core/Wire | Standard envelope for all ACP messages. Anti-replay via nonce + message_id. |
| **ACP-AGENT-1.0** | Core/Identity | Agent data model. AgentID derivation. State machine. Autonomy levels. |
| **ACP-DCMA-1.0** | Core/Delegation | Formal delegation chain model. No-escalation invariant. Transitive revocation. |
| **ACP-RISK-1.0** | Security/Decision | Deterministic risk scoring. Four-factor formula. Auditable via LEDGER. |
| **ACP-ITA-1.0** | Security/Trust | Centralized institutional key registry. Basis for cross-institutional trust. |
| **ACP-ITA-1.1** | Security/Federation | Bilateral federated trust. Non-transitive (1-hop). BFT quorum for consensus. |
| **ACP-REV-1.0** | Security/Lifecycle | Token + agent revocation. Transitive (parent revocation invalidates descendants). |
| **ACP-REP-1.2** | Security/Reputation | Dual-score model (ITS + ERS). Decay. Bootstrap. Composite: 0.6·ITS + 0.4·ERS. |
| **ACP-EXEC-1.0** | Operations/Execution | Single-use execution proof. Decouples authorization from target system. |
| **ACP-LEDGER-1.2** | Operations/Audit | Append-only, hash-chained event store. 14 event types. Core auditability. |
| **ACP-LIA-1.0** | Operations/Liability | Materializes legal responsibility per execution. Enables "bankability". |
| **ACP-PSN-1.0** | Operations/Policy | Immutable policy snapshots. Enables retrospective policy reconstruction. |
| **ACP-HIST-1.0** | Operations/Query | Ledger query layer + signed ExportBundle for cross-institutional audit sharing. |
| **ACP-API-1.0** | Operations/Integration | Complete HTTP surface. The integration contract for ACP node implementors. |
| **ACP-CONF-1.1** | Governance | 5-level cumulative conformance framework. Authoritative implementation requirement. |
| **ACP-CROSS-ORG-1.0** | Operations/Federation | Bilateral cross-org audit trail. Closes asymmetric ledger problem. L4. |
| **ACP-REP-PORTABILITY-1.0** | Security/Federation | Signed reputation transport between institutions. Score ceiling 0.85. L4. |

---

## 3. Inconsistencies

Inconsistencies are classified as:
- 🔴 **CRITICAL** — Protocol integrity or governance correctness is broken
- 🟠 **MAJOR** — Dependency graph or conformance logic is incorrect
- 🟡 **MINOR** — Documentation gap, stale reference, or file hygiene

---

### I-1 🔴 Circular Dependency: LEDGER-1.2 ↔ LIA-1.0 ↔ PSN-1.0

**What the headers say:**

```
ACP-LEDGER-1.2   Depends-on: ..., ACP-LIA-1.0, ACP-PSN-1.0
ACP-LIA-1.0      Depends-on: ACP-EXEC-1.0, ACP-LEDGER-1.2, ...
ACP-PSN-1.0      Depends-on: ACP-RISK-1.0, ACP-SIGN-1.0, ACP-LEDGER-1.2
```

LEDGER depends on LIA and PSN; LIA and PSN both depend on LEDGER. This is a true circular dependency in the header metadata.

**Root cause:** LEDGER-1.2 defines the `LIABILITY_RECORD` and `POLICY_SNAPSHOT_CREATED` event types *on behalf of* LIA and PSN — they were added in v1.1 of the LEDGER. The actual semantic relationship is one-directional: LIA and PSN *emit* events *into* LEDGER. LEDGER does not call into LIA or PSN.

**Required fix:** Remove `ACP-LIA-1.0` and `ACP-PSN-1.0` from LEDGER-1.2's `Depends-on`. Add a `Consumers:` or `Emitters:` field to document the reverse relationship without creating a formal dependency. LEDGER is the sink; LIA and PSN are emitters.

---

### I-2 🔴 CROSS_ORG_INTERACTION and REPUTATION_ATTESTATION_* Not Registered in LEDGER-1.2

ACP-LEDGER-1.2 defines exactly 14 event types (§5.1–§5.14). Two new specifications introduce additional event types:

- **ACP-CROSS-ORG-1.0** introduces: `CROSS_ORG_INTERACTION`
- **ACP-REP-PORTABILITY-1.0** introduces: `REPUTATION_ATTESTATION_ISSUED`, `REPUTATION_ATTESTATION_RECEIVED`

None of these appear in LEDGER-1.2's event type registry, schema definitions, or conformance requirements. This means:

1. A LEDGER-1.2 conformant implementation has no normative schema to validate these events against.
2. The hash-chain integrity spec is silent on how to handle them.
3. There is no `Required-by` link from LEDGER to the new specs.

**Required fix:** Issue **ACP-LEDGER-1.3** adding §5.15, §5.16, §5.17 for the three new event types. Until then, the new specs reference an event store that doesn't formally know they exist.

---

### I-3 🔴 CONF-1.1 L4 References ACP-REP-1.1 (Deprecated)

CONF-1.1 §7.2 explicitly states:

> **7.2 Reputation Extension (ACP-REP-1.1)**
> The implementation MUST: Maintain ReputationScore ∈ [0,1] per agent...

ACP-REP-1.1 is marked:

> ⚠️ **DEPRECATED** — Superseded by **ACP-REP-1.2**

An L4 conformant implementation following CONF-1.1 literally would implement the deprecated spec, missing ERS, Dual Trust Bootstrap, and Reputation Decay. CONF-1.1 must be updated to reference ACP-REP-1.2 at L4.

---

### I-4 🔴 CROSS-ORG-1.0 and REP-PORTABILITY-1.0 Absent from CONF-1.1 L4

Both new specs declare in their headers:

```
**Implements:** ACP-CONF-1.1 Conformance Level L4
```

But CONF-1.1's Level table defines L4 as:

```
L4 | EXTENDED | L3 + PAY + REP + ITA-1.1
```

No mention of CROSS-ORG or REP-PORTABILITY. An implementor reading CONF-1.1 has no obligation to implement these specs to claim L4 conformance. The specs claim L4 status unilaterally, but the normative conformance document doesn't back them.

**Required fix:** Update CONF-1.1 L4 definition to: `L3 + PAY + REP-1.2 + ITA-1.1 + CROSS-ORG-1.0 + REP-PORTABILITY-1.0`

---

### I-5 🟠 CONF-1.1 Level Table Omits MESSAGES, AGENT, DCMA from L1

The Level table says:

```
L1 | CORE | SIGN + CT + CAP-REG + HP
```

But CONF-1.1's own `Depends-on` header lists `ACP-MESSAGES-1.0, ACP-DCMA-1.0`, and the SPEC-INDEX indexes AGENT, MESSAGES, and DCMA as L1-CORE specs. The normative Level table is incomplete — it omits three required specs from the definition of L1 conformance.

**Required fix:** L1 table row should read: `SIGN + CT + CAP-REG + HP + MESSAGES + AGENT + DCMA`

---

### I-6 🟠 DCMA-1.0 (L1-Core) Declares Dependency on LEDGER-1.2 (L3-Operations)

```
ACP-DCMA-1.0  Depends-on: ACP-CT-1.0, ACP-SIGN-1.0, ACP-LEDGER-1.2
```

DCMA is classified as a Core L1 primitive. LEDGER is L3-OPERATIONS. If DCMA genuinely requires LEDGER to function, then an L1 implementation cannot be built without first implementing L3 — which breaks the cumulative conformance model entirely.

**Root cause:** DCMA uses the ledger to record delegation events (`AUTHORIZATION` payloads include `delegation_chain`). But this is a write-only, one-directional relationship — DCMA *instructs* the ledger but does not depend on it for its own correctness.

**Required fix:** Remove `ACP-LEDGER-1.2` from DCMA's `Depends-on`. The formal delegation model in DCMA is self-contained. Its ledger interaction should be described as an operational integration note, not a formal dependency.

---

### I-7 🟠 EXEC-1.0 Depends on API-1.0 / API-1.0 Required-by EXEC-1.0

```
ACP-EXEC-1.0  Depends-on: ACP-SIGN-1.0, ACP-CT-1.0, ACP-API-1.0
ACP-API-1.0   Required-by: ACP-EXEC-1.0, ACP-LEDGER-1.2
```

EXEC depends on API because the ET issuance endpoint (`POST /acp/v1/exec/issue`) is defined in API-1.0. API lists EXEC in its `Required-by` because EXEC defines the token format that the API endpoints carry. This is a co-definition relationship, not a true semantic dependency from EXEC to API.

**Impact:** An implementor building the ET format (EXEC) cannot do so without "depending on" a spec (API) that is 2 levels higher in the conformance hierarchy. This creates an implementation ordering problem.

**Required fix:** Extract the ET endpoint specification into EXEC-1.0 itself, or restructure so API references EXEC (not the reverse). The token format must be specifiable independently of the HTTP transport.

---

### I-8 🟠 ACP-TS-1.1 and ACR-1.0 Duplicated Across Two Directories

Both files appear in:
- `03-acp-protocol/specification/governance/`
- `03-acp-protocol/compliance/`

This creates ambiguity about which copy is canonical and risks divergence if one copy is edited without the other.

**Required fix:** Keep compliance specs in `/compliance/` only. Remove the copies from `/governance/`. Update cross-references.

---

### I-9 🟡 CONF-1.1 L1 Identity Clause References "DID or Equivalent"

CONF-1.1 §4.1:
> Support unique identifiers (DID or equivalent)

ACP-AGENT-1.0 §3 defines:
> `AgentID = base58(SHA-256(pk_bytes))`

This is not a DID. The conformance test for L1 identity uses a concept (DID) that the core spec never uses. This would cause a conformant implementation to fail a literal reading of the conformance clause.

**Required fix:** Replace with "ACP AgentID per ACP-AGENT-1.0 §3 (`base58(SHA-256(pk_bytes))`) or DID (required for L5)."

---

### I-10 🟡 CONF-1.1 L3 Named "FULL" — Inconsistent with SPEC-INDEX and CHANGELOG

CONF-1.1 table: `L3 | FULL`
SPEC-INDEX: `L3-OPERATIONS`
CHANGELOG: uses neither consistently

Three different names for the same level across three documents in the same repo.

**Required fix:** Standardize to a single label. Recommendation: `L3-OPERATIONS` (descriptive of what it adds) over `FULL` (implies completeness, but L4 and L5 exist).

---

### I-11 🟡 LEDGER-1.2 Required-by Field Is Stale

```
Required-by: ACP-CONF-1.0, ACP-REP-1.2
```

Missing references:
- `ACP-CONF-1.1` (CONF-1.0 is deprecated and should not be the forward pointer)
- `ACP-CROSS-ORG-1.0` (declares LEDGER as dependency)
- `ACP-REP-PORTABILITY-1.0` (declares LEDGER as dependency)
- `ACP-LIA-1.0`, `ACP-PSN-1.0`, `ACP-HIST-1.0` (all major ledger consumers)

---

### I-12 🟡 RFC-REGISTRY Is Empty — New Specs Have No RFC Trail

```
| — | — | — | — | — | — | — | — | — | — |
*No RFCs registered as of this date.*
```

ACP-CROSS-ORG-1.0 and ACP-REP-PORTABILITY-1.0 are normative L4 specs. Per RFC-PROCESS, normative specifications must go through the RFC process and be registered here. Neither was. This means:

1. There is no formal review trail for the two new specs.
2. The governance process is bypassed for the most recent protocol additions.
3. An external auditor cannot trace the rationale for introducing these specs.

---

### I-13 🟡 CHANGELOG Has No Entry for CROSS-ORG-1.0 or REP-PORTABILITY-1.0

Latest CHANGELOG entry: v1.9.0 (2026-03-09). The two new specs were added after v1.9.0 and appear in the `[Unreleased]` section (which is empty). This means the version history of the repository is incomplete.

---

### I-14 🟡 ACP-TS-SCHEMA-1.0 Not in SPEC-INDEX

`03-acp-protocol/compliance/ACP-TS-SCHEMA-1.0.md` is a normative JSON Schema for test vectors (complementary to ACP-TS-1.1). It is not catalogued in SPEC-INDEX, not referenced in ACP-TS-1.1's header, and has no `Required-by` connections to anything.

---

### I-15 🟡 ACP-RISK-1.0 Is Misplaced in /security/

ACP-RISK-1.0 is in `specification/security/` but:
- It is listed in `Required-by` of LEDGER-1.2 (operations)
- It is a dependency of the authorization flow (operations)
- CONF-1.1 positions it at L2 because it is required for the *decision engine*, not for security primitives
- The SPEC-INDEX itself notes it is "also listed under Operations"

The spec is a decision/evaluation module, not a security primitive. It belongs in `/operations/`.

---

### I-16 🟡 Stale/Archive Files in Active Spec Directories

| File | Issue |
|------|-------|
| `02-gat-model/Final-Documentation-Structure.md` | Planning artifact from project inception, not a spec or reference. Should be archived. |
| `03-acp-protocol/specification/core/ACP-AGENT-SPEC-0.3.md` | Explicitly deprecated ("renamed to ACP-AGENT-1.0"). Present in active directory, not archived. |
| `04-formal-analysis/Mermaid-Diagram.md` | 4-line standalone Mermaid diagram with no context, no authoring metadata, not referenced anywhere. |

---

### I-17 🟡 CHANGELOG v1.8.0 References Non-Existent "ACP-LEDGER-1.1"

In the CHANGELOG entry for v1.8.0 (ACP-REP-1.2):
> "ACP-LEDGER-1.1 integration: consumption by `evaluation_context`..."

The ledger spec is at version 1.2. There is no ACP-LEDGER-1.1 document in the repo. This is a stale version number in the changelog entry.

---

## 4. Improvement Suggestions

### S-1 🔴 Issue ACP-LEDGER-1.3 to Register New Event Types

The three event types introduced by CROSS-ORG-1.0 and REP-PORTABILITY-1.0 need formal registration in the ledger spec. LEDGER-1.3 should:

1. Add §5.15 `CROSS_ORG_INTERACTION` schema (from CROSS-ORG-1.0 §4)
2. Add §5.16 `REPUTATION_ATTESTATION_ISSUED` schema
3. Add §5.17 `REPUTATION_ATTESTATION_RECEIVED` schema
4. Update `Required-by` to include CROSS-ORG-1.0 and REP-PORTABILITY-1.0
5. Define backwards compatibility: v1.2 implementations MUST treat the three new types as LEDGER-008 (unknown event type, continue chain verification)

Until LEDGER-1.3 exists, the new event types have no normative home.

---

### S-2 🔴 Update CONF-1.1 to a Corrective Revision (v1.1.1 or v1.2)

A single corrective revision to CONF-1.1 should address all four critical/major governance gaps:

| Fix | Change |
|-----|--------|
| L1 table | Add MESSAGES, AGENT, DCMA |
| L2 table | Clarify ITA-1.0 (centralized) vs ITA-1.1 (federation added at L4) |
| L4 table | Replace REP-1.1 → REP-1.2; add CROSS-ORG-1.0; add REP-PORTABILITY-1.0 |
| L4 section §7.2 | Replace "ACP-REP-1.1" reference with "ACP-REP-1.2" |
| L1 §4.1 identity | Replace "DID or equivalent" with "ACP AgentID per ACP-AGENT-1.0 §3" |
| L3 label | Rename "FULL" → "OPERATIONS" for consistency |

---

### S-3 🟠 Fix Dependency Graph Circularity

Three targeted fixes eliminate all circular and cross-layer dependency issues:

**Fix A — LEDGER-1.2 header:**
```
Depends-on: ACP-SIGN-1.0, ACP-CT-1.0, ACP-RISK-1.0, ACP-REV-1.0, ACP-EXEC-1.0
# Remove: ACP-LIA-1.0, ACP-PSN-1.0
# Add note: "Emitters: ACP-LIA-1.0 (LIABILITY_RECORD), ACP-PSN-1.0 (POLICY_SNAPSHOT_CREATED)"
```

**Fix B — DCMA-1.0 header:**
```
Depends-on: ACP-CT-1.0, ACP-SIGN-1.0
# Remove: ACP-LEDGER-1.2
# Add note: "DCMA payloads are included in AUTHORIZATION and LIABILITY_RECORD events (ACP-LEDGER-1.2 §5.2, §5.12)"
```

**Fix C — EXEC-1.0 header:**
```
Depends-on: ACP-SIGN-1.0, ACP-CT-1.0
# Remove: ACP-API-1.0
# The ET endpoint defined in API-1.0 should instead reference EXEC-1.0 (not the reverse)
```

---

### S-4 🟠 Register CROSS-ORG-1.0 and REP-PORTABILITY-1.0 in RFC-REGISTRY

Even retroactively, both specs should receive RFC entries. This provides:
- A rationale trail (why the spec was introduced, what problem it solves)
- A formal review record for external auditors
- Traceability for future breaking-change analysis

Suggested entries:

```
| RFC-2026-001 | Cross-Organizational Interaction Registry | Protocol | [Author] | 2026-03-11 | 2026-03-11 | Implemented | No | ACP-LEDGER-1.x, ACP-CONF-1.1, ACP-HIST-1.0 | ./rfcs/RFC-2026-001.md |
| RFC-2026-002 | Reputation Portability Protocol          | Protocol | [Author] | 2026-03-11 | 2026-03-11 | Implemented | No | ACP-REP-1.2, ACP-LEDGER-1.x, ACP-CONF-1.1  | ./rfcs/RFC-2026-002.md |
```

---

### S-5 🟠 Relocate ACP-RISK-1.0 to /operations/

Move `specification/security/ACP-RISK-1.0.md` → `specification/operations/ACP-RISK-1.0.md`.

Rationale: RISK is an evaluation/decision module, not a cryptographic primitive or trust management module. It belongs alongside EXEC, LEDGER, and API as an operational component. Its current placement in `/security/` creates conceptual confusion for new implementors navigating the spec tree.

---

### S-6 🟡 Introduce a Formal `Emitters:` Header Field in Spec Frontmatter

The current `Depends-on` / `Required-by` pair only captures directional compilation-style dependencies. For ledger-centric specs, there is a distinct third relationship: *"this spec emits events consumed by LEDGER"*. Introducing a formal `Emitters:` field in LEDGER-1.x and a `Emits-to:` field in LIA, PSN, CROSS-ORG, and REP-PORTABILITY would:

1. Eliminate the need for circular `Depends-on` relationships
2. Provide a complete event provenance map
3. Allow tooling to verify that every event type has a registered emitter

Suggested standard header fields:
```
Depends-on:    (compilation deps — must be built/spec'd first)
Required-by:   (consumers of this spec's artifacts)
Emits-to:      (ledger event types this spec produces)
Emitters:      (which specs produce events registered in this spec)
```

---

### S-7 🟡 Add CHANGELOG Entries and Version Bump for New Specs

Two CHANGELOG entries are missing:

```markdown
## [1.10.0] — 2026-03-11

### Added — ACP-CROSS-ORG-1.0 — Cross-Organizational Interaction Registry
- Defines `CROSS_ORG_INTERACTION` as a first-class LEDGER-1.x event type
- CrossOrgBundle bilateral transmission protocol (8 ActionTypes, 6 emission rules)
- 7-step target validation procedure, CrossOrgAck acknowledgment
- Cross-org query extensions on ACP-HIST-1.0
- Closes asymmetric audit trail gap. Implements CONF-1.1 L4.

### Added — ACP-REP-PORTABILITY-1.0 — Reputation Portability
- ReputationAttestation format with score ceiling 0.85
- Eligibility gates: event_count ≥ 10, ITS ≥ 0.50
- Initial ERS discount formula: score × (1 - 1/(1 + refs/10)) × 0.85
- Non-transitivity invariant enforced at issuance
- Two new ledger event types: REPUTATION_ATTESTATION_ISSUED, REPUTATION_ATTESTATION_RECEIVED
- Implements ACP-REP-1.1 §12.1 and CONF-1.1 L4.
```

---

### S-8 🟡 Archive Stale Files

| Action | File |
|--------|------|
| Move to `/archive/` or delete | `02-gat-model/Final-Documentation-Structure.md` |
| Move to `/archive/` or delete | `03-acp-protocol/specification/core/ACP-AGENT-SPEC-0.3.md` |
| Move to `/archive/` or delete | `04-formal-analysis/Mermaid-Diagram.md` |
| Remove duplicate | `03-acp-protocol/specification/governance/ACP-TS-1.1.md` (keep `/compliance/` copy) |
| Remove duplicate | `03-acp-protocol/specification/governance/ACR-1.0.md` (keep `/compliance/` copy) |

---

### S-9 🟡 Add ACP-TS-SCHEMA-1.0 to SPEC-INDEX and ACP-TS-1.1

`ACP-TS-SCHEMA-1.0.md` provides the formal JSON Schema for test vectors — this is a normative artifact for anyone implementing ACR-1.0. It should be:
1. Referenced in ACP-TS-1.1 §X: "The formal JSON Schema for test vectors is defined in ACP-TS-SCHEMA-1.0."
2. Added to SPEC-INDEX under §3E Compliance.

---

### S-10 🟡 Implement Go Reference Support for CROSS-ORG and REP-PORTABILITY

The Go reference implementation (`acp-go`) has packages for: `ledger`, `reputation`, `token`, `risk`, `sign`, `api`, `revocation`, `delegation`, `execution`, `handshake`, `registry`.

The two new L4 federation specs have no corresponding packages. Before these specs can claim `Status: Active/Normative`, a reference implementation should exist. Suggested new packages:

```
pkg/crossorg/      — CrossOrgBundle creation, signing, validation, CrossOrgAck
pkg/portability/   — ReputationAttestation issuance, verification, ERS computation
```

---

## 5. Priority-Ranked Fix List

| Priority | ID | Category | Description |
|----------|----|----------|-------------|
| 1 | I-2 → S-1 | Protocol Integrity | Issue LEDGER-1.3: register CROSS_ORG_INTERACTION, REPUTATION_ATTESTATION_ISSUED/RECEIVED |
| 2 | I-3 + I-4 → S-2 | Governance | Update CONF-1.1: fix L4 definition, fix deprecated REP-1.1 reference, add CROSS-ORG + PORTABILITY |
| 3 | I-1 + I-6 + I-7 → S-3 | Dependency Graph | Fix circular/cross-layer dependencies: LEDGER, DCMA, EXEC headers |
| 4 | I-12 → S-4 | Governance/Audit | Register RFC-2026-001 and RFC-2026-002 retroactively |
| 5 | I-5 | Conformance | Add MESSAGES, AGENT, DCMA to CONF-1.1 L1 table |
| 6 | I-9 | Conformance | Fix CONF-1.1 §4.1 identity clause (AgentID, not DID) |
| 7 | I-13 → S-7 | Documentation | Add CHANGELOG entries for v1.10.0 (new specs) |
| 8 | I-15 → S-5 | File Organization | Relocate RISK-1.0 to /operations/ |
| 9 | I-8 | File Organization | Remove duplicate TS-1.1 and ACR-1.0 from /governance/ |
| 10 | I-14 → S-9 | Documentation | Index ACP-TS-SCHEMA-1.0 in SPEC-INDEX and TS-1.1 |
| 11 | I-10 | Consistency | Standardize L3 label: "FULL" → "OPERATIONS" |
| 12 | I-11 | Metadata | Update LEDGER-1.2 Required-by field |
| 13 | I-16 → S-8 | Hygiene | Archive stale files (Final-Docs, AGENT-SPEC-0.3, Mermaid-Diagram) |
| 14 | I-17 | Documentation | Fix CHANGELOG v1.8.0 reference "LEDGER-1.1" → "LEDGER-1.2" |
| 15 | S-10 | Implementation | Add crossorg/ and portability/ packages to acp-go |

---

## 6. Protocol Integrity Assessment

**Strengths:**
- The constitutional invariant (`Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk`) is coherently expressed across L1 doctrine, L3 core specs, and the execution lifecycle. No spec violates it.
- The hash-chaining mechanism in LEDGER-1.2 is formally correct and sound. Chain integrity is verifiable without trust in the institution.
- The non-transitivity invariants in ITA-1.1 (1-hop federation) and REP-PORTABILITY-1.0 are correctly specified and consistently applied.
- Transitive revocation (DCMA + REV-1.0) is formally defined and correctly referenced.
- The ACP-HP-1.0 Proof-of-Possession closes the stolen-token vulnerability without modifying the CT spec.

**Weaknesses:**
- The two newest L4 specs (CROSS-ORG, REP-PORTABILITY) are protocol orphans: they claim L4 status but are not recognized by L4's governing document (CONF-1.1), and their event types are not registered in the ledger.
- The circular dependency between LEDGER, LIA, and PSN is the most structurally significant inconsistency — it makes the `Depends-on` graph unresolvable by a dependency solver.
- The empty RFC-REGISTRY means the protocol has no formal governance trail for its most recent additions.

**Overall verdict:** The core protocol (L1–L3) is structurally sound. The L4 federation layer was added correctly in design but incompletely wired into the governance framework. The 15 fixes above, prioritized as listed, will bring the repository to full internal consistency.
