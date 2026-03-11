# ACP-ROADMAP
## Project Status
**Version:** 1.0
**Last updated:** 2026-02-23

---

## General Status

The ACP v1.0 technical specification is complete. All 10 documents are finalized and consistent with each other.

```
ACP-SIGN-1.0     ✅  Core — serialization and signing
ACP-CT-1.0       ✅  Core — capability tokens
ACP-CAP-REG-1.0  ✅  Core — capability registry
ACP-HP-1.0       ✅  Core — stateless proof of possession
ACP-RISK-1.0     ✅  Security — deterministic risk model
ACP-REV-1.0      ✅  Security — revocation protocol
ACP-ITA-1.0      ✅  Security — institutional trust anchor
ACP-API-1.0      ✅  Operations — formal HTTP API
ACP-EXEC-1.0     ✅  Operations — execution tokens
ACP-LEDGER-1.0   ✅  Operations — audit ledger
ACP-CONF-1.0     ✅  Governance — conformance
```

---

## Changes Applied at v1.0 Closure

### ACP-API-1.0 — Consistency review findings

All findings identified in the cross-review were applied:

- **§2.3** — Added `X-ACP-PoP` as mandatory header in authenticated endpoints (ACP-HP-1.0)
- **§2.3** — `POST /acp/v1/handshake/challenge` declared as unauthenticated endpoint
- **§5 /authorize step 2.5** — Autonomy_level 0 → immediate DENIED AUTH-008
- **§5 /authorize step 6** — Nonce anti-replay validation with 5-minute window
- **§10 anomalous conditions** — Unknown core capability → 403 CAP-002; unknown extended → ESCALATED
- **§10** — Rev endpoint offline applies ACP-REV-1.0 §5 without exceptions
- **§12** — Added codes HP-004, HP-007, HP-009, HP-010, HP-014
- **§12** — Added AUTH-007 (nonce replay), AUTH-008 (autonomy_level 0)
- **§13 conformance** — X-ACP-PoP verification requirement

### ACP-HP-1.0 — Complete rewrite

The legacy ACP-HP document was rewritten to:
- Adopt stateless model (no sessions, no session_id)
- Reference ACP-SIGN-1.0 for PoP serialization
- Define explicit binding: challenge + method + path + body hash
- Define challenge registry with precise management rules
- Define error codes HP-001 through HP-015
- Integrate with ACP-API-1.0 §15

### ACP-CONF-1.0

- ACP-HP-1.0 incorporated in Level 1 CORE
- Requirements section L1-HP-001 through L1-HP-009 added
- Summary table updated
- Conformance Declaration updated

---

## v1.7.0 — Agent Governance Stack: Liability & Policy Traceability
**Released:** 2026-03-09

### New documents

| Spec | Type | Description |
|---|---|---|
| ACP-LIA-1.0 | Operations | Liability Traceability — materializes responsibility per execution |
| ACP-PSN-1.0 | Operations | Policy Snapshot — immutable record of risk policy state |
| ACP-AGS-1.0 | Architecture | Agent Governance Stack — 8-layer reference framework |

### Updated documents

| Spec | Change |
|---|---|
| ACP-LEDGER-1.0 → 1.1 | Adds event types `LIABILITY_RECORD`, `POLICY_SNAPSHOT_CREATED`, `REPUTATION_UPDATED`; adds `policy_snapshot_ref` and `policy_version` to AUTHORIZATION and RISK_EVALUATION |

### Concept incorporated: Bankability (ARAF)
v1.7.0 completes the four bankability properties defined by the ARAF framework:
- ✅ **Risk-modelable** — ACP-RISK-1.0 + ACP-PSN-1.0
- ✅ **Auditable** — ACP-LEDGER-1.1
- ✅ **Predictable** — ACP-EXEC-1.0 + ACP-CT-1.0
- ✅ **Accountable** — ACP-LIA-1.0

### Forward reference: v1.8.0
- ACP-REP-1.2: Formal Reputation Layer (L7 of the AGS). REPUTATION_UPDATED already defined in ACP-LEDGER-1.1 §5.14.

---

## Pending Work v1.1

The following items were identified during v1.0 development and are reserved for the next minor version:

### ACP-REP-1.1 — Reputation Module
`trust_score` field reserved in `GET /acp/v1/agents/{agent_id}`. In v1.0 the server returns null. ACP-REP-1.1 will define the score calculation and update.

### ACP-ITA-1.1 — Mutual Recognition Between Authorities
Model B (federated) of ACP-ITA-1.0 §11 is defined at interface level but the mutual recognition protocol between ITA authorities is not specified. Required for B2B multi-authority deployments.

### Payment integration
ACP governs authorization of `acp:cap:financial.payment`. The effective payment mechanism is the responsibility of the application layer. Document the recommended integration interface.

---

## Pending Work v2.0

- Evaluation of Ed25519 migration to post-quantum algorithms
- Complete federated trust model
- Version negotiation protocol between implementations

---

## Reference Documents in 05-Reference

The following documents from the original project are maintained as historical reference. They are not conformant with v1.0 and MUST NOT be used as specification.

| File | Note |
|---------|------|
| ACP-LEGACY-HP.md | Replaced by ACP-HP-1.0 |
| ACP-LEGACY-DCMA.md | Partially incorporated in ACP-CT-1.0 §7 |
| ACP-LEGACY-THREAT.md | Conceptual basis for ACP-RISK-1.0 |
| ACP-LEGACY-MFMD.md | Mathematical foundation of ACP-RISK-1.0 |
| ACP-LEGACY-MATH.md | Cryptographic foundation of ACP-SIGN-1.0 |
| ACP-LEGACY-AGENT-v03.md | Precursor of ACP-CT-1.0 |
| ACP-LEGACY-MESSAGES.md | Incorporated in ACP-API-1.0 |
| ACP-LEGACY-AMO.md | Superseded structural framework |
| ACP-LEGACY-PME.md | Basis for future implementation |
