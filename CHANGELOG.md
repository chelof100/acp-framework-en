# Changelog — ACP (Agent Control Protocol)

All notable changes to the ACP specification are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.6.0] — 2026-03-06

### Fixed — Go Reference Server

- **`handleTokensIssue`**: replaces STUB 501 with full Capability Token delegation implementation (Ed25519 sign, ledger `TOKEN_ISSUED`, HTTP 201) — per ACP-CT-1.0
- **`handleAuditQuery`**: adds complete filters `event_type`, `agent_id`, `time_range`, `from_sequence`, `to_sequence`, `limit`, `offset` with in-memory filtering and pagination — per ACP-LEDGER-1.0 §6
- **`handleRevRevoke`**: adds fields `revoke_descendants` (bool) and `sig` (string) to request — per ACP-REV-1.0
- **`handleRepState`**: renames field `state` → `new_state` in request body — per ACP-REP-1.1 §7

### Fixed/Added — Python SDK v1.6.0

- **`client.py`**: complete rewrite — 18 spec-aligned methods (was 13 with wrong field names)
  - New methods: `tokens_issue()`, `agent_register()`, `agent_get()`, `agent_state()`, `escalation_resolve()`
  - Fixed: `reputation_state()` uses `new_state`, `revoke()` adds `revoke_descendants` + `sig`, `audit_query()` all spec filters
- **`tests/test_client.py`**: full coverage — 62 tests covering all 18 methods (was 5 test classes)
- **`pyproject.toml`**: version `1.3.0` → `1.6.0`

### Verified

- `go build ./cmd/acp-server/...` — no errors
- `pytest` — 123/123 tests passing

---

## [1.4.0] — 2026-03-04

### Added — TypeScript SDK
- **`sdk/typescript/src/identity.ts`** — `AgentIdentity` class: `generate()` static method (Ed25519 key pair via libsodium), `agentId` (base58-SHA-256 per ACP-SIGN-1.0), `did` (did:key:z6Mk... format)
- **`sdk/typescript/src/signer.ts`** — `ACPSigner` class: `signCapability()` (Ed25519 over SHA-256(JCS(cap))), `signPoP()` (`Method|Path|Challenge|base64url(SHA-256(body))` binding per ACP-HP-1.0)
- **`sdk/typescript/src/client.ts`** — `ACPClient` class: `register()`, `verify()`, `health()` with correct ACP-HP-1.0 header transport (`Authorization: Bearer`, `X-ACP-Agent-ID`, `X-ACP-Challenge`, `X-ACP-Signature`)
- **`sdk/typescript/tests/`** — 68 tests passing: identity suite (AgentID format, DID format, key pair), signer suite (capability signing, PoP binding), client suite (register/verify/health flows)

### Added — Rust SDK
- **`sdk/rust/src/identity.rs`** — `AgentIdentity` struct: `generate()` (ed25519-dalek), `agent_id()` (base58-SHA-256 per ACP-SIGN-1.0), `did()` (did:key:z6Mk... format)
- **`sdk/rust/src/signer.rs`** — `ACPSigner` struct: `sign_capability()` (Ed25519 over SHA-256(JCS(cap))), `sign_pop()` (ACP-HP-1.0 PoP binding)
- **`sdk/rust/src/client.rs`** — `ACPClient` struct: `register()`, `verify()`, `health()` async methods via reqwest
- **`sdk/rust/tests/`** — 43 tests passing: identity/signer/client test suites
- **`sdk/rust/Cargo.toml`** — dependencies: ed25519-dalek, sha2, bs58, serde_json, reqwest, tokio

### Added — Docker CI/CD
- **`.github/workflows/docker.yml`** — Automated Docker image build and push on merge to main; multi-platform (linux/amd64, linux/arm64); images tagged `chelof100/acp-go:{version}` and `chelof100/acp-go:latest`

---

## [1.3.0] — 2026-03-02

### Fixed — Python SDK (reconciled with Go server v1.0)
- **`sdk/python/acp/identity.py`** — AgentID format corrected: was `"acp:agent:"+base64url(SHA-256(pk))`, now `base58(SHA-256(pk))` matching Go `DeriveAgentID()`
- **`sdk/python/acp/signer.py`** — Capability token signature field: was nested `capability["proof"]["signature"]` (W3C VC style), now flat `capability["sig"]` per ACP-CT-1.0
- **`sdk/python/acp/client.py`** — HTTP transport for `/acp/v1/verify`: was JSON body, now HTTP headers (`Authorization: Bearer`, `X-ACP-Agent-ID`, `X-ACP-Challenge`, `X-ACP-Signature`); PoP binding corrected to `Method|Path|Challenge|base64url(SHA-256(body))` per ACP-HP-1.0; added `register()` method
- **`sdk/python/examples/agent_payment.py`** — Token fields aligned with Go `CapabilityToken` struct; register step added; offline PoP demo uses corrected binding; `--print-pubkey` flag for server setup workflow

### Added — Reference Implementation (IUT + Runner)
- **`pkg/iut`** — Core IUT evaluation package: `Evaluate()` (L1/L2 compliance logic), `SignCapability()` (Ed25519 over SHA-256(JCS(cap))), `resolveDIDKey()` (did:key: → Ed25519 pubkey), `checkDelegation()` (DCMA-1.0 rules)
- **`cmd/acp-evaluate`** — IUT binary conforming to ACP-IUT-PROTOCOL-1.0: reads TestVector from STDIN, writes Response to STDOUT; `--manifest` flag
- **`cmd/acp-runner`** — ACR-1.0 compliance runner: loads test suite, executes IUT per vector, strict comparison, produces `RunReport` + auto-certification `CertRecord`; flags `--impl --suite --level --layer --strict --performance`; 12/12 PASS → `CONFORMANT`
- **`cmd/acp-sign-vectors`** — Tool to replace PLACEHOLDER signatures in test vector files with real Ed25519 signatures using RFC 8037 test key A
- **`pkg/iut/evaluator_test.go`** — `TestCompliance`: loads all 12 ACP-TS-1.1 test vectors, signs PLACEHOLDERs in-memory, asserts decision + error_code (12/12 PASS)
- **`go.sum`** — Added dependency checksums (jcs v1.0.1, base58 v1.2.0)
- **`03-acp-protocol/test-vectors/*.json`** — Fixed issuer DID in all test vectors; real Ed25519 signatures generated via `acp-sign-vectors` (RFC 8037 test key A, seed `9d61b19d…`)

---

## [1.2.0] — 2026

### Added — Compliance Ecosystem
- **ACP-CONF-1.1** (`03-acp-protocol/specification/governance/`) — Conformance specification with 5 cumulative levels L1–L5; replaces the 4-profile model from v1.0 (Core, Extended, Governance, Full); adds L3 (API+EXEC+LEDGER) and L5 (ACP-D+BFT) previously absent; token format uses `conformance_level` instead of `profile`
- **ACP-TS-SCHEMA-1.0** (`03-acp-protocol/compliance/`) — JSON Schema (Draft 2020-12) for test vector validation
- **ACP-TS-1.0** (`03-acp-protocol/compliance/`) — Test Suite specification: required test cases per conformance level L1–L5
- **ACP-TS-1.1** (`03-acp-protocol/compliance/`) — Normative JSON format for test vectors — deterministic, language-agnostic, uses `context.current_time` instead of system time
- **ACP-IUT-PROTOCOL-1.0** (`03-acp-protocol/compliance/`) — Contract between compliance runner and Implementation Under Test (STDIN/STDOUT, 2000ms timeout, deterministic manifest)
- **ACR-1.0** (`03-acp-protocol/compliance/`) — Official Compliance Runner — executes test vectors and emits signed certification records
- **ACP-CERT-1.0** (`03-acp-protocol/compliance/`) — Public Certification System — badge format `ACP-CERT-YYYY-NNNN`, reproducible, cryptographically signed
- **03-acp-protocol/compliance/** directory — full compliance and certification pipeline

### Added — Core Specification
- **ACP-DCMA-1.0** (`03-acp-protocol/specification/core/`) — Multi-agent chained delegation with non-escalation guarantee and transitive revocation; formal predicate `HasCapability'(aⱼ,c)`
- **ACP-AGENT-SPEC-0.3** (`03-acp-protocol/specification/core/`) — Formal agent ontology `A=(ID,C,P,D,L,S)` and agent lifecycle definition
- **ACP-MESSAGES-1.0** (`03-acp-protocol/specification/core/`) — Protocol wire format: 5 message types (Registration, ActionRequest, AuthorizationDecision, StateChange, AuditQuery)

### Added — Security and Formal Models
- **Formal-Security-Model-v2** (`04-formal-analysis/`) — Updated formal security model with proofs covering all 5 layers
- **Formal-Decision-Engine-MFMD** (`04-formal-analysis/`) — Formal decision engine model (MFMD)

### Added — Vision
- **Final-Documentation-Structure** (`02-gat-model/`) — Canonical documentation structure map

### Added — Test Vectors
- **`03-acp-protocol/test-vectors/`** — 12 normative JSON test vectors conforming to ACP-TS-1.1 format, covering:
  - `TS-CORE-POS-001/002` — valid capability (canonical, multi-action)
  - `TS-CORE-NEG-001` — expired token (`EXPIRED`)
  - `TS-CORE-NEG-002` — missing expiry (`MALFORMED_INPUT`)
  - `TS-CORE-NEG-003` — missing nonce (`MALFORMED_INPUT`)
  - `TS-CORE-NEG-004` — invalid signature (`INVALID_SIGNATURE`)
  - `TS-CORE-NEG-005` — revoked token jti (`REVOKED`)
  - `TS-CORE-NEG-006` — untrusted issuer (`UNTRUSTED_ISSUER`)
  - `TS-DCMA-POS-001` — valid single-hop delegation chain
  - `TS-DCMA-NEG-001` — privilege escalation attempt (`ACCESS_DENIED`)
  - `TS-DCMA-NEG-002` — revoked delegator transitive revocation (`REVOKED`)
  - `TS-DCMA-NEG-003` — delegation depth exceeded institutional max_depth (`DELEGATION_DEPTH`)
- **`test-vectors/README.md`** — test key pair documentation, PLACEHOLDER signature convention, coverage table

### Changed — Core Specification
- **ACP-DCMA-1.0 §14** added: Transitive Revocation — Normative Timing — τ_propagation ≤ 60 seconds, cache TTL ≤ 30 seconds, in-flight re-evaluation requirement, atomicity guarantee

### Fixed
- **ACP-CERT-1.0** — certification authority renamed to "ACP-CA" (neutral placeholder); §7 Governance rewritten with explicit decentralization intent: target model is multi-sig (n-of-m) for v2.x and BFT on-chain quorum for ACP-D (L5); no single entity controls certification issuance; `"issuer"` field updated to `"ACP-CA"`
- **ACR-1.0** — signing attribution updated to "ACP Certification Authority (governance entity to be defined by the community)"
- **README.md Roadmap** — IEEE S&P / NDSS paper correctly labeled as "Draft in preparation" (was misleadingly labeled "Submission")

### Added — Repository Infrastructure
- `LICENSE` — Apache 2.0 (copyright 2026 Marcelo Fernandez, TraslaIA)
- `SECURITY.md` — Vulnerability reporting policy with 90-day coordinated disclosure
- `CONTRIBUTING.md` — RFC formal numbered process (ACP-RFC-NNN) for normative changes; PR process for non-normative changes
- `CHANGELOG.md` — This file
- `QUICKSTART.md` — 4 reader paths (understand / implement / evaluate / contribute), conformance levels table, documentation map
- `.github/RFC-TEMPLATE.md` — Full RFC lifecycle template (Draft→Review→Last Call→Accepted/Rejected) with Security Analysis section

---

## [1.1.0] — 2026

### Added — Economic and Reputation Layers
- **ACP-PAY-1.0** (`03-acp-protocol/specification/operations/`) — Economic binding layer (Layer 4): payment commitments, escrow, settlement
- **ACP-REP-1.1** (`03-acp-protocol/specification/security/`) — Adaptive security layer (Layer 5): reputation scoring, dynamic capability adjustment
- **ACP-ITA-1.1** (`03-acp-protocol/specification/security/`) — Updated Byzantine Fault Tolerant consensus; quorum rules `n ≥ 3f+1`, threshold `t ≥ 2f+1`

### Added — Architecture
- **ACP-Architecture-Specification** (`02-gat-model/`) — Unified 3-level / 5-layer architecture specification
- **Three-Layer-Architecture** (`02-gat-model/`) — Strategic 3-level framework (Sovereign AI / GAT Model / ACP Protocol)

### Added — Academic
- **IEEE-NDSS-Paper-Structure** (`06-publications/`) — Draft paper structure for academic publication

### Changed
- Consolidated Layer 3 (ACP-D) and centralized consensus into unified architecture
- Conformance specification updated to cover Layers 4 and 5

---

## [1.0.0] — 2026

### Added — Core Specification (10 normative documents)
- **ACP-SIGN-1.0** — Cryptographic signature scheme: Ed25519, JCS canonicalization, nonce handling
- **ACP-CT-1.0** — Capability Token format: structure, claims, issuer binding, expiry
- **ACP-CAP-REG-1.0** — Capability Registry: registration, lookup, versioning
- **ACP-HP-1.0** — Handshake Protocol: proof of possession
- **ACP-RISK-1.0** — Risk scoring model: dynamic threat assessment
- **ACP-REV-1.0** — Revocation protocol: token invalidation, propagation
- **ACP-ITA-1.0** — Institutional Trust Anchor: centralized issuer model
- **ACP-API-1.0** — REST API specification: endpoints, authentication, error codes
- **ACP-EXEC-1.0** — Execution protocol: action request lifecycle, anti-replay
- **ACP-LEDGER-1.0** — Audit ledger: append-only log, tamper-evidence

### Added — Decentralized Variant
- **ACP-D-Specification** (`03-acp-protocol/specification/decentralized/`) — ACP-D: DID + VC + Self-Sovereign Capability
- **Architecture-Without-Central-Issuer** (`03-acp-protocol/specification/decentralized/`) — Decentralized architecture without central issuer

### Added — Vision and Analysis
- Strategic vision documents (`02-gat-model/`)
- GAT model specifications (`01-sovereign-architecture/`)
- Security analysis (`04-formal-analysis/`)
- Implementation guidance (`05-implementation/`)

---

[Unreleased]: https://github.com/chelof100/acp-framework-en/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/chelof100/acp-framework-en/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/chelof100/acp-framework-en/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/chelof100/acp-framework-en/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/chelof100/acp-framework-en/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/chelof100/acp-framework-en/releases/tag/v1.0.0
