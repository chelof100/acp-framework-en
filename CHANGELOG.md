# Changelog — ACP (Agent Control Protocol)

All notable changes to the ACP specification are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.20.0] — Sprint I (partial) — 2026-03-26

### Added

#### Adversarial Evaluation — Experiment 4 (`compliance/adversarial/`)
- `exp_token_replay.go` — Experiment 4: Token Replay Attack. Four sub-cases demonstrating ACP's bounded replay resistance without nonce tracking.
  - **Case 1 — Normal traffic baseline:** 10 requests, unique resource per call, RS=0, no pattern accumulation, no cooldown. (Comparison anchor.)
  - **Case 2 — Sequential replay:** 10 identical tokens (`financial.transfer / sensitive / NoHistory=true`, RS_base=55 ESCALATED). F_anom Rule 3 fires at request 4 after 3 pattern accumulations in 5-min window (+15 RS → RS=70 DENIED). Cooldown triggers after 3 DENIED; 4/10 subsequent requests blocked.
  - **Case 3 — Concurrent replay:** 5 workers × 4 requests. InMemoryQuerier mutex serializes reads; concurrency does not bypass accumulation. 14/20 requests blocked.
  - **Case 4 — Near-identical replay:** Resource suffix varies per request (`accounts/sensitive-000…009`). Different patternKey per call → Rule 3 never fires → RS stays at 55 (ESCALATED) → no cooldown. Demonstrates bounded replay resistance; motivates §Limitations note.
- `main.go` — Updated: `--exp=4` flag added (`token-replay`); `--exp=0` (all) includes Experiment 4.

#### Paper — v1.20
- `paper/arxiv/main.tex` — Version bumped to v1.20. Added `\subsubsection*{Experiment 4}` with results table and RS-trajectory figure (pgfplots). Updated: abstract (4 attack scenarios), Q4, adversarial section intro, Security Properties (Bounded Replay Resistance paragraph), Limitations (nonce note), Roadmap table, spec changelog, conclusion. Added `\usepackage{pgfplots}`.
- Added `\section{Deployment Considerations}` — state backend selection table (InMemory / Redis / Postgres), agent identity provisioning, multi-organization boundaries (per-org LedgerQuerier, ACP-ITA-1.1 federated trust), cross-agent coordination boundary (L3 scope clarification), integration with existing infrastructure (RBAC/ABAC/ZeroTrust/SIEM), policy tuning guidance (CooldownPeriodSeconds, CooldownTriggerDenials, Rule3ThresholdY, PolicyHash). Framing: "ACP does not replace higher-level coordination or monitoring systems."

#### Redis Pipelining (`compliance/adversarial/`)
- `redis_pipelined.go` — `RedisPipelinedQuerier`: reduces per-request Redis RTTs from ~7-8 to 2.
  - Pipeline 1 (before Evaluate): ZCount(req) + ZCount(denial) + ZCount(pattern) + GET(cooldown) — 1 RTT
  - Evaluate: zero RTTs (served from `readCache`)
  - Pipeline 2 (after Evaluate): ZAdd(req) + ZAdd(pattern) + maybe ZAdd(denial) + maybe SET(cooldown) — 1 RTT
  - Cooldown check inline using `denCount + 1` (semantically equivalent to ShouldEnterCooldown post-flush)
- `exp_backend_stress.go` — Experiment 3 updated with 3-backend comparison + `runStressPipelined`

### Key results (Experiment 3, Intel i7-8665U, Go 1.22, Redis 7 Docker loopback)
| Backend | RTTs/req | Duration | Throughput |
|---------|----------|----------|------------|
| InMemoryQuerier | ~1 | ~15ms | ~600k req/s |
| RedisQuerier (unpipelined) | ~7-8 | ~2.0s | ~4,700 req/s |
| RedisPipelinedQuerier | 2 | ~1.2s | ~8,000 req/s |

Pipelining speedup: ~1.7× (conservative — workload includes cooldown short-circuits that reduce unpipelined overhead)

### Key results (Experiment 4, Intel i7-8665U, Go 1.22)
| Case | Requests | ESCALATED | DENIED | Cooldown-blocked |
|------|----------|-----------|--------|-----------------|
| Normal baseline | 10 | 0 | 0 | 0 |
| Sequential replay | 10 | 3 | 3 | 4 |
| Concurrent replay | 20 | 3 | 3 | 14 |
| Near-identical | 10 | 10 | 0 | 0 |

RS trajectory (sequential): reqs 1–3 → RS=55 (ESCALATED); reqs 4–6 → RS=70 (DENIED, Rule 3); reqs 7–10 → COOLDOWN_ACTIVE.

#### Post-Quantum Implementation — ACP-SIGN-2.0 (`impl/go/pkg/sign2/`)
- `pkg/sign2/sign2.go` — ML-DSA-65 (Dilithium mode3) integrated via `github.com/cloudflare/circl v1.6.3`.
  - `SignHybridFull(msg, edKey, pqKey)` — produces real Ed25519 + ML-DSA-65 signature pair (`mode3.SignTo`).
  - `VerifyHybrid(msg, edPub, pqPub, sig)` — conditional verification: both MUST verify when `PQCSig != nil` (AND); Ed25519 alone when `PQCSig == nil` (backward-compatible transition period per ACP-SIGN-2.0 §4.2).
  - `GenerateHybridKeyPair()` — generates fresh Ed25519 + ML-DSA-65 keypair for tests and provisioning.
  - `SignHybrid` (Ed25519-only path) and wire format `HybridSignature` unchanged.
  - Error codes: SIGN-011 (Ed25519 fail), SIGN-012 (ML-DSA-65 fail), SIGN-013 (PQCSig present, no PQ public key).
- `pkg/sign2/sign2_test.go` — 4 tests: classic path (nil PQCSig accepted), full PQ path (both verify), tampered message (both fail), SIGN-013 error path.
- `impl/go/go.mod` — added `github.com/cloudflare/circl v1.6.3`.
- Performance characteristics of ML-DSA-65 are not evaluated in this work; inclusion demonstrates integration feasibility.

#### Paper — v1.20 (updated)
- Added `\paragraph{Post-Quantum Extension}` in Reference Implementation section: describes `SignHybridFull`, conditional verification (AND when PQCSig present), forward-compatible migration path. Protective framing: "Performance characteristics of ML-DSA-65 are not evaluated in this work."
- Added `pkg/sign2` row to Go packages table (ACP-SIGN-2.0, L1).
- Updated spec changelog caption: "New in v1.20" entry includes ML-DSA-65 CIRCL integration.
- Updated Roadmap: "Post-quantum Go implementation (Dilithium, circl) → v1.20 Complete".
- Updated Limitations: stub → implemented; protective phrase added.
- Updated Conclusion: "HYBRID mode stub" → "real ML-DSA-65 hybrid implementation via Cloudflare CIRCL".

#### Formal Verification — TLA+ Extended Model (`tla/`)
- `tla/ACP_Extended.tla` — `ACP_Extended` module: extends `ACP.tla` with per-agent cooldown temporal state, denial accumulation, static delegation chain integrity.
  - New state variables: `now` (discrete time counter), `denial_count` ([Agents → Nat]), `cooldown_until` ([Agents → Nat]).
  - `Tick` action: advances time by one tick; bounded by `MAX_TIME`. `WF_vars(Tick)` in `Spec` ensures time eventually advances (liveness requirement).
  - `EvaluateRequest`: RS always `ComputeRisk(cap, res)` (deterministic); cooldown overrides decision, not RS (preserves `RiskDeterminism`). `denial_count` increments only for RS-based DENIED, not cooldown-forced DENIED (faithful to ACP-RISK-2.0 §4).
  - `DelegationChain == <<"A1", "A2">>` — hardcoded operator (TLC CFG does not support sequence literals); models 2-hop chain (ACP-DCMA-1.1 §3).
  - Safety invariants (7 total): `TypeInvariant`, `Safety`, `LedgerAppendOnly`, `RiskDeterminism`, `CooldownEnforced` (active cooldown forces DENIED), `CooldownImpliesThreshold` (cooldown only after `COOLDOWN_TRIGGER` denials), `DelegationIntegrity` (no consecutive self-delegation).
  - Temporal properties (2): `LedgerAppendOnlyTemporal` (append-only across steps), `CooldownExpires` (active cooldown eventually expires — conditioned on `cooldown_until[a] <= MAX_TIME` for bounded time horizon correctness).
- `tla/ACP_Extended.cfg` — TLC model-checking configuration: 2 agents × 3 capabilities × 2 resources, ledger bound 5, `COOLDOWN_TRIGGER=3`, `COOLDOWN_WINDOW=3`, `MAX_TIME=5`. Run with `-deadlock` flag (intended terminal states: `now=MAX_TIME` or `Len(ledger)=5`).
- **TLC result** (tla2tools.jar v1.7.1, Java 1.8): *Model checking completed. No error has been found.* 3,031,730 states generated, 1,672,254 distinct states found, graph depth 11. All 7 invariants and both temporal properties hold with zero violations.
- Framing: "model checking of selected safety properties under a bounded state model"; `denial_count` monotone within bounded trace (per-window decay not modeled); dynamic chain mutation out of scope for v1.20.

#### Paper — v1.20 (updated, TLA+)
- Updated `\section{Formal Verification}`: added `\noindent\textbf{Extended model (v1.20)}` paragraph describing `ACP_Extended.tla` module, per-agent cooldown state, 7 invariants, 2 temporal properties, design decisions. Added `\noindent\textbf{Extended TLC result}` with real numbers and protective framing.

---

## [1.19.0] — Sprint H — 2026-03-24

### Added

#### Adversarial Evaluation (`compliance/adversarial/`)
- `compliance/adversarial/` — 8-file Go module (`go-redis/v9` dependency) with 3 ACP-RISK-2.0 adversarial experiments and a `RedisQuerier` implementation of `LedgerMutator`.
- **Experiment 1 — Cooldown Evasion Attack:** 1 agent, 500 requests, alternating high-risk/low-risk pattern. Cooldown triggers after exactly 3 real DENIED decisions; 495/500 requests blocked (99%). Throughput: 815,927 req/s.
- **Experiment 2 — Distributed Multi-Agent Attack:** 100/500/1,000 agents × 10 requests each. Each agent individually blocked after 3 DENIED; total free denials = 3N (linear in agent count). Demonstrates per-agent design boundary.
- **Experiment 3 — State Backend Stress:** 500 agents × 20 requests (10,000 total). InMemoryQuerier ~350k req/s (mutex-bound, ±30% variance); RedisQuerier ~2,100 req/s (RTT-bound, ±4%). Validates LedgerQuerier as replaceable abstraction.
- `redis_querier.go` — Full `RedisQuerier` implementing `LedgerMutator` using Redis sorted sets (ZAdd/ZCount) with per-operation commands (no pipelining).

#### Paper — v1.19
- `paper/arxiv/main.tex` — Version bumped to v1.19. Added `\subsection{Adversarial Evaluation (ACP-RISK-2.0)}` with 3 tables and results. Added Q4 to Evaluation Goals. Updated Limitations, roadmap table (adversarial evaluation v1.19 Complete; Dilithium deferred to v1.20).

### Fixed
- API usage corrected vs planning docs: `PatternKey(agentID, capability, resource)` takes 3 parameters; `ShouldEnterCooldown(agentID, policy, querier, now)` takes 4 parameters with policy second.

---

## [1.17.0] — Sprint F — EN PROGRESO

### Added (parcial — 2026-03-23)

#### Compliance — ACR-1.0 Compliance Runner
- `compliance/runner/` — ACR-1.0 sequence compliance runner. Go module independiente (8 archivos, 548 LOC) con replace directive a `impl/go`. Dos modos: `library` (default, llama a `pkg/risk` directo) y `http` (servidor externo). CLI flags: `--mode`, `--url`, `--dir`, `--out`, `--strict`.
- `compliance/runner/library.go` — `LibraryBackend` implementa el execution contract de ACP-RISK-2.0 §4: `Evaluate()` stateless → `AddRequest()` → `AddPattern()` (siempre, alimenta Rule 3 de F_anom) → `AddDenial()` (condicional) → `ShouldEnterCooldown()` → `SetCooldown(agentID, now.Add(period))`.
- `compliance/runner/http.go` — `HTTPBackend` para validar implementaciones externas via HTTP POST.
- `compliance/runner/report.go` — JSON report + resumen stdout. Exit code 1 si algún test falla (CI-ready).

#### Compliance — Sequence Test Vectors (5 vectores)
- `compliance/runner/testcases/cooldown.json` — `SEQ-COOLDOWN-001`: 3 DENIED en 10 min activan cooldown; step 4 (benign) bloqueado con `denied_reason: COOLDOWN_ACTIVE`.
- `compliance/runner/testcases/f_anom_rule3.json` — `SEQ-FANOM-RULE3-001`: mismo patrón agent+cap+resource ≥3 veces activa Rule 3 (+15 RS); decisión APPROVED→ESCALATED en step 4 (pattern_count=3 visible en Evaluate del step 4, ya que AddPattern ocurre después de Evaluate).
- `compliance/runner/testcases/benign_flow.json` — `SEQ-BENIGN-001`: agente legítimo, 3 requests RS=0, todos APPROVED. Valida ausencia de falsos positivos.
- `compliance/runner/testcases/boundary.json` — `SEQ-BOUNDARY-001`: fronteras exactas RS=35→APPROVED, RS=40→ESCALATED, RS=70→DENIED.
- `compliance/runner/testcases/privilege_jump.json` — `SEQ-PRIVJUMP-001`: agente pasa de data.read/public (RS=0, APPROVED) a admin.delete/restricted (RS=105→100, DENIED) en un solo salto.

**Resultado de verificación:** 5/5 PASS | CONFORMANT

**Commits:** EN `0f04c92` / ES `288d3e4`

#### Formal Verification — TLA+ Model
- `tla/ACP.tla` — TLC-runnable TLA+ module. Formalizes ACP-RISK-2.0 evaluation pipeline with three checked properties: `Safety` (APPROVED decisions have RS ≤ 39), `LedgerAppendOnly` (entries never modified/removed), `RiskDeterminism` (same cap+resource always produces same RS). Corrects v1.16 Appendix B: `LedgerAppendOnly` now uses `[][Len(ledger') >= Len(ledger) ∧ ∀i: ledger'[i] = ledger[i]]_ledger`; `RiskDeterminism` now has a concrete `ComputeRisk` function, not an abstract placeholder.
- `tla/ACP.cfg` — TLC configuration. Bounded constants: Agents={"A1","A2"}, Capabilities={"read","write","financial","admin"}, Resources={"public","sensitive","restricted"}, ledger bound=5. Declares INVARIANTS (TypeInvariant, Safety, LedgerAppendOnly, RiskDeterminism) and PROPERTIES (LedgerAppendOnlyTemporal).

#### Compliance — Canonical Sequence Vectors
- `compliance/test-vectors/sequence/` — canonical location for the 5 stateful test vectors (same content as `compliance/runner/testcases/`, referenced by ACR-1.0 runner with `--dir ../test-vectors/sequence`).
- `compliance/test-vectors/sequence/README.md` — format docs, vector table, execution contract summary.

#### Reference Implementation — Post-Quantum Stub
- `impl/go/pkg/sign2/sign2.go` — ACP-SIGN-2.0 §3.1 HYBRID mode. `SignHybrid()`: Ed25519 real + ML-DSA-65 nil stub (TODO v1.18: cloudflare/circl). `VerifyHybrid()`: verifies Ed25519; tolerates nil PQCSig per transition rules §4.2. `HybridSignature` wire format stable. Narrative: crypto-agility by design — migration path defined, implementation staged.

### Pendiente en Sprint F
- `paper/arxiv/main.tex` — Figura TikZ end-to-end verifiability + §Compliance Testing + §Formal Verification upgrade (Appendix B TLC) + §End-to-End Verifiability
- arXiv v4 — timing: esperar anuncio de `submit/7396824`

---

## [1.16.0] — 2026-03-22

### Added

#### Specification
- `spec/security/ACP-RISK-2.0.md` — supersedes RISK-1.0. Introduces `F_anom` (3 deterministic rules): Rule 1 high request rate (>N in 60s, +20), Rule 2 recent denials (≥X in 24h, +15), Rule 3 repeated pattern via `hash(agent_id||capability||resource)` (≥Y in 5min, +15). Cooldown mechanism (§3.5): 3 DENIED in 10min → agent blocked for `cooldown_period`. Full factor breakdown in evaluation record. `LedgerQuerier` interface. Error codes RISK-008/009. Fail-closed design.
- `spec/core/ACP-SIGN-2.0.md` — post-quantum hybrid signing spec. Ed25519 + ML-DSA-65 (NIST FIPS 204 / Dilithium). Three transition modes: `CLASSIC_ONLY → HYBRID → PQC_ONLY`. Policy fields: `acp_sign_mode`, `pqc_required`, `pqc_required_after`. Wire format and signing/verification procedures. Error codes SIGN-010–015. Reference library: `github.com/cloudflare/circl/sign/dilithium`. Go implementation planned for v1.17. "Crypto-agility by design."
- `spec/operations/ACP-LEDGER-1.3.md` — updated for RISK-2.0: `RISK_EVALUATION` event schema adds `f_anom`, `anomaly_detail` (rule1/2/3_triggered), `denied_reason`, `policy_hash` fields. §13 conformance requirement for RISK-2.0 users.

#### Reference Implementation — Go (23 packages)
- `impl/go/pkg/risk/engine.go` — rewritten for ACP-RISK-2.0. `Evaluate()` entry point. `F_anom` with 3 rules, sliding windows, `PatternKey` (SHA-256 hash). Cooldown short-circuit. `LedgerQuerier` interface with `InMemoryQuerier`. `ShouldEnterCooldown()`. Integer arithmetic only, no floats.
- `impl/go/pkg/risk/engine_v2_test.go` — 26 new tests (33 total pass). Covers all F_anom rules, cooldown trigger/expiry, RS boundary cases, anti-gaming vectors.
- `impl/go/pkg/risk/engine_bench_test.go` — 6 benchmarks: `Evaluate` APPROVED (1,012 ns/op), `Evaluate` DENIED (863 ns/op), `Evaluate` all 3 F_anom rules (1,331 ns/op), `Evaluate` COOLDOWN short-circuit (149 ns/op), `PatternKey` SHA-256 (996 ns/op), `ShouldEnterCooldown` (88 ns/op). Measured on Intel i7-8665U @ 1.90GHz, Go 1.22.

#### Compliance — Test Vectors
- `compliance/test-vectors/risk-2.0/` — 65 unsigned RISK-2.0 vectors (23 APPROVED + 19 ESCALATED + 23 DENIED). 6 blocks: base cases, context factors, history factors, F_anom boundaries, complex mixes, anti-gaming/cooldown/autonomy edge cases. Note: unsigned — test the scoring formula, not the cryptographic pipeline.
- `impl/go/cmd/gen-risk2-vectors/main.go` — reproducible generator for RISK-2.0 vectors.
- `compliance/test-vectors/README.md` — updated: 73 signed + 65 unsigned = 138 total vectors.

#### API
- `openapi/acp-api-1.0.yaml` — endpoint 18: `GET /audit/agent/{id}?window=24h` — agent decision timeline with full F_anom inputs, cooldown state, and factor breakdown per ACP-RISK-2.0 §6. New schemas: `AgentAuditData`, `AgentDecisionEvent`. Total: 18 endpoints.

#### Demo
- `examples/payment-agent/` — payment-agent killer demo. Executable Go server. `POST /admission` → RISK-2.0 evaluation → decision + factor breakdown. Cooldown auto-triggers after 3 DENIED in 10min. Append-only in-memory ledger. `GET /audit/agent/{id}` (endpoint 18). 5 documented scenarios. `go run .` → server on :8080.

#### Paper (local, gitignored)
- `paper/arxiv/main.tex` — updated to v1.16: benchmark table (real ns/op data), Appendix B formal verification sketch (TLA+ module with `Safety`, `LedgerAppendOnly`, `RiskDeterminism` invariants + `THEOREM SafetyAndDeterminism`), roadmap and conclusion updated.

### Published
- **Zenodo:** `10.5281/zenodo.19185033` — ACP v1.16 specification archive. https://zenodo.org/records/19185033
- **arXiv:** `2603.18829` — v3 submitted as `submit/7396824` (replacement). Pending announcement.

---

## [1.15.0] — 2026-03-21

### Added

#### API
- `openapi/acp-api-1.0.yaml` — T5 extended: 17 endpoints covering POLICY-CTX-1.1 + REP-PORTABILITY-1.1. New endpoints: `GET /policy/context/{agent_id}`, `GET /policy/context/history/{agent_id}`, `POST /policy/context/validate`, `GET /reputation/export/{agent_id}`, `GET /reputation/diff`. New schemas: `PolicyContext`, `PolicyContextHistory`, `ReputationExport`.

#### Python SDK — Integrations (GAP-A complete)
- `impl/python/examples/langchain_agent_demo.py` — `@acp_tool()` decorator factory for LangChain. 5 scenarios. `--with-llm` flag for ReAct agent.
- `impl/python/examples/pydantic_ai_demo.py` — `ACPAdmissionGuard` as Pydantic AI `deps`. DENIED/ESCALATED → `ModelRetry`.
- `impl/python/examples/mcp_server_demo.py` — `ACPToolDispatcher`: ACP admission check in MCP dispatch layer. FastMCP-compatible via `dispatcher.mount()`.

### Fixed
- Website HTML audit: corrected version references, updated stats, synchronized EN/ES pages.

---

## [1.14.0] — 2026-03-20

### Added

#### Specification
- `spec/reputation/ACP-REP-PORTABILITY-1.1.md` — supersedes 1.0. Temporal validity enforcement: `valid_from` / `valid_until` per record. Divergence detection: `divergence_flag` when δ > threshold. Portability export signed with institutional key.

#### Demo
- `examples/multi-org-demo/` — GAP-14 multi-org interoperability demo. Org-A issues tokens, Org-B validates cross-org delegation. Docker Compose (`docker-compose.yml`). `go run .` → both orgs on :8080/:8081.

#### Compliance
- `compliance/test-vectors/` — 73 signed test vectors total: 8 CORE + 4 DCMA + 10 HP + 11 LEDGER + 9 EXEC + 9 PROV + 13 PCTX + 9 REP. All carry real Ed25519 signatures over SHA-256(JCS).

### Published
- **arXiv:** `2603.18829` — v1 live (cs.CR primary, cs.AI cross-list).
- **Zenodo:** `10.5281/zenodo.19135282` — ACP v1.14 specification archive.

---

## [1.13.0] — 2026-03-18

### Added

#### Specification
- `spec/core/ACP-DCMA-1.1.md` — supersedes DCMA-1.0. Max depth 7 hops (S-3). Delegation record schema with `delegation_chain_id`, `hop_index`, `delegator_agent_id`, `delegatee_agent_id`. Non-escalation property formally stated.
- `spec/core/ACP-CROSS-ORG-1.1.md` — supersedes CROSS-ORG-1.0. Fault-tolerant bilateral protocol (GAP-10). §9.1 State Invariants. §13.1 Security Considerations. `VerifyBundle()`, `SignBundle()`, `BuildAck()`, `VerifyAck()`.
- `spec/operations/ACP-POLICY-CTX-1.1.md` — supersedes POLICY-CTX-1.0. Temporal validity enforcement for policy snapshots. `valid_from` / `valid_until` on `PolicySnapshot`. Error code PCTX-009 for expired snapshot.

### Published
- **arXiv submission initiated.** arXiv ID: `2603.18829`. Zenodo v1.13: `10.5281/zenodo.19077019`.

---

## [1.12.0] — 2026-03-17

### Added
- `compliance/test-vectors/TS-PROV-*` — 9 new conformance vectors for ACP-PROVENANCE-1.0: TS-PROV-POS-001 (valid 2-hop chain), TS-PROV-POS-002 (direct institutional authorization), TS-PROV-NEG-001..007 (PROV-001/002/003/004/005/007/009 error codes). Real Ed25519 signatures over SHA-256(JCS). **Total: 51 vectors** (8 CORE + 4 DCMA + 10 HP + 11 LEDGER + 9 EXEC + 9 PROV)
- `impl/go/cmd/gen-prov-vectors/main.go` — generator for TS-PROV-* vectors using RFC 8037 test key A
- `paper/arxiv/` — LaTeX source (`main.tex`), bibliography (`references.bib`), submission guide (`SUBMIT.md`) for arXiv cs.CR + cs.AI submission
- `paper/arxiv/SUBMIT.md` — full submission guide: steps, metadata, abstract, endorsement, post-acceptance

### Fixed
- Dependency graph circularity (S-3): `ACP-DCMA-1.0` — removed `ACP-LEDGER-1.2` from Depends-on; `ACP-LEDGER-1.3` — removed `ACP-LIA-1.0` and `ACP-PSN-1.0` from Depends-on; `ACP-EXEC-1.0` — removed `ACP-API-1.0` from Depends-on. Dependency graph is now acyclic and resolvable.

### Changed
- `README.md` — vector coverage row updated: CORE · DCMA · HP · LEDGER · EXEC · PROV; 42→51 vectors; DOI badge updated to `10.5281/zenodo.19077019`
- `paper/draft/ACP-Whitepaper-v1.0.md` — updated to v1.12: 42→51 vectors, PROV coverage added
- `paper/arxiv/main.tex` — 42→51 vectors in all tables

---

## [1.11.0] — 2026-03-16

### Added

#### Specification
- `spec/governance/ACP-CONF-1.2.md` — normative conformance specification superseding CONF-1.1. Corrects L1 (adds AGENT-1.0, DCMA-1.0, MESSAGES-1.0), L3 (adds PROVENANCE-1.0, POLICY-CTX-1.0, PSN-1.0), L4 (adds GOV-EVENTS-1.0, LIA-1.0, HIST-1.0, NOTIFY-1.0, DISC-1.0, BULK-1.0, CROSS-ORG-1.0, REP-PORTABILITY-1.0; updates REP-1.1→1.2, LEDGER-1.2→1.3). Appendix A: mapping from CONF-1.1. Appendix B: deprecated profiles.
- `spec/operations/ACP-LEDGER-1.3.md` — supersedes LEDGER-1.2. `sig` is normative MUST on all production events. LEDGER-012 error code for absent signature. Removes dev-mode ambiguity from §4.4.
- `archive/specs/` — superseded specs moved here with Superseded headers: ACP-CONF-1.0, ACP-CONF-1.1, ACP-LEDGER-1.2, ACP-REP-1.1, ACP-AGENT-SPEC-0.3. `archive/specs/README.md` created.
- `openapi/acp-api-1.0.yaml` — OpenAPI 3.1.0 for all ACP-API-1.0 endpoints (12 endpoints). Security: ACPAgent (Authorization header) + ACPPoP (X-ACP-PoP header). Complete schemas and reusable error responses.
- `ARCHITECTURE.md` — formal domain model: 8 domain concepts, 8-layer governance stack, directed dependency graph (ASCII), 10-step execution lifecycle, 7 formal properties (P-INVARIANT, P-NON-ESCALATION, P-TEMPORAL, P-CHAIN-COMPLETENESS, P-IMMUTABILITY, P-PORTABILITY, P-REVOCABILITY).

#### Compliance — Test Vectors (42 total)
- `TS-HP-POS-001/002`, `TS-HP-NEG-001..008` — 10 vectors for ACP-HP-1.0 (HP-004/006/007/008/009/010/011/014 error codes). Real Ed25519 signatures.
- `TS-LEDGER-POS-001..003`, `TS-LEDGER-NEG-001..008` — 11 vectors for ACP-LEDGER-1.3 (LEDGER-002/003/004/005/006/008/010/012 error codes). Hash chains with SHA-256, real Ed25519 signatures.
- `TS-EXEC-POS-001/002`, `TS-EXEC-NEG-001..007` — 9 vectors for ACP-EXEC-1.0 (EXEC-001..007 error codes). Real Ed25519 execution tokens.
- `impl/go/cmd/gen-ledger-vectors/main.go` — LEDGER vector generator
- `impl/go/cmd/gen-exec-vectors/main.go` — EXEC vector generator
- `impl/go/cmd/acp-sign-vectors/main.go` — rewritten: correct path, HP support

#### Reference Implementation — Go (23 packages)
- `impl/go/pkg/provenance/` — ACP-PROVENANCE-1.0: `Issue()`, `VerifySig()`, `ValidateChain()`, `InMemoryProvenanceStore`. Sentinels PROV-001..009.
- `impl/go/pkg/policyctx/` — ACP-POLICY-CTX-1.0: `Capture()`, `VerifySig()`, `VerifyPolicyHash()`, `ComputePolicyHash()`, `InMemorySnapshotStore`. Sentinels PCTX-001..008.
- `impl/go/pkg/govevents/` — ACP-GOV-EVENTS-1.0: `Emit()`, `VerifySig()`, `IsValidEventType()`, `InMemoryEventStream` with `List(QueryFilter)`. 10 normative payload types. Sentinels GEVE-001..007.
- `impl/go/pkg/lia/` — ACP-LIA-1.0: `Emit()` with §6 assignee resolution (3 rules), `InMemoryLiabilityStore`. Sentinels LIA-001..008.
- `impl/go/pkg/hist/` — ACP-HIST-1.0: `Query()` with full filtering + cursor pagination, `AgentHistory()`, `Export()` (signed ExportBundle). Sentinels HIST-001..007.
- `impl/go/pkg/notify/` — ACP-NOTIFY-1.0: `Subscribe()`, `BuildPayload()`, `VerifyPayloadSig()`, `InMemorySubscriptionStore` with secret rotation. Sentinels NOTI-001..005.
- `impl/go/pkg/disc/` — ACP-DISC-1.0: `Register()` with TTL, expiry-aware `Query(QueryFilter)`, `InMemoryDiscoveryRegistry`. Sentinels DISC-001..004.
- `impl/go/pkg/bulk/` — ACP-BULK-1.0: `ValidateBatchRequest()` (max 100), `ValidateLiabilityQuery()` (max 1000). Sentinels BULK-001..005.
- `impl/go/pkg/crossorg/` — ACP-CROSS-ORG-1.0: `VerifyBundle()`, `SignBundle()`, `BuildAck()`, `VerifyAck()`, `InMemoryCrossOrgStore`. Sentinels CROSS-001..010.
- `impl/go/pkg/pay/` — ACP-PAY-1.0: `VerifyToken()` with double-spend detection by ProofID, `InMemoryPayStore`. Sentinels PAY-001..006+010.
- `impl/go/pkg/psn/` — ACP-PSN-1.0: `Create()`, `Transition()` (atomic under write lock), `VerifySig()`, `InMemorySnapshotStore`. Sentinels PSN-001..007.
- `impl/go/pkg/ledger/` — Updated: 6 new event type constants (`LIABILITY_RECORD`, `POLICY_SNAPSHOT_CREATED`, `REPUTATION_UPDATED`, `PROVENANCE`, `POLICY_SNAPSHOT`, `GOVERNANCE`); verifier enforces LEDGER-008/010/011/012; Version→"1.3".
- `impl/go/pkg/iut/evaluator.go` — Added `SignPoP()` per ACP-HP-1.0 §9.

#### Python SDK & Integrations
- `impl/python/examples/admission_control_demo.py` — `ACPAdmissionGuard` pattern, offline + online modes, 4 scenarios (APPROVED/ESCALATED/DENIED).
- `impl/python/examples/langchain_agent_demo.py` — `@acp_tool()` decorator factory for LangChain. 5 scenarios. `--with-llm` flag for ReAct agent.
- `impl/python/examples/pydantic_ai_demo.py` — `ACPAdmissionGuard` as Pydantic AI `deps`. DENIED/ESCALATED → `ModelRetry`.
- `impl/python/examples/mcp_server_demo.py` — `ACPToolDispatcher`: ACP admission check in MCP dispatch layer. FastMCP-compatible via `dispatcher.mount()`.
- `impl/python/examples/README.md` — index with decision table (APPROVED/ESCALATED/DENIED) for all 4 demos.
- `impl/python/README.md` — SDK README (was missing; caused `pip install -e .` failure).

#### Documentation
- `docs/admission-flow.md` — complete admission check flow guide: 6 steps, error codes, DCMA, cross-org, L1–L4 table, Go + Python examples.
- `paper/draft/ACP-Whitepaper-v1.0.md` — updated to v1.11: §1.2 admission control framing, §8 rewritten (36 specs, 23 Go packages, 51 vectors).
- `Makefile` — `make run`, `make test`, `make docker-build` targets.
- `.env.example` — reference environment configuration.

### Changed
- `README.md` — rewritten: "Admission control for agent actions" tagline; "ACP as Admission Control" section with 6-step flow; ACP vs OPA/IAM/OAuth2/SPIFFE comparison table; admission-framing throughout; roadmap updated.
- `QUICKSTART.md` — rewritten: repo structure aligned (spec/, openapi/, compliance/, impl/go/); Docker zero-setup; Python demo card; corrected impl/go clone path.

---

## [1.10.0] — 2026-03-11

### Added

#### Repository Restructure
- New directory layout: `spec/core/`, `spec/security/`, `spec/operations/`, `spec/governance/`, `spec/decentralized/`; `impl/go/`, `impl/python/`, `impl/rust/`, `impl/typescript/`; `compliance/test-vectors/`; `paper/draft/`, `paper/figures/`; `openapi/`; `docs/`
- `archive/specs/` — placeholder for superseded specifications

#### Evidence Layer Specifications
- `spec/core/ACP-PROVENANCE-1.0.md` — Authority Provenance: structured artifact proving retrospectively from where authority originated at execution time. Distinguishes from DCMA (how to delegate) — this proves the authority chain for audit.
- `spec/operations/ACP-POLICY-CTX-1.0.md` — Policy Context Snapshot: signed point-in-time capture of active policies at action time. Critical for compliance and legal disputes.
- `spec/governance/ACP-GOV-EVENTS-1.0.md` — Governance Event Stream: formal taxonomy of 10 institutional event types (delegation_revoked, agent_suspended, policy_updated, authority_transferred, sanction_applied, capability_suspended, agent_reactivated, delegation_extended, policy_rolled_back, institution_federated).

#### Documentation
- `ARCHITECTURE.md` — formal domain model: 8 concepts (Actor, Agent `A=(ID,C,P,D,L,S)`, Institution, Authority, Interaction, Attestation, History, Reputation), 8-layer governance stack, directed dependency graph, 10-step execution lifecycle, 7 formal properties.
- `docs/architecture-overview.md` — Agent Governance Stack, ACP positioning, layer descriptions.
- `docs/quickstart.md` — conformance levels, spec pointers, implementation paths.
- `docs/faq.md` — what is ACP, relationship to MIR/ARAF, provenance vs delegation, decentralized variant.

---

## [1.9.0] — 2026-03-09

### Added

#### ACP-HIST-1.0 — History Query API
- `GET /acp/v1/audit/query` — filtered, paginated ledger query (event_type, agent_id, institution_id, capability, resource, decision, from_ts, to_ts, from_seq, to_seq, cursor, limit, verify_chain)
- `GET /acp/v1/audit/events/{event_id}` — single event lookup with hash + sig verification
- `GET /acp/v1/audit/agents/{agent_id}/history` — consolidated agent history with computed summary
- `POST /acp/v1/audit/export` — signed, self-verifiable ExportBundle for cross-institutional audit trail sharing
- Cursor-based pagination with 24h expiration
- Role-based authorization model: SYSTEM / SUPERVISOR / AGENT / EXTERNAL_AUDITOR
- On-demand `verify_chain` support; `chain_valid` field in all responses
- Archived event coverage (cold storage 90d–7y) with `X-ACP-Archive-Latency-Seconds` header
- Errors HIST-E001..HIST-E032

#### ACP-ITA-1.1 — Inter-Authority Federation
- FederationRecord: bilaterally signed agreement with dual sig (ARK_A + ARK_B)
- 3-phase establishment protocol (OOB proposal → bilateral signing → activation)
- `GET /ita/v1/federation` — list of active federations for the authority
- `GET /ita/v1/federation/{federation_id}` — complete FederationRecord with both signatures
- `GET /ita/v1/federation/resolve/{institution_id}` — cross-authority institution resolution
- `POST /ita/v1/revocation-notify` — revocation propagation to federated peers
- Cross-authority resolution algorithm (9 steps, no direct trust in remote ITA)
- Non-transitive federation (max 1 direct hop)
- Federation termination: mutual and unilateral with 7-day grace period
- ACP-REP-1.2 integration: cross-institutional events require §8 verification for weight 1.0 in ERS
- Errors ITA-F001..ITA-F016

---


---

## [1.8.0] — 2026-03-09

### Added — ACP-REP-1.2 (Reputation & Trust Layer)

- **`03-acp-protocol/specification/security/ACP-REP-1.2.md`** — Full specification superseding ACP-REP-1.1. Closes L7 of the Agent Governance Stack (ACP-AGS-1.0)
  - **ExternalReputationScore (ERS):** formal external score computed from `REPUTATION_UPDATED` events in ACP-LEDGER-1.1 via weighted moving average by context and time
  - **Dual Trust Model:** formalization of ITS (InternalTrustScore, institutional private) vs ERS (ExternalReputationScore, portable external ecosystem)
  - **Dual Trust Bootstrap:** institution-signed TrustAttestation; `bootstrap_value = internal_score · discount_factor`; effective ceiling 0.195 to prevent artificial inflation
  - **Reputation Decay:** exponential ERS degradation on inactivity; 90-day grace period, 180-day half-life, floor 0.10; does not apply to ITS
  - **New endpoint `GET /acp/v1/rep/{agent_id}/score`:** fast query for authorization hot path; returns `composite_score = 0.6·ITS + 0.4·ERS`; 120 rpm rate limit
  - **New endpoint `POST /acp/v1/rep/{agent_id}/bootstrap`:** institutional TrustAttestation issuance with full validations
  - **Extended `ReputationStore` interface:** 6 new methods for ERS and attestation management
  - **Extended `ReputationConfig`:** 10 new parameters (ERS, decay, composite weights, bootstrap)
  - **Errors REP-E008 to REP-E015** — 8 new error codes
  - **ACP-RISK-1.0 integration:** composite_score → reputational_risk_modifier mapping
  - **ACP-LEDGER-1.1 integration:** consumption by `evaluation_context`; auditable decay events

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

[1.12.0]: https://github.com/chelof100/acp-framework-en/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/chelof100/acp-framework-en/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/chelof100/acp-framework-en/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/chelof100/acp-framework-en/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/chelof100/acp-framework-en/compare/v1.6.0...v1.8.0
[1.6.0]: https://github.com/chelof100/acp-framework-en/compare/v1.4.0...v1.6.0
[1.4.0]: https://github.com/chelof100/acp-framework-en/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/chelof100/acp-framework-en/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/chelof100/acp-framework-en/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/chelof100/acp-framework-en/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/chelof100/acp-framework-en/releases/tag/v1.0.0
