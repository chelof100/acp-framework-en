# ACP Multi-Org Demo (GAP-14)

Executable demo of cross-organization ACP exchange.
Org-A issues signed artifacts; Org-B independently validates and decides.

Specification reference: [arXiv:2603.18829](https://arxiv.org/abs/2603.18829)

---

## What this demo shows

```
Org-A (issuer)                         Org-B (verifier + decision maker)
──────────────────────────────────────────────────────────────────────────
GET /snapshot
  policyctx.Capture() ──────────────>  policyctx.VerifySig()
  reputation.Capture()                 policyctx.VerifyCaptureFreshness()
  sign both with Ed25519               reputation.Validate()
  return Bundle{pubkey, pcs, rep}      reputation.VerifySig()
                                       reputation.CheckDivergence()
                                         → REP-WARN-002 if divergence > 0.30
                                       ACCEPT / DENY  (Org-B's decision)
```

**ACP principle in action:** Org-B emits `REP-WARN-002` when its local score
diverges from Org-A's. It does **not** override Org-A's score or modify the
snapshot. The final ACCEPT/DENY is Org-B's sovereign decision.

---

## Quick start (< 5 minutes)

### Prerequisites

- Docker >= 24 with Compose v2 (`docker compose` command)
- No other setup required

### Run

```bash
cd examples/multi-org-demo
docker compose up --build
```

Wait for the log line:

```
org-b-1  | [org-b] listening on :8081
```

### Trigger a validation

```bash
curl -s http://localhost:8081/request | jq .
```

Expected output (abbreviated):

```json
{
  "decision": "ACCEPT",
  "agent_id": "agent.example.shopping-assistant",
  "policy_ctx_status": "VALID",
  "rep_status": "VALID",
  "org_a_score": 0.82,
  "org_b_score": 0.55,
  "divergence": 0.27,
  "log": [
    "fetching bundle from http://org-a:8080/snapshot",
    "bundle received — snapshot_id=... rep_id=...",
    "verifying PolicyContextSnapshot (ACP-POLICY-CTX-1.1 §6)...",
    "  [OK] signature verified",
    "  [OK] freshness — delta_max=300s within verifier limit 300s",
    "validating ReputationSnapshot (ACP-REP-PORTABILITY-1.1 §6)...",
    "  [OK] structural validation passed",
    "  [OK] signature verified — issuer=org-a.example.com score=0.8200 scale=0-1",
    "checking score divergence (ACP-REP-PORTABILITY-1.1 §7)...",
    "  [OK] divergence=0.2700 within threshold 0.30 — no warning emitted",
    "computing Org-B decision...",
    "  DECISION: ACCEPT ..."
  ]
}
```

### Trigger REP-WARN-002 (divergence warning)

Edit `org-b/main.go`, change `orgBLocalScore = 0.55` to `orgBLocalScore = 0.40`,
then rebuild:

```bash
docker compose up --build
curl -s http://localhost:8081/request | jq .divergence_warning
```

You will see:

```
"REP-WARN-002: score divergence 0.4200 exceeds threshold 0.30 ..."
```

The decision remains `ACCEPT` — divergence is **informational**, not blocking.

### Custom agent ID

```bash
curl -s "http://localhost:8081/request?agent_id=agent.finance.reconciler" | jq .
```

---

## Architecture

```
examples/multi-org-demo/
├── go.mod                   # separate module; replace → ../../impl/go
├── go.sum
├── Dockerfile               # single Dockerfile, ARG ORG selects the binary
├── docker-compose.yml       # build context = repo root
├── org-a/
│   └── main.go              # issuer: HTTP server on :8080
└── org-b/
    └── main.go              # verifier: HTTP server on :8081
```

### Packages used (no reimplementation)

| Package | Source |
|---------|--------|
| `pkg/policyctx` | `impl/go/pkg/policyctx/policyctx.go` |
| `pkg/reputation` | `impl/go/pkg/reputation/{capture,validate,divergence}.go` |

### Key decisions

| Question | Answer |
|----------|--------|
| Signing | Real Ed25519, generated at Org-A startup |
| Canonicalization | JCS (RFC 8785) via `github.com/gowebpki/jcs` |
| Public key distribution | Org-A includes it in every bundle (demo only; use PKI in production) |
| Divergence | REP-WARN-002, non-blocking (§7 ACP-REP-PORTABILITY-1.1) |
| Verifier override | Org-B cannot extend Org-A's `valid_until` |
| Consensus | ACP does not resolve divergence |

---

## Local build (without Docker)

```bash
cd examples/multi-org-demo

# Build both binaries
go build -o org-a-bin ./org-a
go build -o org-b-bin ./org-b

# Start Org-A
./org-a-bin &

# Start Org-B (pointing to local Org-A)
ORG_A_URL=http://localhost:8080 ./org-b-bin &

curl -s http://localhost:8081/request | jq .
```

---

## Conformance

This demo exercises the following ACP conformance levels:

| Spec | Level | Feature |
|------|-------|---------|
| ACP-POLICY-CTX-1.1 | L3-FULL | `policy_captured_at`, `delta_max`, `VerifyCaptureFreshness` |
| ACP-REP-PORTABILITY-1.1 | L4 | `ver=1.1`, Ed25519 sig, `valid_until`, divergence reporting |
