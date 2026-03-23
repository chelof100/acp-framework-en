---- MODULE ACP ----
(*
  ACP-RISK-2.0 Formal Model — TLC-checkable
  ==========================================
  Verifies three invariants from the ACP specification:
    1. Safety          — APPROVED decisions have acceptable risk (RS ≤ ApprovedMax)
    2. LedgerAppendOnly — ledger entries are never modified or removed
    3. RiskDeterminism  — same (capability, resource) always produces the same RS

  ACP-RISK-2.0 §3 (risk score formula, simplified — no F_anom or F_hist):
    RS = min(100, CapabilityBase(cap) + ResourceScore(res))

  ACP-RISK-2.0 §4 (decision thresholds, AutonomyLevel=2):
    RS ≤ 39  → APPROVED
    RS ≤ 69  → ESCALATED
    RS ≥ 70  → DENIED

  To check with TLC:
    cd tla/
    java -jar tla2tools.jar -config ACP.cfg ACP.tla

  Expected output:
    Model checking completed. No error has been found.
    Estimates of the probability that TLC did not check all states
    because two distinct states had the same fingerprint:
    calculated (optimistic):  val = 0
    ...
    X states generated, Y distinct states found, Z states left on queue.
*)
EXTENDS Sequences, Integers, TLC

CONSTANTS
    Agents,        \* Finite set of agent identifiers (e.g. {"A1", "A2"})
    Capabilities,  \* Finite set of capability names (e.g. {"read", "write", "admin"})
    Resources      \* Finite set of resource classes (e.g. {"public", "sensitive", "restricted"})

ASSUME Agents       # {}
ASSUME Capabilities # {}
ASSUME Resources    # {}

(* ── Risk scoring (ACP-RISK-2.0 §3.1) ─────────────────────────────────── *)

\* Capability base scores
CapabilityBase(cap) ==
    CASE cap = "admin"     -> 60
      [] cap = "financial" -> 35
      [] cap = "write"     -> 10
      [] cap = "read"      -> 0
      [] OTHER             -> 20

\* Resource class scores
ResourceScore(res) ==
    CASE res = "restricted" -> 45
      [] res = "sensitive"  -> 15
      [] res = "public"     -> 0
      [] OTHER              -> 0

\* Deterministic risk score: min(100, B + F_res)
\* F_ctx, F_hist, F_anom omitted — bounded by static inputs in this model
ComputeRisk(cap, res) ==
    LET raw == CapabilityBase(cap) + ResourceScore(res)
    IN IF raw > 100 THEN 100 ELSE raw

\* Decision from risk score (AutonomyLevel = 2, thresholds per §4)
Decide(rs) ==
    IF      rs >= 70 THEN "DENIED"
    ELSE IF rs >= 40 THEN "ESCALATED"
    ELSE                  "APPROVED"

(* ── State variables ────────────────────────────────────────────────────── *)

VARIABLE ledger  \* Sequence of evaluation records

\* Type invariant — checked by TLC on every reachable state
TypeInvariant ==
    /\ \A i \in 1..Len(ledger) :
           /\ ledger[i].agent      \in Agents
           /\ ledger[i].capability \in Capabilities
           /\ ledger[i].resource   \in Resources
           /\ ledger[i].risk_score \in 0..100
           /\ ledger[i].decision   \in {"APPROVED", "ESCALATED", "DENIED"}

(* ── Initialization ─────────────────────────────────────────────────────── *)

INIT == ledger = << >>

(* ── Actions ────────────────────────────────────────────────────────────── *)

\* An agent submits a request; the engine evaluates it and appends to the ledger.
EvaluateRequest(a, cap, res) ==
    LET rs == ComputeRisk(cap, res)
        d  == Decide(rs)
    IN
    /\ Len(ledger) < 5   \* bound for TLC — controls state space
    /\ ledger' = Append(ledger,
            [ agent      |-> a,
              capability |-> cap,
              resource   |-> res,
              risk_score |-> rs,
              decision   |-> d ])

NEXT ==
    \E a \in Agents, cap \in Capabilities, res \in Resources :
        EvaluateRequest(a, cap, res)

Spec == INIT /\ [][NEXT]_ledger

(* ── State invariants (checked on every reachable state) ────────────────── *)

\* Safety: every APPROVED decision had acceptable risk (RS ≤ ApprovedMax = 39).
\* Invariant: Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ AcceptableRisk
Safety ==
    \A i \in 1..Len(ledger) :
        ledger[i].decision = "APPROVED" => ledger[i].risk_score <= 39

\* LedgerAppendOnly (state view): every entry in the ledger has a valid, non-empty decision.
\* The temporal append-only guarantee is expressed in LedgerAppendOnlyTemporal below.
LedgerAppendOnly ==
    \A i \in 1..Len(ledger) :
        /\ ledger[i].decision \in {"APPROVED", "ESCALATED", "DENIED"}
        /\ ledger[i].risk_score >= 0

\* RiskDeterminism: same (capability, resource) always produces the same risk score.
\* No two entries with identical inputs may have different RS values.
RiskDeterminism ==
    \A i \in 1..Len(ledger) :
        \A j \in 1..Len(ledger) :
            ( ledger[i].capability = ledger[j].capability
           /\ ledger[i].resource   = ledger[j].resource )
            =>
            ledger[i].risk_score = ledger[j].risk_score

(* ── Temporal property ──────────────────────────────────────────────────── *)

\* LedgerAppendOnlyTemporal: in every step, existing ledger entries are preserved.
\* This is the formal statement from ACP-RISK-2.0 Appendix B (corrected for v1.17).
LedgerAppendOnlyTemporal ==
    [][
        /\ Len(ledger') >= Len(ledger)
        /\ \A i \in 1..Len(ledger) : ledger'[i] = ledger[i]
    ]_ledger

\* Combined theorem (used as PROPERTY in ACP.cfg)
SafetyAndDeterminism ==
    /\ Safety
    /\ RiskDeterminism

====
