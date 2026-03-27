---- MODULE ACP_Extended ----
(*
  ACP-RISK-2.0 Extended Formal Model — TLC-checkable
  ====================================================
  Extends the ACP.tla base model with:
    - Per-agent cooldown temporal state (discrete time)
    - Cooldown enforcement (safety) and expiration (liveness)
    - Denial threshold → cooldown activation
    - Static delegation chain integrity

  New safety invariants (beyond ACP.tla):
    CooldownEnforced       — active cooldown forces DENIED decision
    CooldownImpliesThreshold — cooldown only exists after denial threshold
    DelegationIntegrity    — no consecutive self-delegation in chain

  New temporal property:
    CooldownExpires        — cooldown eventually expires
                             (requires WF_vars(Tick) in Spec)

  Design decisions:
    - Risk score (RS) is always ComputeRisk(cap, res) — deterministic,
      independent of cooldown. Cooldown overrides the decision, not the RS.
      This preserves RiskDeterminism from ACP.tla.
    - denial_count is incremented only for RS-based DENIED decisions,
      not for cooldown-forced DENIED. This models ACP-RISK-2.0 §4 faithfully:
      SetCooldown is triggered by real denials, not cooldown re-enforcement.
      (Approximation: the per-window decay of denial counts is not modeled;
       denial_count is monotone within a bounded trace.)
    - DelegationChain is a static CONSTANT (chain = <<A1, A2>>).
      Dynamic chain mutation is out of scope for v1.20.
    - time horizon bounded by MAX_TIME for TLC tractability.

  To check with TLC:
    cd tla/
    java -jar tla2tools.jar -config ACP_Extended.cfg ACP_Extended.tla

  Expected output:
    Model checking completed. No error has been found.
    X states generated, Y distinct states found, Z states left on queue.
*)

EXTENDS Sequences, Integers, TLC

CONSTANTS
    Agents,           \* Finite set of agent identifiers, e.g. {"A1", "A2"}
    Capabilities,     \* Finite set of capability names
    Resources,        \* Finite set of resource classes
    COOLDOWN_TRIGGER, \* Denial threshold to enter cooldown (e.g. 3)
    COOLDOWN_WINDOW,  \* Cooldown duration in time ticks (e.g. 3)
    MAX_TIME          \* Time horizon bound for TLC tractability (e.g. 5)

\* Static delegation chain: A1 delegates to A2 (ACP-DCMA-1.1 §3).
\* Hardcoded for the bounded model (TLC CFG does not support sequence literals).
\* Paper framing: models a 2-hop chain; dynamic chain mutation is out of scope (v1.21).
DelegationChain == <<"A1", "A2">>

ASSUME Agents       # {}
ASSUME Capabilities # {}
ASSUME Resources    # {}
ASSUME COOLDOWN_TRIGGER \in Nat /\ COOLDOWN_TRIGGER > 0
ASSUME COOLDOWN_WINDOW  \in Nat /\ COOLDOWN_WINDOW > 0
ASSUME MAX_TIME \in Nat /\ MAX_TIME >= COOLDOWN_WINDOW

(* ── Risk scoring (ACP-RISK-2.0 §3.1, simplified — no F_anom/F_hist) ────── *)

\* Capability base scores
CapabilityBase(cap) ==
    CASE cap = "admin"     -> 60
      [] cap = "financial" -> 35
      [] cap = "read"      -> 0
      [] OTHER             -> 10

\* Resource class scores
ResourceScore(res) ==
    CASE res = "sensitive" -> 15
      [] res = "public"    -> 0
      [] OTHER             -> 0

\* Deterministic risk score: min(100, B + F_res)
ComputeRisk(cap, res) ==
    LET raw == CapabilityBase(cap) + ResourceScore(res)
    IN IF raw > 100 THEN 100 ELSE raw

\* Decision from risk score (AutonomyLevel = 2, ACP-RISK-2.0 §4)
Decide(rs) ==
    IF      rs >= 70 THEN "DENIED"
    ELSE IF rs >= 40 THEN "ESCALATED"
    ELSE                  "APPROVED"

(* ── State variables ─────────────────────────────────────────────────────── *)

VARIABLES
    ledger,          \* Seq of eval records — append-only (from ACP.tla)
    now,             \* Nat: discrete time counter
    denial_count,    \* [Agents -> Nat]: per-agent RS-based denial accumulator
    cooldown_until   \* [Agents -> Nat]: per-agent cooldown expiry tick

vars == <<ledger, now, denial_count, cooldown_until>>

(* ── Helpers ─────────────────────────────────────────────────────────────── *)

\* Agent a is currently in cooldown
CooldownActive(a) == cooldown_until[a] > now

(* ── Type invariant ─────────────────────────────────────────────────────── *)

TypeInvariant ==
    /\ \A i \in 1..Len(ledger) :
           /\ ledger[i].agent            \in Agents
           /\ ledger[i].capability       \in Capabilities
           /\ ledger[i].resource         \in Resources
           /\ ledger[i].risk_score       \in 0..100
           /\ ledger[i].decision         \in {"APPROVED", "ESCALATED", "DENIED"}
           /\ ledger[i].cooldown_at_eval \in BOOLEAN
    /\ now \in 0..MAX_TIME
    /\ \A a \in Agents : denial_count[a]  \in Nat
    /\ \A a \in Agents : cooldown_until[a] \in 0..(MAX_TIME + COOLDOWN_WINDOW)

(* ── Initialization ─────────────────────────────────────────────────────── *)

INIT ==
    /\ ledger        = << >>
    /\ now           = 0
    /\ denial_count  = [a \in Agents |-> 0]
    /\ cooldown_until = [a \in Agents |-> 0]

(* ── Actions ─────────────────────────────────────────────────────────────── *)

\* Discrete time advances by one tick.
\* Bounded by MAX_TIME for TLC tractability.
\* WF_vars(Tick) in Spec ensures time eventually advances (liveness).
Tick ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED <<ledger, denial_count, cooldown_until>>

\* An agent submits a request; engine evaluates and updates state atomically.
\* Models ACP-RISK-2.0 execution contract §4 (simplified):
\*   - RS is always ComputeRisk(cap, res) — cooldown overrides decision, not RS.
\*   - denial_count increments only for RS-based DENIED (not cooldown-forced).
\*   - SetCooldown fires when denial_count crosses COOLDOWN_TRIGGER and
\*     cooldown was NOT already active (idempotent per ACP-RISK-2.0 §4).
EvaluateRequest(a, cap, res) ==
    LET cd_active == CooldownActive(a)
        rs        == ComputeRisk(cap, res)
        d         == IF cd_active THEN "DENIED" ELSE Decide(rs)
        entry     == [ agent            |-> a,
                       capability       |-> cap,
                       resource         |-> res,
                       risk_score       |-> rs,
                       decision         |-> d,
                       cooldown_at_eval |-> cd_active ]
        \* Count only RS-based denials (ACP-RISK-2.0 §4 — AddDenial condition)
        new_denial_count ==
            IF d = "DENIED" /\ ~cd_active
            THEN [denial_count EXCEPT ![a] = denial_count[a] + 1]
            ELSE denial_count
        threshold_crossed == new_denial_count[a] >= COOLDOWN_TRIGGER
        \* SetCooldown only when threshold just crossed and no active cooldown
        new_cooldown_until ==
            IF threshold_crossed /\ ~cd_active
            THEN [cooldown_until EXCEPT ![a] = now + COOLDOWN_WINDOW]
            ELSE cooldown_until
    IN
    /\ Len(ledger) < 5
    /\ ledger'         = Append(ledger, entry)
    /\ denial_count'   = new_denial_count
    /\ cooldown_until' = new_cooldown_until
    /\ UNCHANGED now

Next ==
    \/ Tick
    \/ \E a \in Agents, cap \in Capabilities, res \in Resources :
           EvaluateRequest(a, cap, res)

\* WF_vars(Tick) ensures time eventually advances — required for CooldownExpires
Spec == INIT /\ [][Next]_vars /\ WF_vars(Tick)

(* ── Safety invariants ───────────────────────────────────────────────────── *)

\* From ACP.tla: APPROVED decisions had acceptable risk
Safety ==
    \A i \in 1..Len(ledger) :
        ledger[i].decision = "APPROVED" => ledger[i].risk_score <= 39

\* From ACP.tla: ledger entries are well-formed
LedgerAppendOnly ==
    \A i \in 1..Len(ledger) :
        /\ ledger[i].decision    \in {"APPROVED", "ESCALATED", "DENIED"}
        /\ ledger[i].risk_score  >= 0

\* From ACP.tla: same (cap, res) always produces the same RS
\* Holds because RS = ComputeRisk(cap, res) regardless of cooldown state.
RiskDeterminism ==
    \A i \in 1..Len(ledger) :
        \A j \in 1..Len(ledger) :
            ( ledger[i].capability = ledger[j].capability
           /\ ledger[i].resource   = ledger[j].resource )
            =>
            ledger[i].risk_score = ledger[j].risk_score

\* NEW: active cooldown forces DENIED — core safety property (ACP-RISK-2.0 §4, Step 2)
CooldownEnforced ==
    \A i \in 1..Len(ledger) :
        ledger[i].cooldown_at_eval => ledger[i].decision = "DENIED"

\* NEW: cooldown only exists after the denial threshold has been reached
\* Connects TLA+ model to Exp 4 (token replay) denial accumulation.
CooldownImpliesThreshold ==
    \A a \in Agents :
        cooldown_until[a] > now => denial_count[a] >= COOLDOWN_TRIGGER

\* NEW: delegation chain has no consecutive self-delegation (ACP-DCMA-1.1 §3)
DelegationIntegrity ==
    \A i \in 1..Len(DelegationChain) - 1 :
        DelegationChain[i] # DelegationChain[i+1]

(* ── Temporal properties ─────────────────────────────────────────────────── *)

\* From ACP.tla: every existing ledger entry is preserved across steps
LedgerAppendOnlyTemporal ==
    [][
        /\ Len(ledger') >= Len(ledger)
        /\ \A i \in 1..Len(ledger) : ledger'[i] = ledger[i]
    ]_ledger

\* NEW: active cooldown eventually expires — liveness property
\* Requires WF_vars(Tick) in Spec; otherwise now never advances.
\*
\* Conditioned on the cooldown expiry being within the time horizon (MAX_TIME).
\* Rationale: in a bounded time model (now ≤ MAX_TIME), cooldown triggered at
\* now = MAX_TIME has expiry = MAX_TIME + COOLDOWN_WINDOW, which is unreachable.
\* The conditioned form is the correct liveness claim for a bounded model;
\* the unconditional form holds in the unbounded specification.
\*
\* Paper framing: "CooldownExpires verified for all traces where cooldown
\* activation occurs within the time horizon (cooldown_until ≤ MAX_TIME)."
CooldownExpires ==
    \A a \in Agents :
        [](   cooldown_until[a] > now
           /\ cooldown_until[a] <= MAX_TIME
           => <>(now >= cooldown_until[a]))

====
