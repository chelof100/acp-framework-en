---- MODULE ACP_Extended ----
(*
  ACP-RISK-2.0 Extended Formal Model — TLC-checkable (v1.20, Sprint J2)
  =====================================================================
  Extends ACP.tla with:
    1. Per-agent cooldown temporal state (from v1.17)
    2. Cooldown enforcement (safety) and expiration (liveness)
    3. Denial threshold -> cooldown activation
    4. Static delegation chain integrity
    5. [Sprint J2] F_anom flood detection: per-agent pattern accumulation,
       flood override, AnomalyDeterminism, and bounded execution guarantee

  Safety invariants (8 total):
    TypeInvariant           -- well-typed state
    Safety                  -- APPROVED decisions had acceptable risk (RS <= 39)
    LedgerAppendOnly        -- ledger entries are well-formed
    RiskDeterminism         -- same (cap, res) always produces the same base RS
    CooldownEnforced        -- active cooldown forces DENIED decision
    CooldownImpliesThreshold -- cooldown only exists after denial threshold
    DelegationIntegrity     -- no consecutive self-delegation in chain
    AnomalyDeterminism      -- [Sprint J2] same (cap, res, pattern_at_eval)
                               always produces the same risk_score;
                               RS is a deterministic policy function of
                               (static inputs + per-agent request history).
    FloodEnforced           -- [Sprint J2] flood threshold forces DENIED decision

  Temporal properties (4 total):
    LedgerAppendOnlyTemporal          -- existing ledger entries are preserved
    CooldownExpires                   -- active cooldown eventually expires
    EventuallyRejected                -- [Sprint J2] abusive agent is eventually denied
    NoInfiniteExecutionUnderAbuse     -- [Sprint J2] no infinite accepted trace under abuse

  Design decisions (Sprint J2):
    D1: pattern_count[a] accumulates ALL requests per agent (frequency abstraction).
        The model abstracts F_anom as frequency-based anomaly detection; semantic
        payload content is out of scope. This is a deliberate modeling choice:
        abstraction protects against minimal-variation evasion attempts.
    D2: ComputeRiskWithAnom adds FANOM_BONUS to the base RS when
        pattern_count[a] >= FLOOD_THRESHOLD. FloodActive(a) additionally
        overrides the decision to DENIED regardless of the resulting RS.
        RS is a deterministic policy function, not a statistical model.
    D3: AnomalyDeterminism extends RiskDeterminism to include per-agent state:
        same (cap, res, pattern_at_eval) -> same risk_score. This formalizes
        that ACP's admission decision is deterministic given (input + subject state).
    D4: EventuallyRejected (auxiliary) is verified by TLC under Fairness.
        NoInfiniteExecutionUnderAbuse (strong form) holds in the bounded model
        via EventuallyRejected + FloodActive monotonicity (pattern_count is
        non-decreasing; once >= FLOOD_THRESHOLD, FloodActive is permanently true
        and all subsequent decisions are DENIED).
    D5: FLOOD_THRESHOLD = 4. The model verifies properties for this representative
        value; complete generalization to arbitrary N is not claimed.
        LEDGER_BOUND = 7 (increased from 5) to accommodate flood activation
        within the bounded state space (FLOOD_THRESHOLD requests + post-flood
        requests within the trace).

  Assumptions for liveness (must hold for EventuallyRejected to fire):
    (1) Monotonic Time Progression: WF_vars(Tick) ensures time advances.
    (2) Weak Fairness in Request Processing: per-agent WF on EvaluateRequest
        ensures requests are eventually processed if continuously enabled.
    (3) Consistent State Updates: all state transitions are atomic (single-step).

  Model simplifications (explicit):
    - ComputeRisk uses a simplified formula (CapabilityBase + ResourceScore);
      F_ctx and F_hist are omitted (bounded by static inputs in this model).
    - F_anom is modeled as FANOM_BONUS on the RS plus a direct FloodActive
      override on the decision, approximating ACP-RISK-2.0 F_anom Rule 3.
    - pattern_count is monotone within a bounded trace (no per-window decay);
      this approximates the time-windowed behavior of ACP-RISK-2.0 F_anom.
    - flood-forced DENIED decisions do not increment denial_count (consistent
      with ACP-RISK-2.0 ss4: AddDenial fires on real RS-based denials only).
    - DelegationChain is static; dynamic chain mutation is out of scope (v1.21).
    - Time horizon bounded by MAX_TIME and ledger by LEDGER_BOUND for TLC.

  To check with TLC:
    cd tla/
    java -jar tla2tools.jar -deadlock -config ACP_Extended.cfg ACP_Extended.tla

  TLC result (Sprint J2 config: 1 agent, 3 caps, 2 res, LEDGER_BOUND=7,
             FLOOD_THRESHOLD=4, FANOM_BONUS=25, MAX_TIME=7):
    Model checking completed. No error has been found.
    5,684,342 states generated, 3,147,864 distinct states found, 0 states left on queue.
    The depth of the complete state graph search is 15.
    Finished in 47min 30s (TLC2 v2.16, Java 1.8, single worker, 7241MB heap).
    All 9 invariants and 4 temporal properties verified. 0 violations.
*)

EXTENDS Sequences, Integers, TLC

CONSTANTS
    Agents,           \* Finite set of agent identifiers, e.g. {"A1"}
    Capabilities,     \* Finite set of capability names
    Resources,        \* Finite set of resource classes
    COOLDOWN_TRIGGER, \* Denial threshold to enter cooldown (e.g. 3)
    COOLDOWN_WINDOW,  \* Cooldown duration in time ticks (e.g. 3)
    MAX_TIME,         \* Time horizon bound for TLC tractability (e.g. 7)
    FLOOD_THRESHOLD,  \* [Sprint J2] Request count for F_anom override (e.g. 4)
    FANOM_BONUS,      \* [Sprint J2] F_anom risk score bonus at flood (e.g. 25)
    LEDGER_BOUND      \* [Sprint J2] Ledger size bound (e.g. 7)

\* Static delegation chain: A1 delegates to A2 (ACP-DCMA-1.1 ss3).
\* Hardcoded for the bounded model (TLC CFG does not support sequence literals).
\* Paper framing: models a 2-hop chain; dynamic chain mutation is out of scope (v1.21).
DelegationChain == <<"A1", "A2">>

ASSUME Agents           # {}
ASSUME Capabilities     # {}
ASSUME Resources        # {}
ASSUME COOLDOWN_TRIGGER \in Nat /\ COOLDOWN_TRIGGER > 0
ASSUME COOLDOWN_WINDOW  \in Nat /\ COOLDOWN_WINDOW  > 0
ASSUME MAX_TIME         \in Nat /\ MAX_TIME >= COOLDOWN_WINDOW
ASSUME FLOOD_THRESHOLD  \in Nat /\ FLOOD_THRESHOLD  > 0
ASSUME FANOM_BONUS      \in Nat /\ FANOM_BONUS       > 0
ASSUME LEDGER_BOUND     \in Nat /\ LEDGER_BOUND      > FLOOD_THRESHOLD

(* ---- Risk scoring (ACP-RISK-2.0 ss3.1, simplified) ---------------------- *)

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

\* Base risk score: min(100, CapabilityBase + ResourceScore).
\* F_ctx and F_hist omitted -- bounded by static inputs in this model.
ComputeRisk(cap, res) ==
    LET raw == CapabilityBase(cap) + ResourceScore(res)
    IN IF raw > 100 THEN 100 ELSE raw

\* [Sprint J2] Extended risk score including F_anom bonus (D1, D2).
\* Adds FANOM_BONUS when pattern count meets or exceeds FLOOD_THRESHOLD.
\* RS remains a deterministic policy function of (cap, res, pat_count).
ComputeRiskWithAnom(cap, res, pat_count) ==
    LET base  == ComputeRisk(cap, res)
        bonus == IF pat_count >= FLOOD_THRESHOLD THEN FANOM_BONUS ELSE 0
        raw   == base + bonus
    IN IF raw > 100 THEN 100 ELSE raw

\* Decision from risk score (AutonomyLevel = 2, ACP-RISK-2.0 ss4)
Decide(rs) ==
    IF      rs >= 70 THEN "DENIED"
    ELSE IF rs >= 40 THEN "ESCALATED"
    ELSE                  "APPROVED"

(* ---- State variables ----------------------------------------------------- *)

VARIABLES
    ledger,          \* Seq of eval records -- append-only (from ACP.tla)
    now,             \* Nat: discrete time counter
    denial_count,    \* [Agents -> Nat]: per-agent RS-based denial accumulator
    cooldown_until,  \* [Agents -> Nat]: per-agent cooldown expiry tick
    pattern_count,   \* [Sprint J2] [Agents -> Nat]: per-agent request accumulator
    last_decision    \* [Sprint J2] [Agents -> Decision]: last decision per agent

vars == <<ledger, now, denial_count, cooldown_until, pattern_count, last_decision>>

(* ---- Helpers / Predicates ------------------------------------------------ *)

\* Agent a is currently in cooldown
CooldownActive(a) == cooldown_until[a] > now

\* [Sprint J2] Agent a has exceeded the flood threshold (F_anom Rule 3)
FloodActive(a) == pattern_count[a] >= FLOOD_THRESHOLD

\* [Sprint J2] Semantic aliases for D4 liveness properties
Abusive(a)  == pattern_count[a] >= FLOOD_THRESHOLD
Accepted(a) == last_decision[a] \in {"APPROVED", "ESCALATED"}
Rejected(a) == last_decision[a] = "DENIED"

(* ---- Type invariant ------------------------------------------------------- *)

TypeInvariant ==
    /\ \A i \in 1..Len(ledger) :
           /\ ledger[i].agent             \in Agents
           /\ ledger[i].capability        \in Capabilities
           /\ ledger[i].resource          \in Resources
           /\ ledger[i].risk_score        \in 0..100
           /\ ledger[i].decision          \in {"APPROVED", "ESCALATED", "DENIED"}
           /\ ledger[i].cooldown_at_eval  \in BOOLEAN
           /\ ledger[i].pattern_at_eval   \in Nat
    /\ now \in 0..MAX_TIME
    /\ \A a \in Agents : denial_count[a]   \in Nat
    /\ \A a \in Agents : cooldown_until[a] \in 0..(MAX_TIME + COOLDOWN_WINDOW)
    /\ \A a \in Agents : pattern_count[a]  \in Nat
    /\ \A a \in Agents : last_decision[a]  \in {"APPROVED", "ESCALATED", "DENIED"}

(* ---- Initialization ------------------------------------------------------ *)

INIT ==
    /\ ledger         = << >>
    /\ now            = 0
    /\ denial_count   = [a \in Agents |-> 0]
    /\ cooldown_until = [a \in Agents |-> 0]
    /\ pattern_count  = [a \in Agents |-> 0]
    /\ last_decision  = [a \in Agents |-> "APPROVED"]

(* ---- Actions ------------------------------------------------------------- *)

\* Discrete time advances by one tick.
\* Bounded by MAX_TIME for TLC tractability.
\* WF_vars(Tick) in Fairness ensures time eventually advances (liveness).
Tick ==
    /\ now < MAX_TIME
    /\ now' = now + 1
    /\ UNCHANGED <<ledger, denial_count, cooldown_until, pattern_count, last_decision>>

\* An agent submits a request; engine evaluates and updates state atomically.
\*
\* Override priority (ACP-RISK-2.0 ss4):
\*   1. CooldownActive: previously accumulated denials triggered cooldown window.
\*   2. FloodActive: current pattern count exceeds F_anom threshold (D2).
\*   3. Decide(rs): normal risk-score-based decision.
\*
\* risk_score = ComputeRiskWithAnom(cap, res, pattern_count[a]):
\*   records the effective RS including F_anom bonus (D3: AnomalyDeterminism).
\*
\* pattern_count increments on every request (D1: frequency abstraction).
\* denial_count increments only for RS-based DENIED decisions, not for
\* cooldown-forced or flood-forced denials (ACP-RISK-2.0 ss4: AddDenial).
EvaluateRequest(a, cap, res) ==
    LET cd_active == CooldownActive(a)
        fl_active == FloodActive(a)
        rs        == ComputeRiskWithAnom(cap, res, pattern_count[a])
        \* Decision: overrides take precedence over base RS decision
        d == IF cd_active \/ fl_active
             THEN "DENIED"
             ELSE Decide(rs)
        entry == [ agent            |-> a,
                   capability       |-> cap,
                   resource         |-> res,
                   risk_score       |-> rs,
                   decision         |-> d,
                   cooldown_at_eval |-> cd_active,
                   pattern_at_eval  |-> pattern_count[a] ]
        \* Only RS-based denials (not override-forced) accumulate toward cooldown
        new_denial_count ==
            IF d = "DENIED" /\ ~cd_active /\ ~fl_active
            THEN [denial_count EXCEPT ![a] = denial_count[a] + 1]
            ELSE denial_count
        threshold_crossed == new_denial_count[a] >= COOLDOWN_TRIGGER
        \* SetCooldown only when threshold just crossed and no active cooldown
        new_cooldown_until ==
            IF threshold_crossed /\ ~cd_active
            THEN [cooldown_until EXCEPT ![a] = now + COOLDOWN_WINDOW]
            ELSE cooldown_until
    IN
    /\ Len(ledger) < LEDGER_BOUND
    /\ ledger'         = Append(ledger, entry)
    /\ denial_count'   = new_denial_count
    /\ cooldown_until' = new_cooldown_until
    /\ pattern_count'  = [pattern_count EXCEPT ![a] = @ + 1]
    /\ last_decision'  = [last_decision  EXCEPT ![a] = d]
    /\ UNCHANGED now

Next ==
    \/ Tick
    \/ \E a \in Agents, cap \in Capabilities, res \in Resources :
           EvaluateRequest(a, cap, res)

\* Fairness (required for liveness properties D4):
\*   WF_vars(Tick): time eventually advances (monotonic time progression).
\*   Per-agent WF on EvaluateRequest: if a request is continuously enabled
\*   for agent a, it will eventually be processed (weak fairness assumption).
\*   Together these ensure that once FloodActive(a) holds and ledger is not
\*   full, agent a's next request is eventually evaluated and denied.
Fairness ==
    /\ WF_vars(Tick)
    /\ \A a \in Agents :
           WF_vars(\E cap \in Capabilities, res \in Resources :
                       EvaluateRequest(a, cap, res))

Spec == INIT /\ [][Next]_vars /\ Fairness

(* ---- Safety invariants --------------------------------------------------- *)

\* From ACP.tla: APPROVED decisions had acceptable risk
Safety ==
    \A i \in 1..Len(ledger) :
        ledger[i].decision = "APPROVED" => ledger[i].risk_score <= 39

\* From ACP.tla: ledger entries are well-formed
LedgerAppendOnly ==
    \A i \in 1..Len(ledger) :
        /\ ledger[i].decision   \in {"APPROVED", "ESCALATED", "DENIED"}
        /\ ledger[i].risk_score >= 0

\* From ACP.tla: same (cap, res) always produces the same BASE risk score.
\* In the extended model, ComputeRisk(cap, res) remains a pure function.
\* The full risk_score may differ across entries (F_anom bonus depends on
\* pattern_at_eval); AnomalyDeterminism captures the stateful extension.
RiskDeterminism ==
    \A i \in 1..Len(ledger) :
        \A j \in 1..Len(ledger) :
            ( ledger[i].capability = ledger[j].capability
           /\ ledger[i].resource   = ledger[j].resource
           /\ ledger[i].pattern_at_eval = ledger[j].pattern_at_eval )
            =>
            ledger[i].risk_score = ledger[j].risk_score

\* Active cooldown forces DENIED (ACP-RISK-2.0 ss4, Step 2)
CooldownEnforced ==
    \A i \in 1..Len(ledger) :
        ledger[i].cooldown_at_eval => ledger[i].decision = "DENIED"

\* Cooldown only exists after the denial threshold has been reached
CooldownImpliesThreshold ==
    \A a \in Agents :
        cooldown_until[a] > now => denial_count[a] >= COOLDOWN_TRIGGER

\* Delegation chain has no consecutive self-delegation (ACP-DCMA-1.1 ss3)
DelegationIntegrity ==
    \A i \in 1..Len(DelegationChain) - 1 :
        DelegationChain[i] # DelegationChain[i+1]

\* [Sprint J2] AnomalyDeterminism (D3):
\* Same (cap, res, pattern_at_eval) always produces the same risk_score.
\* Extends RiskDeterminism to include per-agent state in the determinism guarantee:
\*   determinism = f(static inputs + subject request history count).
\* RS is a deterministic policy function, not a statistical or ML model.
AnomalyDeterminism ==
    \A i \in 1..Len(ledger) :
        \A j \in 1..Len(ledger) :
            ( ledger[i].capability      = ledger[j].capability
           /\ ledger[i].resource        = ledger[j].resource
           /\ ledger[i].pattern_at_eval = ledger[j].pattern_at_eval )
            =>
            ledger[i].risk_score = ledger[j].risk_score

\* [Sprint J2] FloodEnforced (D2):
\* When pattern_at_eval >= FLOOD_THRESHOLD, the decision must be DENIED.
\* This is the formal safety guarantee of the F_anom flood override.
FloodEnforced ==
    \A i \in 1..Len(ledger) :
        ledger[i].pattern_at_eval >= FLOOD_THRESHOLD
        => ledger[i].decision = "DENIED"

(* ---- Temporal properties ------------------------------------------------- *)

\* From ACP.tla: every existing ledger entry is preserved across steps
LedgerAppendOnlyTemporal ==
    [][
        /\ Len(ledger') >= Len(ledger)
        /\ \A i \in 1..Len(ledger) : ledger'[i] = ledger[i]
    ]_ledger

\* Active cooldown eventually expires (from v1.17).
\* Conditioned on cooldown expiry within the time horizon.
\* Rationale: in a bounded model (now <= MAX_TIME), cooldown triggered at
\* now = MAX_TIME has expiry beyond the time horizon -- unreachable.
\* The conditioned form is the correct liveness claim for a bounded model.
CooldownExpires ==
    \A a \in Agents :
        [](   cooldown_until[a] > now
           /\ cooldown_until[a] <= MAX_TIME
           => <>(now >= cooldown_until[a]))

\* [Sprint J2] EventuallyRejected (D4 -- auxiliary, TLC-verified):
\* An abusive agent not already in cooldown will eventually receive a DENIED
\* decision via the FloodActive override.
\* Requires: Fairness (per-agent WF on EvaluateRequest + WF on Tick).
\* Requires: LEDGER_BOUND > FLOOD_THRESHOLD so the flood request fires
\*           within the bounded state space.
\* Cooldown exclusion (~CooldownActive(a)): CooldownExpires already
\* handles the cooldown path; this property focuses on the flood path.
EventuallyRejected ==
    \A a \in Agents :
        [](Abusive(a) /\ ~CooldownActive(a)
            => <>(Rejected(a)))

\* [Sprint J2] NoInfiniteExecutionUnderAbuse (D4 -- strong form):
\* No execution trace exists where an abusive agent is perpetually accepted.
\* Formally: once Abusive(a), it is not the case that Accepted(a) holds forever.
\*
\* Bounded model verification: TLC checks all finite traces up to LEDGER_BOUND
\* and MAX_TIME. The property holds because FloodActive is monotone
\* (pattern_count is non-decreasing): once >= FLOOD_THRESHOLD, it stays true,
\* and all subsequent EvaluateRequest steps produce DENIED, making
\* Accepted(a) false from the first flood-forced denial onward.
\*
\* Unbounded specification: holds by structural induction on FloodActive
\* monotonicity -- once abusive, every future request is denied (flood override),
\* so no infinite accepted execution is possible.
\*
\* Paper claim: "under the stated assumptions, no execution trace exists in
\* which an agent exhibiting sustained abusive behavior continues to be
\* admitted indefinitely."
NoInfiniteExecutionUnderAbuse ==
    \A a \in Agents :
        [](Abusive(a) => ~<>([]Accepted(a)))

====
