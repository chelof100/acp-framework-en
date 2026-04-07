# ACP v1.24 Sprint Plan — BAR-Monitor + Counterfactual API
# Fecha de diseño: 2026-04-07
# Estado: LISTO PARA EJECUCIÓN

---

## CONTEXTO: Por qué existe este sprint

v1.23 introdujo Exp 9 (Deviation Collapse) y la sección §Limits of Execution-Only
Governance. Esas contribuciones son conceptualmente correctas pero incompletas:

- BAR existe como métrica post-hoc (se calcula sobre un experimento fijo)
- No existe un mecanismo que detecte desvío en tiempo real
- El counterfactual está hardcodeado en exp_deviation_collapse.go, no es una API reutilizable

v1.24 convierte las ideas de v1.23 en mecanismos de protocolo:
- BAR-Monitor: de métrica a instrumento de gobernanza activo
- EvaluateCounterfactual: de experimento a API de la librería

FUENTE DEL DISEÑO: Brainstorming sesión 2026-04-07. Análisis comparativo con
sesión ChatGPT (archivo: C:\Users\Mariana\Desktop\Chelo\v1.24 chatgpt brainstorming analisis.md).
Ver análisis completo en memory: sprint_v124_v125_analysis.md

---

## DECISIONES DE DISEÑO CRÍTICAS (no renegociar sin justificación)

### D1: Ventana por N evaluaciones, NO temporal
**Por qué:** BAR es una métrica de gobernanza, no de throughput. Si el sistema
procesa pocas requests en una hora, una ventana temporal da una muestra estadísticamente
irrelevante. N evaluaciones garantiza siempre el mismo tamaño de muestra.
**Consecuencia:** BARMonitor NO importa time.Time. Es agnóstico al reloj.

### D2: BARMonitor es componente separado, NO dentro de LedgerQuerier
**Por qué:** LedgerQuerier es estado de admisión (qué ha pasado). BARMonitor es
meta-gobernanza (qué está pasando con el patrón de decisiones). Mezclarlos viola
separación de responsabilidades.
**Consecuencia:** pkg/barmonitor es un package independiente. El caller decide
cuándo llamar Record() — típicamente en runRequest() después de Evaluate().

### D3: ΔBAR (trend detection) es parte de v1.24, no de v1.25
**Por qué:** Sin ΔBAR, BAR-Monitor es solo un threshold check. Eso se lee como
"observabilidad operacional". Con ΔBAR, detecta el régimen de cambio ANTES de
llegar al colapso. Eso es gobernanza proactiva. La diferencia entre los dos en
el paper es la diferencia entre feature y contribución.
**Implementación:** ΔBAR = BAR(segunda mitad del ring) - BAR(primera mitad del ring).
Negativo sostenido = declining. Costo de implementación: trivial. Valor: alto.

### D4: Mutations son ADITIVAS sobre base (no reemplazos)
**Por qué:** Una API de reemplazo pierde interpretabilidad. "Aplica solo ExternalIP=true
sobre cualquier request base" es más útil que "reemplaza el request entero".
Con mutaciones aditivas, el caller controla exactamente qué señal está inyectando.
**Consecuencia:** Mutation tiene todos los campos como pointers (*string, *Context, etc.).
nil = no modificar. non-nil = aplicar.

### D5: ΔBAR alert threshold = -0.10 (configurable)
**Por qué:** Una variación de -10% en BAR entre la primera y segunda mitad del
window es estadísticamente significativa para N=100. Para N pequeños puede ser ruido.
El threshold es configurable; -0.10 es el default.

### D6: Framing del paper — "bounded operational region"
**Por qué (insight del brainstorming):** cooldown detecta EXCESO de actividad
inadmisible (cota superior). BAR-Monitor detecta AUSENCIA de actividad inadmisible
(cota inferior). Juntos definen una región operacional acotada en la que la
gobernanza es tanto correcta como significativa. Este framing es paper-level insight
y debe aparecer explícitamente en §Boundary Activation Monitoring y en §Contributions.

---

## DELIVERABLE 1: pkg/barmonitor

### Ubicación
C:\Users\Mariana\Desktop\Chelo\ACP\ACP-PROTOCOL-EN\acp-go\pkg\barmonitor\

### Archivo: monitor.go (spec completa)

```go
// Package barmonitor implements Boundary Activation Rate (BAR) monitoring
// for ACP deployments.
//
// BAR measures whether the ACP admissibility boundary is actively exercised:
//
//   BAR_N = |{d_i ∈ D_N | d_i ∈ {ESCALATED, DENIED}}| / N
//
// where D_N is the sliding window of the last N evaluation decisions.
//
// BARMonitor tracks BAR and ΔBAR (trend) and emits an Alert when either:
//   - BAR_N < θ (threshold condition): boundary is insufficiently exercised
//   - ΔBAR < δ (trend condition): boundary interaction is declining
//
// BARMonitor operates independently of admission control logic. It does not
// alter decisions; it observes whether decisions remain meaningful.
//
// Usage:
//
//   m := barmonitor.New(barmonitor.DefaultConfig())
//   // after each risk.Evaluate():
//   if alert, bar := m.Record(result.Decision); alert != nil {
//       // handle alert: BAR is low or declining
//   }
package barmonitor

import (
    "sync"

    "github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// Config holds BARMonitor configuration.
type Config struct {
    // WindowSize N: number of evaluations in the sliding window.
    // Must be >= 4 (required for trend computation). Default: 100.
    WindowSize int

    // Threshold θ: minimum acceptable BAR. Alert fires when BAR_N < θ.
    // Range: (0.0, 1.0). Default: 0.05.
    Threshold float64

    // TrendThreshold δ: minimum acceptable ΔBAR. Alert fires when ΔBAR < δ.
    // Negative value = declining BAR is acceptable only to this magnitude.
    // Default: -0.10.
    TrendThreshold float64
}

// DefaultConfig returns a production-ready default configuration.
//
// WindowSize=100 provides statistically stable BAR estimates.
// Threshold=0.05 alerts when fewer than 5% of decisions exercise the boundary.
// TrendThreshold=-0.10 alerts when the second half of the window has 10+ points
// lower BAR than the first half (progressive decline detection).
func DefaultConfig() Config {
    return Config{
        WindowSize:     100,
        Threshold:      0.05,
        TrendThreshold: -0.10,
    }
}

// AlertReason categorizes the type of low-activation condition detected.
type AlertReason string

const (
    // AlertThreshold fires when BAR_N < θ (already in low-activation regime).
    AlertThreshold AlertReason = "THRESHOLD"

    // AlertTrend fires when ΔBAR < δ (progressive boundary interaction decline).
    // BAR may still be above θ, but the trend indicates collapse is approaching.
    AlertTrend AlertReason = "TREND"
)

// Alert is emitted by BARMonitor.Record when a low-activation condition is detected.
type Alert struct {
    // BAR is the current Boundary Activation Rate over the window.
    BAR float64

    // Trend is ΔBAR: BAR(second half) - BAR(first half) of the window.
    // Negative = declining boundary interaction.
    Trend float64

    // Reason indicates which condition triggered the alert.
    Reason AlertReason

    // WindowFill is the number of evaluations currently in the window (≤ WindowSize).
    // Low WindowFill (< WindowSize/2) means estimates are less reliable.
    WindowFill int
}

// BARMonitor tracks Boundary Activation Rate over a sliding window of
// recent evaluation decisions.
//
// BARMonitor is safe for concurrent use.
type BARMonitor struct {
    mu   sync.Mutex
    cfg  Config
    ring []risk.Decision // circular buffer, capacity = cfg.WindowSize
    pos  int             // next write position in ring
    fill int             // number of valid entries (saturates at WindowSize)
}

// New creates a BARMonitor with the given configuration.
// Panics if cfg.WindowSize < 4 or cfg.Threshold not in (0,1).
func New(cfg Config) *BARMonitor {
    if cfg.WindowSize < 4 {
        panic("barmonitor: WindowSize must be >= 4")
    }
    if cfg.Threshold <= 0 || cfg.Threshold >= 1 {
        panic("barmonitor: Threshold must be in (0,1)")
    }
    return &BARMonitor{
        cfg:  cfg,
        ring: make([]risk.Decision, cfg.WindowSize),
    }
}

// Record adds a decision to the monitor.
//
// Returns (*Alert, bar):
//   - Alert != nil if a low-activation condition was detected.
//   - bar is the current BAR_N (always returned, regardless of alert).
//
// Alert fires on:
//   - BAR_N < cfg.Threshold  (AlertThreshold)
//   - ΔBAR < cfg.TrendThreshold  (AlertTrend)
// If both conditions hold, AlertThreshold takes precedence.
func (m *BARMonitor) Record(d risk.Decision) (*Alert, float64) {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Write to circular buffer.
    m.ring[m.pos] = d
    m.pos = (m.pos + 1) % m.cfg.WindowSize
    if m.fill < m.cfg.WindowSize {
        m.fill++
    }

    bar := m.computeBAR()
    trend := m.computeTrend()

    if bar < m.cfg.Threshold {
        return &Alert{BAR: bar, Trend: trend, Reason: AlertThreshold, WindowFill: m.fill}, bar
    }
    if trend < m.cfg.TrendThreshold {
        return &Alert{BAR: bar, Trend: trend, Reason: AlertTrend, WindowFill: m.fill}, bar
    }
    return nil, bar
}

// BAR returns the current Boundary Activation Rate.
//
//   BAR_N = |{d_i ∈ D_N | d_i ∈ {ESCALATED, DENIED}}| / N
func (m *BARMonitor) BAR() float64 {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.computeBAR()
}

// Trend returns ΔBAR: the difference between the BAR of the second half
// and the first half of the current window.
//
//   ΔBAR = BAR(D_N[N/2..N]) - BAR(D_N[0..N/2])
//
// A negative ΔBAR indicates declining boundary interaction.
// Returns 0 if fewer than 4 evaluations have been recorded.
func (m *BARMonitor) Trend() float64 {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.computeTrend()
}

// WindowFill returns the number of evaluations currently in the window.
// Starts at 0, grows until it saturates at cfg.WindowSize.
func (m *BARMonitor) WindowFill() int {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.fill
}

// Reset clears all state. After Reset(), BAR() == 0 and WindowFill() == 0.
func (m *BARMonitor) Reset() {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.ring = make([]risk.Decision, m.cfg.WindowSize)
    m.pos = 0
    m.fill = 0
}

// computeBAR counts ESCALATED+DENIED in the current window.
// Caller must hold m.mu.
func (m *BARMonitor) computeBAR() float64 {
    if m.fill == 0 {
        return 0
    }
    var active int
    for i := 0; i < m.fill; i++ {
        if isActive(m.ring[i]) {
            active++
        }
    }
    return float64(active) / float64(m.fill)
}

// computeTrend computes ΔBAR = BAR(second half) - BAR(first half).
// Returns 0 if fill < 4.
// Caller must hold m.mu.
func (m *BARMonitor) computeTrend() float64 {
    if m.fill < 4 {
        return 0
    }
    half := m.fill / 2
    var firstActive, secondActive int
    for i := 0; i < half; i++ {
        if isActive(m.ring[i]) {
            firstActive++
        }
    }
    for i := half; i < m.fill; i++ {
        if isActive(m.ring[i]) {
            secondActive++
        }
    }
    firstBAR := float64(firstActive) / float64(half)
    secondBAR := float64(secondActive) / float64(m.fill-half)
    return secondBAR - firstBAR
}

// isActive returns true if the decision exercises the admissibility boundary.
func isActive(d risk.Decision) bool {
    return d == risk.ESCALATED || d == risk.DENIED
}
```

### Archivo: monitor_test.go (spec de tests)

Tests requeridos — todos deben pasar:

1. `TestNew_PanicsOnBadConfig` — WindowSize<4 y Threshold fuera de (0,1) deben panic
2. `TestRecord_EmptyWindow_BAR0` — sin registros, BAR()=0
3. `TestRecord_AllAPPROVED_BAR0` — 100 APPROVED → BAR=0.00 → Alert(AlertThreshold)
4. `TestRecord_AllDENIED_BAR1` — 100 DENIED → BAR=1.00 → no alert (BAR > threshold)
5. `TestRecord_PhaseADistribution` — 6 APPROVED + 7 ESCALATED + 7 DENIED → BAR≈0.70 → no alert
6. `TestRecord_ThresholdAlert` — secuencia que baja BAR por debajo de threshold → Alert(AlertThreshold)
7. `TestRecord_TrendAlert` — secuencia con decline progresivo → Alert(AlertTrend) antes de threshold
8. `TestRecord_TrendAlert_BeforeThreshold` — CLAVE: ΔBAR dispara ANTES de que BAR llegue a θ
9. `TestRecord_ConcurrentAccess` — 10 goroutines × 100 Record() → sin race condition (go test -race)
10. `TestReset_ClearsState` — después de Reset(), BAR=0 y fill=0
11. `TestWindowFill_SaturatesAtWindowSize` — fill nunca supera WindowSize
12. `TestRecord_ReturnsCurrentBAR` — siempre retorna bar, incluso cuando alert==nil

### Archivo: go.mod consideration
`pkg/barmonitor` importa `pkg/risk` para `risk.Decision`. Verificar que no hay ciclo.
`pkg/risk` NO debe importar `pkg/barmonitor` (dependencia unidireccional).

---

## DELIVERABLE 2: pkg/risk — EvaluateCounterfactual

### Archivo: pkg/risk/counterfactual.go (spec completa)

```go
// Package risk — counterfactual.go
// EvaluateCounterfactual provides the Counterfactual Evaluation API introduced
// in ACP v1.24.
//
// Counterfactual evaluation verifies that an ACP deployment retains the
// structural capacity to enforce: given a set of mutations representing
// conditions absent from the observed stream, the engine can still produce
// ESCALATED or DENIED decisions.
//
// Mutations are ADDITIVE: only non-nil fields override the base request.
// This preserves interpretability — each mutation tests a specific signal
// in isolation.

package risk

import "time"

// Mutation describes a transformation applied to a base EvalRequest.
// All pointer fields are optional: nil means "keep the base value".
//
// The three built-in mutation categories from ACP v1.24 are:
//   - Structural: elevate Capability + ResourceClass
//   - Behavioral: inject Context + History flags
//   - Temporal:   pre-load ledger state via LedgerSetup
type Mutation struct {
    // Label identifies this mutation for reporting. Required.
    Label string

    // Capability overrides base.Capability if non-nil.
    Capability *string

    // ResourceClass overrides base.ResourceClass if non-nil.
    ResourceClass *ResourceClass

    // Resource overrides base.Resource if non-nil.
    Resource *string

    // Context overrides base.Context if non-nil (full replacement of Context struct).
    Context *Context

    // History overrides base.History if non-nil (full replacement of History struct).
    History *History

    // LedgerSetup, if non-nil, is called with a fresh InMemoryQuerier before
    // evaluation. Use this for temporal mutations that require pre-loaded state.
    // If nil, a fresh empty querier is used.
    LedgerSetup func(*InMemoryQuerier, time.Time)
}

// CounterfactualResult holds the result of evaluating a single mutation.
type CounterfactualResult struct {
    // Label is the mutation's label.
    Label string

    // Decision is the engine's decision for this mutation.
    Decision Decision

    // RSFinal is the computed risk score for this mutation.
    RSFinal int

    // Err is non-nil if risk.Evaluate returned an error for this mutation.
    Err error
}

// BAR computes the Boundary Activation Rate for a slice of results.
//
//   BAR = |{r ∈ results | r.Decision ∈ {ESCALATED, DENIED}}| / len(results)
//
// Returns 0 for empty input.
func BAR(results []CounterfactualResult) float64 {
    if len(results) == 0 {
        return 0
    }
    var active int
    for _, r := range results {
        if r.Err == nil && (r.Decision == ESCALATED || r.Decision == DENIED) {
            active++
        }
    }
    return float64(active) / float64(len(results))
}

// EvaluateCounterfactual applies each mutation to the base request and
// evaluates the mutated request against the ACP risk engine.
//
// Each mutation uses an independent querier: either a fresh InMemoryQuerier
// (if Mutation.LedgerSetup is nil) or one pre-loaded by LedgerSetup.
// Mutations do not share state.
//
// The base request's Policy and Now fields are preserved in all mutations.
func EvaluateCounterfactual(base EvalRequest, mutations []Mutation, now time.Time) []CounterfactualResult {
    results := make([]CounterfactualResult, len(mutations))
    for i, mut := range mutations {
        req := applyMutation(base, mut)
        req.Now = now

        var q LedgerQuerier
        if mut.LedgerSetup != nil {
            iq := NewInMemoryQuerier()
            mut.LedgerSetup(iq, now)
            q = iq
        } else {
            q = NewInMemoryQuerier()
        }

        result, err := Evaluate(req, q)
        results[i] = CounterfactualResult{Label: mut.Label, Err: err}
        if err == nil {
            results[i].Decision = result.Decision
            results[i].RSFinal = result.RSFinal
        }
    }
    return results
}

// applyMutation returns a copy of base with non-nil mutation fields applied.
func applyMutation(base EvalRequest, mut Mutation) EvalRequest {
    req := base
    if mut.Capability != nil {
        req.Capability = *mut.Capability
    }
    if mut.ResourceClass != nil {
        req.ResourceClass = *mut.ResourceClass
    }
    if mut.Resource != nil {
        req.Resource = *mut.Resource
    }
    if mut.Context != nil {
        req.Context = *mut.Context
    }
    if mut.History != nil {
        req.History = *mut.History
    }
    return req
}

// ─── Built-in mutation factories ─────────────────────────────────────────────
// These factories produce the three standard mutation categories from ACP v1.24.
// They guarantee DENIED decisions when evaluated with DefaultPolicyConfig().

// StructuralMutation returns a mutation that elevates capability to
// financial.transfer and resource class to Restricted.
// Expected RS: 35 + 45 = 80 → DENIED (> EscalatedMax=69).
// No context, history, or ledger state required.
func StructuralMutation() Mutation {
    cap := "acp:cap:financial.transfer"
    res := "accounts/restricted-fund"
    rc := ResourceRestricted
    return Mutation{
        Label:         "structural",
        Capability:    &cap,
        Resource:      &res,
        ResourceClass: &rc,
    }
}

// BehavioralMutation returns a mutation that injects ExternalIP, OffHours,
// RecentDenial, and FreqAnomaly on top of structural escalation.
// Expected RS: 35+45+20+15+20+15 = 150 → capped 100 → DENIED.
func BehavioralMutation() Mutation {
    cap := "acp:cap:financial.transfer"
    res := "accounts/restricted-fund"
    rc := ResourceRestricted
    ctx := Context{ExternalIP: true, OffHours: true}
    hist := History{RecentDenial: true, FreqAnomaly: true}
    return Mutation{
        Label:         "behavioral",
        Capability:    &cap,
        Resource:      &res,
        ResourceClass: &rc,
        Context:       &ctx,
        History:       &hist,
    }
}

// TemporalMutation returns a mutation that pre-loads the ledger to trigger
// all three F_anom rules for (agentID, financial.transfer, restricted-fund).
//
//   Rule 1: CountPattern(patKey, 60s) > 10  → +20  (11 entries at -30s)
//   Rule 2: CountDenials(agentID, 24h) ≥ 3  → +15  (3 entries at -1h)
//   Rule 3: CountPattern(patKey, 5min) ≥ 3  → +15  (satisfied by Rule 1 entries)
//   F_anom total: +50
//
// Expected RS: 35 + 45 + 50 = 130 → capped 100 → DENIED.
func TemporalMutation(agentID string) Mutation {
    cap := "acp:cap:financial.transfer"
    res := "accounts/restricted-fund"
    rc := ResourceRestricted
    return Mutation{
        Label:         "temporal",
        Capability:    &cap,
        Resource:      &res,
        ResourceClass: &rc,
        LedgerSetup: func(q *InMemoryQuerier, now time.Time) {
            patKey := PatternKey(agentID, "acp:cap:financial.transfer", "accounts/restricted-fund")
            for i := 0; i < 11; i++ {
                q.AddPattern(patKey, now.Add(-30*time.Second))
            }
            for i := 0; i < 3; i++ {
                q.AddDenial(agentID, now.Add(-1*time.Hour))
            }
        },
    }
}
```

NOTA: `TemporalMutation` necesita que `applyMutation` preserve el `AgentID` del base
para que `PatternKey` use el agentID correcto. Verificar que `applyMutation` no
resetea AgentID — no lo hace, AgentID no es un campo de Mutation.

### Tests para counterfactual.go

Archivo: `pkg/risk/counterfactual_test.go`

1. `TestBAR_Empty` — BAR([]) = 0
2. `TestBAR_AllAPPROVED` — BAR([APPROVED×20]) = 0.00
3. `TestBAR_PhaseADistribution` — BAR([APPROVED×6, ESCALATED×7, DENIED×7]) = 0.70
4. `TestBAR_PhaseCDistribution` — BAR([DENIED×60]) = 1.00
5. `TestEvaluateCounterfactual_StructuralMutation_DENIED` — factory retorna DENIED
6. `TestEvaluateCounterfactual_BehavioralMutation_DENIED` — factory retorna DENIED
7. `TestEvaluateCounterfactual_TemporalMutation_DENIED` — factory retorna DENIED
8. `TestEvaluateCounterfactual_MutationsAreAdditive` — nil fields no modifican base
9. `TestEvaluateCounterfactual_IndependentQueriers` — mutation N no contamina mutation N+1
10. `TestEvaluateCounterfactual_PreservesPolicy` — Policy del base se mantiene

### Refactor de exp_deviation_collapse.go (OPCIONAL para v1.24)

Phase C de Exp 9 puede refactorizarse para usar EvaluateCounterfactual():
```go
// Reemplazar evaluateCounterfactuals() con:
cfMutations := []risk.Mutation{
    risk.StructuralMutation(),
    risk.BehavioralMutation(),
    risk.TemporalMutation(agentID),
}
// Para cada case en dataset:
results := risk.EvaluateCounterfactual(c.req, cfMutations, now)
```

DECISIÓN: Este refactor es OPCIONAL para v1.24. El experimento ya funciona y
los números son correctos. Refactorizarlo es limpieza — hacerlo si hay tiempo,
no es bloqueante para el paper.

---

## DELIVERABLE 3: Paper — §Boundary Activation Monitoring

### Ubicación exacta en main.tex
Dentro de `\section{Limits of Execution-Only Governance}` (que ya existe en v1.23),
DESPUÉS de `\subsection{Experiment 9: Deviation Collapse and Restoration}` y
ANTES de `\subsection{Extended Governance Objective}`.

Es decir, el orden de subsecciones en §Limits pasa de:
```
§X.1 Degenerate Admissibility
§X.2 Preservation of Failure Conditions at Bind
§X.3 Counterfactual Evaluation
§X.4 Deviation Collapse
§X.5 Experiment 9
§X.6 Extended Governance Objective
```
a:
```
§X.1 Degenerate Admissibility
§X.2 Preservation of Failure Conditions at Bind
§X.3 Counterfactual Evaluation
§X.4 Deviation Collapse
§X.5 Experiment 9
§X.6 Boundary Activation Monitoring   ← NUEVA
§X.7 Extended Governance Objective
```

### Texto completo para §X.6 Boundary Activation Monitoring

```latex
\subsection{Boundary Activation Monitoring}
\label{sec:bar-monitor}

While Experiment~9 demonstrates that admissibility enforcement can become
vacuous under deviation collapse, practical deployments require a mechanism
to detect this condition as it emerges---before the degenerate regime is
fully reached.
We introduce \emph{Boundary Activation Monitoring} (BAR-Monitor), a
lightweight mechanism that tracks whether the admissibility boundary is
actively exercised over time.

\begin{definition}[Boundary Activation Rate over sliding window]
Let $\mathcal{D}_N = (d_1, d_2, \ldots, d_N)$ be the sequence of the last
$N$ evaluation decisions, $d_i \in \{\texttt{APPROVED},\,\texttt{ESCALATED},\,\texttt{DENIED}\}$.
The Boundary Activation Rate over window $N$ is:
\[
  \mathrm{BAR}_N = \frac{|\{d_i \in \mathcal{D}_N \mid d_i \in \{\texttt{ESCALATED},\,\texttt{DENIED}\}\}|}{N}
\]
\end{definition}

\textbf{Trend detection (ΔBAR).}
A fixed threshold on $\mathrm{BAR}_N$ detects that a deployment has already
entered a low-activation regime, but not that it is approaching one.
We define ΔBAR to capture this:
\[
  \Delta\mathrm{BAR} = \mathrm{BAR}\!\left(\mathcal{D}_N\!\left[\tfrac{N}{2}{:}N\right]\right)
                     - \mathrm{BAR}\!\left(\mathcal{D}_N\!\left[0{:}\tfrac{N}{2}\right]\right)
\]
A sustained $\Delta\mathrm{BAR} < \delta$ (default $\delta = -0.10$) indicates
progressive loss of boundary interaction even when $\mathrm{BAR}_N$ remains
above the alert threshold $\theta$.

\begin{definition}[Low-activation regime]
A deployment enters a low-activation regime if either:
\begin{itemize}[noitemsep]
  \item $\mathrm{BAR}_N < \theta$ \hfill (threshold condition), or
  \item $\Delta\mathrm{BAR} < \delta$ \hfill (trend condition)
\end{itemize}
where $\theta \in (0,1)$ and $\delta < 0$ are configurable parameters.
The threshold condition detects current low activation; the trend condition
detects progressive decline before the threshold is reached.
\end{definition}

\textbf{Complementarity with temporal enforcement.}
ACP's cooldown mechanism imposes an \emph{upper-bound} constraint: when
inadmissible activity exceeds a threshold (3~DENIED decisions in 10~minutes),
the agent is blocked.
BAR-Monitor imposes a \emph{lower-bound} constraint: when inadmissible
activity falls below a threshold, the deployment is flagged as potentially
entering a degenerate regime.
Together, cooldown and BAR-Monitor define a bounded operational region in
which governance is both \emph{safe} (cooldown prevents excess) and
\emph{meaningful} (BAR-Monitor ensures boundary remains active).

\textbf{Cooldown interaction.}
This complementarity has a structural consequence beyond semantics.
Deviation collapse does not only reduce BAR to zero---it also prevents the
accumulation of DENIED decisions required to trigger cooldown.
In the sanitized Phase~B of Experiment~9, no DENIED decisions are produced,
which means the cooldown mechanism is never activated and the
$9.5\times$~short-circuit path (88\,ns) is never exercised.
Upstream sanitization therefore neutralizes both the primary enforcement
boundary and the secondary containment mechanism that depends on DENIED
events as inputs.

\textbf{Implementation.}
BAR-Monitor is implemented as a circular buffer of $N$ decisions
(\texttt{pkg/barmonitor}) operating independently of admission control logic.
Each call to \texttt{Record(d~Decision)} updates the buffer and returns an
\texttt{Alert} if the low-activation condition is detected.
The mechanism does not alter admission decisions; it observes whether
decisions remain meaningful.
```

---

## DELIVERABLE 4: Paper — §Contributions actualizadas

### Cambios exactos
Las contribuciones actuales en v1.23 tienen 7 items. Para v1.24, añadir 2 nuevos items
al FINAL de la lista (después del item de Exp 9).

Item a agregar (1 de 2) — Failure Condition Preservation:
```latex
  \item \textbf{Failure condition preservation as a governance requirement.}
    We establish failure condition preservation as a necessary requirement
    for effective admission control: a system must not only enforce admissibility
    correctly but must preserve the conditions under which enforcement can fire.
    This separates \emph{correct enforcement} from \emph{effective governance}
    and provides the theoretical foundation for deviation collapse detection.
```

Item a agregar (2 de 2) — BAR-Monitor:
```latex
  \item \textbf{Boundary Activation Monitoring (BAR-Monitor).}
    We introduce BAR-Monitor, a mechanism that detects loss of boundary
    interaction by tracking both $\mathrm{BAR}_N$ (current activation level)
    and $\Delta\mathrm{BAR}$ (trend toward collapse).
    BAR-Monitor provides the lower-bound complement to cooldown's upper-bound
    constraint, defining a bounded operational region in which governance
    remains both safe and meaningful (Section~\ref{sec:bar-monitor}).
```

### Frase a endurecer en el item de Exp 9 existente
Actual: "We demonstrate that a system may remain fully compliant while its
admissibility boundary is never exercised."
Cambiar a: "We demonstrate empirically that a system may remain fully compliant
while its admissibility boundary is never exercised
($\mathrm{BAR}_A = 0.70 \to \mathrm{BAR}_B = 0.00$, $n=20$)."
(Agrega los números reales, más duro para reviewers.)

---

## DELIVERABLE 5: Paper — "bounded operational region" framing

### Dónde agregar
En §Limits of Execution-Only Governance → §X.7 Extended Governance Objective
(que ya existe), agregar al inicio del párrafo de definición:

```latex
% Agregar antes de la definición existente de Extended Governance Objective:
\textbf{Bounded operational region.}
The extended governance objective emerges from two complementary constraints.
Cooldown enforces an upper bound: excessive inadmissible activity triggers
containment.
BAR-Monitor enforces a lower bound: insufficient boundary interaction signals
a degenerate regime.
A deployment satisfying both constraints operates within a bounded region
where governance is simultaneously correct and meaningful.
```

---

## ORDEN DE IMPLEMENTACIÓN (ejecutar en este orden)

### Fase 1: Código (sin tocar paper)
1. Crear `acp-go/pkg/barmonitor/monitor.go` — spec completa arriba
2. Crear `acp-go/pkg/barmonitor/monitor_test.go` — 12 tests
3. `go test ./pkg/barmonitor/...` — todos deben pasar
4. Crear `acp-go/pkg/risk/counterfactual.go` — spec completa arriba
5. Crear `acp-go/pkg/risk/counterfactual_test.go` — 10 tests
6. `go test ./pkg/risk/...` — todos deben pasar
7. `go build ./...` — build limpio
8. Opcional: refactor exp_deviation_collapse.go para usar EvaluateCounterfactual

### Fase 2: Paper
9. Agregar §X.6 Boundary Activation Monitoring (texto completo arriba)
10. Agregar 2 nuevos items en §Contributions
11. Endurecer frase del item Exp 9 con números reales
12. Agregar "bounded operational region" framing en §Extended Governance Objective
13. Compilar en Overleaf — verificar que no hay errores LaTeX

### Fase 3: Release
14. Verificar que `go test ./...` pasa completo
15. Actualizar CHANGELOG.md con v1.24
16. Compilar PDF final en Overleaf
17. Subir a Zenodo → obtener nuevo DOI
18. Actualizar DOI en main.tex L116, README, web
19. Subir a arXiv como replacement → será v8
20. Update README: v8 (v1.24)
21. Deploy web (6+ HTML locales)

---

## SUCCESS CRITERIA

- [ ] `go build ./...` pasa sin errores
- [ ] `go test ./pkg/barmonitor/...` — 12/12 tests pasan
- [ ] `go test ./pkg/risk/...` — incluye counterfactual tests
- [ ] `go test -race ./...` — sin race conditions
- [ ] BAR([APPROVED×20]) = 0.00 con Alert(AlertThreshold)
- [ ] BAR([APPROVED×6, ESCALATED×7, DENIED×7]) ≈ 0.70 sin alert
- [ ] BAR([DENIED×60]) = 1.00 sin alert
- [ ] ΔBAR alert dispara ANTES de que BAR llegue a threshold (TrendAlert test)
- [ ] EvaluateCounterfactual con 3 built-in factories → BAR=1.00
- [ ] Mutations son aditivas: nil fields preservan base request
- [ ] Paper compila en Overleaf sin errores
- [ ] §Boundary Activation Monitoring aparece entre §Exp 9 y §Extended Governance Objective
- [ ] 9 contributions bullets en total (7 existentes + 2 nuevos)

---

## QUÉ NO HACER EN v1.24 (límites explícitos)

- ❌ HTTP endpoint POST /acp/v1/counterfactual — es v1.25+ (requiere auth, signing, versioning)
- ❌ TLA+ invariantes de deviation collapse — es v1.25 (no bloquea el paper)
- ❌ Exp 9 Phase D (validación experimental de ΔBAR decline gradual) — es v1.25
- ❌ Per-agent BAR tracking — requiere diseño cuidadoso de threshold por AutonomyLevel, no hay tiempo
- ❌ Integrar BARMonitor dentro de LedgerQuerier — viola separación de responsabilidades
- ❌ Endpoint HTTP de monitoreo en tiempo real — es producto, no paper
- ❌ Reemplazar §Contributions section entera — solo agregar 2 items
