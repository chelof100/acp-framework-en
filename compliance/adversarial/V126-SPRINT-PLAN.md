# ACP v1.26 Sprint Plan — Formal Adversary Model + Threshold Sensitivity + AgentSpec Comparison + BAR Statistical Guarantees
# Fecha de diseño: 2026-04-08
# Estado: DISEÑADO — listo para ejecutar
# Dependencias: v1.25 completo ✅ (Exp 10, BAR-Monitor, EvaluateCounterfactual, 11 invariants TLA+)

---

## CONTEXTO Y MOTIVACIÓN

v1.25 cierra el loop experimental con Exp 10 (knowledge-aware adversarial evasion).
El paper tiene 10 experimentos, 11 invariants TLA+, 6 nuevas citas de LLM agent security,
y una sección de Related Work actualizada.

El feedback de ChatGPT (revisión externa) identificó dos gaps estructurales que impiden
llegar a IEEE TDSC / ACM TOPS:

  GAP-1: Los experimentos no tienen un adversary model formal — son ejemplos bien
          diseñados pero no constituyen una taxonomía evaluada contra clases de ataque.
          Un reviewer puede decir "¿cómo sé que estos son los ataques relevantes?"

  GAP-2: Los thresholds (39/69) son engineering choices sin justificación empírica.
          Un reviewer pedirá sensibilidad: "¿cambian las conclusiones con 30/60?"

v1.26 cierra estos gaps con 4 objetivos que no requieren despliegue real y son
ejecutables con el código Go existente + análisis analítico para BAR.

---

## OBJETIVO 1: Modelo de Adversario Formal

### Por qué

Hoy los 10 experimentos son descritos en prosa como "ataques". Formalizarlos como
una taxonomía convierte los experimentos en evidencia sistemática, no anecdótica.
Es el cambio de mayor impacto en el paper con menor costo de implementación.

### Diseño

Definir formalmente en el paper (nueva sección §Adversary Model antes de §Experiments):

```
Adversary A = (K, S, B) where:
  K ∈ {black-box, formula-aware, full-state}   -- knowledge level
  S ∈ {threshold-hugging, evasion, flood, collusion}  -- strategy class
  B ∈ ℕ  -- request budget

black-box:     adversary observes only APPROVED/DENIED/ESCALATED decisions
formula-aware: adversary knows RS = capBase + F_ctx + F_hist + F_res + F_anom
               and all weight values (ACP-RISK-3.0 published spec)
full-state:    adversary additionally knows the current ledger state
               (all pattern counts and denial history)
```

Mapeo de experimentos a clases de adversario:

| Exp | Adversary Class        | K             | S                  | Result         |
|-----|------------------------|---------------|--------------------|----------------|
| 1   | Cooldown Evasion       | black-box     | threshold-hugging  | contained      |
| 2   | Multi-Agent Flood      | black-box     | flood              | contained      |
| 3   | Backend Stress         | black-box     | flood              | degraded perf  |
| 4   | Token Replay           | black-box     | evasion            | contained      |
| 5-8 | State Mixing           | formula-aware | cross-ctx          | fixed in 3.0   |
| 9   | Sanitization/Drift     | black-box     | upstream           | BAR detects    |
| 10  | Knowledge-Aware Evasion| formula-aware | evasion (RS=0)     | BAR detects    |

### Key findings que emergen de la taxonomía

1. Per-decision enforcement is sufficient against black-box adversaries (Exp 1-4).
2. Formula-aware adversaries break per-decision enforcement but are detected by BAR (Exp 10).
3. Deviation collapse (Exp 9) is an environmental threat, not adversarial — but BAR-Monitor
   handles both classes with the same mechanism.
4. Full-state adversaries are outside the threat model of v1.0 (acknowledged in Limitations).

### Implementación en paper

- Nueva sección §Adversary Model (~1.5 páginas) antes de §Experiments
- Tabla de mapeo experimentos → clases
- Modificar intro de cada experimento para referenciar la clase de adversario
- Agregar en §Limitations: "full-state adversary with real-time ledger access is outside
  the v1.0 threat model; addressed in ACP-D-1.0 (decentralized)"

### Archivos tocados
- `paper/arxiv/main.tex` únicamente
- No requiere cambios de código Go

---

## OBJETIVO 2: Análisis de Sensibilidad de Thresholds

### Por qué

Los valores APPROVED≤39, ESCALATED 40–69, DENIED≥70 son engineering choices.
Un reviewer preguntará: "¿son los resultados sensibles a estos valores?"
La respuesta empírica es más fuerte que cualquier argumento textual.

### Diseño experimental

**Configuraciones a probar (5 threshold pairs):**

| Config | APPROVED threshold | DENIED threshold | Label      |
|--------|-------------------|------------------|------------|
| T1     | ≤29               | ≥60              | strict     |
| T2     | ≤34               | ≥65              | moderate-  |
| T3     | ≤39               | ≥70              | default ← actual |
| T4     | ≤44               | ≥75              | moderate+  |
| T5     | ≤49               | ≥80              | relaxed    |

**Dataset:** Mismo buildDataset() de Exp 9 (20 casos, conocidos RS values).

**Métricas por configuración:**
- BAR (Boundary Activation Rate) — cuántos casos activan la frontera
- False-denial rate — casos con RS en zona "legítima" que ahora son DENIED
- Coverage — cuántos casos siguen siendo APPROVED

**Implementación Go:**

```go
// exp_threshold_sensitivity.go — nuevo archivo
func RunThresholdSensitivity(_ Config) {
    configs := []ThresholdConfig{
        {ApprovedMax: 29, DeniedMin: 60, Label: "strict"},
        {ApprovedMax: 34, DeniedMin: 65, Label: "moderate-"},
        {ApprovedMax: 39, DeniedMin: 70, Label: "default"},
        {ApprovedMax: 44, DeniedMin: 75, Label: "moderate+"},
        {ApprovedMax: 49, DeniedMin: 80, Label: "relaxed"},
    }
    // Para cada config:
    //   - Evaluar buildDataset() con threshold modificado
    //   - Capturar APPROVED/ESCALATED/DENIED counts
    //   - Calcular BAR y false-denial rate
    //   - Imprimir tabla comparativa
}
```

Nota: risk.Evaluate() usa policy.ApproveThreshold y policy.DenyThreshold del PolicyConfig.
Modificar PolicyConfig en cada iteración.

Verificar: `risk.DefaultPolicyConfig()` retorna ApproveThreshold=39, DenyThreshold=70.
Confirmar que PolicyConfig tiene campos ApproveThreshold/DenyThreshold antes de implementar.

**Resultado esperado:** BAR y false-denial varían de forma monótona con los thresholds,
confirmando que la elección T3 (default) balancea enforcement y false-denial rate.
La tabla en el paper justifica los valores con evidencia en vez de "los elegimos así."

### Registro en main.go
- Añadir `--exp=11` para RunThresholdSensitivity
- Añadir al case 0

### Archivos tocados
- `compliance/adversarial/exp_threshold_sensitivity.go` — nuevo
- `compliance/adversarial/main.go` — registrar exp 11
- `paper/arxiv/main.tex` — nueva subsección §Threshold Sensitivity (Experiment 11)

---

## OBJETIVO 3: Comparación Funcional con AgentSpec

### Por qué

Wang et al. (ICSE 2026, wang2025agentspec) es el trabajo más cercano a ACP.
Hoy el paper tiene solo una tabla de features. Un reviewer que conoce AgentSpec
preguntará: "¿cuál es la diferencia funcional concreta?"

### Diseño

NO requiere correr AgentSpec. La comparación es analítica basada en la semántica
formal de AgentSpec descrita en el paper (arxiv:2503.18666).

**Dimensiones de comparación:**

1. **Enforcement granularity**
   - AgentSpec: property-based rules sobre tool calls (LTL-style constraints)
   - ACP: admission control con risk scoring + stateful signals

2. **Threat model cubierto**
   - AgentSpec: compliance con propiedades definidas por el operador (safety constraints)
   - ACP: admission control adversarial + governance collapse detection (BAR)

3. **Detectability of deviation collapse**
   - AgentSpec: no equivalent to BAR — if the upstream constraints are relaxed, 
     AgentSpec approves everything silently
   - ACP: BAR-Monitor detects this regime explicitly

4. **Composability**
   - AgentSpec: operates on LLM tool calls (prompt layer adjacent)
   - ACP: operates at the execution layer, composable with AgentSpec

5. **Formal verification**
   - AgentSpec: policy synthesis proved correct
   - ACP: safety+liveness model-checked (TLA+, 11 invariants, 5.6M states)

**Scenario concreto para la comparación:**
Usar el scenario de Exp 10 (knowledge-aware evasion, RS=0 siempre APPROVED).
Argumentar formalmente que AgentSpec sin una explicit BAR-equivalent property
no detectaría este collapse — porque cada decision cumple la policy.
ACP detecta via ΔBAR.

Este es el punto más fuerte: ACP añade una dimensión de governance monitoring
que ningún enforcement-only sistema puede dar.

### Implementación en paper

- Nueva subsección §Comparison with AgentSpec dentro de §Related Work
  (o dentro de §Discussion — decidir en la sesión de implementación)
- ~1 página: tabla estructurada + párrafo del scenario de Exp 10
- NO requiere cambios de código Go

### Archivos tocados
- `paper/arxiv/main.tex` únicamente

---

## OBJETIVO 4: Garantías Estadísticas para BAR

### Por qué

BAR es una métrica empírica hoy. Añadir un resultado analítico —
"dada una tasa de evasión p, ¿cuál es la probabilidad de que BAR-Monitor detecte
antes del threshold?"  — convierte BAR en una herramienta con garantías verificables.
Esto es lo que separa un "monitoring metric" de una "detection mechanism with guarantees."

### Diseño analítico

Sea la ventana W = WindowSize = 40. En Exp 10 Phase E:
- Cada request es APPROVED con probabilidad (1-p) o boundary-activating con probabilidad p
  (simplificando: p = fracción no-evadida del dataset)
- BAR en la ventana = X/W donde X ~ Binomial(W, p)

**Resultado clave — Theorem (Detection Guarantee):**

```
Sea p_0 = BAR baseline (fracción de boundary-activating requests en condiciones normales).
Sea p_1 = BAR bajo evasión (p_1 < p_0).
Sea τ = Threshold (= 0.10).
Sea W = WindowSize (= 40).

Si p_0 > τ y p_1 < τ, entonces:
  P(BAR-Monitor fires THRESHOLD within W requests) = P(X ≤ τ·W) where X ~ Bin(W, p_1)

Para ΔBAR early-warning (fires when trend < TrendThreshold = -0.15):
  En el half-window model: Trend = BAR(W/2..W) - BAR(1..W/2)
  Fires when E[BAR(W/2..W)] - E[BAR(1..W/2)] < -0.15
```

**Valores concretos para el paper (W=40, τ=0.10, baseline p_0=0.70):**

| p_1 (under attack) | P(THRESHOLD within 40 req) | Expected batches to detect |
|--------------------|---------------------------|---------------------------|
| 0.00               | ~1.00                     | 1                         |
| 0.05               | 0.94                      | ~1.1                      |
| 0.10 (= τ)         | 0.50                      | ~2                        |
| 0.15               | 0.08                      | —                         |

Para ΔBAR early-warning: con p_1=0.57 (Batch 2 de Exp 10), mostrar que la
probabilidad de una caída de ≥0.25 en el half-window es alta bajo la distribución Binomial.

**Implementación:** cálculo analítico con math.go o inline en el paper como derivación.
No requiere simulación — es un resultado matemático usando scipy/wolframalpha para verificar
y presentado como proposición con proof sketch en el paper.

### Implementación en paper

- Nueva subsección §Detection Guarantees dentro de §Boundary Activation Monitoring
  (después de la descripción de BAR-Monitor, antes de los experimentos)
- ~1 página: definición formal + Theorem + tabla de valores concretos
- Proof sketch en el cuerpo, proof completa como apéndice si es necesario

### Archivos tocados
- `paper/arxiv/main.tex` únicamente
- Opcional: pequeño script Go/Python para verificar los números (no va al paper)

---

## ORDEN DE EJECUCIÓN RECOMENDADO

```
1. Objetivo 2 (Threshold Sensitivity) — primero porque requiere código Go nuevo
   Ejecutar go run . --exp=11 para capturar números reales antes de escribir el paper

2. Objetivo 1 (Adversary Model) — paper only, mayor impacto estructural
   Escribir §Adversary Model con tabla de mapeo de los 10 experimentos

3. Objetivo 4 (BAR Statistical Guarantees) — analítico, paper only
   Calcular valores con Binomial distribution, escribir §Detection Guarantees

4. Objetivo 3 (AgentSpec Comparison) — paper only, más corto
   Expandir §Related Work con comparación funcional + Exp 10 scenario

5. Recompilar PDF y verificar
6. Commit + push EN y ES (código Go) — solo EN (paper)
7. Submit arXiv v8 — v1.25+v1.26 combinados (primera submission desde v7)
   DOI en paper: 10.5281/zenodo.19473832 (Zenodo v1.25, ya publicado)
   Nota: NO subir v1.25 por separado — esperar v1.26 completo
```

---

## ARCHIVOS TOCADOS — RESUMEN

| Archivo | Cambio | Objetivo |
|---------|--------|----------|
| `compliance/adversarial/exp_threshold_sensitivity.go` | NUEVO | O2 |
| `compliance/adversarial/main.go` | añadir --exp=11 | O2 |
| `paper/arxiv/main.tex` | §Adversary Model (nuevo) | O1 |
| `paper/arxiv/main.tex` | §Threshold Sensitivity Exp 11 (nuevo) | O2 |
| `paper/arxiv/main.tex` | §Detection Guarantees (nuevo) | O4 |
| `paper/arxiv/main.tex` | §AgentSpec Comparison (nuevo/expandido) | O3 |
| `paper/arxiv/references.bib` | no nuevas citas requeridas | — |

---

## INFORMACIÓN TÉCNICA CLAVE (para no tener que re-leer el código)

### ACP-RISK-3.0 formula
RS = capBase + F_res + F_ctx + F_hist + F_anom
Thresholds: APPROVED ≤ 39, ESCALATED 40–69, DENIED ≥ 70 (capped 100)

capBase:  data.read=0, data.write=10, financial.transfer=35, admin.manage=60
F_res:    Public=0, Sensitive=15, Restricted=45
F_ctx:    OffHours=15, ExternalIP=20, GeoOutside=15, NonBusinessDay=10 (sum)
F_hist:   RecentDenial=20, FreqAnomaly=15 (sum)
F_anom:   Rule1(burst)=20, Rule2(denials)=15, Rule3(pattern)=15 (sum, max 50)

### BAR y BARMonitor
BAR = (ESCALATED + DENIED) / total (sliding window)
Config: WindowSize=40, Threshold=0.10, TrendThreshold=-0.15
Trend = BAR(second half of window) − BAR(first half)
Alert types: THRESHOLD (BAR < 0.10), TREND (Trend < -0.15)

### Exp 9 baseline dataset
20 casos: APPROVED=6, ESCALATED=7, DENIED=7 → BAR_A=0.70
buildDataset() en exp_deviation_collapse.go — reutilizar siempre

### Exp 10 Phase E results (actual output)
Batch 1: 0%   evasion, BAR=0.70, ΔBAR=+0.60, no alert
Batch 2: 25%  evasion, BAR=0.57, ΔBAR=−0.25, TREND ← early warning
Batch 3: 50%  evasion, BAR=0.33, ΔBAR=−0.25, TREND
Batch 4: 75%  evasion, BAR=0.10, ΔBAR=−0.20, TREND
Batch 5: 100% evasion, BAR=0.00, ΔBAR=+0.00, THRESHOLD

### Módulos Go relevantes
- pkg/risk: Evaluate(), EvalRequest, PolicyConfig, DefaultPolicyConfig()
- pkg/barmonitor: New(Config), Record(Decision) → (*Alert, float64), Trend(), WindowFill()
- risk.NewInMemoryQuerier() para F_anom=0
- buildDataset(), evaluateSet(), evaluateCounterfactuals() en exp_deviation_collapse.go

### Repos
- EN: github.com/chelof100/acp-framework-en (paper + código)
- ES: github.com/chelof100/acp-framework (solo código — sin paper)
- Cualquier cambio de código va a AMBOS repos en el mismo commit o inmediatamente después

### DOI actual
Zenodo v1.26: 10.5281/zenodo.19482968
Zenodo v1.25: 10.5281/zenodo.19473832
arXiv: 2603.18829 (v8 pendiente — submit después de v1.26)

---

## ESTADO — 2026-04-08

- [x] O2: exp_threshold_sensitivity.go + --exp=11
- [x] O2: Capturar números reales (go run . --exp=11) → BAR monotónico (0.75→0.60), false-denial=0.00
- [x] O1: §Adversary Model en main.tex — A=(K,S,B) + tabla experimentos + 4 findings
- [x] O2: §Threshold Sensitivity (Exp 11) en main.tex — tabla resultados + 3 findings
- [x] O4: §Detection Guarantees en main.tex — Proposition binomial + ΔBAR early-warning
- [x] O3: §AgentSpec Comparison en main.tex — tabla 5 dimensiones + Exp 10 scenario
- [x] Recompilar PDF — 76 páginas, sin errores
- [x] Commit + push EN (commit bec1c5b)
- [x] Commit + push ES (commit 9e6219b)
- [ ] Submit arXiv v8 (v1.25+v1.26 combinados — primera submission desde v7)
- [ ] Deploy web (specification.html + specification-es.html a Hostinger)
