# ACP v1.25 Sprint Plan — ΔBAR Validation + TLA+ + Counterfactual API L2
# Fecha de diseño: 2026-04-07
# Estado: DISEÑADO — ejecutar después de v1.24 completo
# Dependencias: v1.24 completo (pkg/barmonitor, EvaluateCounterfactual, §Boundary Activation Monitoring en paper)

---

## CONTEXTO

v1.25 tiene tres sprints independientes que comparten el objetivo de consolidar
las contribuciones de v1.24 con validación empírica y verificación formal.

El orden de ejecución recomendado:
  Sprint A: Exp 9 Phase D  (más rápido, mayor impacto en paper)
  Sprint B: TLA+ Deviation Collapse  (cierra el gap de verificación formal)
  Sprint C: Counterfactual API Level 2  (opcional, solo si hay tiempo)

---

## SPRINT A: Exp 9 Phase D — Validación Experimental de ΔBAR

### Por qué es necesario

v1.24 define ΔBAR formalmente y lo implementa en pkg/barmonitor, pero el paper
solo tiene la definición — no hay experimento que lo valide. Un reviewer fuerte
puede señalar: "definen ΔBAR pero no muestran que funciona."

Phase D cierra ese gap: simula decline gradual de BAR (upstream drift progresivo)
y demuestra que ΔBAR dispara la alerta ANTES de que BAR llegue al threshold.

### Diseño de Phase D

**Setup:**
- Usar el dataset de Exp 9 Phase A (20 casos, BAR=0.70) como punto de partida
- Simular "upstream drift" como una función que va aumentando progresivamente
  el número de requests sanitizadas en cada batch
- Batch 1: 0% sanitizado → BAR≈0.70
- Batch 2: 25% sanitizado → BAR≈0.52
- Batch 3: 50% sanitizado → BAR≈0.35
- Batch 4: 75% sanitizado → BAR≈0.17
- Batch 5: 100% sanitizado → BAR≈0.00 (colapso total)

**BARMonitor en Phase D:**
```go
// Usar pkg/barmonitor con WindowSize=20 (un batch), Threshold=0.10, TrendThreshold=-0.15
m := barmonitor.New(barmonitor.Config{
    WindowSize:     20,
    Threshold:      0.10,
    TrendThreshold: -0.15,
})
// Procesar los 5 batches secuencialmente, reportando BAR y ΔBAR después de cada uno.
// ΔBAR alert debe disparar en Batch 3 o 4 (antes de que BAR llegue a 0.00).
```

**Output esperado:**
```
Phase D (Drift Simulation):
  Batch 1 (drift=0%):   BAR=0.70  ΔBAR=0.00  Alert=none
  Batch 2 (drift=25%):  BAR=0.52  ΔBAR=-0.18 Alert=TREND   ← ΔBAR alerta aquí
  Batch 3 (drift=50%):  BAR=0.35  ΔBAR=-0.17 Alert=TREND
  Batch 4 (drift=75%):  BAR=0.17  ΔBAR=-0.18 Alert=THRESHOLD+TREND
  Batch 5 (drift=100%): BAR=0.00  ΔBAR=-0.17 Alert=THRESHOLD+TREND
```

El punto clave para el paper: en Batch 2, ΔBAR detecta el decline cuando BAR
todavía es 0.52 — muy por encima del threshold de 0.10. El sistema da tiempo de
reaccionar antes de que colapse.

**Implementación:**
- Agregar función `runPhaseD()` en exp_deviation_collapse.go
- Agregar Phase D a la tabla tab:exp9-bar con columna BAR + columna ΔBAR
- Actualizar figura fig:exp9-bar para mostrar las 4 fases (A/B/C/D) si el gráfico
  lo permite, o crear una figura separada para Phase D (fig:exp9-drift)

**Texto del paper para Phase D:**
```latex
\textbf{Phase D (Drift Simulation).}
To validate ΔBAR as an early-warning mechanism, we simulate progressive
upstream drift by increasing the proportion of sanitized requests across
five evaluation batches (0\%, 25\%, 50\%, 75\%, 100\% sanitized).
Using a sliding window of $N=20$ evaluations, ΔBAR fires an alert at
Batch~2 ($\mathrm{BAR}=0.52$, $\Delta\mathrm{BAR}=-0.18$), significantly
before the threshold condition fires at Batch~4 ($\mathrm{BAR}=0.17$).
This demonstrates that trend detection provides advance warning proportional
to the rate of drift, enabling intervention before the degenerate regime is reached.
```

### Actualización de la tabla
La tabla actual (tab:exp9-bar) tiene 3 filas (A/B/C). Agregar fila D:

| Phase | APPROVED | ESCALATED | DENIED | BAR | ΔBAR |
|-------|----------|-----------|--------|-----|------|
| A (Baseline) | 0.30 | 0.35 | 0.35 | 0.70 | — |
| B (Sanitized) | 1.00 | 0.00 | 0.00 | 0.00 | ← collapse |
| C (Counterfactual) | 0.00 | 0.00 | 1.00 | 1.00 | ← restored |
| D (Drift, peak alert) | 0.48 | 0.26 | 0.26 | 0.52 | -0.18 ← TREND alert |

Nota: los números exactos de Phase D se actualizan después de ejecutar el experimento.

---

## SPRINT B: TLA+ — Invariantes de Deviation Collapse

### Por qué es importante

La sección §Limits define formalmente Degenerate Admissibility y Failure Condition
Preservation. Esas definiciones no están en el modelo TLA+. Un reviewer de venue
top (IEEE S&P, USENIX Security) va a señalar: "§Limits makes formal claims but the
TLA+ model doesn't verify them."

Sprint B cierra ese gap. IMPORTANTE: posicionar correctamente lo que TLA+ verifica
(ver advertencia abajo).

### Advertencia sobre el alcance de la verificación TLA+

TLA+ verifica propiedades sobre el MODELO, no sobre el sistema bajo sanitización.
Los invariantes que se pueden verificar son:

**Lo que SÍ se puede probar:**
- "El espacio de acciones del modelo contiene zonas de rechazo" (condición estructural necesaria)
- "Bajo la política por defecto, existen capability+resource que producen DENIED"
- "BAR-Monitor emite alerta cuando se le alimentan N decisiones APPROVED consecutivas"

**Lo que NO se puede probar con TLA+:**
- "El sistema real no colapsa bajo sanitización" (eso requiere verificación del pipeline completo)
- "ΔBAR siempre detecta decline antes que el threshold" (eso es probabilístico)

En el paper, posicionar como: "establishes a necessary structural condition for
failure condition preservation" — no más fuerte que eso.

### Invariantes a agregar al modelo TLA+

Ubicación: `tla/` en el repo ACP-PROTOCOL-EN. Ver modelo existente.

**Invariante I_FCP (Failure Condition Preservation):**
```tla
\* Existe al menos un (cap, res) que el engine evaluaría como DENIED
\* bajo la política por defecto y estado vacío.
FailureConditionPreservation ==
  \E cap \in {"acp:cap:financial.transfer", "acp:cap:admin.manage"},
     res \in {"restricted"} :
    EvaluationResult(cap, res, EmptyContext, EmptyHistory, EmptyState) = "DENIED"
```

**Invariante I_NDA (No Degenerate Admissibility — condición estructural):**
```tla
\* Si el dominio del agente incluye financial.transfer + restricted,
\* la evaluación con estado vacío no puede ser APPROVED.
NoDegenerateAdmissibility ==
  \/ "acp:cap:financial.transfer" \notin AgentCapabilities
  \/ ResourceRestricted \notin AgentResources
  \/ EvaluationResult("acp:cap:financial.transfer", ResourceRestricted,
                       EmptyContext, EmptyHistory, EmptyState) \neq "APPROVED"
```

**Propiedad temporal T_BARAlerts (liveness del monitor):**
```tla
\* Si en toda traza las últimas N decisiones son APPROVED,
\* BAR-Monitor eventualmente emite una alerta.
BARMonitorLiveness ==
  (\A i \in 1..N : decisions[i] = "APPROVED") =>
    <>(AlertEmitted = TRUE)
```

### Actualización del paper (§Formal Verification)
Agregar una nota al final de la sección de verificación formal existente:

```latex
\textbf{Structural failure condition preservation.}
We add two invariants to the TLA+ model verifying necessary structural
conditions for failure condition preservation
(Section~\ref{sec:deviation-collapse}):
\textit{FailureConditionPreservation} asserts that the evaluated action space
contains at least one request that the engine evaluates as \texttt{DENIED}
under default policy and empty ledger state;
\textit{NoDegenerateAdmissibility} asserts that high-risk capability/resource
combinations are never \texttt{APPROVED} from empty state.
These invariants hold in all $5{,}684{,}342+\Delta$ states explored.
We note that these establish \emph{necessary structural conditions}, not
sufficient conditions for runtime failure condition preservation under
arbitrary upstream transformations.
```

---

## SPRINT C: Counterfactual API Level 2 — Endpoint HTTP (OPCIONAL)

### Condición de activación
Sprint C solo se ejecuta si:
a) Sprints A y B están completos y hay tiempo, O
b) Una venue específica lo pide, O
c) Existe un caso de uso real de interoperabilidad

### Diseño del endpoint

**Spec OpenAPI:**
```yaml
/acp/v1/counterfactual:
  post:
    summary: Evaluate counterfactual mutations
    requestBody:
      schema:
        type: object
        properties:
          base:
            $ref: '#/components/schemas/EvalRequest'
          mutations:
            type: array
            items:
              $ref: '#/components/schemas/Mutation'
    responses:
      200:
        schema:
          type: object
          properties:
            results:
              type: array
              items:
                $ref: '#/components/schemas/CounterfactualResult'
            bar:
              type: number
              description: Boundary Activation Rate for this set of results
```

**Decisiones de diseño:**
- El endpoint usa el mismo engine y política que el deployment
- LedgerSetup no es parte del payload HTTP (temporal mutations requieren state management — fuera de scope para L2)
- El endpoint solo soporta mutaciones Structural y Behavioral vía HTTP
- Temporal mutations quedan para uso vía librería directo
- La respuesta incluye BAR calculado sobre los resultados
- Autenticación: misma que /acp/v1/evaluate (ACP-CT-1.0)

**Nota de scope:** Este endpoint es útil para herramientas de testing externo y
para conformance testing de terceros. Si ACP quiere ser adoptado ampliamente,
poder verificar que "tu deployment puede producir DENIED" via HTTP es valioso.
Pero es scope de producto, no de paper — presentarlo en Implementation section,
no en Contributions.

---

## ACTUALIZACIÓN DEL ROADMAP EN PAPER (a hacer cuando v1.25 se ejecute)

Agregar a la tabla de roadmap:

```latex
Boundary Activation Monitoring (\texttt{pkg/barmonitor}, ΔBAR trend detection) & v1.24 Complete \\
\texttt{EvaluateCounterfactual} API (\texttt{pkg/risk}, additive mutations, 3 built-in factories) & v1.24 Complete \\
Experiment~9 Phase~D: ΔBAR early-warning validation (upstream drift simulation) & v1.25 Complete \\
TLA+ invariants: FailureConditionPreservation, NoDegenerateAdmissibility & v1.25 Complete \\
```

---

## SUCCESS CRITERIA v1.25

### Sprint A (Phase D)
- [ ] runPhaseD() implementado en exp_deviation_collapse.go
- [ ] ΔBAR alert dispara en Batch 2 (BAR todavía > 0.40)
- [ ] Threshold alert dispara en Batch 4 (confirma que ΔBAR fue primero)
- [ ] Tabla tab:exp9-bar actualizada con columna ΔBAR
- [ ] Texto "Phase D" en paper con números reales

### Sprint B (TLA+)
- [ ] FailureConditionPreservation: TLC pasa sin violaciones
- [ ] NoDegenerateAdmissibility: TLC pasa sin violaciones
- [ ] BARMonitorLiveness: TLC pasa (liveness)
- [ ] Paper §Formal Verification actualizado con nota de posicionamiento correcto

### Sprint C (HTTP, opcional)
- [ ] openapi/acp-api-1.0.yaml actualizado con /acp/v1/counterfactual
- [ ] Implementación en server Go existente
- [ ] Tests de integración (HTTP mode)
- [ ] Documentado en §Implementation, NO en §Contributions

---

## DEPENDENCIAS ENTRE SPRINTS

```
v1.23 (Exp 9, §Limits)
  └── v1.24 (pkg/barmonitor, EvaluateCounterfactual, §BAR-Monitor en paper)
        ├── v1.25-A (Phase D — usa pkg/barmonitor directamente)
        ├── v1.25-B (TLA+ — usa definiciones de §Limits como referencia)
        └── v1.25-C (HTTP — usa EvaluateCounterfactual como backend)
```

Sprint A y Sprint B son independientes entre sí — pueden ejecutarse en paralelo.
Sprint C depende de que EvaluateCounterfactual (v1.24) esté estable.

---

## POSICIONAMIENTO ACADÉMICO DE v1.25

Si v1.25 se completa con Sprints A+B:

El paper pasa de:
  "identificamos deviation collapse y demostramos BAR"

a:
  "identificamos deviation collapse, demostramos BAR, validamos ΔBAR como
   mecanismo de early warning, y verificamos formalmente las condiciones
   estructurales en TLA+"

Eso cierra todos los gaps que un reviewer de venue top puede señalar en §Limits.
Con v1.24+v1.25, la sección §Limits of Execution-Only Governance está completa
tanto empírica como formalmente.
