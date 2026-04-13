# v1.28 Sprint Plan

**Fecha inicio:** 2026-04-13  
**Estado:** EN PROGRESO  
**Paper base:** v1.27, 87pp, compilado limpio, arXiv v8 (submit/7461998) en moderación

---

## Objetivo

Cerrar v1.28 con Exp 13 validado + sección en paper + mejoras narrativas.
OPA queda como mención de una oración en Related Work — sin benchmark, sin subsección.
El benchmark completo OPA va en v1.29 cuando haya datos.

---

## Decisiones de diseño (sesión 2026-04-13)

| # | Decisión | Razonamiento |
|---|----------|--------------|
| D1 | OPA = una oración en Related Work (v1.28), no subsección | Sin datos no se puede defender subsección ante reviewer |
| D2 | Subsección OPA completa → v1.29 (con benchmark o sin él) | Primero tener resultados, luego texto |
| D3 | OPA v1.29 = Related Work (no Exp 14) | Comparación de modelo computacional, no experimento cuantitativo |
| D4 | Framing OPA: "expressibility", no "performance" | "ACP addresses constraints that cannot be expressed stateless without external state" |
| D5 | v1.29 OPA no requiere implementar OPA+Redis real | Describir arquitectura + complejidad requerida es suficiente |

---

## Tareas v1.28

### Bloque 1 — Validación Exp 13 (BLOQUEO: sin esto no hay v1.28)
- [x] **1.1** Verificar que código existe (`exp_coordination_window.go`) ✅
- [x] **1.2** Verificar API real: `AnomalyDetail`, `RSFinal`, `EvalResult` — todos confirmados ✅
- [ ] **1.3** Compilar: `go build ./...` en compliance/adversarial
- [ ] **1.4** Correr: `go run . --exp=13`
- [ ] **1.5** Capturar output completo (tabla + per-agent detail + boundary trace)
- [ ] **1.6** Validar linealidad: CW_approved/N debe ser constante ≈ k₀ (desvío < 10%)
- [ ] **1.7** Guardar output en `exp13_output.txt`

### Bloque 2 — Paper (después de Bloque 1)
- [ ] **2.1** Insertar sección Exp 13 en main.tex  
  - Fuente: `C:\Users\Mariana\Desktop\Chelo\v1.28 chatgpt v2.md` líneas 161-301  
  - Reemplazar `k₀` con número real del output  
  - Reemplazar `REFUSE` → `DENIED` (implementación) — nota: modelo TLA+ usa REFUSE, paper usa DENIED
- [ ] **2.2** LLM Integration — mover subsección al cuerpo principal (después de §Deterministic Risk Evaluation)
- [ ] **2.3** Related Work — agregar 1 oración sobre OPA (texto exacto abajo)
- [ ] **2.4** `\texttt{}` audit — verificar 40 ocurrencias ACP-RISK-3.0, consistencia
- [ ] **2.5** Related Work — fortalecer distinciones SAGA/AgentSpec/OPA/Cedar/Kyverno (según estado actual)

### Bloque 3 — Cierre
- [ ] **3.1** Compilar paper: 0 errores, 0 undefined refs
- [ ] **3.2** Verificar página count (esperado ~88-90pp)
- [ ] **3.3** Zenodo v1.28 — subir PDF, actualizar DOI en main.tex
- [ ] **3.4** arXiv v9 — preparar submit

---

## Texto OPA para Related Work (una oración, v1.28)

Usar exactamente esto (ajustar posición en la sección):

> Stateless policy engines such as OPA~\cite{opa} evaluate requests in isolation and cannot enforce behavioral constraints that depend on execution history without external state integration, a capability that ACP provides natively through its stateful ledger design.

Si `opa` no está en el .bib, agregar:
```bibtex
@misc{opa,
  title        = {{Open Policy Agent}},
  author       = {{Open Policy Agent Contributors}},
  year         = {2024},
  howpublished = {\url{https://www.openpolicyagent.org}},
  note         = {Accessed: 2026-04-13}
}
```

---

## Diseño Exp 13 (referencia rápida)

**Archivo:** `compliance/adversarial/exp_coordination_window.go`  
**Comando:** `cd compliance/adversarial && go run . --exp=13`

**Setup verificado:**
- Capability: `acp:cap:financial.transfer` + Resource: `accounts/shared-ops` (public)
- B=35, F_res=0 → RS=35 baseline → APPROVED (ApprovedMax=39)
- `policy.AnomalyRule1ThresholdN = 2` → count > 2 en 60s → Rule1 +20 → RS=70 DENIED
- `policy.AnomalyRule3ThresholdY = 2` → count ≥ 2 en 5min → Rule3 +15 → RS=50 ESCALATED
- k₀=3 requests por agente: req#1 APPROVED → req#2 ESCALATED → req#3 DENIED

**API real confirmada:**
- `risk.Evaluate(req, q)` → `*risk.EvalResult`
- `result.Decision` (APPROVED/ESCALATED/DENIED)
- `result.RSFinal` (int)
- `result.AnomalyDetail.Rule1Triggered`, `.Rule2Triggered`, `.Rule3Triggered`
- `risk.PatternKey(agentID, cap, res)` → SHA-256(agentID|cap|res) — per-agent scope

**Variantes:**
- V1: 1 agente secuencial (baseline)
- V2: round-robin N=2,3,5
- V3: burst 5 agentes

**Tabla esperada:**
| N | CW_approved | CW_total | TTB_reqs |
|---|-------------|----------|----------|
| 1 | 1           | 2        | 3        |
| 2 | 2           | 4        | 5        |
| 3 | 3           | 6        | 7        |
| 5 | 5           | 10       | 11       |

**Validación linealidad:** CW_approved/N debe ser ≈ 1 para todos los N (constante = k₀=1).  
Si no es constante → revisar policy config y re-analizar claim antes de tocar paper.

---

## Claim principal del paper (Exp 13)

> ACP does not rely on detecting coordination across agents. Instead, it enforces per-agent behavioral bounds, ensuring that coordinated activity scales at most linearly with the number of participants.

> Total executable actions ∈ O(N)

> This behavior emerges directly from the use of agent-scoped pattern keys (SHA-256(agentID|cap|res)), which isolate risk accumulation across participants.

---

## Conexión narrativa (trilogía)

```
Exp 9  → deviation collapse: condiciones de fallo desaparecen
TLA+   → 4.29B estados, 0 violations: estados problemáticos no alcanzables  
Exp 13 → O(N): coordinación no escala más allá de lineal (per-agent bound)

Together: ACP constrains both the existence and the scaling of undesirable behaviors.
```

---

## Notas de sesión

- `exp_coordination_window.go` estaba ya escrito en sesión anterior — NO reescribir
- `main.go` tiene `case 13` y `RunCoordinationWindow(cfg)` en case 0 — correcto
- Import real: `github.com/chelof100/acp-framework/acp-go/pkg/risk` → `replace` en go.mod apunta a `../../impl/go`
- No hay `Amount` en `risk.ActionInput` — ChatGPT v1 template era incorrecto, código real usa `EvalRequest{Capability, Resource, ResourceClass, Policy}`
- `runRequest` está en `config.go` línea 56, no en archivo separado

---

## v1.29 (no tocar en esta sesión)

- OPA benchmark: Related Work (no Exp 14)  
- Framing: expressibility computacional, no performance
- Diseño: Escenario A (stateless), B (frequency), C (cooldown) — tabla comparativa
- Mención "OPA + external state" debe estar anticipada en el texto
- No necesita implementar OPA+Redis real — arquitectura descriptiva es suficiente
- Ver `C:\Users\Mariana\Desktop\Chelo\v1.28-v1.29 opa chatgpt.md` para diseño completo
