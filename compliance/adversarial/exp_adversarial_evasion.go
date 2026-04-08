package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/barmonitor"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunAdversarialEvasion runs Experiment 10: Knowledge-Aware Adversarial Evasion.
//
// Attack premise: the adversary has complete knowledge of the ACP-RISK-3.0 formula:
//
//	RS = capabilityBase + F_res + F_ctx + F_hist + F_anom
//
// By selecting acp:cap:data.read (B=0) + PUBLIC resource (F_res=0) + clean
// context and history (F_ctx=F_hist=0) + a fresh querier (F_anom=0), the adversary
// guarantees RS=0 → APPROVED for every individual request.  Per-decision
// enforcement correctly approves each case; no engine error is ever raised.
// Yet BAR collapses to 0.00: the admissibility boundary is never exercised.
//
// This experiment demonstrates three things:
//
//  1. Per-decision enforcement is structurally blind to a knowledge-aware adversary.
//  2. BAR-Monitor detects the collapse via ΔBAR early-warning before the threshold.
//  3. EvaluateCounterfactual confirms structural enforcement capacity is preserved.
//
// Metric: BAR = (ESCALATED + DENIED) / total
//
//	Phase A (Baseline)            — diverse dataset → BAR ≈ 0.70
//	Phase B (Adversarial Evasion) — all requests crafted to RS=0 → BAR = 0.00
//	Phase C (Counterfactual)      — 3 mutations → BAR = 1.00 (structural capacity intact)
//	Phase E (Progressive Evasion) — 0→80% evasion rate, BARMonitor early-warning
func RunAdversarialEvasion(_ Config) {
	policy := risk.DefaultPolicyConfig()
	now := time.Now()
	const agentID = "agent-adversarial-evasion"

	fmt.Println("=== Experiment 10: Knowledge-Aware Adversarial Evasion ===")
	fmt.Println()
	fmt.Println("Attack: adversary knows full ACP-RISK-3.0 formula. Uses data.read +")
	fmt.Println("PUBLIC resource + clean context/history → RS=0 → always APPROVED.")
	fmt.Println("Each per-decision evaluation is correct. BAR collapses to 0.00.")
	fmt.Println()

	// ── Phase A: Baseline ─────────────────────────────────────────────────────
	dataset := buildDataset(agentID, policy, now)
	qA := risk.NewInMemoryQuerier()
	resultsA := evaluateSet(dataset, qA, policy, now)
	printPhaseResult("A (Baseline)", resultsA)

	// ── Phase B: Adversarial Evasion ──────────────────────────────────────────
	evaded := buildEvasionDataset(agentID, policy, now, len(dataset))
	qB := risk.NewInMemoryQuerier()
	resultsB := evaluateSet(evaded, qB, policy, now)
	printPhaseResult("B (Adversarial Evasion)", resultsB)
	if resultsB.BAR == 0 {
		fmt.Println("  → EVASION CONFIRMED: per-decision enforcement approved all requests")
		fmt.Println("  No engine errors. ACP-RISK-3.0 evaluated correctly for each case.")
		fmt.Println("  Boundary was not exercised — BAR collapsed to 0.00.")
	}

	// ── Phase C: Counterfactual ────────────────────────────────────────────────
	// Reuse the same 3 mutations as Experiment 9. Even though the adversary
	// evaded per-decision enforcement entirely, the structural capacity to
	// produce DENIED is unaffected — EvaluateCounterfactual confirms this.
	cfResults := evaluateCounterfactuals(dataset, agentID, policy, now)
	printPhaseResult("C (Counterfactual)", cfResults)
	if cfResults.BAR > 0 {
		fmt.Println("  → STRUCTURAL CAPACITY INTACT: enforcement boundaries remain representable")
		fmt.Println("  BAR-Monitor + EvaluateCounterfactual together detect and characterize")
		fmt.Println("  evasion that is invisible to per-decision inspection.")
	}

	// ── Phase E: Progressive Evasion (BARMonitor) ─────────────────────────────
	phaseERes := runPhaseE(agentID, policy, now)
	printPhaseEResults(phaseERes)

	// ── Summary ───────────────────────────────────────────────────────────────
	printSummaryTable(resultsA, resultsB, cfResults)
}

// buildEvasionDataset builds n cases that all evaluate to RS=0 → APPROVED.
// Each case uses:
//   - Capability: acp:cap:data.read (capBase=0)
//   - ResourceClass: PUBLIC (F_res=0)
//   - Context: zero flags (F_ctx=0)
//   - History: zero flags (F_hist=0)
//   - Fresh querier is used at evaluation time (F_anom=0)
//
// RS = 0 + 0 + 0 + 0 + 0 = 0 → APPROVED for every case.
func buildEvasionDataset(agentID string, policy risk.PolicyConfig, now time.Time, n int) []testCase {
	out := make([]testCase, n)
	for i := 0; i < n; i++ {
		out[i] = testCase{
			label: fmt.Sprintf("evasion-%02d", i+1),
			req: risk.EvalRequest{
				AgentID:       agentID,
				Capability:    "acp:cap:data.read",
				Resource:      fmt.Sprintf("metrics/public-%02d", i+1),
				ResourceClass: risk.ResourcePublic,
				Context:       risk.Context{},
				History:       risk.History{},
				Policy:        policy,
				Now:           now,
			},
			wantRS:       0,
			wantDecision: risk.APPROVED,
		}
	}
	return out
}

// phaseEResult holds per-batch output for the progressive evasion simulation.
type phaseEResult struct {
	BatchNum   int
	EvasionPct int     // percentage of cases replaced with evasion cases
	BAR        float64 // BAR after this batch fed into the monitor
	Trend      float64 // ΔBAR after this batch
	Alert      *barmonitor.Alert
	WindowFill int
}

// runPhaseE simulates progressive knowledge-aware evasion across 5 batches.
//
// Each batch consists of the full 20-case dataset from Phase A, but with an
// increasing fraction of boundary-activating cases (ESCALATED/DENIED) replaced
// by crafted evasion cases (RS=0 → APPROVED). The replacement targets the LAST
// N cases of the dataset, where DENIED cases are concentrated.
//
// The BARMonitor uses window=40 (two full batches), so ΔBAR compares each batch
// against the previous one. This enables early-warning detection at Batch 2,
// three batches before full collapse at Batch 5.
//
// Evasion schedule (nEvaded = evasionPct × 20 / 100):
//
//	Batch 1:  0% evaded → full baseline         → BAR≈0.70
//	Batch 2: 25% evaded →  5 cases replaced     → BAR≈0.45 (TREND alert fires)
//	Batch 3: 50% evaded → 10 cases replaced     → BAR≈0.20
//	Batch 4: 75% evaded → 15 cases replaced     → BAR≈0.05
//	Batch 5:100% evaded → all 20 replaced       → BAR=0.00 (THRESHOLD alert)
func runPhaseE(agentID string, policy risk.PolicyConfig, now time.Time) []phaseEResult {
	dataset := buildDataset(agentID, policy, now)
	evadedAll := buildEvasionDataset(agentID, policy, now, len(dataset))
	q := risk.NewInMemoryQuerier()

	m := barmonitor.New(barmonitor.Config{
		WindowSize:     40,
		Threshold:      0.10,
		TrendThreshold: -0.15,
	})

	evasionPcts := []int{0, 25, 50, 75, 100}
	results := make([]phaseEResult, 0, len(evasionPcts))

	for batchNum, evasionPct := range evasionPcts {
		// Replace the LAST nEvaded cases with evasion cases.
		// The baseline dataset is sorted with APPROVED first and DENIED last,
		// so this targets the boundary-activating cases first.
		nEvaded := (evasionPct * len(dataset)) / 100
		batch := make([]testCase, len(dataset))
		evadeFrom := len(dataset) - nEvaded
		for i := range dataset {
			if i >= evadeFrom {
				batch[i] = evadedAll[i]
			} else {
				batch[i] = dataset[i]
			}
		}

		// Feed all decisions into BARMonitor; capture final state at batch end.
		var finalAlert *barmonitor.Alert
		var finalBAR float64
		for j, c := range batch {
			req := c.req
			req.Now = now
			result, err := risk.Evaluate(req, q)
			var dec risk.Decision
			if err != nil {
				dec = risk.DENIED
			} else {
				dec = result.Decision
			}
			a, bar := m.Record(dec)
			if j == len(batch)-1 {
				finalAlert = a
				finalBAR = bar
			}
		}

		results = append(results, phaseEResult{
			BatchNum:   batchNum + 1,
			EvasionPct: evasionPct,
			BAR:        finalBAR,
			Trend:      m.Trend(),
			Alert:      finalAlert,
			WindowFill: m.WindowFill(),
		})
	}
	return results
}

// printPhaseEResults prints the progressive evasion simulation table.
func printPhaseEResults(results []phaseEResult) {
	fmt.Println("\nPhase E (Progressive Evasion — BARMonitor):")
	fmt.Printf("  %-10s  %-9s  %-6s  %-7s  %-20s\n", "Batch", "Evasion%", "BAR", "ΔBAR", "Alert")
	for _, r := range results {
		alertStr := "none"
		if r.Alert != nil {
			alertStr = string(r.Alert.Reason)
		}
		fmt.Printf("  Batch %-4d  %-9d  %-6.2f  %-7.2f  %s\n",
			r.BatchNum, r.EvasionPct, r.BAR, r.Trend, alertStr)
	}
}
