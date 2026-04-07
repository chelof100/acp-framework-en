package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/barmonitor"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// testCase is a labeled evaluation case with a deterministic RS and expected decision.
type testCase struct {
	label        string
	req          risk.EvalRequest
	wantRS       int
	wantDecision risk.Decision
}

// PhaseResult holds aggregate counts and BAR for a single experiment phase.
type PhaseResult struct {
	Total     int
	Approved  int
	Escalated int
	Denied    int
	BAR       float64 // (Escalated + Denied) / Total
}

// counterfactualCase is a single counterfactual mutation with its label.
type counterfactualCase struct {
	label string
	req   risk.EvalRequest
}

// RunDeviationCollapse runs Experiment 9: Deviation Collapse and Restoration.
//
// Demonstrates that ACP may be functioning correctly (no engine errors) while
// the admissibility boundary is never exercised because upstream sanitization
// eliminates all signals that would produce ESCALATED or DENIED decisions.
//
// Metric: BAR = (ESCALATED + DENIED) / total
//
//	Phase A (Baseline)       — diverse dataset → BAR ≈ 0.70
//	Phase B (Sanitized)      — upstream sanitizer → BAR = 0.00 (collapse)
//	Phase C (Counterfactual) — 3 mutations × 20 cases → BAR ≈ 0.70–0.80 (restored)
func RunDeviationCollapse(_ Config) {
	policy := risk.DefaultPolicyConfig()
	now := time.Now()
	const agentID = "agent-deviation-test"

	fmt.Println("=== Experiment 9: Deviation Collapse and Restoration ===")

	// ── Phase A: Baseline ─────────────────────────────────────────────────────
	dataset := buildDataset(agentID, policy, now)
	qA := risk.NewInMemoryQuerier()
	resultsA := evaluateSet(dataset, qA, policy, now)
	printPhaseResult("A (Baseline)", resultsA)

	// ── Phase B: Upstream Sanitization ───────────────────────────────────────
	sanitized := sanitizeDataset(dataset)
	qB := risk.NewInMemoryQuerier()
	resultsB := evaluateSet(sanitized, qB, policy, now)
	printPhaseResult("B (Sanitized)", resultsB)
	if resultsB.BAR == 0 {
		fmt.Println("  → DEVIATION COLLAPSE CONFIRMED: boundary not exercised")
		fmt.Println("  ACP engine returned no errors — enforcement is functioning. Boundary was not exercised.")
	}

	// ── Phase C: Counterfactual Injection ─────────────────────────────────────
	cfResults := evaluateCounterfactuals(dataset, agentID, policy, now)
	printPhaseResult("C (Counterfactual)", cfResults)
	if cfResults.BAR > 0 {
		fmt.Println("  → BOUNDARY RESTORED: failure conditions remain representable")
	}

	// ── Phase D: Drift Simulation ─────────────────────────────────────────────
	phaseDRes := runPhaseD(agentID, policy, now)
	printPhaseDResults(phaseDRes)

	// ── Summary table ─────────────────────────────────────────────────────────
	printSummaryTable(resultsA, resultsB, cfResults)
}

// buildDataset constructs the controlled 20-case baseline dataset.
// Each case has a deterministic RS: RS = capabilityBase + F_ctx + F_hist + F_res.
// All cases use a fresh querier, so F_anom = 0.
//
// Distribution: APPROVED=6 (RS≤39), ESCALATED=7 (40≤RS≤69), DENIED=7 (RS≥70).
// BAR_A = (7+7)/20 = 0.70.
func buildDataset(agentID string, policy risk.PolicyConfig, now time.Time) []testCase {
	mk := func(
		label string,
		cap, res string,
		rc risk.ResourceClass,
		ctx risk.Context,
		hist risk.History,
		wantRS int,
		wantDec risk.Decision,
	) testCase {
		return testCase{
			label: label,
			req: risk.EvalRequest{
				AgentID:       agentID,
				Capability:    cap,
				Resource:      res,
				ResourceClass: rc,
				Context:       ctx,
				History:       hist,
				Policy:        policy,
				Now:           now,
			},
			wantRS:       wantRS,
			wantDecision: wantDec,
		}
	}

	noCtx := risk.Context{}
	noHist := risk.History{}

	return []testCase{
		// ── APPROVED (RS ≤ 39) — 6 cases ──────────────────────────────────────
		// B=0  + F_res=0  = 0
		mk("approved-data.read/public",
			"acp:cap:data.read", "metrics/public", risk.ResourcePublic, noCtx, noHist, 0, risk.APPROVED),
		// B=10 + F_res=0  = 10
		mk("approved-data.write/public",
			"acp:cap:data.write", "logs/public", risk.ResourcePublic, noCtx, noHist, 10, risk.APPROVED),
		// B=35 + F_res=0  = 35
		mk("approved-financial/public",
			"acp:cap:financial.transfer", "reports/public", risk.ResourcePublic, noCtx, noHist, 35, risk.APPROVED),
		// B=0  + F_res=15 = 15
		mk("approved-data.read/sensitive",
			"acp:cap:data.read", "user/profile", risk.ResourceSensitive, noCtx, noHist, 15, risk.APPROVED),
		// B=10 + F_res=0  + OffHours=15 = 25
		mk("approved-data.write/public/offhours",
			"acp:cap:data.write", "logs/public", risk.ResourcePublic,
			risk.Context{OffHours: true}, noHist, 25, risk.APPROVED),
		// B=0  + F_res=0  + NonBusinessDay=10 = 10
		mk("approved-data.read/public/nonbizday",
			"acp:cap:data.read", "metrics/public", risk.ResourcePublic,
			risk.Context{NonBusinessDay: true}, noHist, 10, risk.APPROVED),

		// ── ESCALATED (40 ≤ RS ≤ 69) — 7 cases ───────────────────────────────
		// B=35 + F_res=15 = 50
		mk("escalated-financial/sensitive",
			"acp:cap:financial.transfer", "accounts/sensitive-001", risk.ResourceSensitive, noCtx, noHist, 50, risk.ESCALATED),
		// B=60 + F_res=0  = 60
		mk("escalated-admin/public",
			"acp:cap:admin.manage", "system/config", risk.ResourcePublic, noCtx, noHist, 60, risk.ESCALATED),
		// B=10 + F_res=15 + ExternalIP=20 = 45
		mk("escalated-data.write/sensitive/extip",
			"acp:cap:data.write", "user/records", risk.ResourceSensitive,
			risk.Context{ExternalIP: true}, noHist, 45, risk.ESCALATED),
		// B=35 + F_res=0  + ExternalIP=20 = 55
		mk("escalated-financial/public/extip",
			"acp:cap:financial.transfer", "reports/public", risk.ResourcePublic,
			risk.Context{ExternalIP: true}, noHist, 55, risk.ESCALATED),
		// B=0  + F_res=45 = 45
		mk("escalated-data.read/restricted",
			"acp:cap:data.read", "vault/restricted", risk.ResourceRestricted, noCtx, noHist, 45, risk.ESCALATED),
		// B=35 + F_res=15 + OffHours=15 = 65
		mk("escalated-financial/sensitive/offhours",
			"acp:cap:financial.transfer", "accounts/sensitive-002", risk.ResourceSensitive,
			risk.Context{OffHours: true}, noHist, 65, risk.ESCALATED),
		// B=10 + F_res=15 + ExternalIP=20 + OffHours=15 = 60
		mk("escalated-data.write/sensitive/extip/offhours",
			"acp:cap:data.write", "user/records", risk.ResourceSensitive,
			risk.Context{ExternalIP: true, OffHours: true}, noHist, 60, risk.ESCALATED),

		// ── DENIED (RS ≥ 70) — 7 cases ────────────────────────────────────────
		// B=35 + F_res=45 = 80
		mk("denied-financial/restricted",
			"acp:cap:financial.transfer", "accounts/restricted-fund", risk.ResourceRestricted, noCtx, noHist, 80, risk.DENIED),
		// B=60 + F_res=15 = 75
		mk("denied-admin/sensitive",
			"acp:cap:admin.manage", "system/sensitive", risk.ResourceSensitive, noCtx, noHist, 75, risk.DENIED),
		// B=60 + F_res=0  + ExternalIP=20 + OffHours=15 = 95
		mk("denied-admin/public/extip/offhours",
			"acp:cap:admin.manage", "system/config", risk.ResourcePublic,
			risk.Context{ExternalIP: true, OffHours: true}, noHist, 95, risk.DENIED),
		// B=35 + F_res=45 + ExternalIP=20 = 100
		mk("denied-financial/restricted/extip",
			"acp:cap:financial.transfer", "accounts/restricted-fund", risk.ResourceRestricted,
			risk.Context{ExternalIP: true}, noHist, 100, risk.DENIED),
		// B=0  + F_res=45 + ExternalIP=20 + GeoOutside=15 + OffHours=15 = 95
		mk("denied-data.read/restricted/extip/geo/offhours",
			"acp:cap:data.read", "vault/restricted", risk.ResourceRestricted,
			risk.Context{ExternalIP: true, GeoOutside: true, OffHours: true}, noHist, 95, risk.DENIED),
		// B=35 + F_res=15 + RecentDenial=20 + ExternalIP=20 = 90
		mk("denied-financial/sensitive/recentdenial/extip",
			"acp:cap:financial.transfer", "accounts/sensitive-003", risk.ResourceSensitive,
			risk.Context{ExternalIP: true}, risk.History{RecentDenial: true}, 90, risk.DENIED),
		// B=60 + F_res=45 = 105 → capped 100
		mk("denied-admin/restricted",
			"acp:cap:admin.manage", "vault/restricted", risk.ResourceRestricted, noCtx, noHist, 100, risk.DENIED),
	}
}

// sanitizeDataset returns a copy of cases with all risk signals removed:
// Capability → data.read, ResourceClass → Public, Context and History zeroed.
// RS = 0 for every case → APPROVED guaranteed.
func sanitizeDataset(cases []testCase) []testCase {
	out := make([]testCase, len(cases))
	for i, c := range cases {
		r := c.req
		r.Capability = "acp:cap:data.read"
		r.ResourceClass = risk.ResourcePublic
		r.Resource = "metrics/public"
		r.Context = risk.Context{}
		r.History = risk.History{}
		out[i] = testCase{
			label:        c.label + "_sanitized",
			req:          r,
			wantRS:       0,
			wantDecision: risk.APPROVED,
		}
	}
	return out
}

// evaluateSet evaluates each case against the provided querier and returns
// aggregate counts. Calls risk.Evaluate directly (no state accumulation between
// cases) so each case is evaluated in isolation against the same querier snapshot.
func evaluateSet(cases []testCase, q risk.LedgerQuerier, _ risk.PolicyConfig, now time.Time) PhaseResult {
	var r PhaseResult
	r.Total = len(cases)
	for _, c := range cases {
		req := c.req
		req.Now = now
		result, err := risk.Evaluate(req, q)
		if err != nil {
			r.Denied++
			continue
		}
		switch result.Decision {
		case risk.APPROVED:
			r.Approved++
		case risk.ESCALATED:
			r.Escalated++
		default:
			r.Denied++
		}
	}
	if r.Total > 0 {
		r.BAR = float64(r.Escalated+r.Denied) / float64(r.Total)
	}
	return r
}

// generateCounterfactuals generates 3 mutations for a single base request.
// All three are designed to guarantee DENIED when evaluated with their
// respective querier (see evaluateCounterfactuals).
func generateCounterfactuals(_ risk.EvalRequest, agentID string, policy risk.PolicyConfig, now time.Time) []counterfactualCase {
	return []counterfactualCase{
		// Mutation 1 — Structural: elevate capability + resource class.
		// RS = 35 (financial) + 45 (restricted) = 80 → DENIED.
		{
			label: "structural",
			req: risk.EvalRequest{
				AgentID:       agentID,
				Capability:    "acp:cap:financial.transfer",
				Resource:      "accounts/restricted-fund",
				ResourceClass: risk.ResourceRestricted,
				Policy:        policy,
				Now:           now,
			},
		},
		// Mutation 2 — Behavioral: inject context + history flags on top of structural.
		// RS = 35 + 45 + ExternalIP=20 + OffHours=15 + RecentDenial=20 + FreqAnomaly=15
		//    = 150 → capped 100 → DENIED.
		{
			label: "behavioral",
			req: risk.EvalRequest{
				AgentID:       agentID,
				Capability:    "acp:cap:financial.transfer",
				Resource:      "accounts/restricted-fund",
				ResourceClass: risk.ResourceRestricted,
				Context:       risk.Context{ExternalIP: true, OffHours: true},
				History:       risk.History{RecentDenial: true, FreqAnomaly: true},
				Policy:        policy,
				Now:           now,
			},
		},
		// Mutation 3 — Temporal: ledger pre-loaded to trigger all three F_anom rules.
		// RS = 35 + 45 + Rule1=20 + Rule2=15 + Rule3=15 = 130 → capped 100 → DENIED.
		// Evaluated against buildTemporalQuerier output in evaluateCounterfactuals.
		{
			label: "temporal",
			req: risk.EvalRequest{
				AgentID:       agentID,
				Capability:    "acp:cap:financial.transfer",
				Resource:      "accounts/restricted-fund",
				ResourceClass: risk.ResourceRestricted,
				Policy:        policy,
				Now:           now,
			},
		},
	}
}

// buildTemporalQuerier returns an InMemoryQuerier pre-loaded to trigger all
// three F_anom rules for (agentID, financial.transfer, accounts/restricted-fund):
//
//	Rule 1: CountPattern(patKey, 60s) > 10  → F_anom += 20  (11 entries at -30s)
//	Rule 2: CountDenials(agentID, 24h) ≥ 3  → F_anom += 15  (3 entries at -1h)
//	Rule 3: CountPattern(patKey, 5min) ≥ 3  → F_anom += 15  (satisfied by Rule 1 entries)
//	Total F_anom = +50
func buildTemporalQuerier(agentID string, _ risk.PolicyConfig, now time.Time) *risk.InMemoryQuerier {
	q := risk.NewInMemoryQuerier()
	patKey := risk.PatternKey(agentID, "acp:cap:financial.transfer", "accounts/restricted-fund")

	// Rule 1: 11 patterns within last 60 seconds → CountPattern(patKey,60s) = 11 > 10
	for i := 0; i < 11; i++ {
		q.AddPattern(patKey, now.Add(-30*time.Second))
	}
	// Rule 2: 3 denials within last 24 hours → CountDenials(agentID,24h) = 3 ≥ 3
	for i := 0; i < 3; i++ {
		q.AddDenial(agentID, now.Add(-1*time.Hour))
	}
	// Rule 3: additional 3 patterns within 5 min (entries at -30s already satisfy this,
	// but we add explicit entries at -2min for clarity)
	for i := 0; i < 3; i++ {
		q.AddPattern(patKey, now.Add(-2*time.Minute))
	}
	return q
}

// evaluateCounterfactuals generates 3 mutations × len(cases) = 60 evaluations.
// Mutations 1 (structural) and 2 (behavioral) use fresh queriers.
// Mutation 3 (temporal) reuses a single pre-loaded querier (read-only evaluation).
func evaluateCounterfactuals(cases []testCase, agentID string, policy risk.PolicyConfig, now time.Time) PhaseResult {
	var r PhaseResult
	// Build temporal querier once — all temporal mutations share the same
	// (agentID, capability, resource) tuple, so one querier serves all 20 cases.
	temporalQ := buildTemporalQuerier(agentID, policy, now)

	for _, c := range cases {
		cfCases := generateCounterfactuals(c.req, agentID, policy, now)
		for _, cf := range cfCases {
			req := cf.req
			req.Now = now

			var q risk.LedgerQuerier
			if cf.label == "temporal" {
				q = temporalQ
			} else {
				q = risk.NewInMemoryQuerier()
			}

			result, err := risk.Evaluate(req, q)
			r.Total++
			if err != nil {
				r.Denied++
				continue
			}
			switch result.Decision {
			case risk.APPROVED:
				r.Approved++
			case risk.ESCALATED:
				r.Escalated++
			default:
				r.Denied++
			}
		}
	}
	if r.Total > 0 {
		r.BAR = float64(r.Escalated+r.Denied) / float64(r.Total)
	}
	return r
}

// printPhaseResult prints a single-line summary for one phase.
func printPhaseResult(label string, r PhaseResult) {
	fmt.Printf("Phase %s: total=%d  APPROVED=%d  ESCALATED=%d  DENIED=%d  BAR=%.2f\n",
		label, r.Total, r.Approved, r.Escalated, r.Denied, r.BAR)
}

// phaseDResult holds per-batch output for the drift simulation.
type phaseDResult struct {
	BatchNum    int
	DriftPct    int     // percentage of cases sanitized (0, 25, 50, 75, 100)
	BAR         float64 // BAR after this batch is fed into the monitor
	Trend       float64 // ΔBAR after this batch
	Alert       *barmonitor.Alert
	WindowFill  int
}

// runPhaseD simulates progressive upstream drift across 5 batches.
//
// Each batch consists of the full 20-case dataset from Phase A, but with an
// increasing fraction of cases sanitized (stripped of all risk signals).
// Sanitization targets boundary-activating cases first (from the end of the
// dataset, where DENIED cases are concentrated), so BAR degrades meaningfully
// with each batch.
//
// The BARMonitor uses a window of 40 (two batches), enabling ΔBAR to compare
// the current batch against the previous one and detect inter-batch decline.
//
// Drift schedule (nSanitized = driftPct × 20 / 100):
//
//	Batch 1:  0% sanitized → all 20 baseline  → BAR≈0.70
//	Batch 2: 25% sanitized →  5 DENIED cases sanitized → BAR≈0.45
//	Batch 3: 50% sanitized → 10 boundary cases sanitized → BAR≈0.20
//	Batch 4: 75% sanitized → 15 boundary cases sanitized → BAR≈0.00
//	Batch 5:100% sanitized → all 20 sanitized → BAR=0.00
//
// Expected: ΔBAR alert fires at Batch 2 (BAR≈0.575 >> threshold=0.10),
// demonstrating early-warning detection before the degenerate regime.
// Threshold alert fires at Batch 5 (collapse confirmed).
//
// Alert tracking: we report the alert produced by the last decision of each
// batch to reflect the monitor's state at batch completion, not warm-up noise.
func runPhaseD(agentID string, policy risk.PolicyConfig, now time.Time) []phaseDResult {
	dataset := buildDataset(agentID, policy, now)
	sanitized := sanitizeDataset(dataset)
	q := risk.NewInMemoryQuerier()

	// Window=40 spans exactly two batches (2×20), so ΔBAR compares the current
	// batch (second half of window) against the previous batch (first half).
	// Threshold=0.10; TrendThreshold=-0.15.
	m := barmonitor.New(barmonitor.Config{
		WindowSize:     40,
		Threshold:      0.10,
		TrendThreshold: -0.15,
	})

	driftPcts := []int{0, 25, 50, 75, 100}
	results := make([]phaseDResult, 0, len(driftPcts))

	for batchNum, driftPct := range driftPcts {
		// Sanitize the LAST nSanitized cases — these are DENIED and ESCALATED
		// cases in the dataset, which are the boundary-activating requests.
		nSanitized := (driftPct * len(dataset)) / 100 // floor division
		batch := make([]testCase, len(dataset))
		sanitizeFrom := len(dataset) - nSanitized
		for i := range dataset {
			if i >= sanitizeFrom {
				batch[i] = sanitized[i]
			} else {
				batch[i] = dataset[i]
			}
		}

		// Feed all decisions in this batch into the monitor.
		// Capture the alert and BAR from the very last decision of the batch
		// to report batch-completion state, not warm-up noise.
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

		results = append(results, phaseDResult{
			BatchNum:   batchNum + 1,
			DriftPct:   driftPct,
			BAR:        finalBAR,
			Trend:      m.Trend(),
			Alert:      finalAlert,
			WindowFill: m.WindowFill(),
		})
	}
	return results
}

// printPhaseDResults prints the drift simulation table.
func printPhaseDResults(results []phaseDResult) {
	fmt.Println("\nPhase D (Drift Simulation):")
	fmt.Printf("  %-10s  %-6s  %-6s  %-7s  %-20s\n", "Batch", "Drift%", "BAR", "ΔBAR", "Alert")
	for _, r := range results {
		alertStr := "none"
		if r.Alert != nil {
			alertStr = string(r.Alert.Reason)
		}
		fmt.Printf("  Batch %-4d  %-6d  %-6.2f  %-7.2f  %s\n",
			r.BatchNum, r.DriftPct, r.BAR, r.Trend, alertStr)
	}
}

// printSummaryTable prints the three-phase comparison table with proportions.
func printSummaryTable(a, b, c PhaseResult) {
	fmt.Println("\nSummary:")
	fmt.Printf("%-25s  %-9s  %-9s  %-9s  %-6s\n", "Phase", "APPROVED", "ESCALATED", "DENIED", "BAR")
	printSummaryRow("A (Baseline)", a)
	printSummaryRow("B (Sanitized)", b)
	printSummaryRow("C (Counterfactual)", c)
}

func printSummaryRow(label string, r PhaseResult) {
	if r.Total == 0 {
		return
	}
	suffix := ""
	if label == "B (Sanitized)" {
		suffix = " ← collapse"
	} else if label == "C (Counterfactual)" {
		suffix = " ← restored"
	}
	fmt.Printf("%-25s  %-9.2f  %-9.2f  %-9.2f  %-6.2f%s\n",
		label,
		float64(r.Approved)/float64(r.Total),
		float64(r.Escalated)/float64(r.Total),
		float64(r.Denied)/float64(r.Total),
		r.BAR,
		suffix)
}
