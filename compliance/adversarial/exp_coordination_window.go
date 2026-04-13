package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunCoordinationWindow runs Experiment 13: Bounded Coordination Window.
//
// Evaluates the extent to which N coordinated agents can execute approved
// financial operations before ACP triggers the first DENIED decision.
//
// Setup: financial.transfer on a shared public resource. Anomaly thresholds
// set low (Rule1N=2, Rule3Y=2) so risk escalates after a predictable number
// of requests per agent:
//
//	RS = B(35) + F_res(0) + F_anom(0 → +15 → +35)
//	Request 1: count=1, no rules triggered → RS=35 → APPROVED
//	Request 2: Rule3 triggered (+15)       → RS=50 → ESCALATED
//	Request 3: Rule3+Rule1 triggered (+35) → RS=70 → DENIED
//
// ACP-RISK-3.0 scopes PatternKey per-agent (SHA-256(agentID|cap|res)).
// Each agent accumulates risk independently — there is no cross-agent
// anomaly accumulation. As a result, the coordination window scales
// linearly with the number of agents: CW_approved = N × k₀.
//
// Three variants:
//
//	V1 — 1 agent sequential (baseline per-agent bound)
//	V2 — N agents round-robin (2, 3, 5 agents) on the same shared resource
//	V3 — 5 agents burst (each agent runs to its DENIED before next starts)
func RunCoordinationWindow(_ Config) {
	fmt.Println("=== Experiment 13: Bounded Coordination Window ===")
	fmt.Println()

	// Tuned policy: low anomaly thresholds expose the coordination window.
	// financial.transfer + public: B=35, F_res=0 → RS=35 baseline (APPROVED).
	// Rule3(Y=2): on 2nd pattern occurrence in 5min → +15 → RS=50 (ESCALATED).
	// Rule1(N=2): on 3rd pattern occurrence in 60s  → +20 → RS=70 (DENIED).
	// Per agent: 1 APPROVED → 1 ESCALATED → DENIED. k₀=3 requests per agent.
	policy := risk.DefaultPolicyConfig()
	policy.AnomalyRule1ThresholdN = 2 // count > 2 in 60s triggers Rule1 (+20)
	policy.AnomalyRule3ThresholdY = 2 // count ≥ 2 in 5min triggers Rule3 (+15)

	fmt.Printf("Scenario : acp:cap:financial.transfer / accounts/shared-ops (public)\n")
	fmt.Printf("Baseline : B=35 + F_res=0 = RS 35 → APPROVED (ApprovedMax=39)\n")
	fmt.Printf("Escalation: +Rule3(≥%d/5min)→RS=50 ESCALATED  +Rule1(>%d/60s)→RS=70 DENIED\n",
		policy.AnomalyRule3ThresholdY, policy.AnomalyRule1ThresholdN)
	fmt.Printf("Per-agent: req#1=APPROVED  req#2=ESCALATED  req#3=DENIED  (k₀=3)\n")
	fmt.Println()

	// ─── Table header ────────────────────────────────────────────────────────
	fmt.Printf("  %-28s  %-6s  %-10s  %-10s  %-10s\n",
		"Variant", "N", "CW_appr", "CW_total", "TTB_reqs")
	fmt.Printf("  %-28s  %-6s  %-10s  %-10s  %-10s\n",
		"-------", "-", "-------", "--------", "--------")

	// V1 — single agent baseline
	cw1, cw1tot, ttb1 := cwRoundRobin(1, policy)
	fmt.Printf("  %-28s  %-6d  %-10d  %-10d  %-10d\n",
		"V1 — Sequential", 1, cw1, cw1tot, ttb1)

	// V2 — N agents round-robin
	for _, n := range []int{2, 3, 5} {
		cw, cwTot, ttb := cwRoundRobin(n, policy)
		label := fmt.Sprintf("V2 — Round-robin (%d agents)", n)
		fmt.Printf("  %-28s  %-6d  %-10d  %-10d  %-10d\n",
			label, n, cw, cwTot, ttb)
	}

	// V3 — 5 agents burst (each agent completes before next begins)
	cwB, cwBtot, ttbB := cwBurst(5, policy)
	fmt.Printf("  %-28s  %-6d  %-10d  %-10d  %-10d\n",
		"V3 — Burst (5 agents)", 5, cwB, cwBtot, ttbB)

	// ─── Per-agent contribution detail (V2, N=3) ─────────────────────────────
	fmt.Println()
	fmt.Println("--- Per-agent contribution (V2, N=3) ---")
	cwRoundRobinVerbose(3, policy)

	// ─── Boundary Activation Point (V2, N=5) ─────────────────────────────────
	fmt.Println()
	fmt.Println("--- Boundary Activation Point (V2, N=5) ---")
	cwBoundaryTrace(5, policy)

	// ─── Findings ─────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("=== Findings ===")
	fmt.Printf("CW_approved = N × k₀  (linear): each agent independently contributes\n")
	fmt.Printf("k₀=1 approved op before anomaly escalates (Rule3) then blocks (Rule1).\n")
	fmt.Println()
	fmt.Printf("TTB_reqs    = N×(k₀-1)+1 (round-robin): more agents delay the first\n")
	fmt.Printf("block in total-request count, but do not reduce per-agent exposure.\n")
	fmt.Println()
	fmt.Println("Design boundary: PatternKey = SHA-256(agentID | cap | res) ensures")
	fmt.Println("per-agent scope. N agents targeting the same resource accumulate risk")
	fmt.Println("independently. Total approved operations = N × k₀ (linear in N).")
	fmt.Println()
	fmt.Println("ACP bounds coordination per-agent. Resource-level attribution against")
	fmt.Println("coordinated access requires an additional mechanism beyond RISK-3.0")
	fmt.Println("per-agent admission control (identified as future work).")
}

// makeCoordReq returns a financial.transfer request on a shared public resource.
// Baseline RS = B(35) + F_res(0) = 35 → APPROVED (ApprovedMax=39, Level 2).
func makeCoordReq(agentID string, policy risk.PolicyConfig) risk.EvalRequest {
	return risk.EvalRequest{
		AgentID:       agentID,
		Capability:    "acp:cap:financial.transfer",
		Resource:      "accounts/shared-ops",
		ResourceClass: risk.ResourcePublic,
		Policy:        policy,
	}
}

// cwRoundRobin runs N agents in strict round-robin on a shared ledger.
// Each agent sends one request per round until the first DENIED is encountered.
// Returns: (CW_approved, CW_total, TTB_reqs).
//
//   - CW_approved: total APPROVED decisions across all agents before first DENIED.
//   - CW_total:    total non-DENIED decisions (APPROVED + ESCALATED).
//   - TTB_reqs:    1-based request number of the first DENIED.
func cwRoundRobin(n int, policy risk.PolicyConfig) (approved, cwTotal, ttbReqs int) {
	q := risk.NewInMemoryQuerier()
	agents := make([]string, n)
	for i := range agents {
		agents[i] = fmt.Sprintf("rr-agent-%02d", i+1)
	}

	now := time.Now()
	reqNum := 0

	for reqNum < 1000 { // safety guard
		for _, agentID := range agents {
			reqNum++
			req := makeCoordReq(agentID, policy)
			req.Now = now
			now = now.Add(time.Millisecond)

			result := runRequest(q, req, policy)
			switch result.Decision {
			case risk.APPROVED:
				approved++
				cwTotal++
			case risk.ESCALATED:
				cwTotal++
			case risk.DENIED:
				ttbReqs = reqNum
				return
			}
		}
	}
	return
}

// cwBurst runs N agents sequentially (agent 1 to first DENIED, then agent 2, ...).
// Simulates a burst coordination strategy where each agent exhausts its window.
// Returns: (CW_approved, CW_total, TTB_reqs) — TTB_reqs is agent-1's first DENIED.
func cwBurst(n int, policy risk.PolicyConfig) (approved, cwTotal, ttbReqs int) {
	q := risk.NewInMemoryQuerier()
	now := time.Now()
	reqNum := 0
	firstDenied := 0

	for i := 0; i < n; i++ {
		agentID := fmt.Sprintf("burst-agent-%02d", i+1)
		for j := 0; j < 100; j++ { // safety guard per agent
			reqNum++
			req := makeCoordReq(agentID, policy)
			req.Now = now
			now = now.Add(time.Millisecond)

			result := runRequest(q, req, policy)
			switch result.Decision {
			case risk.APPROVED:
				approved++
				cwTotal++
			case risk.ESCALATED:
				cwTotal++
			case risk.DENIED:
				if firstDenied == 0 {
					firstDenied = reqNum
				}
				goto nextAgent
			}
		}
	nextAgent:
	}
	ttbReqs = firstDenied
	return
}

// cwRoundRobinVerbose runs N agents round-robin and prints per-agent detail.
func cwRoundRobinVerbose(n int, policy risk.PolicyConfig) {
	q := risk.NewInMemoryQuerier()
	agents := make([]string, n)
	perApproved := make([]int, n)
	perEscalated := make([]int, n)
	blocked := make([]bool, n)

	for i := range agents {
		agents[i] = fmt.Sprintf("agent-%02d", i+1)
	}

	fmt.Printf("  %-10s  %-10s  %-12s  %-10s\n",
		"Agent", "Approved", "Escalated", "Outcome")
	fmt.Printf("  %-10s  %-10s  %-12s  %-10s\n",
		"-----", "--------", "---------", "-------")

	now := time.Now()
	for reqNum := 0; reqNum < 1000; reqNum++ {
		anyActive := false
		for i, agentID := range agents {
			if blocked[i] {
				continue
			}
			anyActive = true
			req := makeCoordReq(agentID, policy)
			req.Now = now
			now = now.Add(time.Millisecond)

			result := runRequest(q, req, policy)
			switch result.Decision {
			case risk.APPROVED:
				perApproved[i]++
			case risk.ESCALATED:
				perEscalated[i]++
			case risk.DENIED:
				blocked[i] = true
				fmt.Printf("  %-10s  %-10d  %-12d  DENIED\n",
					agentID, perApproved[i], perEscalated[i])
			}
		}
		if !anyActive {
			break
		}
	}
}

// cwBoundaryTrace prints the RS progression for each request in a round-robin run.
func cwBoundaryTrace(n int, policy risk.PolicyConfig) {
	q := risk.NewInMemoryQuerier()
	agents := make([]string, n)
	for i := range agents {
		agents[i] = fmt.Sprintf("agent-%02d", i+1)
	}

	fmt.Printf("  %-6s  %-10s  %-6s  %-10s  %-12s\n",
		"Req#", "Agent", "RS", "Decision", "Anomaly")
	fmt.Printf("  %-6s  %-10s  %-6s  %-10s  %-12s\n",
		"----", "-----", "--", "--------", "-------")

	now := time.Now()
	reqNum := 0
	for reqNum < 1000 {
		for _, agentID := range agents {
			reqNum++
			req := makeCoordReq(agentID, policy)
			req.Now = now
			now = now.Add(time.Millisecond)

			result := runRequest(q, req, policy)

			rules := ""
			if result.AnomalyDetail.Rule1Triggered {
				rules += "R1 "
			}
			if result.AnomalyDetail.Rule2Triggered {
				rules += "R2 "
			}
			if result.AnomalyDetail.Rule3Triggered {
				rules += "R3"
			}
			if rules == "" {
				rules = "—"
			}

			fmt.Printf("  %-6d  %-10s  %-6d  %-10s  %-12s\n",
				reqNum, agentID, result.RSFinal, string(result.Decision), rules)

			if result.Decision == risk.DENIED {
				return
			}
		}
	}
}
