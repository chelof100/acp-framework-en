package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/barmonitor"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// agentTool describes one tool available to the multi-tool agent.
type agentTool struct {
	name          string
	capability    string
	resource      string
	resourceClass risk.ResourceClass
	baseRS        int // RS under default policy with clean state (F_anom=0, F_hist=0, F_ctx=0)
}

// tools available to the agent — RS values under ACP-RISK-3.0 default policy.
//
//	weather_query:  capBase=0  + F_res=0  = RS 0  → APPROVED
//	user_profile:   capBase=0  + F_res=15 = RS 15 → APPROVED
//	system_audit:   capBase=60 + F_res=0  = RS 60 → ESCALATED
//	fund_transfer:  capBase=35 + F_res=45 = RS 80 → DENIED
var agentTools = []agentTool{
	{"weather_query", "acp:cap:data.read",
		"weather/public", risk.ResourcePublic, 0},
	{"user_profile", "acp:cap:data.read",
		"user/profile", risk.ResourceSensitive, 15},
	{"system_audit", "acp:cap:admin.manage",
		"system/config", risk.ResourcePublic, 60},
	{"fund_transfer", "acp:cap:financial.transfer",
		"accounts/restricted-fund", risk.ResourceRestricted, 80},
}

// toolIdx returns the agentTool for the given name.
func toolByName(name string) agentTool {
	for _, t := range agentTools {
		if t.name == name {
			return t
		}
	}
	panic("unknown tool: " + name)
}

// sessionStep is one entry in a scripted agent session.
type sessionStep struct {
	tool  string // tool name
	phase string // "A", "B", or "C"
}

// RunAgentMultitool runs Experiment 12: Multi-Tool Agent Admission Control.
//
// Scenario: a three-phase agent session simulating normal operation, an IPI-induced
// attack, and a recovery period. State (denial history, cooldown, pattern counts)
// persists across phases via a shared InMemoryQuerier.
//
// Tool RS values (ACP-RISK-3.0 default, clean state):
//
//	weather_query:  RS= 0  → APPROVED
//	user_profile:   RS=15  → APPROVED
//	system_audit:   RS=60  → ESCALATED
//	fund_transfer:  RS=80  → DENIED
//
// Phase A (t0,        10 req): Baseline — diverse legitimate ops.
// Phase B (t0+1min,    8 req): IPI chain — attacker-induced fund_transfer flood.
//
//	After 3 total denials (1 from A + 2 from B), cooldown activates (300s).
//	Subsequent requests in B hit COOLDOWN_ACTIVE → all DENIED.
//
// Phase C (t0+60min,  10 req): Recovery — cooldown expired.
//
//	F_anom Rule 2 persists (CountDenials in 24h = 3 ≥ threshold=3 → +15).
//	system_audit RS rises 60→75 (DENIED, was ESCALATED in Phase A).
//	fund_transfer RS rises 80→95 (DENIED, F_anom persists).
//
// Key finding: ACP's stateful ledger creates persistent enforcement consequences
// that outlast the attack window. A stateless engine would fully reset after
// cooldown expiry; ACP's 24h denial history elevates borderline capabilities
// (system_audit: ESCALATED→DENIED) for the remainder of the anomaly window.
func RunAgentMultitool(_ Config) {
	policy := risk.DefaultPolicyConfig()
	const agentID = "agent-exp12-multitool"

	// t0 is the start of the session. Phases use distinct timestamps to
	// control which events fall within the 10-min cooldown window vs. the 24h F_anom window.
	t0 := time.Now()
	tB := t0.Add(1 * time.Minute)   // Phase B: within 10-min cooldown detection window
	tC := t0.Add(60 * time.Minute)  // Phase C: cooldown expired (>5 min), F_anom still active (<24h)

	// Shared querier — state persists across all phases.
	q := risk.NewInMemoryQuerier()

	// BAR-Monitor: window=40, threshold=0.10, trend=-0.15.
	m := barmonitor.New(barmonitor.Config{
		WindowSize:     40,
		Threshold:      0.10,
		TrendThreshold: -0.15,
	})

	fmt.Println("=== Experiment 12: Multi-Tool Agent Admission Control ===")
	fmt.Println()
	fmt.Printf("Agent:   %s\n", agentID)
	fmt.Printf("Policy:  ACP-RISK-3.0 default (APPROVED≤39, DENIED≥70, CooldownTrigger=3, Rule2=3)\n")
	fmt.Printf("Monitor: WindowSize=40, Threshold=0.10, TrendThreshold=-0.15\n")
	fmt.Println()

	// ── Phase A: Baseline ─────────────────────────────────────────────────────
	// 10 requests: diverse legitimate operations.
	// fund_transfer (RS=80) appears once — a legitimate high-value transfer.
	phaseASeq := []string{
		"weather_query", "weather_query", "weather_query", "weather_query",
		"user_profile", "user_profile", "user_profile",
		"system_audit", "system_audit",
		"fund_transfer", // RS=80 → DENIED, AddDenial(count=1 in 10min)
	}
	rA := runSession(phaseASeq, agentID, policy, q, m, t0, "A (Baseline)")

	// ── Phase B: IPI Chain ────────────────────────────────────────────────────
	// 8 requests: attacker-injected instructions flood fund_transfer.
	// After fund_transfer×2 in B, total denials in 10-min window = 3 → cooldown triggers.
	// All subsequent requests (fund_transfer×3 + system_audit×3) → COOLDOWN_ACTIVE.
	phaseBSeq := []string{
		"fund_transfer",  // RS=80 → DENIED (total in 10min: 2 → no cooldown yet)
		"fund_transfer",  // RS=80 → DENIED (total in 10min: 3 → cooldown activates)
		"fund_transfer",  // COOLDOWN_ACTIVE → DENIED
		"fund_transfer",  // COOLDOWN_ACTIVE → DENIED
		"fund_transfer",  // COOLDOWN_ACTIVE → DENIED
		"system_audit",   // COOLDOWN_ACTIVE → DENIED (cooldown is agent-wide)
		"system_audit",   // COOLDOWN_ACTIVE → DENIED
		"system_audit",   // COOLDOWN_ACTIVE → DENIED
	}
	rB := runSession(phaseBSeq, agentID, policy, q, m, tB, "B (IPI Chain)")

	// ── Phase C: Recovery ─────────────────────────────────────────────────────
	// 10 requests at t+60min: cooldown expired (300s << 60min).
	// F_anom Rule 2 persists: CountDenials(agentID, 24h) = 3 ≥ 3 → +15 on every request.
	// system_audit: RS = 60 + 15 = 75 → DENIED (was ESCALATED in Phase A).
	// fund_transfer: RS = 80 + 15 = 95 → DENIED (elevated from Phase A).
	phaseCSeq := []string{
		"weather_query", "weather_query", "weather_query", "weather_query",
		"user_profile", "user_profile", "user_profile",
		"system_audit",   // RS=75 → DENIED (ESCALATED→DENIED: F_anom persists)
		"fund_transfer",  // RS=95 → DENIED
		"fund_transfer",  // RS=95 → DENIED
	}
	rC := runSession(phaseCSeq, agentID, policy, q, m, tC, "C (Recovery)")

	// ── Summary ───────────────────────────────────────────────────────────────
	printExp12Summary(rA, rB, rC)
}

// phaseStats holds aggregate counts and BAR for one session phase.
type phaseStats struct {
	label     string
	total     int
	approved  int
	escalated int
	denied    int
	bar       float64
}

// runSession executes a scripted sequence of tool calls against the shared querier,
// feeding each decision into the BAR-Monitor. Returns aggregate stats.
// now is used as the timestamp for all requests in this phase.
func runSession(
	seq []string,
	agentID string,
	policy risk.PolicyConfig,
	q LedgerMutator,
	m *barmonitor.BARMonitor,
	now time.Time,
	label string,
) phaseStats {
	stats := phaseStats{label: label, total: len(seq)}

	fmt.Printf("── Phase %s ────────────────────────────────────────────\n", label)
	fmt.Printf("%-6s  %-14s  %-5s  %-8s  %-6s\n", "Step", "Tool", "RS", "Decision", "BAR")

	for i, toolName := range seq {
		tool := toolByName(toolName)
		req := risk.EvalRequest{
			AgentID:       agentID,
			Capability:    tool.capability,
			Resource:      tool.resource,
			ResourceClass: tool.resourceClass,
			Policy:        policy,
			Now:           now,
		}

		result := runRequest(q, req, policy)
		alert, bar := m.Record(result.Decision)

		switch result.Decision {
		case risk.APPROVED:
			stats.approved++
		case risk.ESCALATED:
			stats.escalated++
		default:
			stats.denied++
		}

		alertStr := ""
		if alert != nil {
			alertStr = fmt.Sprintf(" ← %s", alert.Reason)
		}

		reason := ""
		if result.DeniedReason != "" {
			reason = fmt.Sprintf(" [%s]", result.DeniedReason)
		}

		fmt.Printf("%-6d  %-14s  %-5d  %-8s  %.2f%s%s\n",
			i+1, toolName, result.RSFinal, result.Decision, bar, reason, alertStr)
	}

	if stats.total > 0 {
		stats.bar = float64(stats.escalated+stats.denied) / float64(stats.total)
	}
	fmt.Printf("Phase %s: APPROVED=%d  ESCALATED=%d  DENIED=%d  BAR=%.2f\n\n",
		label, stats.approved, stats.escalated, stats.denied, stats.bar)
	return stats
}

// printExp12Summary prints the three-phase comparison table and key findings.
func printExp12Summary(a, b, c phaseStats) {
	total := a.total + b.total + c.total
	allApproved := a.approved + b.approved + c.approved
	allEscalated := a.escalated + b.escalated + c.escalated
	allDenied := a.denied + b.denied + c.denied
	allBAR := float64(allEscalated+allDenied) / float64(total)

	fmt.Println("── Summary ──────────────────────────────────────────────")
	fmt.Printf("%-25s  %-5s  %-9s  %-10s  %-7s  %-6s\n",
		"Phase", "Req", "APPROVED", "ESCALATED", "DENIED", "BAR")
	fmt.Println("------------------------------------------------------------------------")
	printExp12Row(a)
	printExp12Row(b)
	printExp12Row(c)
	fmt.Println("------------------------------------------------------------------------")
	fmt.Printf("%-25s  %-5d  %-9d  %-10d  %-7d  %.2f\n",
		"Total", total, allApproved, allEscalated, allDenied, allBAR)

	fmt.Println()
	fmt.Println("Key findings:")
	fmt.Println("  1. Phase A (baseline): per-request enforcement denies fund_transfer (RS=80).")
	fmt.Println("     system_audit ESCALATED (RS=60), not denied — borderline capability admitted.")
	fmt.Println()
	fmt.Println("  2. Phase B (IPI chain): 2 additional denials trigger cooldown (total=3 in 10min).")
	fmt.Println("     Agent-wide lockdown: ALL subsequent ops DENIED including system_audit.")
	fmt.Println("     A stateless engine would deny fund_transfer only; ACP denies all agent ops.")
	fmt.Println()
	fmt.Println("  3. Phase C (recovery): cooldown expired, but F_anom Rule 2 persists (24h window).")
	fmt.Println("     system_audit RS: 60 → 75 (ESCALATED → DENIED). F_anom+15 crosses denial threshold.")
	fmt.Println("     fund_transfer RS: 80 → 95. Persistent post-attack risk elevation.")
	fmt.Println("     A stateless engine would fully reset; ACP enforcement posture remains elevated.")
}

func printExp12Row(s phaseStats) {
	fmt.Printf("%-25s  %-5d  %-9d  %-10d  %-7d  %.2f\n",
		s.label, s.total, s.approved, s.escalated, s.denied, s.bar)
}
