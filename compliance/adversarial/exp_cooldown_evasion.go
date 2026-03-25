package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunCooldownEvasion runs Experiment 1: Cooldown Evasion Attack.
//
// Adversarial strategy: a single agent alternates between high-risk requests
// (→DENIED, RS=80) and low-risk requests (→APPROVED, RS=0), attempting to
// prevent cooldown by mixing legitimate activity between hostile requests.
//
// ACP behavior: the cooldown counter tracks real DENIED decisions independently
// of APPROVED decisions. After CooldownTriggerDenials=3 real denials in 10 min,
// cooldown activates and all subsequent requests are blocked (COOLDOWN_ACTIVE)
// regardless of capability or risk score.
//
// Expected outcome: cooldown triggers after exactly 3 DENIED decisions.
// All remaining requests are blocked. Evasion pattern is ineffective.
func RunCooldownEvasion(_ Config) {
	const nReqs = 500
	const agentID = "attacker-evasion-001"

	policy := risk.DefaultPolicyConfig()
	q := risk.NewInMemoryQuerier()
	m := newMetrics()

	start := time.Now()
	for i := int64(0); i < nReqs; i++ {
		var req risk.EvalRequest
		if i%2 == 0 {
			req = makeHighRiskReq(agentID, policy) // even → DENIED (RS=80)
		} else {
			req = makeLowRiskReq(agentID, policy) // odd → APPROVED (RS=0)
		}
		result := runRequest(q, req, policy)
		m.add(string(result.Decision), result.DeniedReason, i)
	}
	m.finalize(time.Since(start))

	fmt.Println("=== Experiment 1: Cooldown Evasion Attack ===")
	fmt.Printf("Pattern  : 1 agent, alternating high-risk/low-risk, %d requests\n", nReqs)
	fmt.Printf("Policy   : CooldownTriggerDenials=%d, CooldownPeriodSeconds=%d\n\n",
		policy.CooldownTriggerDenials, policy.CooldownPeriodSeconds)
	m.print()
	fmt.Printf("\nVerdict  : cooldown triggered after %d real DENIED decisions.\n", m.Denied)
	pct := float64(m.CooldownHits) / float64(nReqs) * 100
	fmt.Printf("           %d/%d requests blocked (%.1f%%). Evasion pattern ineffective.\n",
		m.CooldownHits, nReqs, pct)
}
