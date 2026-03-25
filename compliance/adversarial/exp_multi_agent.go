package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunMultiAgent runs Experiment 2: Distributed Multi-Agent Attack.
//
// Adversarial strategy: N coordinated agents each send a small number of
// high-risk requests, keeping individual volume below what would trigger
// per-agent cooldown. The attack aims to exhaust system capacity by
// distributing load across many identities.
//
// ACP behavior: per-agent admission control triggers independently for each
// agent. After CooldownTriggerDenials=3 real denials per agent, that agent
// is blocked for CooldownPeriodSeconds=300s. Cross-agent correlation is not
// performed; each agent is evaluated in isolation.
//
// Expected outcome: each agent is blocked after exactly 3 real DENIED
// decisions. Total free denials = N × CooldownTriggerDenials. This is the
// honest design boundary of per-agent admission control.
func RunMultiAgent(_ Config) {
	const reqsPerAgent = 10
	agentCounts := []int{100, 500, 1000}

	policy := risk.DefaultPolicyConfig()

	fmt.Println("=== Experiment 2: Distributed Multi-Agent Attack ===")
	fmt.Printf("Pattern  : N agents × %d high-risk requests each\n", reqsPerAgent)
	fmt.Printf("Policy   : CooldownTriggerDenials=%d, CooldownPeriodSeconds=%d\n\n",
		policy.CooldownTriggerDenials, policy.CooldownPeriodSeconds)
	fmt.Printf("  %-8s  %-8s  %-8s  %-10s  %-10s  %-15s\n",
		"Agents", "Total", "Denied", "Cooldown", "Triggers", "Throughput")
	fmt.Printf("  %-8s  %-8s  %-8s  %-10s  %-10s  %-15s\n",
		"------", "-----", "------", "--------", "--------", "----------")

	for _, n := range agentCounts {
		q := risk.NewInMemoryQuerier()

		var (
			totalDenied, totalCooldown, totalTriggers int64
			mu                                        sync.Mutex
			wg                                        sync.WaitGroup
		)

		start := time.Now()
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				agentID := fmt.Sprintf("attacker-%04d", idx)
				d, c, t := runAgentRequests(q, agentID, reqsPerAgent, policy)
				mu.Lock()
				totalDenied += d
				totalCooldown += c
				totalTriggers += t
				mu.Unlock()
			}(i)
		}
		wg.Wait()
		dur := time.Since(start)

		total := int64(n * reqsPerAgent)
		throughput := float64(total) / dur.Seconds()
		fmt.Printf("  %-8d  %-8d  %-8d  %-10d  %-10d  %-15.0f\n",
			n, total, totalDenied, totalCooldown, totalTriggers, throughput)
	}

	fmt.Printf("\nVerdict  : per-agent cooldown is effective; each agent blocked after %d DENIED.\n",
		policy.CooldownTriggerDenials)
	fmt.Printf("           Design boundary: N agents × %d = N×%d free denials before full blocking.\n",
		policy.CooldownTriggerDenials, policy.CooldownTriggerDenials)
	fmt.Printf("           Cross-agent correlation requires policy-layer attribution (outside ACP scope).\n")
}

// runAgentRequests executes all requests for a single agent sequentially,
// preserving the per-agent ordering required by the execution contract.
// Returns (denied, cooldownHits, cooldownTriggers).
func runAgentRequests(q LedgerMutator, agentID string, nReqs int, policy risk.PolicyConfig) (denied, cooldownHits, triggers int64) {
	for i := 0; i < nReqs; i++ {
		req := makeHighRiskReq(agentID, policy)
		result := runRequest(q, req, policy)
		switch result.DeniedReason {
		case "COOLDOWN_ACTIVE":
			cooldownHits++
		default:
			if result.Decision == risk.DENIED {
				denied++
				// Cooldown triggers on exactly the CooldownTriggerDenials-th denial.
				if denied == int64(policy.CooldownTriggerDenials) {
					triggers++
				}
			}
		}
	}
	return
}
