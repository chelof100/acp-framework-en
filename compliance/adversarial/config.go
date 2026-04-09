package main

import (
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// Config holds experiment-wide configuration.
type Config struct {
	RedisAddr string
}

// LedgerMutator combines read access (risk.LedgerQuerier) with write mutations.
// Both *risk.InMemoryQuerier and *RedisQuerier satisfy this interface.
type LedgerMutator interface {
	risk.LedgerQuerier
	AddRequest(agentID string, t time.Time)
	AddDenial(agentID string, t time.Time)
	AddPattern(patternKey string, t time.Time)
	SetCooldown(agentID string, until time.Time)
}

// makeHighRiskReq returns a financial/restricted request that evaluates to DENIED (RS=80).
// B=35 (acp:cap:financial.) + F_res=45 (restricted) = RS 80 > EscalatedMax(69) → DENIED.
func makeHighRiskReq(agentID string, policy risk.PolicyConfig) risk.EvalRequest {
	return risk.EvalRequest{
		AgentID:       agentID,
		Capability:    "acp:cap:financial.transfer",
		Resource:      "accounts/restricted-fund",
		ResourceClass: risk.ResourceRestricted,
		Policy:        policy,
	}
}

// makeLowRiskReq returns a data-read/public request that evaluates to APPROVED (RS=0).
// B=0 (acp:cap:data.read) + F_res=0 (public) = RS 0 ≤ ApprovedMax(39) → APPROVED.
func makeLowRiskReq(agentID string, policy risk.PolicyConfig) risk.EvalRequest {
	return risk.EvalRequest{
		AgentID:       agentID,
		Capability:    "acp:cap:data.read",
		Resource:      "metrics/public",
		ResourceClass: risk.ResourcePublic,
		Policy:        policy,
	}
}

// runRequest executes the full ACP-RISK-2.0 execution contract for one request.
//
// Contract order (ACP-RISK-2.0 §4):
//  1. Evaluate(req, q)            — sees state before this request's mutations
//  2. AddRequest, AddPattern      — always
//  3. AddDenial                   — only on real DENIED (DeniedReason != "COOLDOWN_ACTIVE")
//  4. ShouldEnterCooldown         — only on real DENIED
//  5. SetCooldown(now + period)   — only if ShouldEnterCooldown returns true
func runRequest(q LedgerMutator, req risk.EvalRequest, policy risk.PolicyConfig) *risk.EvalResult {
	// Use req.Now if already set (e.g. by time-controlled experiments); otherwise wall clock.
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	req.Now = now

	result, err := risk.Evaluate(req, q)
	if err != nil {
		// RISK-008: fail-closed on querier error
		return &risk.EvalResult{Decision: risk.DENIED, DeniedReason: "QUERIER_ERROR"}
	}

	patKey := risk.PatternKey(req.AgentID, req.Capability, req.Resource)
	q.AddRequest(req.AgentID, now)
	q.AddPattern(patKey, now)

	if result.Decision == risk.DENIED && result.DeniedReason != "COOLDOWN_ACTIVE" {
		q.AddDenial(req.AgentID, now)
		if enter, _ := risk.ShouldEnterCooldown(req.AgentID, policy, q, now); enter {
			q.SetCooldown(req.AgentID, now.Add(time.Duration(policy.CooldownPeriodSeconds)*time.Second))
		}
	}

	return result
}
