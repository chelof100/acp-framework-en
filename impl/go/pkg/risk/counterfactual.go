// counterfactual.go — ACP v1.24 Counterfactual Evaluation API
//
// EvaluateCounterfactual verifies that an ACP deployment retains the structural
// capacity to enforce: given a set of mutations representing conditions absent
// from the observed request stream, the engine can still produce ESCALATED or
// DENIED decisions.
//
// Mutations are ADDITIVE: only non-nil fields override the base request.
// This preserves interpretability — each mutation tests a specific signal
// in isolation, keeping all other factors constant.
//
// Three built-in mutation factories cover the standard ACP v1.24 categories:
//
//	StructuralMutation()        — elevate capability + resource class
//	BehavioralMutation()        — inject context + history flags
//	TemporalMutation(agentID)   — pre-load ledger state to trigger all F_anom rules

package risk

import "time"

// Mutation describes an additive transformation applied to a base EvalRequest.
// Only non-nil pointer fields are applied; nil means "keep the base value".
//
// Three mutation categories exist per ACP v1.24 §Counterfactual Evaluation:
//   - Structural: elevate Capability and/or ResourceClass
//   - Behavioral: inject Context and/or History flags
//   - Temporal:   pre-load ledger state via LedgerSetup
type Mutation struct {
	// Label identifies this mutation in results. Required.
	Label string

	// Capability overrides base.Capability if non-nil.
	Capability *string

	// ResourceClass overrides base.ResourceClass if non-nil.
	ResourceClass *ResourceClass

	// Resource overrides base.Resource if non-nil.
	Resource *string

	// Context overrides base.Context if non-nil (full struct replacement).
	Context *Context

	// History overrides base.History if non-nil (full struct replacement).
	History *History

	// LedgerSetup, if non-nil, is called with a fresh InMemoryQuerier and the
	// evaluation timestamp before Evaluate is called. Use for temporal mutations
	// that require pre-loaded ledger state.
	// If nil, a fresh empty InMemoryQuerier is used.
	LedgerSetup func(*InMemoryQuerier, time.Time)
}

// CounterfactualResult holds the result of evaluating a single mutation.
type CounterfactualResult struct {
	// Label is copied from the mutation.
	Label string

	// Decision is the engine's decision for this mutation.
	// Zero value ("") if Err != nil.
	Decision Decision

	// RSFinal is the computed risk score for this mutation.
	// Zero if Err != nil.
	RSFinal int

	// Err is non-nil if risk.Evaluate returned an error for this mutation.
	Err error
}

// BAR computes the Boundary Activation Rate for a slice of counterfactual results.
//
//	BAR = |{r ∈ results | r.Err == nil ∧ r.Decision ∈ {ESCALATED, DENIED}}| / len(results)
//
// Returns 0 for empty input. Results with Err != nil are counted in the
// denominator but not the numerator (fail-closed: errors lower BAR).
func BAR(results []CounterfactualResult) float64 {
	if len(results) == 0 {
		return 0
	}
	var active int
	for _, r := range results {
		if r.Err == nil && (r.Decision == ESCALATED || r.Decision == DENIED) {
			active++
		}
	}
	return float64(active) / float64(len(results))
}

// EvaluateCounterfactual applies each mutation to the base request and evaluates
// the result against the ACP risk engine.
//
// Each mutation is evaluated independently:
//   - A fresh InMemoryQuerier is created per mutation.
//   - If Mutation.LedgerSetup is non-nil, the querier is pre-loaded before Evaluate.
//   - Mutations do not share state.
//
// The base request's AgentID, Policy, and Now fields are always preserved.
func EvaluateCounterfactual(base EvalRequest, mutations []Mutation, now time.Time) []CounterfactualResult {
	results := make([]CounterfactualResult, len(mutations))
	for i, mut := range mutations {
		req := applyMutation(base, mut)
		req.Now = now

		q := NewInMemoryQuerier()
		if mut.LedgerSetup != nil {
			mut.LedgerSetup(q, now)
		}

		result, err := Evaluate(req, q)
		results[i] = CounterfactualResult{Label: mut.Label, Err: err}
		if err == nil {
			results[i].Decision = result.Decision
			results[i].RSFinal = result.RSFinal
		}
	}
	return results
}

// applyMutation returns a copy of base with all non-nil mutation fields applied.
// AgentID and Policy are never overridden by a mutation.
func applyMutation(base EvalRequest, mut Mutation) EvalRequest {
	req := base
	if mut.Capability != nil {
		req.Capability = *mut.Capability
	}
	if mut.ResourceClass != nil {
		req.ResourceClass = *mut.ResourceClass
	}
	if mut.Resource != nil {
		req.Resource = *mut.Resource
	}
	if mut.Context != nil {
		req.Context = *mut.Context
	}
	if mut.History != nil {
		req.History = *mut.History
	}
	return req
}

// ── Built-in mutation factories ───────────────────────────────────────────────

// StructuralMutation returns a mutation that elevates capability to
// financial.transfer and resource class to Restricted.
//
// RS (DefaultPolicyConfig, empty ledger, no context/history):
//
//	B=35 (financial.transfer) + F_res=45 (restricted) = 80 → DENIED (>EscalatedMax=69)
func StructuralMutation() Mutation {
	cap := "acp:cap:financial.transfer"
	res := "accounts/restricted-fund"
	rc := ResourceRestricted
	return Mutation{
		Label:         "structural",
		Capability:    &cap,
		Resource:      &res,
		ResourceClass: &rc,
	}
}

// BehavioralMutation returns a mutation that combines structural escalation
// with ExternalIP, OffHours, RecentDenial, and FreqAnomaly flags.
//
// RS (DefaultPolicyConfig, empty ledger):
//
//	B=35 + F_res=45 + ExternalIP=20 + OffHours=15 + RecentDenial=20 + FreqAnomaly=15
//	= 150 → capped 100 → DENIED
func BehavioralMutation() Mutation {
	cap := "acp:cap:financial.transfer"
	res := "accounts/restricted-fund"
	rc := ResourceRestricted
	ctx := Context{ExternalIP: true, OffHours: true}
	hist := History{RecentDenial: true, FreqAnomaly: true}
	return Mutation{
		Label:         "behavioral",
		Capability:    &cap,
		Resource:      &res,
		ResourceClass: &rc,
		Context:       &ctx,
		History:       &hist,
	}
}

// TemporalMutation returns a mutation that pre-loads the ledger to trigger
// all three F_anom rules for (agentID, financial.transfer, restricted-fund).
//
// Ledger state injected:
//
//	Rule 1: 11 patterns at -30s → CountPattern(patKey,60s)=11 > N=10  → +20
//	Rule 2: 3 denials at -1h   → CountDenials(agentID,24h)=3 ≥ X=3   → +15
//	Rule 3: satisfied by Rule 1 entries (11 patterns within 5min)     → +15
//	F_anom total: +50
//
// RS (DefaultPolicyConfig):
//
//	B=35 + F_res=45 + F_anom=50 = 130 → capped 100 → DENIED
func TemporalMutation(agentID string) Mutation {
	cap := "acp:cap:financial.transfer"
	res := "accounts/restricted-fund"
	rc := ResourceRestricted
	return Mutation{
		Label:         "temporal",
		Capability:    &cap,
		Resource:      &res,
		ResourceClass: &rc,
		LedgerSetup: func(q *InMemoryQuerier, now time.Time) {
			patKey := PatternKey(agentID, "acp:cap:financial.transfer", "accounts/restricted-fund")
			// Rule 1: >10 patterns in last 60s
			for i := 0; i < 11; i++ {
				q.AddPattern(patKey, now.Add(-30*time.Second))
			}
			// Rule 2: ≥3 denials in last 24h
			for i := 0; i < 3; i++ {
				q.AddDenial(agentID, now.Add(-1*time.Hour))
			}
			// Rule 3 is satisfied by the Rule 1 entries (11 patterns within 5min window)
		},
	}
}
