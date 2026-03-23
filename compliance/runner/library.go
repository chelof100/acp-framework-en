package main

import (
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// LibraryBackend wraps pkg/risk directly — no subprocess, no network.
//
// It implements the ACP-RISK-2.0 execution contract (ACP-RISK-2.0 §4):
//
//  1. Evaluate()      — stateless; reads querier, no side effects
//  2. AddRequest()    — always, regardless of outcome
//  3. AddPattern()    — always; feeds F_anom Rule 3
//  4. AddDenial()     — only when DENIED
//  5. SetCooldown()   — only when ShouldEnterCooldown returns true
//
// The runner is responsible for updating state after each evaluation so that
// the system behaves as it would in production (stateful, multi-step flows).
type LibraryBackend struct {
	querier *risk.InMemoryQuerier
	policy  risk.PolicyConfig
}

// NewLibraryBackend returns a fresh LibraryBackend with the reference policy.
func NewLibraryBackend() *LibraryBackend {
	return &LibraryBackend{
		querier: risk.NewInMemoryQuerier(),
		policy:  risk.DefaultPolicyConfig(),
	}
}

// Reset creates a new querier, clearing all accumulated state.
// Called by the runner before the first step of each test case.
func (b *LibraryBackend) Reset() {
	b.querier = risk.NewInMemoryQuerier()
}

// Evaluate runs the full execution contract for one step.
func (b *LibraryBackend) Evaluate(req RunnerRequest) (ACPResponse, error) {
	// Capture now ONCE — all querier operations in this step use the same timestamp.
	now := time.Now()

	evalReq := risk.EvalRequest{
		AgentID:       req.AgentID,
		Capability:    req.Capability,
		Resource:      req.Resource,
		ResourceClass: risk.ResourceClass(req.ResourceClass),
		Context: risk.Context{
			ExternalIP:      req.Context.ExternalIP,
			OffHours:        req.Context.OffHours,
			NonBusinessDay:  req.Context.NonBusinessDay,
			GeoOutside:      req.Context.GeoOutside,
			TimestampDrift:  req.Context.TimestampDrift,
			UntrustedDevice: req.Context.UntrustedDevice,
		},
		History: risk.History{
			DenialRateHigh:        req.History.DenialRateHigh,
			UnresolvedEscalations: req.History.UnresolvedEscalations,
			RecentDenial:          req.History.RecentDenial,
			FreqAnomaly:           req.History.FreqAnomaly,
			AmountNearLimit:       req.History.AmountNearLimit,
			NoHistory:             req.History.NoHistory,
		},
		Policy: b.policy,
		Now:    now,
	}

	// Step 1: Evaluate — stateless; reads querier, produces no side effects.
	result, err := risk.Evaluate(evalReq, b.querier)
	if err != nil {
		return ACPResponse{}, err
	}

	// Step 2: Record request — always, regardless of outcome.
	b.querier.AddRequest(req.AgentID, now)

	// Step 3: Record pattern — always; feeds F_anom Rule 3.
	// CRITICAL: omitting this silently kills Rule 3 — patterns never accumulate.
	patKey := risk.PatternKey(req.AgentID, req.Capability, req.Resource)
	b.querier.AddPattern(patKey, now)

	// Step 4 + 5: On DENIED, record denial and check cooldown.
	if result.Decision == risk.DENIED {
		b.querier.AddDenial(req.AgentID, now)

		should, _ := risk.ShouldEnterCooldown(req.AgentID, b.policy, b.querier, now)
		if should {
			// SetCooldown takes the EXPIRY time, not the current time.
			period := time.Duration(b.policy.CooldownPeriodSeconds) * time.Second
			b.querier.SetCooldown(req.AgentID, now.Add(period))
		}
	}

	return ACPResponse{
		Decision:     string(result.Decision),
		RiskScore:    result.RSFinal,
		DeniedReason: result.DeniedReason,
	}, nil
}
