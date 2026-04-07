package risk_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// ── BAR() helper ─────────────────────────────────────────────────────────────

func TestBAR_Empty(t *testing.T) {
	if got := risk.BAR(nil); got != 0 {
		t.Fatalf("BAR(nil)=%v, want 0", got)
	}
	if got := risk.BAR([]risk.CounterfactualResult{}); got != 0 {
		t.Fatalf("BAR([])=%v, want 0", got)
	}
}

func TestBAR_AllAPPROVED(t *testing.T) {
	results := make([]risk.CounterfactualResult, 20)
	for i := range results {
		results[i] = risk.CounterfactualResult{Label: "x", Decision: risk.APPROVED}
	}
	if got := risk.BAR(results); got != 0 {
		t.Fatalf("all APPROVED: BAR=%v, want 0", got)
	}
}

func TestBAR_PhaseADistribution(t *testing.T) {
	// 6 APPROVED + 7 ESCALATED + 7 DENIED = BAR = 14/20 = 0.70
	results := make([]risk.CounterfactualResult, 20)
	for i := 0; i < 6; i++ {
		results[i] = risk.CounterfactualResult{Decision: risk.APPROVED}
	}
	for i := 6; i < 13; i++ {
		results[i] = risk.CounterfactualResult{Decision: risk.ESCALATED}
	}
	for i := 13; i < 20; i++ {
		results[i] = risk.CounterfactualResult{Decision: risk.DENIED}
	}
	if got := risk.BAR(results); got != 0.70 {
		t.Fatalf("Phase A: BAR=%v, want 0.70", got)
	}
}

func TestBAR_PhaseCDistribution(t *testing.T) {
	// 60 DENIED = BAR = 1.00
	results := make([]risk.CounterfactualResult, 60)
	for i := range results {
		results[i] = risk.CounterfactualResult{Decision: risk.DENIED}
	}
	if got := risk.BAR(results); got != 1.0 {
		t.Fatalf("Phase C: BAR=%v, want 1.0", got)
	}
}

func TestBAR_ErrorsCountInDenominator(t *testing.T) {
	// 1 error + 1 DENIED = BAR = 1/2 = 0.5 (fail-closed: errors lower BAR)
	results := []risk.CounterfactualResult{
		{Label: "ok", Decision: risk.DENIED},
		{Label: "err", Err: errFake},
	}
	if got := risk.BAR(results); got != 0.5 {
		t.Fatalf("1 error + 1 DENIED: BAR=%v, want 0.5", got)
	}
}

// ── EvaluateCounterfactual — built-in factories ──────────────────────────────

func TestEvaluateCounterfactual_StructuralMutation_DENIED(t *testing.T) {
	base := baseRequest(t)
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{risk.StructuralMutation()}, time.Now())
	r := results[0]
	if r.Err != nil {
		t.Fatalf("structural: err=%v", r.Err)
	}
	if r.Decision != risk.DENIED {
		t.Fatalf("structural: decision=%v, want DENIED", r.Decision)
	}
	if r.RSFinal < 70 {
		t.Fatalf("structural: RS=%d, want >=70", r.RSFinal)
	}
}

func TestEvaluateCounterfactual_BehavioralMutation_DENIED(t *testing.T) {
	base := baseRequest(t)
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{risk.BehavioralMutation()}, time.Now())
	r := results[0]
	if r.Err != nil {
		t.Fatalf("behavioral: err=%v", r.Err)
	}
	if r.Decision != risk.DENIED {
		t.Fatalf("behavioral: decision=%v, want DENIED", r.Decision)
	}
}

func TestEvaluateCounterfactual_TemporalMutation_DENIED(t *testing.T) {
	base := baseRequest(t)
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{risk.TemporalMutation(base.AgentID)}, time.Now())
	r := results[0]
	if r.Err != nil {
		t.Fatalf("temporal: err=%v", r.Err)
	}
	if r.Decision != risk.DENIED {
		t.Fatalf("temporal: decision=%v, want DENIED", r.Decision)
	}
}

func TestEvaluateCounterfactual_AllThreeFactories_BAR100(t *testing.T) {
	base := baseRequest(t)
	mutations := []risk.Mutation{
		risk.StructuralMutation(),
		risk.BehavioralMutation(),
		risk.TemporalMutation(base.AgentID),
	}
	results := risk.EvaluateCounterfactual(base, mutations, time.Now())
	if got := risk.BAR(results); got != 1.0 {
		t.Fatalf("all 3 factories: BAR=%v, want 1.0", got)
	}
}

// ── EvaluateCounterfactual — additive semantics ───────────────────────────────

func TestEvaluateCounterfactual_MutationsAreAdditive_NilPreservesBase(t *testing.T) {
	// A mutation with all nil fields should leave base unchanged.
	base := risk.EvalRequest{
		AgentID:       "test-agent",
		Capability:    "acp:cap:data.read",
		Resource:      "metrics/public",
		ResourceClass: risk.ResourcePublic,
		Policy:        risk.DefaultPolicyConfig(),
		Now:           time.Now(),
	}
	nilMut := risk.Mutation{Label: "nil-mutation"}
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{nilMut}, base.Now)
	r := results[0]
	if r.Err != nil {
		t.Fatalf("nil mutation: err=%v", r.Err)
	}
	// data.read + public + no context/history + empty ledger → RS=0 → APPROVED
	if r.Decision != risk.APPROVED {
		t.Fatalf("nil mutation on low-risk base: decision=%v, want APPROVED", r.Decision)
	}
}

func TestEvaluateCounterfactual_OnlyContextOverridden(t *testing.T) {
	// Base: data.read + public (RS=0). Mutation adds only ExternalIP=true (+20).
	// Expected RS = 0+20 = 20 → APPROVED (still below 39).
	base := risk.EvalRequest{
		AgentID:       "test-agent",
		Capability:    "acp:cap:data.read",
		Resource:      "metrics/public",
		ResourceClass: risk.ResourcePublic,
		Policy:        risk.DefaultPolicyConfig(),
	}
	ctx := risk.Context{ExternalIP: true}
	mut := risk.Mutation{Label: "extip-only", Context: &ctx}
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{mut}, time.Now())
	r := results[0]
	if r.Err != nil {
		t.Fatalf("extip only: err=%v", r.Err)
	}
	if r.Decision != risk.APPROVED {
		t.Fatalf("data.read+public+ExternalIP: RS=%d decision=%v, want APPROVED", r.RSFinal, r.Decision)
	}
	if r.RSFinal != 20 {
		t.Fatalf("data.read+public+ExternalIP: RS=%d, want 20", r.RSFinal)
	}
}

func TestEvaluateCounterfactual_AgentIDPreserved(t *testing.T) {
	// AgentID must never be overridden by a mutation — it's needed for TemporalMutation.
	const agentID = "preserved-agent"
	base := baseRequest(t)
	base.AgentID = agentID
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{risk.TemporalMutation(agentID)}, time.Now())
	if results[0].Err != nil {
		t.Fatalf("temporal with preserved agentID: err=%v", results[0].Err)
	}
	if results[0].Decision != risk.DENIED {
		t.Fatalf("temporal with preserved agentID: decision=%v, want DENIED", results[0].Decision)
	}
}

func TestEvaluateCounterfactual_PolicyPreservedFromBase(t *testing.T) {
	// The base request's Policy must be used in all mutations.
	base := baseRequest(t)
	// With default policy, structural → DENIED (RS=80 > EscalatedMax=69)
	results := risk.EvaluateCounterfactual(base, []risk.Mutation{risk.StructuralMutation()}, time.Now())
	if results[0].Decision != risk.DENIED {
		t.Fatalf("policy preserved: decision=%v, want DENIED", results[0].Decision)
	}
}

// ── EvaluateCounterfactual — isolation ───────────────────────────────────────

func TestEvaluateCounterfactual_IndependentQueriers(t *testing.T) {
	// Two identical temporal mutations evaluated back-to-back must NOT contaminate
	// each other (each must get its own fresh+pre-loaded querier).
	base := baseRequest(t)
	agentID := base.AgentID
	mutations := []risk.Mutation{
		risk.TemporalMutation(agentID),
		risk.TemporalMutation(agentID),
	}
	results := risk.EvaluateCounterfactual(base, mutations, time.Now())
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("temporal[%d]: err=%v", i, r.Err)
		}
		if r.Decision != risk.DENIED {
			t.Fatalf("temporal[%d]: decision=%v, want DENIED (independent queriers)", i, r.Decision)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// baseRequest returns a low-risk base request (data.read/public → APPROVED).
// All mutations in these tests are applied on top of this base.
func baseRequest(t *testing.T) risk.EvalRequest {
	t.Helper()
	return risk.EvalRequest{
		AgentID:       "test-agent-cf",
		Capability:    "acp:cap:data.read",
		Resource:      "metrics/public",
		ResourceClass: risk.ResourcePublic,
		Policy:        risk.DefaultPolicyConfig(),
	}
}

// errFake is a sentinel for test results that have an error.
var errFake = fmt.Errorf("fake error")
