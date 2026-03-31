package risk

import (
	"testing"
	"time"
)

// TestStateMixing demonstrates the cross-context contamination vulnerability in
// ACP-RISK-2.0: Rule 1 (high request rate) counts requests keyed by agentID
// only, not by capability or resource context.
//
// Consequence: low-risk activity in one capability context (data.read) primes
// the Rule 1 counter and causes false denials in a higher-risk context
// (financial.transfer) — a decision outcome that would not occur in clean state.
//
// Experiment structure:
//
//	Control:      fresh querier, one financial.transfer/sensitive request → ESCALATED (RS=50)
//	Contaminated: 11 prior data.read/public requests (all APPROVED, RS≤35),
//	              then one financial.transfer/sensitive request → DENIED (RS=70)
//
// The contamination mechanism: Rule 1 fires when CountRequests(agentID, 60s) > N.
// Because CountRequests is scoped to agentID only, all 11 data.read requests
// contribute to the same counter as the subsequent financial.transfer request.
// Rule 3 does NOT contaminate across contexts because it is keyed by
// PatternKey(agentID, capability, resource) — a capability-and-resource-specific
// hash — and the two phases use distinct pattern keys.
//
// The experiment is not derivable from the ACP-RISK-2.0 specification alone:
// the scoping of Rule 1 vs Rule 3 is an implementation detail of CountRequests
// vs CountPattern, and the contamination effect requires running the engine
// across two distinct capability contexts.
func TestStateMixing(t *testing.T) {
	t.Skip("documents RISK-2.0 state-mixing vulnerability — superseded by TestStateMixingFixed (RISK-3.0)")
	policy := DefaultPolicyConfig()
	baseNow := time.Now() // fixed once — never advanced

	const (
		agentID         = "legitimate-agent-1"
		lowRiskCap      = "acp:cap:data.read"
		highRiskCap     = "acp:cap:financial.transfer"
		phase1Requests  = 11 // = AnomalyRule1ThresholdN + 1
	)

	// RS_base verification (derived from engine constants):
	// data.read/public:        capabilityBase=0  + resourceScore(public)=0     = 0
	// financial.transfer/sens: capabilityBase=35 + resourceScore(sensitive)=15 = 50
	expectedBaseClean := 50
	expectedBaseContam := 50 + 20 // Rule 1 contribution

	// ── Control: clean state, single financial.transfer/sensitive ────────────
	controlQuerier := NewInMemoryQuerier()
	controlQuerier.AddRequest(agentID, baseNow)
	controlQuerier.AddPattern(PatternKey(agentID, highRiskCap, string(ResourceSensitive)), baseNow)

	controlReq := EvalRequest{
		AgentID:       agentID,
		Capability:    highRiskCap,
		Resource:      string(ResourceSensitive),
		ResourceClass: ResourceSensitive,
		Policy:        policy,
		Now:           baseNow,
	}
	controlResult, err := Evaluate(controlReq, controlQuerier)
	if err != nil {
		t.Fatalf("control: Evaluate error: %v", err)
	}
	t.Logf("Control (clean state):    RS=%d, F_anom=%d, Decision=%s",
		controlResult.RSFinal, controlResult.Factors.Anomaly, controlResult.Decision)

	if controlResult.Decision != ESCALATED {
		t.Fatalf("control: expected ESCALATED (RS=%d), got %s (RS=%d)",
			expectedBaseClean, controlResult.Decision, controlResult.RSFinal)
	}
	if controlResult.RSFinal != expectedBaseClean {
		t.Fatalf("control: RS=%d, want %d", controlResult.RSFinal, expectedBaseClean)
	}

	// ── Phase 1: low-risk data.read workload (all APPROVED, RS≤35) ───────────
	// Each request increments the agentID-scoped Rule 1 counter.
	// Note: at request #3 Rule 3 fires for the data.read pattern key (+15),
	// and at request #11 Rule 1 also fires (+20). Combined RS = 0+15+20 = 35
	// — still APPROVED because RS_base(data.read/public) = 0.
	contamQuerier := NewInMemoryQuerier()
	lowRiskPatKey := PatternKey(agentID, lowRiskCap, string(ResourcePublic))

	for i := 1; i <= phase1Requests; i++ {
		contamQuerier.AddRequest(agentID, baseNow)
		contamQuerier.AddPattern(lowRiskPatKey, baseNow)
		req := EvalRequest{
			AgentID:       agentID,
			Capability:    lowRiskCap,
			Resource:      string(ResourcePublic),
			ResourceClass: ResourcePublic,
			Policy:        policy,
			Now:           baseNow,
		}
		result, err := Evaluate(req, contamQuerier)
		if err != nil {
			t.Fatalf("phase 1 request #%d: Evaluate error: %v", i, err)
		}
		if result.Decision != APPROVED {
			t.Fatalf("phase 1 request #%d: expected APPROVED, got %s (RS=%d, F_anom=%d)",
				i, result.Decision, result.RSFinal, result.Factors.Anomaly)
		}
	}

	// Verify Rule 1 is now primed (CountRequests > AnomalyRule1ThresholdN).
	count, err := contamQuerier.CountRequests(agentID, 60*time.Second, baseNow)
	if err != nil {
		t.Fatalf("CountRequests error: %v", err)
	}
	t.Logf("Phase 1 complete: %d data.read requests → CountRequests=%d (Rule1 threshold N=%d, primed=%v)",
		phase1Requests, count, policy.AnomalyRule1ThresholdN, count > policy.AnomalyRule1ThresholdN)

	if count <= policy.AnomalyRule1ThresholdN {
		t.Fatalf("precondition: Rule 1 not primed — CountRequests=%d, need >%d",
			count, policy.AnomalyRule1ThresholdN)
	}

	// ── Phase 2: financial.transfer/sensitive in contaminated state ───────────
	// Rule 1: CountRequests will be 12 (11 from phase 1 + 1 from AddRequest here) > 10 → +20
	// Rule 3: PatternKey(agentID, financial.transfer, sensitive) ≠ lowRiskPatKey → count=1 < 3 → 0
	// RS = 35 + 15 + 20 = 70 → DENIED
	contamQuerier.AddRequest(agentID, baseNow)
	contamQuerier.AddPattern(PatternKey(agentID, highRiskCap, string(ResourceSensitive)), baseNow)

	contamReq := EvalRequest{
		AgentID:       agentID,
		Capability:    highRiskCap,
		Resource:      string(ResourceSensitive),
		ResourceClass: ResourceSensitive,
		Policy:        policy,
		Now:           baseNow,
	}
	contamResult, err := Evaluate(contamReq, contamQuerier)
	if err != nil {
		t.Fatalf("phase 2: Evaluate error: %v", err)
	}
	t.Logf("Phase 2 (contaminated):   RS=%d, F_anom=%d, Decision=%s (Rule1=%v Rule2=%v Rule3=%v)",
		contamResult.RSFinal, contamResult.Factors.Anomaly, contamResult.Decision,
		contamResult.AnomalyDetail.Rule1Triggered,
		contamResult.AnomalyDetail.Rule2Triggered,
		contamResult.AnomalyDetail.Rule3Triggered)

	// ── Summary ───────────────────────────────────────────────────────────────
	t.Logf("State-mixing effect: %s (clean) → %s (after %d data.read requests)",
		controlResult.Decision, contamResult.Decision, phase1Requests)
	t.Logf("RS elevation: %d → %d (+%d from Rule 1, cross-context agentID counter)",
		controlResult.RSFinal, contamResult.RSFinal,
		contamResult.RSFinal-controlResult.RSFinal)
	t.Logf("Contamination threshold: %d requests in any context primes Rule 1 (AnomalyRule1ThresholdN=%d)",
		policy.AnomalyRule1ThresholdN+1, policy.AnomalyRule1ThresholdN)
	t.Logf("Rule 3 isolation confirmed: cross-context pattern key does not contaminate (Rule3=%v)",
		contamResult.AnomalyDetail.Rule3Triggered)

	// ── Assertions ────────────────────────────────────────────────────────────

	// Phase 2 in contaminated state must produce DENIED.
	if contamResult.Decision != DENIED {
		t.Fatalf("state-mixing: expected DENIED (RS=%d), got %s (RS=%d)",
			expectedBaseContam, contamResult.Decision, contamResult.RSFinal)
	}
	if contamResult.RSFinal != expectedBaseContam {
		t.Fatalf("contaminated RS: got %d, want %d", contamResult.RSFinal, expectedBaseContam)
	}

	// Rule 1 must have triggered (cross-context agentID counter).
	if !contamResult.AnomalyDetail.Rule1Triggered {
		t.Fatal("state-mixing: Rule 1 must trigger via cross-context request count")
	}

	// Rule 2 must NOT trigger (no denials in contaminated querier yet).
	if contamResult.AnomalyDetail.Rule2Triggered {
		t.Fatal("state-mixing: Rule 2 must not trigger (no prior denials)")
	}

	// Rule 3 must NOT trigger (distinct pattern key between contexts).
	if contamResult.AnomalyDetail.Rule3Triggered {
		t.Fatal("state-mixing: Rule 3 must not trigger (different patternKey — isolation holds)")
	}

	// Control RS must be the clean base score.
	if controlResult.RSFinal != expectedBaseClean {
		t.Fatalf("clean RS: got %d, want %d", controlResult.RSFinal, expectedBaseClean)
	}

	// The RS delta equals exactly the Rule 1 contribution (+20).
	rsDelta := contamResult.RSFinal - controlResult.RSFinal
	if rsDelta != 20 {
		t.Fatalf("RS delta: got %d, want 20 (Rule 1 contribution)", rsDelta)
	}
}
