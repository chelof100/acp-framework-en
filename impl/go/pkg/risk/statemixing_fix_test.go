package risk

import (
	"testing"
	"time"
)

// TestStateMixingFixed demonstrates that ACP-RISK-3.0 eliminates the cross-context
// contamination vulnerability documented in TestStateMixing.
//
// Under RISK-3.0, Rule 1 is scoped to the interaction context via PatternKey,
// not to the agent globally. Therefore, high-frequency activity in one context
// does not elevate risk scores in unrelated contexts.
//
// Experiment 7 — three scenarios:
//
//	A. Clean state: financial.transfer/sensitive → ESCALATED (RS=50)
//	B. After 11 data.read/public: financial.transfer/sensitive → ESCALATED (RS=50, NOT DENIED)
//	C. 11 financial.transfer/sensitive (same context): → DENIED (RS=85)
//
// Scenario C verifies that enforcement is preserved within a single context.
func TestStateMixingFixed(t *testing.T) {
	policy := DefaultPolicyConfig()
	baseNow := time.Now()

	const (
		agentID        = "legitimate-agent-1"
		lowRiskCap     = "acp:cap:data.read"
		highRiskCap    = "acp:cap:financial.transfer"
		phase1Requests = 11
	)

	// ── Scenario A: clean state ──────────────────────────────────────────────
	cleanQuerier := NewInMemoryQuerier()
	cleanPatKey := PatternKey(agentID, highRiskCap, string(ResourceSensitive))
	cleanQuerier.AddPattern(cleanPatKey, baseNow)

	cleanReq := EvalRequest{
		AgentID:       agentID,
		Capability:    highRiskCap,
		Resource:      string(ResourceSensitive),
		ResourceClass: ResourceSensitive,
		Policy:        policy,
		Now:           baseNow,
	}
	cleanResult, err := Evaluate(cleanReq, cleanQuerier)
	if err != nil {
		t.Fatalf("scenario A: Evaluate error: %v", err)
	}
	t.Logf("Scenario A (clean): RS=%d, Decision=%s", cleanResult.RSFinal, cleanResult.Decision)
	if cleanResult.Decision != ESCALATED {
		t.Fatalf("scenario A: expected ESCALATED, got %s (RS=%d)", cleanResult.Decision, cleanResult.RSFinal)
	}
	if cleanResult.RSFinal != 50 {
		t.Fatalf("scenario A: expected RS=50, got %d", cleanResult.RSFinal)
	}

	// ── Scenario B: after 11 data.read/public — no contamination ────────────
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
			t.Fatalf("scenario B phase 1 request #%d: error: %v", i, err)
		}
		if result.Decision != APPROVED {
			t.Fatalf("scenario B phase 1 request #%d: expected APPROVED, got %s (RS=%d)",
				i, result.Decision, result.RSFinal)
		}
	}

	// Now evaluate financial.transfer/sensitive — should NOT be contaminated
	contamQuerier.AddRequest(agentID, baseNow)
	highRiskPatKey := PatternKey(agentID, highRiskCap, string(ResourceSensitive))
	contamQuerier.AddPattern(highRiskPatKey, baseNow)

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
		t.Fatalf("scenario B: Evaluate error: %v", err)
	}
	t.Logf("Scenario B (after 11 data.read): RS=%d, Decision=%s, Rule1=%v Rule2=%v Rule3=%v",
		contamResult.RSFinal, contamResult.Decision,
		contamResult.AnomalyDetail.Rule1Triggered,
		contamResult.AnomalyDetail.Rule2Triggered,
		contamResult.AnomalyDetail.Rule3Triggered)

	if contamResult.Decision != ESCALATED {
		t.Fatalf("scenario B: expected ESCALATED (no contamination), got %s (RS=%d)",
			contamResult.Decision, contamResult.RSFinal)
	}
	if contamResult.RSFinal != 50 {
		t.Fatalf("scenario B: expected RS=50 (clean base), got %d", contamResult.RSFinal)
	}
	if contamResult.AnomalyDetail.Rule1Triggered {
		t.Fatal("scenario B: Rule 1 must NOT trigger — context isolation broken")
	}

	// ── Scenario C: 11 financial.transfer/sensitive — enforcement preserved ──
	sameCtxQuerier := NewInMemoryQuerier()
	sameCtxPatKey := PatternKey(agentID, highRiskCap, string(ResourceSensitive))

	var firstDenied int
	for i := 1; i <= 11; i++ {
		sameCtxQuerier.AddRequest(agentID, baseNow)
		sameCtxQuerier.AddPattern(sameCtxPatKey, baseNow)
		req := EvalRequest{
			AgentID:       agentID,
			Capability:    highRiskCap,
			Resource:      string(ResourceSensitive),
			ResourceClass: ResourceSensitive,
			Policy:        policy,
			Now:           baseNow,
		}
		result, err := Evaluate(req, sameCtxQuerier)
		if err != nil {
			t.Fatalf("scenario C request #%d: error: %v", i, err)
		}
		if result.Decision == DENIED && firstDenied == 0 {
			firstDenied = i
			t.Logf("Scenario C: first DENIED at request #%d (RS=%d)", i, result.RSFinal)
		}
	}

	if firstDenied == 0 {
		t.Fatal("scenario C: expected DENIED within 11 requests, but none occurred")
	}
	expectedFirstDenied := policy.AnomalyRule1ThresholdN + 1 // = 11
	if firstDenied != expectedFirstDenied {
		t.Fatalf("scenario C: expected first DENIED at #%d, got #%d", expectedFirstDenied, firstDenied)
	}

	t.Logf("RISK-3.0 summary:")
	t.Logf("  Scenario A (clean):         RS=50, ESCALATED (context isolation baseline)")
	t.Logf("  Scenario B (contaminated):  RS=50, ESCALATED (state-mixing eliminated)")
	t.Logf("  Scenario C (same-context):  first DENIED at #%d (enforcement preserved)", firstDenied)
}
