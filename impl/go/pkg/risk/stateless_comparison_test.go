package risk

import (
	"testing"
	"time"
)

// TestStatelessVsACP demonstrates the structural necessity of stateful enforcement.
//
// Scenario: attacker-1 sends 500 financial.transfer requests to a public resource.
// RS_base = 35 (capability) + 0 (public resource) = 35 — always below ApprovedMax=39.
// A stateless engine sees 500 independent safe requests and approves all of them.
// ACP sees a trace: pattern accumulation triggers ESCALATED at #3, DENIED at #11,
// and COOLDOWN_ACTIVE at #14 after 3 denials.
//
// State is updated prior to evaluation: the system records attempts, not outcomes.
// The evaluation timestamp is fixed to remove time-based decay as a confounding
// variable and isolate pure behavioral accumulation effects.
func TestStatelessVsACP(t *testing.T) {
	const (
		agentID  = "attacker-1"
		cap      = "acp:cap:financial.transfer"
		resource = string(ResourcePublic)
		total    = 500
	)

	policy := DefaultPolicyConfig()
	baseNow := time.Now() // fixed once — never advanced inside the loop

	querier := NewInMemoryQuerier()
	stateless := NewStatelessEngine(policy)
	patKey := PatternKey(agentID, cap, resource)

	// Counters — ACP
	var acpApproved, acpEscalated, acpDenied, acpCooldown int
	var firstEscalated, firstDenied, cooldownTriggeredAt int

	// Counters — Stateless
	var slApproved int

	for i := 1; i <= total; i++ {
		// ── Model A: state updated prior to evaluation ────────────────────────
		querier.AddRequest(agentID, baseNow)
		querier.AddPattern(patKey, baseNow)

		req := EvalRequest{
			AgentID:       agentID,
			Capability:    cap,
			Resource:      resource,
			ResourceClass: ResourcePublic,
			Policy:        policy,
			Now:           baseNow,
		}

		// ── ACP evaluation ────────────────────────────────────────────────────
		acpResult, err := Evaluate(req, querier)
		if err != nil {
			t.Fatalf("request #%d: ACP Evaluate error: %v", i, err)
		}

		switch {
		case acpResult.Decision == DENIED && acpResult.DeniedReason == "COOLDOWN_ACTIVE":
			acpCooldown++
		case acpResult.Decision == DENIED:
			acpDenied++
			if firstDenied == 0 {
				firstDenied = i
				t.Logf("[%d] Transition → DENIED (RS=%d, F_anom=%d)", i, acpResult.RSFinal, acpResult.Factors.Anomaly)
			}
			// Record denial; check whether cooldown threshold is reached.
			querier.AddDenial(agentID, baseNow)
			should, cerr := ShouldEnterCooldown(agentID, policy, querier, baseNow)
			if cerr != nil {
				t.Fatalf("request #%d: ShouldEnterCooldown error: %v", i, cerr)
			}
			if should {
				until := baseNow.Add(time.Duration(policy.CooldownPeriodSeconds) * time.Second)
				querier.SetCooldown(agentID, until)
				if cooldownTriggeredAt == 0 {
					cooldownTriggeredAt = i
					t.Logf("[%d] Cooldown SET (3 denials reached)", i)
				}
			}
		case acpResult.Decision == ESCALATED:
			acpEscalated++
			if firstEscalated == 0 {
				firstEscalated = i
				t.Logf("[%d] Transition → ESCALATED (RS=%d, F_anom=%d)", i, acpResult.RSFinal, acpResult.Factors.Anomaly)
			}
		case acpResult.Decision == APPROVED:
			acpApproved++
		}

		// ── Stateless evaluation ──────────────────────────────────────────────
		slResult, err := stateless.Evaluate(req)
		if err != nil {
			t.Fatalf("request #%d: Stateless Evaluate error: %v", i, err)
		}
		if slResult.Decision == APPROVED {
			slApproved++
		}
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	t.Logf("Early signal latency: first ESCALATED at request #%d", firstEscalated)
	t.Logf("Enforcement latency:  first DENIED    at request #%d", firstDenied)
	t.Logf("Cooldown triggered:                   at request #%d", cooldownTriggeredAt)
	t.Logf("Stateless: %d APPROVED / %d rest", slApproved, total-slApproved)
	t.Logf("ACP: %d APPROVED / %d ESCALATED / %d DENIED / %d COOLDOWN",
		acpApproved, acpEscalated, acpDenied, acpCooldown)

	// ── Assertions (relative to policy — no hardcoded magic numbers) ──────────

	// Enforcement latency: Rule1 triggers when count > AnomalyRule1ThresholdN,
	// which happens at request N+1.
	expectedFirstDenied := policy.AnomalyRule1ThresholdN + 1
	if firstDenied != expectedFirstDenied {
		t.Fatalf("enforcement latency: got first DENIED at request #%d, want #%d (AnomalyRule1ThresholdN=%d)",
			firstDenied, expectedFirstDenied, policy.AnomalyRule1ThresholdN)
	}

	// Early signal: Rule3 triggers when pattern count >= AnomalyRule3ThresholdY,
	// which first happens at request Y (after Y AddPattern calls).
	expectedFirstEscalated := policy.AnomalyRule3ThresholdY
	if firstEscalated != expectedFirstEscalated {
		t.Fatalf("early signal latency: got first ESCALATED at request #%d, want #%d (AnomalyRule3ThresholdY=%d)",
			firstEscalated, expectedFirstEscalated, policy.AnomalyRule3ThresholdY)
	}

	// Cooldown is triggered at the CooldownTriggerDenials-th DENIED request.
	expectedCooldownTrigger := firstDenied + policy.CooldownTriggerDenials - 1
	if cooldownTriggeredAt != expectedCooldownTrigger {
		t.Fatalf("cooldown trigger: SetCooldown called at request #%d, want #%d",
			cooldownTriggeredAt, expectedCooldownTrigger)
	}

	// Stateless approves every request — it cannot see the trace.
	if slApproved != total {
		t.Fatalf("stateless: expected %d APPROVED, got %d", total, slApproved)
	}

	// ACP count breakdown.
	wantACPApproved := firstEscalated - 1
	wantACPEscalated := firstDenied - firstEscalated
	wantACPDenied := policy.CooldownTriggerDenials
	wantACPCooldown := total - cooldownTriggeredAt

	if acpApproved != wantACPApproved {
		t.Errorf("ACP APPROVED: got %d, want %d", acpApproved, wantACPApproved)
	}
	if acpEscalated != wantACPEscalated {
		t.Errorf("ACP ESCALATED: got %d, want %d", acpEscalated, wantACPEscalated)
	}
	if acpDenied != wantACPDenied {
		t.Errorf("ACP DENIED: got %d, want %d", acpDenied, wantACPDenied)
	}
	if acpCooldown != wantACPCooldown {
		t.Errorf("ACP COOLDOWN: got %d, want %d", acpCooldown, wantACPCooldown)
	}
}
