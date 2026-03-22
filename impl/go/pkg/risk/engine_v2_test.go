package risk

import (
	"testing"
	"time"
)

// Reference timestamp used across all v2 tests (mirrors compliance test vectors).
var t0 = time.Unix(1700000000, 0)

// ── PatternKey ────────────────────────────────────────────────────────────────

func TestPatternKey_Determinism(t *testing.T) {
	k1 := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc/001")
	k2 := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc/001")
	if k1 != k2 {
		t.Fatalf("PatternKey not deterministic: %q != %q", k1, k2)
	}
}

func TestPatternKey_Length(t *testing.T) {
	k := PatternKey("agent-A", "acp:cap:data.read", "org/reports/Q1")
	if len(k) != 32 {
		t.Fatalf("PatternKey length = %d, want 32", len(k))
	}
}

func TestPatternKey_Uniqueness(t *testing.T) {
	k1 := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc/001")
	k2 := PatternKey("agent-B", "acp:cap:financial.payment", "org/acc/001")
	k3 := PatternKey("agent-A", "acp:cap:data.read", "org/acc/001")
	if k1 == k2 || k1 == k3 {
		t.Fatal("PatternKey collision detected")
	}
}

// ── F_anom Rule 1: high request rate ─────────────────────────────────────────

func TestRule1_Triggered(t *testing.T) {
	q := NewInMemoryQuerier()
	// Add N+1 = 11 requests in the last 60s.
	for i := 0; i < 11; i++ {
		q.AddRequest("agent-A", t0.Add(-time.Duration(i)*time.Second))
	}
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnomalyDetail.Rule1Triggered {
		t.Error("Rule1 should trigger when count > N")
	}
	if res.Factors.Anomaly < 20 {
		t.Errorf("Anomaly factor = %d, want ≥ 20", res.Factors.Anomaly)
	}
}

func TestRule1_NotTriggered_BoundaryExact(t *testing.T) {
	q := NewInMemoryQuerier()
	// Exactly N = 10 requests — not triggered (> N required).
	for i := 0; i < 10; i++ {
		q.AddRequest("agent-A", t0.Add(-time.Duration(i)*time.Second))
	}
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnomalyDetail.Rule1Triggered {
		t.Error("Rule1 must NOT trigger when count == N (boundary: count > N)")
	}
}

// ── F_anom Rule 2: recent denials ────────────────────────────────────────────

func TestRule2_Triggered(t *testing.T) {
	q := NewInMemoryQuerier()
	for i := 0; i < 3; i++ {
		q.AddDenial("agent-A", t0.Add(-time.Duration(i)*time.Hour))
	}
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnomalyDetail.Rule2Triggered {
		t.Error("Rule2 should trigger with 3 denials in 24h (≥ X=3)")
	}
}

func TestRule2_NotTriggered(t *testing.T) {
	q := NewInMemoryQuerier()
	q.AddDenial("agent-A", t0.Add(-1*time.Hour))
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnomalyDetail.Rule2Triggered {
		t.Error("Rule2 must NOT trigger with only 1 denial")
	}
}

// ── F_anom Rule 3: repeated pattern ──────────────────────────────────────────

func TestRule3_Triggered(t *testing.T) {
	q := NewInMemoryQuerier()
	key := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc")
	for i := 0; i < 3; i++ {
		q.AddPattern(key, t0.Add(-time.Duration(i)*time.Minute))
	}
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnomalyDetail.Rule3Triggered {
		t.Error("Rule3 should trigger with 3 pattern hits in 5min (≥ Y=3)")
	}
}

func TestRule3_NotTriggered(t *testing.T) {
	q := NewInMemoryQuerier()
	key := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc")
	q.AddPattern(key, t0.Add(-1*time.Minute))
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnomalyDetail.Rule3Triggered {
		t.Error("Rule3 must NOT trigger with only 1 pattern hit")
	}
}

// ── All 3 rules triggered: max F_anom = 50 ───────────────────────────────────

func TestAllRulesTriggered_MaxAnomaly(t *testing.T) {
	q := NewInMemoryQuerier()
	for i := 0; i < 11; i++ {
		q.AddRequest("agent-A", t0.Add(-time.Duration(i)*time.Second))
	}
	for i := 0; i < 3; i++ {
		q.AddDenial("agent-A", t0.Add(-time.Duration(i)*time.Hour))
	}
	key := PatternKey("agent-A", "acp:cap:financial.payment", "org/acc")
	for i := 0; i < 3; i++ {
		q.AddPattern(key, t0.Add(-time.Duration(i)*time.Minute))
	}
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Factors.Anomaly != 50 {
		t.Errorf("All rules triggered: F_anom = %d, want 50", res.Factors.Anomaly)
	}
	if !res.AnomalyDetail.Rule1Triggered || !res.AnomalyDetail.Rule2Triggered || !res.AnomalyDetail.Rule3Triggered {
		t.Error("All three rules must be triggered")
	}
}

// ── Score cap at 100 ─────────────────────────────────────────────────────────

func TestScoreCap(t *testing.T) {
	q := NewInMemoryQuerier()
	// financial.payment + restricted + all context flags + all history + all anomaly
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Context: Context{ExternalIP: true, OffHours: true, GeoOutside: true, UntrustedDevice: true},
		History: History{RecentDenial: true, DenialRateHigh: true, FreqAnomaly: true},
		Policy:  DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.RSFinal > 100 {
		t.Errorf("RSFinal = %d, must be ≤ 100", res.RSFinal)
	}
}

// ── Factor breakdown correctness ─────────────────────────────────────────────

func TestFactorBreakdown_FinancialRestricted(t *testing.T) {
	// financial.payment + restricted, no context/history/anomaly → RS=80
	q := NewInMemoryQuerier()
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Factors.Base != 35 {
		t.Errorf("Base = %d, want 35", res.Factors.Base)
	}
	if res.Factors.Resource != 45 {
		t.Errorf("Resource = %d, want 45", res.Factors.Resource)
	}
	if res.RSFinal != 80 {
		t.Errorf("RSFinal = %d, want 80", res.RSFinal)
	}
	if res.Decision != DENIED {
		t.Errorf("Decision = %s, want DENIED", res.Decision)
	}
}

func TestFactorBreakdown_DataReadPublic(t *testing.T) {
	// data.read + public → RS=0 → APPROVED
	q := NewInMemoryQuerier()
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Factors.Base != 0 {
		t.Errorf("Base = %d, want 0", res.Factors.Base)
	}
	if res.Factors.Resource != 0 {
		t.Errorf("Resource = %d, want 0", res.Factors.Resource)
	}
	if res.Decision != APPROVED {
		t.Errorf("Decision = %s, want APPROVED", res.Decision)
	}
}

// ── Decision thresholds ───────────────────────────────────────────────────────

func TestDecision_Approved(t *testing.T) {
	q := NewInMemoryQuerier()
	// data.read + public = RS=0 → APPROVED
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if res.Decision != APPROVED {
		t.Errorf("expected APPROVED, got %s", res.Decision)
	}
}

func TestDecision_Escalated(t *testing.T) {
	q := NewInMemoryQuerier()
	// data.write + sensitive = 10+15 = 25 → under 40 → APPROVED actually
	// Use financial.payment + public = 35+0 = 35 → APPROVED (≤39)
	// Use financial.payment + sensitive = 35+15 = 50 → ESCALATED
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/r", ResourceClass: ResourceSensitive,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if res.Decision != ESCALATED {
		t.Errorf("expected ESCALATED (RS=%d), got %s", res.RSFinal, res.Decision)
	}
}

func TestDecision_Denied(t *testing.T) {
	q := NewInMemoryQuerier()
	// financial.payment + restricted = 35+45 = 80 → DENIED
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/r", ResourceClass: ResourceRestricted,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if res.Decision != DENIED {
		t.Errorf("expected DENIED (RS=%d), got %s", res.RSFinal, res.Decision)
	}
}

// ── Autonomy level overrides ──────────────────────────────────────────────────

func TestAutonomyLevel0_AlwaysDenied(t *testing.T) {
	q := NewInMemoryQuerier()
	p := DefaultPolicyConfig()
	p.AutonomyLevel = 0
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: p, Now: t0,
	}, q)
	if res.Decision != DENIED {
		t.Errorf("AutonomyLevel=0: expected DENIED, got %s", res.Decision)
	}
	if res.DeniedReason != "AUTONOMY_LEVEL_0" {
		t.Errorf("DeniedReason = %q, want AUTONOMY_LEVEL_0", res.DeniedReason)
	}
}

func TestAutonomyLevel1_NoAutoApprove(t *testing.T) {
	q := NewInMemoryQuerier()
	p := DefaultPolicyConfig()
	p.AutonomyLevel = 1
	// Even RS=0 should not be APPROVED at level 1.
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: p, Now: t0,
	}, q)
	if res.Decision == APPROVED {
		t.Error("AutonomyLevel=1: APPROVED is not allowed")
	}
}

func TestAutonomyLevel4_HighThreshold(t *testing.T) {
	q := NewInMemoryQuerier()
	p := DefaultPolicyConfig()
	p.AutonomyLevel = 4
	p.ApprovedMax = 79
	p.EscalatedMax = 89
	// RS=80: should be ESCALATED with custom thresholds.
	res, _ := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/r", ResourceClass: ResourceRestricted,
		Policy: p, Now: t0,
	}, q)
	if res.Decision != ESCALATED {
		t.Errorf("expected ESCALATED with custom thresholds, got %s (RS=%d)", res.Decision, res.RSFinal)
	}
}

// ── Cooldown ──────────────────────────────────────────────────────────────────

func TestCooldown_Active(t *testing.T) {
	q := NewInMemoryQuerier()
	q.SetCooldown("agent-A", t0.Add(5*time.Minute))
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != DENIED {
		t.Errorf("expected DENIED during cooldown, got %s", res.Decision)
	}
	if res.DeniedReason != "COOLDOWN_ACTIVE" {
		t.Errorf("DeniedReason = %q, want COOLDOWN_ACTIVE", res.DeniedReason)
	}
}

func TestCooldown_Expired(t *testing.T) {
	q := NewInMemoryQuerier()
	// Cooldown expired 1 second before t0.
	q.SetCooldown("agent-A", t0.Add(-1*time.Second))
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeniedReason == "COOLDOWN_ACTIVE" {
		t.Error("expired cooldown must not block evaluation")
	}
}

// ── ShouldEnterCooldown ───────────────────────────────────────────────────────

func TestShouldEnterCooldown_Triggers(t *testing.T) {
	q := NewInMemoryQuerier()
	p := DefaultPolicyConfig()
	for i := 0; i < 3; i++ {
		q.AddDenial("agent-A", t0.Add(-time.Duration(i)*time.Minute))
	}
	entered, err := ShouldEnterCooldown("agent-A", p, q, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !entered {
		t.Error("expected cooldown to trigger after 3 DENIED in 10min")
	}
}

func TestShouldEnterCooldown_NotTriggered(t *testing.T) {
	q := NewInMemoryQuerier()
	p := DefaultPolicyConfig()
	q.AddDenial("agent-A", t0.Add(-1*time.Minute))
	entered, err := ShouldEnterCooldown("agent-A", p, q, t0)
	if err != nil {
		t.Fatal(err)
	}
	if entered {
		t.Error("must not enter cooldown with only 1 denial")
	}
}

// ── Fail-closed on nil querier ────────────────────────────────────────────────

func TestNilQuerier_FailClosed(t *testing.T) {
	_, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, nil)
	if err == nil {
		t.Error("nil querier must return error (fail-closed RISK-008)")
	}
}

// ── AnomalyDetail always present ─────────────────────────────────────────────

func TestAnomalyDetail_AlwaysPresent(t *testing.T) {
	q := NewInMemoryQuerier()
	res, err := Evaluate(EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:data.read",
		Resource: "org/r", ResourceClass: ResourcePublic,
		Policy: DefaultPolicyConfig(), Now: t0,
	}, q)
	if err != nil {
		t.Fatal(err)
	}
	// AnomalyDetail is always populated (zero values = no rules triggered).
	_ = res.AnomalyDetail
}

// ── Determinism ───────────────────────────────────────────────────────────────

func TestDeterminism(t *testing.T) {
	makeQuerier := func() *InMemoryQuerier {
		q := NewInMemoryQuerier()
		q.AddDenial("agent-A", t0.Add(-1*time.Hour))
		q.AddRequest("agent-A", t0.Add(-5*time.Second))
		return q
	}
	req := EvalRequest{
		AgentID: "agent-A", Capability: "acp:cap:financial.payment",
		Resource: "org/acc", ResourceClass: ResourceRestricted,
		Context: Context{ExternalIP: true},
		Policy:  DefaultPolicyConfig(), Now: t0,
	}
	r1, _ := Evaluate(req, makeQuerier())
	r2, _ := Evaluate(req, makeQuerier())
	if r1.RSFinal != r2.RSFinal || r1.Decision != r2.Decision {
		t.Errorf("non-deterministic: (%d,%s) vs (%d,%s)", r1.RSFinal, r1.Decision, r2.RSFinal, r2.Decision)
	}
}
