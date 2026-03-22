package risk

import (
	"testing"
	"time"
)

// Benchmark setup — reusable querier and requests.

func newBenchQuerier() *InMemoryQuerier {
	return NewInMemoryQuerier()
}

func approvedReq(policy PolicyConfig) EvalRequest {
	return EvalRequest{
		AgentID:       "acp:agent:org.example:BenchAgent-001",
		Capability:    "acp:cap:data.read",
		Resource:      "org.example/reports/Q1",
		ResourceClass: ResourcePublic,
		Policy:        policy,
		Now:           time.Unix(1700000000, 0),
	}
}

func deniedReq(policy PolicyConfig) EvalRequest {
	return EvalRequest{
		AgentID:       "acp:agent:org.example:BenchAgent-001",
		Capability:    "acp:cap:financial.payment",
		Resource:      "org.example/accounts/ACC-001",
		ResourceClass: ResourceRestricted,
		Policy:        policy,
		Now:           time.Unix(1700000000, 0),
	}
}

// BenchmarkEvaluate_Approved — baseline APPROVED path (data.read, public, no anomaly).
func BenchmarkEvaluate_Approved(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()
	req := approvedReq(policy)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Evaluate(req, q)
	}
}

// BenchmarkEvaluate_Denied — DENIED path (financial.payment + restricted, no anomaly).
func BenchmarkEvaluate_Denied(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()
	req := deniedReq(policy)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Evaluate(req, q)
	}
}

// BenchmarkEvaluate_WithAnomalyRules — all three F_anom rules active.
func BenchmarkEvaluate_WithAnomalyRules(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()

	agentID := "acp:agent:org.example:BenchAgent-Anom"
	cap := "acp:cap:financial.payment"
	res := "org.example/accounts/ACC-002"
	patKey := PatternKey(agentID, cap, res)
	now := time.Unix(1700000000, 0)

	// Seed Rule 1: 11 requests in last 60s (> N=10)
	for i := 0; i < 11; i++ {
		q.AddRequest(agentID, now.Add(-time.Duration(i)*5*time.Second))
	}
	// Seed Rule 2: 3 denials in last 24h (>= X=3)
	for i := 0; i < 3; i++ {
		q.AddDenial(agentID, now.Add(-time.Duration(i+1)*time.Hour))
	}
	// Seed Rule 3: 3 pattern hits in last 5min (>= Y=3)
	for i := 0; i < 3; i++ {
		q.AddPattern(patKey, now.Add(-time.Duration(i+1)*time.Minute))
	}

	req := EvalRequest{
		AgentID:       agentID,
		Capability:    cap,
		Resource:      res,
		ResourceClass: ResourceRestricted,
		Policy:        policy,
		Now:           now,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Evaluate(req, q)
	}
}

// BenchmarkEvaluate_CooldownActive — short-circuit path (no RS computation).
func BenchmarkEvaluate_CooldownActive(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()

	agentID := "acp:agent:org.example:BenchAgent-Cooldown"
	now := time.Unix(1700000000, 0)
	q.SetCooldown(agentID, now.Add(5*time.Minute))

	req := EvalRequest{
		AgentID:       agentID,
		Capability:    "acp:cap:financial.payment",
		Resource:      "org.example/accounts/ACC-003",
		ResourceClass: ResourceRestricted,
		Policy:        policy,
		Now:           now,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Evaluate(req, q)
	}
}

// BenchmarkPatternKey — hash computation for F_anom Rule 3.
func BenchmarkPatternKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PatternKey(
			"acp:agent:org.example:BenchAgent-001",
			"acp:cap:financial.payment",
			"org.example/accounts/ACC-001",
		)
	}
}

// BenchmarkShouldEnterCooldown — cooldown threshold check.
func BenchmarkShouldEnterCooldown(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()
	agentID := "acp:agent:org.example:BenchAgent-CD"
	now := time.Unix(1700000000, 0)

	// Seed 2 denials (below threshold of 3 — will return false)
	for i := 0; i < 2; i++ {
		q.AddDenial(agentID, now.Add(-time.Duration(i+1)*time.Minute))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ShouldEnterCooldown(agentID, policy, q, now)
	}
}
