package risk

import (
	"fmt"
	"sort"
	"sync"
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

// ── G1.1 Latency comparison: baseline vs ACP ─────────────────────────────────
//
// benchBaseline simulates a minimal request path with no control logic.
// Same request shape as ACP — reads the three key fields — but performs no
// evaluation. Used as the reference point for measuring ACP overhead.
// Using _ = 1+1 would be fake; the baseline must have the same call structure.
func benchBaseline(req EvalRequest) {
	_ = req.AgentID
	_ = req.Capability
	_ = req.Resource
}

// BenchmarkLatencyComparison measures ns/op and allocs for baseline vs ACP.
// Produces the primary official numbers for the paper.
//
// Run with:
//
//	go test -bench=BenchmarkLatencyComparison -benchmem ./pkg/risk/
func BenchmarkLatencyComparison(b *testing.B) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()
	req := approvedReq(policy)

	b.Run("baseline", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchBaseline(req)
		}
	})

	b.Run("acp_approved", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.Now = time.Now()
			_, _ = Evaluate(req, q)
		}
	})
}

// ── G1.1 Percentile measurement: p50 / p95 / p99 ────────────────────────────
//
// TestLatencyPercentiles measures the distribution of latency for baseline vs
// ACP, reporting p50/p95/p99 and the absolute overhead per call.
// These are the numbers that go into the paper's evaluation table.
//
// Uses batch measurement (batchSize calls per sample) to work around the
// limited timer resolution on Windows (~100ns). Each sample is the average
// ns/call over the batch. On Linux the numbers are finer-grained.
//
// Run with:
//
//	go test -run=TestLatencyPercentiles -v ./pkg/risk/
const (
	percentileSamples = 1_000 // number of batch samples
	batchSize         = 1_000 // calls per sample → each result = avg ns/call
)

func TestLatencyPercentiles(t *testing.T) {
	policy := DefaultPolicyConfig()
	q := newBenchQuerier()
	req := approvedReq(policy)

	// Measure baseline — same request shape, no control logic.
	// Batched so that even Windows timers produce non-zero readings.
	baseNs := make([]int64, percentileSamples)
	for i := range baseNs {
		start := time.Now()
		for j := 0; j < batchSize; j++ {
			benchBaseline(req)
		}
		elapsed := time.Since(start).Nanoseconds()
		baseNs[i] = elapsed / batchSize // avg ns per call
	}

	// Measure ACP — full Evaluate() path.
	acpNs := make([]int64, percentileSamples)
	for i := range acpNs {
		start := time.Now()
		for j := 0; j < batchSize; j++ {
			req.Now = time.Now()
			_, _ = Evaluate(req, q)
		}
		elapsed := time.Since(start).Nanoseconds()
		acpNs[i] = elapsed / batchSize // avg ns per call
	}

	type row struct {
		label string
		pct   float64
	}
	percentiles := []row{
		{"p50", 0.50},
		{"p95", 0.95},
		{"p99", 0.99},
	}

	t.Logf("─────────────────────────────────────────────────────────────────")
	t.Logf("  %-6s  %16s  %12s  %14s", "Metric", "Baseline (ns/op)", "ACP (ns/op)", "Overhead (ns)")
	t.Logf("─────────────────────────────────────────────────────────────────")
	for _, p := range percentiles {
		base := nsPercentile(baseNs, p.pct)
		acp := nsPercentile(acpNs, p.pct)
		t.Logf("  %-6s  %16d  %12d  %+14d", p.label, base, acp, acp-base)
	}
	t.Logf("─────────────────────────────────────────────────────────────────")
	t.Logf("  Samples: %d batches x %d calls each", percentileSamples, batchSize)
	t.Logf("  Method:  avg ns/call per batch (works on Windows low-res timers)")
	t.Logf("  Note:    report absolute overhead (ns), not percentage.")
	t.Logf("           (baseline ~0 makes %% overhead misleading for reviewers)")
	t.Logf("─────────────────────────────────────────────────────────────────")

	baseP50 := nsPercentile(baseNs, 0.50)
	acpP50 := nsPercentile(acpNs, 0.50)
	t.Logf("  >> Paper sentence: \"ACP introduces ~%d ns latency overhead per request (p50)\"",
		acpP50-baseP50)
}

// nsPercentile returns the p-th percentile (0.0–1.0) of a nanosecond slice.
// The input slice is copied before sorting so the original is not modified.
func nsPercentile(data []int64, p float64) int64 {
	sorted := make([]int64, len(data))
	copy(sorted, data)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ── G1.4 Scenario comparison: clean / with history / F_anom / cooldown ───────
//
// BenchmarkEvaluate_Scenarios compares ns/op across the four execution paths
// that correspond to different agent behavioral states. Demonstrates that
// cooldown is the fastest path (short-circuit) and full F_anom the slowest.
//
// Run with:
//
//	go test -bench=BenchmarkEvaluate_Scenarios -benchmem ./pkg/risk/
func BenchmarkEvaluate_Scenarios(b *testing.B) {
	policy := DefaultPolicyConfig()
	now := time.Unix(1700000000, 0)

	// Scenario 1: clean state — no history, no anomaly.
	b.Run("clean_state", func(b *testing.B) {
		q := newBenchQuerier()
		req := approvedReq(policy)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Evaluate(req, q)
		}
	})

	// Scenario 2: with accumulated history — denials + patterns seeded,
	// but below threshold so F_anom does not trigger.
	b.Run("with_history", func(b *testing.B) {
		q := newBenchQuerier()
		agentID := "acp:agent:org.example:BenchAgent-Hist"
		cap := "acp:cap:data.read"
		res := "org.example/reports/Q1"
		patKey := PatternKey(agentID, cap, res)
		// 2 denials (below X=3) and 2 pattern hits (below Y=3)
		for i := 0; i < 2; i++ {
			q.AddDenial(agentID, now.Add(-time.Duration(i+1)*time.Hour))
			q.AddPattern(patKey, now.Add(-time.Duration(i+1)*time.Minute))
		}
		req := EvalRequest{
			AgentID:       agentID,
			Capability:    cap,
			Resource:      res,
			ResourceClass: ResourcePublic,
			Policy:        policy,
			Now:           now,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Evaluate(req, q)
		}
	})

	// Scenario 3: all F_anom rules active — worst-case evaluation path.
	b.Run("fanom_all_rules", func(b *testing.B) {
		q := newBenchQuerier()
		agentID := "acp:agent:org.example:BenchAgent-FA"
		cap := "acp:cap:financial.payment"
		res := "org.example/accounts/ACC-004"
		patKey := PatternKey(agentID, cap, res)
		for i := 0; i < 11; i++ {
			q.AddRequest(agentID, now.Add(-time.Duration(i)*5*time.Second))
		}
		for i := 0; i < 3; i++ {
			q.AddDenial(agentID, now.Add(-time.Duration(i+1)*time.Hour))
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
	})

	// Scenario 4: cooldown active — fastest path (short-circuit at Step 2,
	// before RS computation). Expected to be faster than clean_state.
	b.Run("cooldown_active", func(b *testing.B) {
		q := newBenchQuerier()
		agentID := "acp:agent:org.example:BenchAgent-CD2"
		q.SetCooldown(agentID, now.Add(5*time.Minute))
		req := EvalRequest{
			AgentID:       agentID,
			Capability:    "acp:cap:financial.payment",
			Resource:      "org.example/accounts/ACC-005",
			ResourceClass: ResourceRestricted,
			Policy:        policy,
			Now:           now,
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = Evaluate(req, q)
		}
	})
}

// ── G1.2 Throughput under concurrent load ────────────────────────────────────
//
// BenchmarkThroughputConcurrent measures ns/op with 10, 100, and 500 concurrent
// workers all sharing a single InMemoryQuerier. Reveals the scaling curve and
// the saturation point where state backend contention becomes the bottleneck.
//
// To compute req/s from results: req/s = 1e9 / ns_per_op
//
// Expected pattern:
//   10→100 workers: near-linear scaling (lock contention low)
//   100→500 workers: throughput degrades (mutex serializes InMemoryQuerier)
//
// Key insight for the paper:
//   ACP is state-bound, not CPU-bound. The decision function itself is
//   computationally cheap; throughput is limited by state backend access.
//
// Run with:
//
//	go test -bench=BenchmarkThroughputConcurrent -benchmem -benchtime=3s ./pkg/risk/
func BenchmarkThroughputConcurrent(b *testing.B) {
	policy := DefaultPolicyConfig()

	run := func(workers int) func(b *testing.B) {
		return func(b *testing.B) {
			q := newBenchQuerier()
			start := make(chan struct{})
			var wg sync.WaitGroup

			b.ReportAllocs()
			b.ResetTimer()

			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					req := EvalRequest{
						AgentID:       fmt.Sprintf("acp:agent:org.example:Worker-%d", id),
						Capability:    "acp:cap:data.read",
						Resource:      "org.example/reports/Q1",
						ResourceClass: ResourcePublic,
						Policy:        policy,
					}
					<-start // all workers start simultaneously
					iters := b.N / workers
					if iters < 1 {
						iters = 1
					}
					for i := 0; i < iters; i++ {
						req.Now = time.Now()
						_, _ = Evaluate(req, q)
					}
				}(w)
			}

			close(start) // release all workers at once
			wg.Wait()
		}
	}

	b.Run("10-workers", run(10))
	b.Run("100-workers", run(100))
	b.Run("500-workers", run(500))
}

// TestThroughputRPS runs BenchmarkThroughputConcurrent scenarios manually and
// prints the derived req/s for each worker count. Useful for the paper table.
//
// Run with:
//
//	go test -run=TestThroughputRPS -v ./pkg/risk/
func TestThroughputRPS(t *testing.T) {
	policy := DefaultPolicyConfig()
	const callsPerWorkerSet = 50_000 // total calls per worker count

	type result struct {
		workers int
		nsPerOp float64
		rps     float64
	}

	workerCounts := []int{10, 100, 500}
	results := make([]result, 0, len(workerCounts))

	for _, workers := range workerCounts {
		q := newBenchQuerier()
		start := make(chan struct{})
		var wg sync.WaitGroup
		itersPerWorker := callsPerWorkerSet / workers

		startTime := time.Now()

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				req := EvalRequest{
					AgentID:       fmt.Sprintf("acp:agent:org.example:Worker-%d", id),
					Capability:    "acp:cap:data.read",
					Resource:      "org.example/reports/Q1",
					ResourceClass: ResourcePublic,
					Policy:        policy,
				}
				<-start
				for i := 0; i < itersPerWorker; i++ {
					req.Now = time.Now()
					_, _ = Evaluate(req, q)
				}
			}(w)
		}

		close(start)
		wg.Wait()

		elapsed := time.Since(startTime)
		totalCalls := workers * itersPerWorker
		nsPerOp := float64(elapsed.Nanoseconds()) / float64(totalCalls)
		rps := 1e9 / nsPerOp

		results = append(results, result{workers, nsPerOp, rps})
	}

	t.Logf("─────────────────────────────────────────────────────────────────")
	t.Logf("  %-10s  %14s  %16s  %s", "Workers", "ns/op (avg)", "req/s", "Observation")
	t.Logf("─────────────────────────────────────────────────────────────────")
	for i, r := range results {
		obs := ""
		if i == 0 {
			obs = "baseline concurrency"
		} else if r.rps > results[i-1].rps {
			obs = "scaling up"
		} else {
			obs = "contention — state-bound"
		}
		t.Logf("  %-10d  %14.1f  %16.0f  %s", r.workers, r.nsPerOp, r.rps, obs)
	}
	t.Logf("─────────────────────────────────────────────────────────────────")
	t.Logf("  Calls per run: %d per worker count", callsPerWorkerSet)
	t.Logf("  Backend: InMemoryQuerier (sync.Mutex — shared across all workers)")
	t.Logf("  Key insight: throughput limited by state backend, not decision function")
	t.Logf("─────────────────────────────────────────────────────────────────")
}

// ── G1.3 State contention: 1 / 100 / 1000 distinct agents ───────────────────
//
// BenchmarkStateContention holds workers constant (10) and varies the number
// of distinct agents in the pool. Each worker is assigned an agent by
// workerID % agentCount.
//
// With 1 agent: all workers hit the same state keys → maximum per-key
// contention AND state lists grow long → CountRequests scans a longer slice.
//
// With many agents: state is spread across agent IDs → shorter per-agent
// lists → faster CountRequests, less per-key contention.
//
// The shared mutex (InMemoryQuerier) means some lock contention persists
// regardless of agent count — this is the architectural constraint to document.
//
// Run with:
//
//	go test -bench=BenchmarkStateContention -benchmem -benchtime=3s ./pkg/risk/
func BenchmarkStateContention(b *testing.B) {
	policy := DefaultPolicyConfig()
	const workers = 10

	run := func(agentCount int) func(b *testing.B) {
		return func(b *testing.B) {
			q := newBenchQuerier()
			start := make(chan struct{})
			var wg sync.WaitGroup

			b.ReportAllocs()
			b.ResetTimer()

			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					agentID := fmt.Sprintf("acp:agent:org.example:Agent-%d", id%agentCount)
					req := EvalRequest{
						AgentID:       agentID,
						Capability:    "acp:cap:data.read",
						Resource:      "org.example/reports/Q1",
						ResourceClass: ResourcePublic,
						Policy:        policy,
					}
					<-start
					iters := b.N / workers
					if iters < 1 {
						iters = 1
					}
					for i := 0; i < iters; i++ {
						req.Now = time.Now()
						_, _ = Evaluate(req, q)
						// Include AddRequest to simulate the execution contract:
						// state accumulates over time, making CountRequests
						// progressively slower for agents with long histories.
						q.AddRequest(agentID, req.Now)
					}
				}(w)
			}

			close(start)
			wg.Wait()
		}
	}

	b.Run("1-agent", run(1))
	b.Run("100-agents", run(100))
	b.Run("1000-agents", run(1000))
}

// TestStateContentionRPS measures req/s across agent pool sizes and reports
// the bottleneck analysis. Run with:
//
//	go test -run=TestStateContentionRPS -v ./pkg/risk/
func TestStateContentionRPS(t *testing.T) {
	policy := DefaultPolicyConfig()
	const (
		workers          = 10
		callsPerAgentSet = 30_000
	)

	type result struct {
		agents  int
		nsPerOp float64
		rps     float64
	}

	agentCounts := []int{1, 100, 1000}
	results := make([]result, 0, len(agentCounts))

	for _, agentCount := range agentCounts {
		q := newBenchQuerier()
		start := make(chan struct{})
		var wg sync.WaitGroup
		itersPerWorker := callsPerAgentSet / workers

		startTime := time.Now()

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				agentID := fmt.Sprintf("acp:agent:org.example:Agent-%d", id%agentCount)
				req := EvalRequest{
					AgentID:       agentID,
					Capability:    "acp:cap:data.read",
					Resource:      "org.example/reports/Q1",
					ResourceClass: ResourcePublic,
					Policy:        policy,
				}
				<-start
				for i := 0; i < itersPerWorker; i++ {
					req.Now = time.Now()
					_, _ = Evaluate(req, q)
					q.AddRequest(agentID, req.Now)
				}
			}(w)
		}

		close(start)
		wg.Wait()

		elapsed := time.Since(startTime)
		totalCalls := workers * itersPerWorker
		nsPerOp := float64(elapsed.Nanoseconds()) / float64(totalCalls)
		rps := 1e9 / nsPerOp

		results = append(results, result{agentCount, nsPerOp, rps})
	}

	t.Logf("─────────────────────────────────────────────────────────────────────────")
	t.Logf("  %-12s  %14s  %14s  %s", "Agents", "ns/op (avg)", "req/s", "Bottleneck analysis")
	t.Logf("─────────────────────────────────────────────────────────────────────────")
	for i, r := range results {
		analysis := ""
		switch {
		case i == 0:
			analysis = "max per-key contention + growing state lists"
		case r.rps > results[i-1].rps*1.1:
			analysis = "state spread → shorter lists, less per-key lock"
		default:
			analysis = "mutex shared → lock contention persists"
		}
		t.Logf("  %-12d  %14.1f  %14.0f  %s", r.agents, r.nsPerOp, r.rps, analysis)
	}
	t.Logf("─────────────────────────────────────────────────────────────────────────")
	t.Logf("  Workers fixed at: %d", workers)
	t.Logf("  Execution contract: Evaluate() + AddRequest() per call")
	t.Logf("  Key result: shared mutex serializes access regardless of agent count")
	t.Logf("  Key result: 1-agent case also penalized by growing CountRequests scan")
	t.Logf("  Architectural note: production backends (Redis, Postgres) avoid both")
	t.Logf("─────────────────────────────────────────────────────────────────────────")
}

