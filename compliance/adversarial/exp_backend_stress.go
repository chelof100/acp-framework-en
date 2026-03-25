package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunBackendStress runs Experiment 3: State Backend Stress.
//
// Compares InMemoryQuerier (mutex-protected in-process slices) against
// RedisQuerier (network-backed sorted sets) under concurrent load.
//
// Workload: 500 agents × 20 requests = 10,000 total requests, all concurrent.
// Each agent runs its requests sequentially (required by execution contract).
//
// Expected outcome: InMemoryQuerier throughput is bounded by Go mutex contention
// on shared state; RedisQuerier throughput is bounded by network RTT. The
// comparison motivates LedgerQuerier as a replaceable abstraction.
//
// If Redis is unavailable, the Redis run is skipped with an informative message.
func RunBackendStress(cfg Config) {
	const (
		agentCount   = 500
		reqsPerAgent = 20
	)
	total := int64(agentCount * reqsPerAgent)
	policy := risk.DefaultPolicyConfig()

	fmt.Println("=== Experiment 3: State Backend Stress ===")
	fmt.Printf("Pattern  : %d agents × %d requests = %d total (concurrent agents, sequential per agent)\n\n",
		agentCount, reqsPerAgent, total)
	fmt.Printf("  %-20s  %-14s  %-15s\n", "Backend", "Duration", "Throughput")
	fmt.Printf("  %-20s  %-14s  %-15s\n", "-------", "--------", "----------")

	// Run 1: InMemoryQuerier
	{
		q := risk.NewInMemoryQuerier()
		dur, tp := runStress(q, agentCount, reqsPerAgent, policy)
		fmt.Printf("  %-20s  %-14v  %-15.0f\n", "InMemoryQuerier", dur.Round(time.Millisecond), tp)
	}

	// Run 2: RedisQuerier
	{
		rq, err := NewRedisQuerier(cfg.RedisAddr)
		if err != nil {
			fmt.Printf("  %-20s  SKIPPED (%v)\n", "RedisQuerier", err)
			fmt.Println("\nNote: start Redis with:  docker run -p 6379:6379 redis:7")
			fmt.Println("      or set --redis-addr to an Upstash endpoint.")
			return
		}
		defer rq.Close()
		rq.Flush() // clean slate before run
		dur, tp := runStress(rq, agentCount, reqsPerAgent, policy)
		fmt.Printf("  %-20s  %-14v  %-15.0f\n", "RedisQuerier", dur.Round(time.Millisecond), tp)
		fmt.Println("\nVerdict  : compare throughput delta — mutex contention (InMemory) vs network RTT (Redis).")
		fmt.Println("           LedgerQuerier abstraction enables production backends without engine changes.")
	}
}

// runStress executes the concurrent workload against q and returns (duration, throughput).
// Each agent runs its own goroutine; requests within an agent are sequential.
func runStress(q LedgerMutator, agentCount, reqsPerAgent int, policy risk.PolicyConfig) (time.Duration, float64) {
	total := int64(agentCount * reqsPerAgent)
	var wg sync.WaitGroup

	start := time.Now()
	wg.Add(agentCount)
	for i := 0; i < agentCount; i++ {
		go func(idx int) {
			defer wg.Done()
			agentID := fmt.Sprintf("stress-%04d", idx)
			for j := 0; j < reqsPerAgent; j++ {
				req := makeHighRiskReq(agentID, policy)
				runRequest(q, req, policy)
			}
		}(i)
	}
	wg.Wait()
	dur := time.Since(start)

	return dur, float64(total) / dur.Seconds()
}
