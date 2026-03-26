package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunBackendStress runs Experiment 3: State Backend Stress.
//
// Compares three backend implementations under concurrent load:
//   Run 1 — InMemoryQuerier: in-process mutex over slices (~1 RTT equivalent)
//   Run 2 — RedisQuerier: 1 Redis command per operation (~7–8 RTTs/request)
//   Run 3 — RedisPipelinedQuerier: 2 RTTs/request (read pipeline + write pipeline)
//
// Workload: 500 agents × 20 requests = 10,000 total, all concurrent.
// Each agent runs its requests sequentially (required by execution contract).
//
// Expected: InMemory bounded by mutex contention; Redis bounded by RTT;
// pipelined Redis demonstrates ~3–4× throughput gain over single-command Redis.
//
// If Redis is unavailable, Runs 2 and 3 are skipped with an informative message.
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
	fmt.Printf("  %-28s  %-6s  %-14s  %-15s\n", "Backend", "RTTs", "Duration", "Throughput")
	fmt.Printf("  %-28s  %-6s  %-14s  %-15s\n", "-------", "----", "--------", "----------")

	// Run 1: InMemoryQuerier
	{
		q := risk.NewInMemoryQuerier()
		dur, tp := runStress(q, agentCount, reqsPerAgent, policy)
		fmt.Printf("  %-28s  %-6s  %-14v  %-15.0f\n", "InMemoryQuerier", "~1", dur.Round(time.Millisecond), tp)
	}

	// Runs 2 & 3 require Redis.
	rq, err := NewRedisQuerier(cfg.RedisAddr)
	if err != nil {
		fmt.Printf("  %-28s  SKIPPED (%v)\n", "RedisQuerier (unpipelined)", err)
		fmt.Printf("  %-28s  SKIPPED\n", "RedisPipelinedQuerier")
		fmt.Println("\nNote: start Redis with:  docker run -p 6379:6379 redis:7")
		fmt.Println("      or set --redis-addr to an Upstash endpoint.")
		return
	}
	defer rq.Close()

	// Run 2: RedisQuerier (unpipelined — 1 command per operation)
	{
		rq.Flush()
		dur, tp := runStress(rq, agentCount, reqsPerAgent, policy)
		fmt.Printf("  %-28s  %-6s  %-14v  %-15.0f\n", "RedisQuerier (unpipelined)", "~7–8", dur.Round(time.Millisecond), tp)
	}

	// Run 3: RedisPipelinedQuerier (2 RTTs per request)
	{
		rpq, err := NewRedisPipelinedQuerier(cfg.RedisAddr)
		if err != nil {
			fmt.Printf("  %-28s  SKIPPED (%v)\n", "RedisPipelinedQuerier", err)
			return
		}
		defer rpq.Close()
		rpq.Flush()
		dur, tp := runStressPipelined(rpq, agentCount, reqsPerAgent, policy)
		fmt.Printf("  %-28s  %-6s  %-14v  %-15.0f\n", "RedisPipelinedQuerier", "2", dur.Round(time.Millisecond), tp)
	}

	fmt.Println()
	fmt.Println("Verdict  : InMemory bounded by mutex contention; Redis bounded by network RTT.")
	fmt.Println("           Pipelining collapses ~7–8 RTTs to 2 (read pipeline + write pipeline).")
	fmt.Println("           LedgerQuerier abstraction enables backend optimization without engine changes.")
}

// runStressPipelined executes the concurrent workload against a RedisPipelinedQuerier.
// Uses RedisPipelinedQuerier.RunRequest instead of the shared runRequest helper.
func runStressPipelined(q *RedisPipelinedQuerier, agentCount, reqsPerAgent int, policy risk.PolicyConfig) (time.Duration, float64) {
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
				q.RunRequest(req, policy)
			}
		}(i)
	}
	wg.Wait()
	dur := time.Since(start)

	return dur, float64(total) / dur.Seconds()
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
