// Package main provides adversarial evaluation experiments for ACP-RISK-2.0.
//
// Usage:
//
//	go run . [--exp=N] [--redis-addr=host:port]
//
// Experiments:
//
//	1: Cooldown Evasion Attack (1 agent, alternating pattern)
//	2: Distributed Multi-Agent Attack (100/500/1000 agents)
//	3: State Backend Stress (InMemoryQuerier vs RedisQuerier)
//	0: All experiments (default)
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	exp := flag.Int("exp", 0, "experiment: 0=all, 1=cooldown-evasion, 2=multi-agent, 3=backend-stress")
	redisAddr := flag.String("redis-addr", "localhost:6379", "Redis address for experiment 3")
	flag.Parse()

	cfg := Config{RedisAddr: *redisAddr}

	switch *exp {
	case 0:
		RunCooldownEvasion(cfg)
		fmt.Println()
		RunMultiAgent(cfg)
		fmt.Println()
		RunBackendStress(cfg)
	case 1:
		RunCooldownEvasion(cfg)
	case 2:
		RunMultiAgent(cfg)
	case 3:
		RunBackendStress(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown experiment: %d\n", *exp)
		os.Exit(1)
	}
}
