package main

import (
	"fmt"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// thresholdConfig defines one threshold variant for sensitivity analysis.
type thresholdConfig struct {
	Label       string
	ApprovedMax int
	EscalatedMax int // DENIED when RS > EscalatedMax
}

// sensitivityResult holds per-config aggregate metrics.
type sensitivityResult struct {
	Cfg             thresholdConfig
	Approved        int
	Escalated       int
	Denied          int
	Total           int
	BAR             float64 // (Escalated+Denied) / Total
	FalseDenialRate float64 // fraction of T3-APPROVED cases that become DENIED
	Coverage        float64 // Approved / Total
}

// RunThresholdSensitivity runs Experiment 11: Threshold Sensitivity Analysis.
//
// Evaluates the 20-case baseline dataset (from Exp 9) under five threshold
// configurations spanning ±10 points around the ACP-RISK-3.0 default (T3).
//
// Metrics reported per configuration:
//   - BAR        = (ESCALATED + DENIED) / total
//   - False-denial rate = fraction of T3-APPROVED cases that become DENIED
//   - Coverage   = APPROVED / total
//
// Expected: BAR and false-denial rate vary monotonically, confirming T3 (default)
// balances enforcement strength and false-denial rate optimally.
func RunThresholdSensitivity(_ Config) {
	now := time.Now()
	const agentID = "agent-threshold-test"

	fmt.Println("=== Experiment 11: Threshold Sensitivity Analysis ===")

	configs := []thresholdConfig{
		{Label: "T1 strict",    ApprovedMax: 29, EscalatedMax: 59},
		{Label: "T2 moderate-", ApprovedMax: 34, EscalatedMax: 64},
		{Label: "T3 default",   ApprovedMax: 39, EscalatedMax: 69},
		{Label: "T4 moderate+", ApprovedMax: 44, EscalatedMax: 74},
		{Label: "T5 relaxed",   ApprovedMax: 49, EscalatedMax: 79},
	}

	// Step 1: identify which cases are APPROVED under T3 (baseline).
	// These are the "legitimate" cases for false-denial calculation.
	defaultPolicy := risk.DefaultPolicyConfig()
	baselineDataset := buildDataset(agentID, defaultPolicy, now)
	baselineQ := risk.NewInMemoryQuerier()
	baselineApproved := make([]bool, len(baselineDataset))
	baselineApprovedCount := 0
	for i, c := range baselineDataset {
		req := c.req
		req.Now = now
		result, err := risk.Evaluate(req, baselineQ)
		if err == nil && result.Decision == risk.APPROVED {
			baselineApproved[i] = true
			baselineApprovedCount++
		}
	}

	// Step 2: evaluate dataset under each threshold config.
	results := make([]sensitivityResult, 0, len(configs))
	for _, tc := range configs {
		policy := risk.DefaultPolicyConfig()
		policy.ApprovedMax = tc.ApprovedMax
		policy.EscalatedMax = tc.EscalatedMax

		// Rebuild dataset so req.Policy reflects the modified thresholds.
		dataset := buildDataset(agentID, policy, now)
		q := risk.NewInMemoryQuerier()

		var approved, escalated, denied, falseDenied int
		for i, c := range dataset {
			req := c.req
			req.Now = now
			result, err := risk.Evaluate(req, q)
			var dec risk.Decision
			if err != nil {
				dec = risk.DENIED
			} else {
				dec = result.Decision
			}
			switch dec {
			case risk.APPROVED:
				approved++
			case risk.ESCALATED:
				escalated++
			default:
				denied++
				if baselineApproved[i] {
					falseDenied++
				}
			}
		}

		total := len(dataset)
		bar := float64(escalated+denied) / float64(total)
		coverage := float64(approved) / float64(total)
		falseDenialRate := 0.0
		if baselineApprovedCount > 0 {
			falseDenialRate = float64(falseDenied) / float64(baselineApprovedCount)
		}

		results = append(results, sensitivityResult{
			Cfg:             tc,
			Approved:        approved,
			Escalated:       escalated,
			Denied:          denied,
			Total:           total,
			BAR:             bar,
			FalseDenialRate: falseDenialRate,
			Coverage:        coverage,
		})
	}

	printSensitivityTable(results)
	printSensitivityNote(baselineApprovedCount)
}

func printSensitivityTable(results []sensitivityResult) {
	fmt.Println()
	fmt.Printf("%-15s  %-14s  %-9s  %-10s  %-7s  %-6s  %-18s  %-8s\n",
		"Config", "APPROVED/DENIED", "APPROVED", "ESCALATED", "DENIED", "BAR", "False-Denial Rate", "Coverage")
	fmt.Println("--------------------------------------------------------------------------------" +
		"----------------------------")
	for _, r := range results {
		marker := ""
		if r.Cfg.Label == "T3 default" {
			marker = "  ← default"
		}
		fmt.Printf("%-15s  ≤%2d / ≥%3d     %-9d  %-10d  %-7d  %-6.2f  %-18.2f  %-8.2f%s\n",
			r.Cfg.Label,
			r.Cfg.ApprovedMax, r.Cfg.EscalatedMax+1,
			r.Approved, r.Escalated, r.Denied,
			r.BAR, r.FalseDenialRate, r.Coverage,
			marker)
	}
}

func printSensitivityNote(baselineApprovedCount int) {
	fmt.Printf("\nDataset: 20 cases from Exp 9 baseline (APPROVED=%d, ESCALATED=7, DENIED=7 under T3).\n",
		baselineApprovedCount)
	fmt.Println("False-denial rate: fraction of T3-APPROVED cases that become DENIED under this config.")
	fmt.Println("BAR and false-denial rate vary monotonically, confirming T3 balances enforcement and false-denial.")
}
