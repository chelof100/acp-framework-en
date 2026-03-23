// Command acp-risk-runner is the ACP-RISK-2.0 sequence compliance runner (ACR-1.0).
//
// It executes stateful, multi-step test cases against the ACP-RISK-2.0 engine
// in two modes:
//
//   - library: calls pkg/risk directly (default, no external dependencies)
//   - http:    posts requests to an external ACP server
//
// The runner implements the ACP-RISK-2.0 execution contract, validating that
// cooldown activation, F_anom rule accumulation, and threshold boundaries
// behave correctly across request sequences.
//
// Usage:
//
//	acp-risk-runner --mode library --dir testcases
//	acp-risk-runner --mode library --dir testcases --out report.json
//	acp-risk-runner --mode http --url http://localhost:8080/admission --dir testcases
package main

import (
	"fmt"
	"os"
)

const runnerVersion = "1.0"

func main() {
	cfg := parseFlags()

	// Build backend.
	var backend Backend
	switch cfg.Mode {
	case "library":
		backend = NewLibraryBackend()
	case "http":
		backend = NewHTTPBackend(cfg.URL)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q (valid: library|http)\n", cfg.Mode)
		os.Exit(1)
	}

	// Load test cases.
	cases, err := loadTestCases(cfg.Dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	if len(cases) == 0 {
		fmt.Fprintf(os.Stderr, "no test cases found in %q\n", cfg.Dir)
		os.Exit(1)
	}

	fmt.Printf("ACP Compliance Runner %s — mode=%s — %d test case(s)\n\n",
		runnerVersion, cfg.Mode, len(cases))

	// Execute all test cases.
	results := make([]TestCaseResult, 0, len(cases))
	for _, tc := range cases {
		r := runTestCase(tc, backend)
		results = append(results, r)
	}

	// Build and print human-readable summary.
	report := buildReport(cfg.Mode, results)
	printSummary(report)

	// Write JSON report.
	if cfg.Out != "" {
		if err := writeReport(report, cfg.Out); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Report written to %s\n", cfg.Out)
	}

	// Exit code: 0 = all pass, 1 = any failure (when --strict=true).
	if report.Status == "NON_CONFORMANT" && cfg.Strict {
		os.Exit(1)
	}
}
