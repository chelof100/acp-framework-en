package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// runTestCase executes all steps of a TestCase against the backend.
// The backend is Reset before the first step.
func runTestCase(tc TestCase, backend Backend) TestCaseResult {
	backend.Reset()

	result := TestCaseResult{ID: tc.ID}
	allPass := true

	for i, step := range tc.Steps {
		resp, err := backend.Evaluate(step.RunnerRequest)
		sr := StepResult{
			Index:    i + 1,
			Expected: step.Expected,
			Got:      resp,
		}
		if err != nil {
			sr.Status = "ERROR"
			sr.Message = err.Error()
			allPass = false
		} else {
			sr.Status, sr.Message = validateStep(step.Expected, resp)
			if sr.Status != "PASS" {
				allPass = false
			}
		}
		result.Steps = append(result.Steps, sr)
	}

	if allPass {
		result.Status = "PASS"
	} else {
		result.Status = "FAIL"
	}
	return result
}

// validateStep compares the expected outcome with the actual response.
func validateStep(expected Expected, got ACPResponse) (status, message string) {
	if expected.Decision != got.Decision {
		return "FAIL", fmt.Sprintf("decision: want %q got %q", expected.Decision, got.Decision)
	}
	if expected.RiskScore != nil && *expected.RiskScore != got.RiskScore {
		return "FAIL", fmt.Sprintf("risk_score: want %d got %d", *expected.RiskScore, got.RiskScore)
	}
	if expected.DeniedReason != "" && expected.DeniedReason != got.DeniedReason {
		return "FAIL", fmt.Sprintf("denied_reason: want %q got %q", expected.DeniedReason, got.DeniedReason)
	}
	return "PASS", ""
}

// buildReport assembles the final Report from all test case results.
func buildReport(mode string, results []TestCaseResult) Report {
	passed, failed := 0, 0
	for _, r := range results {
		if r.Status == "PASS" {
			passed++
		} else {
			failed++
		}
	}
	status := "CONFORMANT"
	if failed > 0 {
		status = "NON_CONFORMANT"
	}
	return Report{
		Mode:      mode,
		Total:     len(results),
		Passed:    passed,
		Failed:    failed,
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TestCases: results,
	}
}

// printSummary prints a human-readable summary to stdout.
func printSummary(report Report) {
	for _, tc := range report.TestCases {
		mark := "PASS"
		if tc.Status != "PASS" {
			mark = "FAIL"
		}
		fmt.Printf("[%s] %s\n", mark, tc.ID)
		for _, sr := range tc.Steps {
			stepMark := "  ok"
			if sr.Status != "PASS" {
				stepMark = "  !!"
			}
			fmt.Printf("%s  step %d: want=%s got=%s RS=%d",
				stepMark, sr.Index, sr.Expected.Decision, sr.Got.Decision, sr.Got.RiskScore)
			if sr.Got.DeniedReason != "" {
				fmt.Printf(" reason=%s", sr.Got.DeniedReason)
			}
			if sr.Message != "" {
				fmt.Printf(" — %s", sr.Message)
			}
			fmt.Println()
		}
	}
	fmt.Printf("\n%d/%d PASS | %s\n", report.Passed, report.Total, report.Status)
}

// writeReport writes the report as JSON to outPath, or to stdout if outPath is empty.
func writeReport(report Report, outPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if outPath == "" {
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(outPath, data, 0o644)
}
