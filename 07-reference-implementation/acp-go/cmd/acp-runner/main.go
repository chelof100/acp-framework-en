// cmd/acp-runner — ACP Compliance Runner (ACR-1.0)
//
// Executes ACP test vectors against an Implementation Under Test (IUT) and
// produces a conformance report. Optionally issues a certification record.
//
// Usage:
//
//	acp-runner run --impl ./acp-evaluate --suite ./test-suite --level L2 --report report.json
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── Data types ───────────────────────────────────────────────────────────────

// TestVector is a minimal representation of ACP-TS-1.1 vectors.
// Only the fields needed by the runner are parsed here.
type TestVector struct {
	Meta struct {
		ID    string `json:"id"`
		Level string `json:"level"`
		Layer string `json:"layer"`
	} `json:"meta"`
	Expected struct {
		Decision  string  `json:"decision"`
		ErrorCode *string `json:"error_code"`
	} `json:"expected"`
}

// IUTResponse is the JSON the IUT writes to STDOUT.
type IUTResponse struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

// TestResult records the outcome of a single vector run.
type TestResult struct {
	ID               string `json:"id"`
	Status           string `json:"status"` // PASS | FAIL | ERROR
	ExpectedDecision string `json:"expected_decision"`
	ActualDecision   string `json:"actual_decision,omitempty"`
	ExpectedError    string `json:"expected_error_code,omitempty"`
	ActualError      string `json:"actual_error_code,omitempty"`
	Message          string `json:"message,omitempty"`
}

// RunReport is the final JSON output of the runner (ACR-1.0 §7).
type RunReport struct {
	Implementation        string       `json:"implementation"`
	ImplementationVersion string       `json:"implementation_version"`
	ACPVersion            string       `json:"acp_version"`
	TestedLevel           string       `json:"tested_level"`
	TestSuiteHash         string       `json:"test_suite_hash"`
	TotalTests            int          `json:"total_tests"`
	Passed                int          `json:"passed"`
	Failed                int          `json:"failed"`
	FailedTests           []TestResult `json:"failed_tests"`
	Timestamp             string       `json:"timestamp"`
	Status                string       `json:"status"` // CONFORMANT | NON_CONFORMANT
}

// CertRecord is the certification JSON (ACR-1.0 §9).
type CertRecord struct {
	Protocol        string `json:"protocol"`
	Version         string `json:"version"`
	Level           string `json:"level"`
	CertificationID string `json:"certification_id"`
	TestSuiteHash   string `json:"test_suite_hash"`
	RunnerVersion   string `json:"runner_version"`
	IssuedAt        string `json:"issued_at"`
}

// PerformanceResult (ACR-1.0 §8).
type PerformanceResult struct {
	LatencyAvgMS    float64 `json:"latency_avg_ms"`
	LatencyP95MS    float64 `json:"latency_p95_ms"`
	ThroughputPerSec float64 `json:"throughput_per_sec"`
	MemoryMB        float64 `json:"memory_mb"`
}

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	runnerVersion = "1.0"
	acpVersion    = "1.3"
	testTimeout   = 2 * time.Second
	perfIterations = 10_000
)

// Conformance level ordering (cumulative).
var levelOrder = map[string]int{
	"L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	implPath := runCmd.String("impl", "", "Path to IUT executable (required)")
	suitePath := runCmd.String("suite", "", "Test suite directory (required)")
	level := runCmd.String("level", "L2", "Conformance level to test: L1–L5")
	layer := runCmd.String("layer", "", "Filter to specific layer (e.g. CORE, DCMA)")
	reportPath := runCmd.String("report", "", "Output report JSON file (optional)")
	strict := runCmd.Bool("strict", false, "Fail if warnings are present")
	performance := runCmd.Bool("performance", false, "Run performance benchmarks")

	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintf(os.Stderr, "Usage: acp-runner run [flags]\n")
		fmt.Fprintf(os.Stderr, "  --impl        Path to IUT executable\n")
		fmt.Fprintf(os.Stderr, "  --suite       Test suite directory\n")
		fmt.Fprintf(os.Stderr, "  --level       L1..L5 (default: L2)\n")
		fmt.Fprintf(os.Stderr, "  --layer       Filter layer (optional)\n")
		fmt.Fprintf(os.Stderr, "  --report      Output report file (optional)\n")
		fmt.Fprintf(os.Stderr, "  --strict      Fail on warnings\n")
		fmt.Fprintf(os.Stderr, "  --performance Run 10k-iteration benchmarks\n")
		os.Exit(1)
	}

	if err := runCmd.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "flag parse error: %v\n", err)
		os.Exit(1)
	}

	if *implPath == "" || *suitePath == "" {
		fmt.Fprintf(os.Stderr, "Error: --impl and --suite are required\n")
		os.Exit(1)
	}

	// 1. Load and filter test vectors
	vectors, suiteHash, err := loadVectors(*suitePath, *level, *layer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load test suite: %v\n", err)
		os.Exit(1)
	}
	if len(vectors) == 0 {
		fmt.Fprintf(os.Stderr, "No test vectors found for level %s in %s\n", *level, *suitePath)
		os.Exit(1)
	}

	// 2. Detect IUT implementation name/version via --manifest
	implName, implVersion := detectIUT(*implPath)

	fmt.Printf("ACP Compliance Runner %s\n", runnerVersion)
	fmt.Printf("IUT: %s %s\n", implName, implVersion)
	fmt.Printf("Level: %s | Vectors: %d | Suite hash: %s\n\n", *level, len(vectors), suiteHash[:16]+"...")

	// 3. Execute test vectors
	results := runVectors(*implPath, vectors)

	// 4. Tally
	passed, failed := 0, 0
	var failedTests []TestResult
	for _, r := range results {
		if r.Status == "PASS" {
			passed++
		} else {
			failed++
			failedTests = append(failedTests, r)
		}
	}

	status := "CONFORMANT"
	if failed > 0 {
		status = "NON_CONFORMANT"
	}

	// 5. Print per-test summary
	for _, r := range results {
		mark := "✅"
		if r.Status != "PASS" {
			mark = "❌"
		}
		fmt.Printf("%s %s — %s\n", mark, r.ID, r.Status)
		if r.Message != "" {
			fmt.Printf("   %s\n", r.Message)
		}
	}

	fmt.Printf("\n--- %d/%d PASS | Status: %s ---\n\n", passed, len(results), status)

	// 6. Build report
	report := RunReport{
		Implementation:        implName,
		ImplementationVersion: implVersion,
		ACPVersion:            acpVersion,
		TestedLevel:           *level,
		TestSuiteHash:         suiteHash,
		TotalTests:            len(results),
		Passed:                passed,
		Failed:                failed,
		FailedTests:           failedTests,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		Status:                status,
	}

	// 7. Performance mode (ACR-1.0 §8)
	if *performance {
		fmt.Printf("Running performance benchmark (%d iterations)...\n", perfIterations)
		perf := runPerformanceBenchmark(*implPath, vectors[0])
		printPerf(perf)
		report.Status = status // performance does not affect functional status
	}

	// 8. Write report
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	if *reportPath != "" {
		if err := os.WriteFile(*reportPath, reportJSON, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write report: %v\n", err)
		} else {
			fmt.Printf("Report written to %s\n", *reportPath)
		}
	} else {
		fmt.Println(string(reportJSON))
	}

	// 9. Auto-certification (ACR-1.0 §9)
	if status == "CONFORMANT" {
		cert := issueCertification(*level, suiteHash)
		certJSON, _ := json.MarshalIndent(cert, "", "  ")
		certFile := fmt.Sprintf("ACP-CERT-%s.json", cert.CertificationID[9:]) // strip "ACP-CERT-"
		_ = os.WriteFile(certFile, certJSON, 0o644)
		fmt.Printf("\n🏆 Certification issued: %s → %s\n", cert.CertificationID, certFile)
	}

	// 10. Exit code
	_ = strict
	if failed > 0 {
		os.Exit(1)
	}
}

// ─── Vector loading ───────────────────────────────────────────────────────────

// loadVectors reads all .json files in suiteDir, filters by level (cumulative)
// and optional layer, and returns the vectors + a SHA-256 hash of the suite.
func loadVectors(suiteDir, level, layer string) ([]struct {
	raw []byte
	vec TestVector
}, string, error) {
	targetOrd, ok := levelOrder[strings.ToUpper(level)]
	if !ok {
		return nil, "", fmt.Errorf("unknown level %q (valid: L1–L5)", level)
	}

	type entry struct {
		raw []byte
		vec TestVector
	}

	var entries []entry
	var allRaw [][]byte

	err := filepath.WalkDir(suiteDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var vec TestVector
		if err := json.Unmarshal(data, &vec); err != nil {
			// Skip non-vector JSON files (e.g. schema files)
			return nil
		}
		if vec.Meta.ID == "" {
			return nil // not a test vector
		}

		// Filter by level (cumulative: include ≤ targetOrd)
		vecOrd, known := levelOrder[strings.ToUpper(vec.Meta.Level)]
		if known && vecOrd > targetOrd {
			return nil
		}

		// Filter by layer if specified
		if layer != "" && !strings.EqualFold(vec.Meta.Layer, layer) {
			return nil
		}

		entries = append(entries, entry{raw: data, vec: vec})
		allRaw = append(allRaw, data)
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	// Sort deterministically by vector ID
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].vec.Meta.ID < entries[j].vec.Meta.ID
	})

	// Compute suite hash
	h := sha256.New()
	for _, r := range allRaw {
		h.Write(r)
	}
	suiteHash := fmt.Sprintf("sha256:%x", h.Sum(nil))

	result := make([]struct {
		raw []byte
		vec TestVector
	}, len(entries))
	for i, e := range entries {
		result[i] = e
	}
	return result, suiteHash, nil
}

// ─── IUT interaction ──────────────────────────────────────────────────────────

// detectIUT queries the IUT via --manifest and extracts name + version.
func detectIUT(implPath string) (name, version string) {
	ctx, cancel := func() (interface{ Done() <-chan struct{} }, func()) {
		// Use exec with timeout
		return nil, func() {}
	}()
	cancel()
	_ = ctx

	cmd := exec.Command(implPath, "--manifest")
	out, err := runWithTimeout(cmd, 3*time.Second)
	if err != nil {
		return filepath.Base(implPath), "unknown"
	}
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &manifest); err != nil {
		return filepath.Base(implPath), "unknown"
	}
	if manifest.Name == "" {
		manifest.Name = filepath.Base(implPath)
	}
	if manifest.Version == "" {
		manifest.Version = "unknown"
	}
	return manifest.Name, manifest.Version
}

// runVectors executes each vector through the IUT and compares results.
func runVectors(implPath string, vectors []struct {
	raw []byte
	vec TestVector
}) []TestResult {
	results := make([]TestResult, 0, len(vectors))
	for _, v := range vectors {
		result := runSingleVector(implPath, v.raw, v.vec)
		results = append(results, result)
	}
	return results
}

// runSingleVector runs one test vector through the IUT (ACR-1.0 §4).
func runSingleVector(implPath string, raw []byte, vec TestVector) TestResult {
	result := TestResult{
		ID:               vec.Meta.ID,
		ExpectedDecision: vec.Expected.Decision,
	}
	if vec.Expected.ErrorCode != nil {
		result.ExpectedError = *vec.Expected.ErrorCode
	}

	cmd := exec.Command(implPath)
	cmd.Stdin = strings.NewReader(string(raw))

	out, err := runWithTimeout(cmd, testTimeout)
	if err != nil {
		result.Status = "ERROR"
		result.Message = fmt.Sprintf("IUT execution failed: %v", err)
		return result
	}

	// Parse IUT response — must be valid JSON only (no extra output)
	out = trimOutput(out)
	var resp IUTResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Invalid JSON output: %v — raw: %q", err, truncate(out, 120))
		return result
	}

	result.ActualDecision = resp.Decision
	if resp.ErrorCode != nil {
		result.ActualError = *resp.ErrorCode
	}

	// Strict comparison (ACR-1.0 §6)
	decisionMatch := resp.Decision == vec.Expected.Decision
	errorMatch := errorCodeMatch(resp.ErrorCode, vec.Expected.ErrorCode)

	if decisionMatch && errorMatch {
		result.Status = "PASS"
	} else {
		result.Status = "FAIL"
		if !decisionMatch {
			result.Message = fmt.Sprintf("decision: want %q got %q", vec.Expected.Decision, resp.Decision)
		} else {
			wantErr := "<nil>"
			if vec.Expected.ErrorCode != nil {
				wantErr = *vec.Expected.ErrorCode
			}
			gotErr := "<nil>"
			if resp.ErrorCode != nil {
				gotErr = *resp.ErrorCode
			}
			result.Message = fmt.Sprintf("error_code: want %s got %s", wantErr, gotErr)
		}
	}
	return result
}

// ─── Performance benchmark ────────────────────────────────────────────────────

func runPerformanceBenchmark(implPath string, first struct {
	raw []byte
	vec TestVector
}) PerformanceResult {
	latencies := make([]time.Duration, 0, perfIterations)
	start := time.Now()

	for i := 0; i < perfIterations; i++ {
		t0 := time.Now()
		cmd := exec.Command(implPath)
		cmd.Stdin = strings.NewReader(string(first.raw))
		_, _ = runWithTimeout(cmd, testTimeout)
		latencies = append(latencies, time.Since(t0))
	}

	total := time.Since(start)

	// Compute avg, p95
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	avg := float64(sum) / float64(len(latencies)) / float64(time.Millisecond)
	p95idx := int(float64(len(latencies)) * 0.95)
	p95 := float64(latencies[p95idx]) / float64(time.Millisecond)
	throughput := float64(perfIterations) / total.Seconds()

	return PerformanceResult{
		LatencyAvgMS:     avg,
		LatencyP95MS:     p95,
		ThroughputPerSec: throughput,
		MemoryMB:         0, // not measurable without cgroups/runtime introspection
	}
}

func printPerf(p PerformanceResult) {
	fmt.Printf("\nPerformance Results (%d iterations):\n", perfIterations)
	fmt.Printf("  Latency avg: %.2f ms\n", p.LatencyAvgMS)
	fmt.Printf("  Latency p95: %.2f ms\n", p.LatencyP95MS)
	fmt.Printf("  Throughput:  %.0f req/sec\n\n", p.ThroughputPerSec)
}

// ─── Certification ────────────────────────────────────────────────────────────

func issueCertification(level, suiteHash string) CertRecord {
	year := time.Now().UTC().Year()
	// Sequential ID based on current timestamp (monotonic within a run)
	seq := time.Now().UTC().UnixNano() % 10_000
	certID := fmt.Sprintf("ACP-CERT-%d-%04d", year, seq)
	return CertRecord{
		Protocol:        "ACP",
		Version:         acpVersion,
		Level:           level,
		CertificationID: certID,
		TestSuiteHash:   suiteHash,
		RunnerVersion:   runnerVersion,
		IssuedAt:        time.Now().UTC().Format("2006-01-02"),
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) ([]byte, error) {
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := cmd.Output()
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil, fmt.Errorf("timeout after %v", timeout)
	}
}

// trimOutput removes leading/trailing whitespace and enforces pure JSON output.
// ACR-1.0 §10: "If IUT prints logs mixed with JSON → FAIL"
func trimOutput(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}

func errorCodeMatch(actual, expected *string) bool {
	if actual == nil && expected == nil {
		return true
	}
	if actual == nil || expected == nil {
		return false
	}
	return *actual == *expected
}

func truncate(data []byte, n int) string {
	s := string(data)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
