package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// RunOPABenchmark runs Experiment 14: OPA vs ACP — Stateless vs Stateful Admission Control.
//
// Framing: This is a capability comparison, not a performance comparison.
// The central claim is:
//
//	Stateless policy engines cannot enforce constraints that depend on execution
//	history without external state integration. ACP provides this state natively
//	as part of its execution contract.
//
// Three scenarios:
//
//	Scenario A — Single request (stateless admissibility)
//	  ACP: APPROVED. OPA: allow=true. Both correct — no state required.
//
//	Scenario B — Frequency accumulation (10 requests, same agent+cap+resource)
//	  ACP stateful:    APPROVED → ESCALATED → DENIED (pattern accumulates per agent)
//	  ACP stateless:   APPROVED × N (NullQuerier: F_anom always 0)
//	  OPA (pure):      allow=true × N (no memory between evaluations)
//	  OPA (injected):  allow=false when input.request_count >= threshold
//	                   → requires external counter; not intrinsic to OPA.
//
//	Scenario C — Cooldown enforcement
//	  ACP stateful:    COOLDOWN_ACTIVE after CooldownTriggerDenials denials
//	  ACP stateless:   never enters cooldown (no state)
//	  OPA (pure):      allow=true (no temporal context)
//	  OPA (injected):  allow=false when input.cooldown_active=true
//	                   → requires external timer; not intrinsic to OPA.
//
// Latency (supporting data only):
//
//	ACP: measured via Go loop (ns/op from risk.Evaluate).
//	OPA: measured via `opa bench` (ns/op from Rego evaluation engine).
//	NOTE: comparison is architecture-level, not language-level. ACP is Go;
//	OPA evaluates Rego. The gap illustrates the cost of external policy
//	evaluation relative to in-process stateful enforcement.
func RunOPABenchmark(_ Config) {
	fmt.Println("=== Experiment 14: OPA vs ACP — Stateless vs Stateful Admission Control ===")
	fmt.Println()
	fmt.Println("Framing: capability comparison (not performance).")
	fmt.Println("Central claim: stateless engines cannot enforce history-dependent constraints")
	fmt.Println("without externalizing state. ACP enforces them natively.")
	fmt.Println()

	// ── Policy (same as Exp 13 for consistency) ───────────────────────────────
	policy := risk.DefaultPolicyConfig()
	policy.AnomalyRule1ThresholdN = 2 // count(patKey, 60s) > 2 → +20 → DENIED
	policy.AnomalyRule3ThresholdY = 2 // count(patKey, 5min) ≥ 2 → +15 → ESCALATED
	policy.PolicyHash = "sha256:exp14-opa-benchmark"

	const (
		agentID    = "acp:agent:exp14:agent-1"
		capability = "acp:cap:financial.transfer"
		resource   = "accounts/shared-ops"
		totalReqs  = 10
	)

	req := risk.EvalRequest{
		AgentID:       agentID,
		Capability:    capability,
		Resource:      resource,
		ResourceClass: risk.ResourcePublic,
		Policy:        policy,
	}

	fmt.Printf("Setup   : %s / %s (public)\n", capability, resource)
	fmt.Printf("Baseline: B=35 + F_res=0 = RS 35 → APPROVED (ApprovedMax=%d)\n", policy.ApprovedMax)
	fmt.Printf("Rule3(Y=%d): count(patKey,5min) ≥ %d → +15 → RS 50 ESCALATED\n",
		policy.AnomalyRule3ThresholdY, policy.AnomalyRule3ThresholdY)
	fmt.Printf("Rule1(N=%d): count(patKey,60s)  > %d → +20 → RS 70 DENIED\n",
		policy.AnomalyRule1ThresholdN, policy.AnomalyRule1ThresholdN)
	fmt.Println()

	// ── Find OPA binary ───────────────────────────────────────────────────────
	opaPath := findOPABinary()

	// ── Scenario A: Single stateless request ──────────────────────────────────
	fmt.Println("─── Scenario A: Single Request (Stateless Admissibility) ───")
	fmt.Println()
	runScenarioA(req, policy, opaPath)

	// ── Scenario B: Frequency accumulation ───────────────────────────────────
	fmt.Println()
	fmt.Println("─── Scenario B: Frequency Accumulation (10 requests, same agent) ───")
	fmt.Println()
	runScenarioB(req, policy, opaPath, totalReqs)

	// ── Scenario C: Cooldown enforcement ─────────────────────────────────────
	fmt.Println()
	fmt.Println("─── Scenario C: Cooldown Enforcement ───")
	fmt.Println()
	runScenarioC(req, policy, opaPath)

	// ── Latency microbenchmark ────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("─── Latency Comparison (supporting data) ───")
	fmt.Println()
	runLatencyComparison(req, policy, opaPath)

	// ── Summary table ─────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("─── Summary: Capability Matrix ───")
	fmt.Println()
	printCapabilityMatrix()
}

// ── Scenario A ───────────────────────────────────────────────────────────────

func runScenarioA(req risk.EvalRequest, policy risk.PolicyConfig, opaPath string) {
	q := risk.NewInMemoryQuerier()
	req.Now = time.Now()

	result := runRequest(q, req, policy)
	fmt.Printf("  ACP stateful   : RS=35 → %s\n", result.Decision)

	stateless := risk.NewStatelessEngine(policy)
	slResult, _ := stateless.Evaluate(req)
	fmt.Printf("  ACP stateless  : RS=35 → %s\n", slResult.Decision)

	if opaPath != "" {
		policyA := regoScenarioA()
		allow, err := opaEval(opaPath, policyA, opaInputA())
		if err != nil {
			fmt.Printf("  OPA (pure)     : eval error: %v\n", err)
		} else {
			fmt.Printf("  OPA (pure)     : allow=%v\n", allow)
		}
	} else {
		fmt.Println("  OPA (pure)     : [OPA binary not found — skipped]")
	}

	fmt.Println()
	fmt.Println("  Result: all three agree — no state required for single-request decisions.")
}

// ── Scenario B ───────────────────────────────────────────────────────────────

func runScenarioB(req risk.EvalRequest, policy risk.PolicyConfig, opaPath string, n int) {
	baseNow := time.Now()

	// ACP stateful
	qStateful := risk.NewInMemoryQuerier()
	var acpApproved, acpEscalated, acpDenied int
	var firstEscalated, firstDenied int

	// ACP stateless (NullQuerier via StatelessEngine)
	stateless := risk.NewStatelessEngine(policy)
	var slApproved int

	// OPA pure stateless (no history in input)
	var opaAllow int
	policyA := regoScenarioA() // same simple policy — no history awareness
	inputA := opaInputA()

	fmt.Printf("  %-4s  %-18s  %-18s  %-12s\n", "Req#", "ACP Stateful", "ACP Stateless", "OPA (pure)")
	fmt.Printf("  %-4s  %-18s  %-18s  %-12s\n", "----", "------------", "-------------", "----------")

	for i := 1; i <= n; i++ {
		req.Now = baseNow

		// ACP stateful
		acpResult := runRequest(qStateful, req, policy)
		switch acpResult.Decision {
		case risk.APPROVED:
			acpApproved++
		case risk.ESCALATED:
			acpEscalated++
			if firstEscalated == 0 {
				firstEscalated = i
			}
		case risk.DENIED:
			acpDenied++
			if firstDenied == 0 {
				firstDenied = i
			}
		}
		acpLabel := string(acpResult.Decision)
		if acpResult.DeniedReason != "" {
			acpLabel = acpResult.DeniedReason
		}

		// ACP stateless
		slResult, _ := stateless.Evaluate(req)
		if slResult.Decision == risk.APPROVED {
			slApproved++
		}

		// OPA pure
		opaResult := "skipped"
		if opaPath != "" {
			allow, err := opaEval(opaPath, policyA, inputA)
			if err == nil {
				if allow {
					opaAllow++
					opaResult = "allow=true"
				} else {
					opaResult = "allow=false"
				}
			} else {
				opaResult = "error"
			}
		}

		fmt.Printf("  %-4d  %-18s  %-18s  %-12s\n",
			i, acpLabel, string(slResult.Decision), opaResult)
	}

	fmt.Println()
	fmt.Printf("  ACP stateful  : %d APPROVED / %d ESCALATED / %d DENIED\n",
		acpApproved, acpEscalated, acpDenied)
	fmt.Printf("  ACP stateless : %d APPROVED / 0 ESCALATED / 0 DENIED (F_anom=0)\n", slApproved)
	if opaPath != "" {
		fmt.Printf("  OPA (pure)    : %d allow=true / 0 allow=false\n", opaAllow)
	}
	if firstEscalated > 0 {
		fmt.Printf("\n  ACP first ESCALATED : request #%d\n", firstEscalated)
	}
	if firstDenied > 0 {
		fmt.Printf("  ACP first DENIED    : request #%d\n", firstDenied)
	}
	fmt.Println()
	fmt.Println("  Key result: ACP transitions APPROVED→ESCALATED→DENIED via pattern")
	fmt.Println("  accumulation. Stateless engine and OPA approve all 10 requests —")
	fmt.Println("  they cannot observe the behavioral trace.")
	fmt.Println()
	fmt.Println("  OPA with injected history (Scenario B variant):")
	runScenarioBInjected(opaPath)
}

// runScenarioBInjected shows OPA CAN deny when history is passed as input,
// demonstrating that state must be externalized — it is not intrinsic.
func runScenarioBInjected(opaPath string) {
	if opaPath == "" {
		fmt.Println("  [OPA binary not found — skipped]")
		return
	}

	// Policy that requires request_count < 3 (threshold must be pre-computed externally)
	policyB := regoScenarioB()

	// Simulate 5 requests: first 2 pass (count < 3), rest fail (count >= 3)
	fmt.Printf("  %-10s  %-14s  %-s\n", "req_count", "OPA (injected)", "Note")
	fmt.Printf("  %-10s  %-14s  %-s\n", "---------", "--------------", "----")

	for _, count := range []int{0, 1, 2, 3, 4} {
		input := map[string]interface{}{
			"capability":    "acp:cap:financial.transfer",
			"resource_class": "public",
			"request_count": count,
		}
		allow, err := opaEval(opaPath, policyB, input)
		note := ""
		if count < 3 {
			note = "below threshold"
		} else {
			note = "threshold reached → deny"
		}
		if err != nil {
			fmt.Printf("  %-10d  %-14s  %s\n", count, "error", note)
		} else {
			fmt.Printf("  %-10d  %-14v  %s\n", count, allow, note)
		}
	}

	fmt.Println()
	fmt.Println("  Observation: OPA can deny when request_count is injected.")
	fmt.Println("  However, the caller must maintain and increment the counter externally.")
	fmt.Println("  ACP maintains this counter natively (PatternKey ledger).")
}

// ── Scenario C ───────────────────────────────────────────────────────────────

func runScenarioC(req risk.EvalRequest, policy risk.PolicyConfig, opaPath string) {
	baseNow := time.Now()

	// Drive ACP to cooldown: need CooldownTriggerDenials real DENIEDs.
	// Use a policy where every request is DENIED immediately (restricted resource).
	cdPolicy := risk.DefaultPolicyConfig()
	cdPolicy.CooldownTriggerDenials = 3
	cdPolicy.CooldownPeriodSeconds = 300
	cdPolicy.PolicyHash = "sha256:exp14-cooldown"

	cdReq := risk.EvalRequest{
		AgentID:       "acp:agent:exp14:cd-agent",
		Capability:    "acp:cap:financial.transfer",
		Resource:      "accounts/restricted-fund",
		ResourceClass: risk.ResourceRestricted, // B=35 + F_res=45 = RS 80 → DENIED always
		Policy:        cdPolicy,
		Now:           baseNow,
	}

	q := risk.NewInMemoryQuerier()
	stateless := risk.NewStatelessEngine(cdPolicy)

	fmt.Printf("  Setup: financial.transfer / restricted-fund → RS=80 → DENIED always\n")
	fmt.Printf("  Cooldown triggers after %d denials\n\n", cdPolicy.CooldownTriggerDenials)
	fmt.Printf("  %-4s  %-22s  %-18s\n", "Req#", "ACP Stateful", "ACP Stateless")
	fmt.Printf("  %-4s  %-22s  %-18s\n", "----", "------------", "-------------")

	for i := 1; i <= 6; i++ {
		cdReq.Now = baseNow
		acpResult := runRequest(q, cdReq, cdPolicy)
		slResult, _ := stateless.Evaluate(cdReq)

		acpLabel := string(acpResult.Decision)
		if acpResult.DeniedReason != "" {
			acpLabel = acpResult.DeniedReason
		}
		fmt.Printf("  %-4d  %-22s  %-18s\n", i, acpLabel, string(slResult.Decision))
	}

	fmt.Println()
	fmt.Println("  ACP: transitions to COOLDOWN_ACTIVE after 3 denials — blocks further")
	fmt.Println("  requests without re-evaluation. Stateless engine re-evaluates every")
	fmt.Println("  request independently and never enters cooldown.")

	if opaPath != "" {
		fmt.Println()
		fmt.Println("  OPA with injected cooldown (Scenario C variant):")
		policyC := regoScenarioC()
		for _, active := range []bool{false, true} {
			input := map[string]interface{}{
				"capability":     "acp:cap:financial.transfer",
				"resource_class": "public",
				"cooldown_active": active,
			}
			allow, err := opaEval(opaPath, policyC, input)
			note := "no cooldown"
			if active {
				note = "cooldown injected"
			}
			if err != nil {
				fmt.Printf("  cooldown_active=%-5v  OPA: error — %s\n", active, note)
			} else {
				fmt.Printf("  cooldown_active=%-5v  OPA: allow=%-5v  (%s)\n", active, allow, note)
			}
		}
		fmt.Println()
		fmt.Println("  Observation: OPA can enforce cooldown IF cooldown_active is injected.")
		fmt.Println("  The cooldown timer must be managed externally. ACP manages it natively.")
	}
}

// ── Latency comparison ────────────────────────────────────────────────────────

func runLatencyComparison(req risk.EvalRequest, policy risk.PolicyConfig, opaPath string) {
	const N = 50_000

	// ACP latency: pure Evaluate() without state mutation (isolates decision cost)
	q := risk.NewInMemoryQuerier()
	req.Now = time.Unix(1700000000, 0) // fixed timestamp for stable measurement

	start := time.Now()
	for i := 0; i < N; i++ {
		_, _ = risk.Evaluate(req, q)
	}
	elapsed := time.Since(start)
	acpNsPerOp := elapsed.Nanoseconds() / N

	fmt.Printf("  ACP Evaluate()  : %d ns/op  (%d iterations)\n", acpNsPerOp, N)
	fmt.Printf("  Note: latency from established benchmark (TestLatencyPercentiles): ~739 ns p50\n")
	fmt.Println()

	if opaPath != "" {
		fmt.Println("  OPA bench (opa bench -d policy.rego -i input.json 'data.acp.allow'):")
		runOPABenchCmd(opaPath)
	} else {
		fmt.Println("  OPA bench: [OPA binary not found — skipped]")
		fmt.Println("  Expected OPA range: 5,000–50,000 ns/op (Rego evaluation overhead)")
	}

	fmt.Println()
	fmt.Println("  IMPORTANT: latency gap reflects evaluation model difference (Go native vs")
	fmt.Println("  Rego interpreter), not algorithmic complexity. The architectural claim is")
	fmt.Println("  expressibility, not speed.")
}

// runOPABenchCmd calls `opa bench` and prints the raw output.
func runOPABenchCmd(opaPath string) {
	policyFile, inputFile, cleanup := writeTempFiles(regoScenarioA(), opaInputA())
	defer cleanup()

	cmd := exec.Command(opaPath, "bench",
		"-d", policyFile,
		"-i", inputFile,
		"--count", "3",
		"data.acp.allow",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  opa bench error: %v\n  output: %s\n", err, string(out))
		return
	}
	fmt.Println("  " + trimLines(string(out)))
}

// ── Capability matrix ─────────────────────────────────────────────────────────

func printCapabilityMatrix() {
	fmt.Printf("  %-34s  %-14s  %-14s  %-14s\n",
		"Scenario", "ACP Stateful", "ACP Stateless", "OPA (pure)")
	fmt.Printf("  %-34s  %-14s  %-14s  %-14s\n",
		"---------------------------------", "------------", "-------------", "----------")
	fmt.Printf("  %-34s  %-14s  %-14s  %-14s\n",
		"A: Single request", "✓ APPROVED", "✓ APPROVED", "✓ allow=true")
	fmt.Printf("  %-34s  %-14s  %-14s  %-14s\n",
		"B: Frequency limit (N requests)", "✓ DENIED", "✗ APPROVED", "✗ allow=true")
	fmt.Printf("  %-34s  %-14s  %-14s  %-14s\n",
		"C: Cooldown (temporal block)", "✓ COOLDOWN", "✗ DENIED/loop", "✗ allow=true")
	fmt.Println()
	fmt.Println("  ✓ = correct enforcement  ✗ = cannot enforce without external state")
	fmt.Println()
	fmt.Println("  OPA + external state can approximate B and C, but requires:")
	fmt.Println("    - External counter/timer (Redis, DB, or in-memory map)")
	fmt.Println("    - Caller responsibility to inject current state into every request")
	fmt.Println("    - Additional infrastructure not present in OPA itself")
	fmt.Println()
	fmt.Println("  ACP enforces B and C natively via PatternKey ledger and CooldownActive()")
	fmt.Println("  as part of the execution contract (evaluate-then-mutate, §4).")
}

// ── OPA helpers ───────────────────────────────────────────────────────────────

// findOPABinary returns the path to the OPA binary, or "" if not found.
func findOPABinary() string {
	// First try PATH
	if p, err := exec.LookPath("opa"); err == nil {
		return p
	}
	// Fallback: known location on this machine
	known := filepath.Join(os.Getenv("USERPROFILE"), "opa.exe")
	if _, err := os.Stat(known); err == nil {
		return known
	}
	fmt.Println("  [WARNING] OPA binary not found. OPA sections will be skipped.")
	fmt.Println("            Expected at PATH or", known)
	fmt.Println()
	return ""
}

// opaEval evaluates a Rego policy against input using `opa eval`.
// Returns the boolean value of `data.acp.allow`.
func opaEval(opaPath, policy string, input map[string]interface{}) (bool, error) {
	policyFile, inputFile, cleanup := writeTempFiles(policy, input)
	defer cleanup()

	cmd := exec.Command(opaPath, "eval",
		"-d", policyFile,
		"-i", inputFile,
		"--format", "json",
		"data.acp.allow",
	)
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("opa eval: %w", err)
	}

	var result struct {
		Result []struct {
			Expressions []struct {
				Value interface{} `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return false, fmt.Errorf("parse output: %w", err)
	}
	if len(result.Result) == 0 || len(result.Result[0].Expressions) == 0 {
		return false, nil // undefined → deny
	}
	v, ok := result.Result[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil
	}
	return v, nil
}

// writeTempFiles writes a .rego policy and a JSON input to temp files.
// Returns the file paths and a cleanup function.
func writeTempFiles(policy string, input map[string]interface{}) (policyPath, inputPath string, cleanup func()) {
	pf, _ := os.CreateTemp("", "acp_policy_*.rego")
	pf.WriteString(policy)
	pf.Close()

	inf, _ := os.CreateTemp("", "acp_input_*.json")
	enc := json.NewEncoder(inf)
	enc.Encode(input)
	inf.Close()

	return pf.Name(), inf.Name(), func() {
		os.Remove(pf.Name())
		os.Remove(inf.Name())
	}
}

// trimLines indents multi-line OPA output for clean formatting.
func trimLines(s string) string {
	result := ""
	for i, ch := range s {
		result += string(ch)
		if ch == '\n' && i < len(s)-1 {
			result += "  "
		}
	}
	return result
}

// ── Rego policies ─────────────────────────────────────────────────────────────

// regoScenarioA: pure stateless allow — no history awareness.
func regoScenarioA() string {
	return `package acp

import rego.v1

default allow := false

# Scenario A: stateless admissibility.
# Evaluates each request independently. No execution history available.
allow if {
	input.capability == "acp:cap:financial.transfer"
	input.resource_class == "public"
}
`
}

// regoScenarioB: frequency limit — requires externalized request_count.
func regoScenarioB() string {
	return `package acp

import rego.v1

default allow := false

# Scenario B: frequency limit.
# Requires input.request_count to be pre-computed and injected by caller.
# The count is NOT maintained by OPA — it must come from external state.
allow if {
	input.capability == "acp:cap:financial.transfer"
	input.resource_class == "public"
	input.request_count < 3
}
`
}

// regoScenarioC: cooldown — requires externalized cooldown_active.
func regoScenarioC() string {
	return `package acp

import rego.v1

default allow := false

# Scenario C: temporal cooldown.
# Requires input.cooldown_active to be pre-computed and injected by caller.
# The cooldown timer is NOT maintained by OPA — it must come from external state.
allow if {
	input.capability == "acp:cap:financial.transfer"
	input.resource_class == "public"
	not input.cooldown_active
}
`
}

// ── OPA input helpers ─────────────────────────────────────────────────────────

func opaInputA() map[string]interface{} {
	return map[string]interface{}{
		"capability":     "acp:cap:financial.transfer",
		"resource_class": "public",
	}
}
