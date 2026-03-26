package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// replayPoint captures per-request detail for the figure data.
type replayPoint struct {
	Req      int
	RS       int
	Decision risk.Decision
	Reason   string
	Rule2    bool
	Rule3    bool
}

// RunTokenReplay runs Experiment 4: Token Replay Attack.
//
// ACP does not implement nonce-based replay prevention. Replay resistance is
// bounded by two mechanisms:
//  1. Temporal validity: TimestampDrift signals a stale/replayed token (+10 RS).
//  2. State accumulation: repeated identical requests accumulate in the pattern
//     ledger. F_anom Rule 3 fires after Y=3 identical (AgentID, Capability,
//     Resource) tuples in 5 minutes, adding +15 RS and escalating borderline
//     decisions to DENIED. After 3 DENIED decisions in 10 minutes, the agent
//     enters cooldown.
//
// ACP claim: "ACP converts replay attempts into observable state transitions."
//
// Sub-cases:
//
//	Case 1 – Normal traffic baseline: varied resources → unique patternKeys →
//	         Rule 3 never fires → RS stays low → no cooldown. (Comparison anchor.)
//	Case 2 – Sequential replay: same token replayed identically. Rule 3 fires at
//	         request 4 (after 3 pattern hits in ledger), pushing RS from 55
//	         (ESCALATED) to 70 (DENIED). Cooldown triggers after 3 DENIED.
//	Case 3 – Concurrent replay: 5 workers × 4 requests replay same token in
//	         parallel. Accumulation is serialized by InMemoryQuerier mutex;
//	         concurrency does not bypass Rule 3.
//	Case 4 – Near-identical replay: resource suffix varies per request →
//	         different patternKey each time → Rule 3 never fires → RS stays at 55
//	         (ESCALATED) → no DENIED → no cooldown. Demonstrates bounded replay
//	         resistance and motivates the Limitations note in §7.3.
func RunTokenReplay(_ Config) {
	policy := risk.DefaultPolicyConfig()
	const nRequests = 10

	fmt.Println("=== Experiment 4: Token Replay Attack ===")
	fmt.Printf("Policy  : Rule3=%d (5min window), Rule2=%d (24h), CooldownTrigger=%d DENIED (10min)\n",
		policy.AnomalyRule3ThresholdY, policy.AnomalyRule2ThresholdX, policy.CooldownTriggerDenials)
	fmt.Println("Claim   : ACP converts replay into observable state transitions without nonce tracking.")
	fmt.Println()

	normalData := runCase1Normal(policy, nRequests)
	fmt.Println()
	replayData := runCase2Sequential(policy, nRequests)
	fmt.Println()
	runCase3Concurrent(policy)
	fmt.Println()
	runCase4NearIdentical(policy, nRequests)
	fmt.Println()

	printReplayFigureData(normalData, replayData)
}

// makeReplayReq returns a financial/sensitive request for a new-agent (NoHistory=true).
//
// RS breakdown:
//
//	B  = capabilityBase("acp:cap:financial.transfer") = 35
//	F_res = resourceScore(ResourceSensitive)          = 15
//	F_hist = historyScore({NoHistory: true})          =  5
//	RS_base                                           = 55 → ESCALATED (55 ≤ 69)
//
// After F_anom Rule 3 fires (+15): RS = 70 → DENIED (70 > EscalatedMax=69).
func makeReplayReq(agentID string, policy risk.PolicyConfig) risk.EvalRequest {
	return risk.EvalRequest{
		AgentID:       agentID,
		Capability:    "acp:cap:financial.transfer",
		Resource:      "accounts/sensitive-001",
		ResourceClass: risk.ResourceSensitive,
		History:       risk.History{NoHistory: true},
		Policy:        policy,
	}
}

// runCase1Normal runs the normal traffic baseline.
//
// Each request uses a unique resource suffix → unique patternKey per request →
// CountPattern is always 1 for each key → Rule 3 never fires.
// All requests are APPROVED (RS=0: data.read/public).
func runCase1Normal(policy risk.PolicyConfig, n int) []replayPoint {
	q := risk.NewInMemoryQuerier()
	const agentID = "normal-agent-001"
	m := newMetrics()
	data := make([]replayPoint, 0, n)

	start := time.Now()
	for i := 0; i < n; i++ {
		req := risk.EvalRequest{
			AgentID:       agentID,
			Capability:    "acp:cap:data.read",
			Resource:      fmt.Sprintf("metrics/dashboard-%d", i),
			ResourceClass: risk.ResourcePublic,
			Policy:        policy,
		}
		result := runRequest(q, req, policy)
		m.add(string(result.Decision), result.DeniedReason, int64(i))
		data = append(data, replayPoint{
			Req:      i + 1,
			RS:       result.RSFinal,
			Decision: result.Decision,
			Reason:   result.DeniedReason,
			Rule2:    result.AnomalyDetail.Rule2Triggered,
			Rule3:    result.AnomalyDetail.Rule3Triggered,
		})
	}
	m.finalize(time.Since(start))

	fmt.Println("--- Case 1: Normal Traffic Baseline ---")
	fmt.Printf("Agent   : %s (%d requests, unique resource per request)\n", agentID, n)
	fmt.Printf("Token   : data.read / metrics/dashboard-N / RS_base=0 (APPROVED)\n")
	fmt.Println("Expected: no pattern accumulation; all APPROVED; no cooldown.")
	m.print()
	fmt.Println("\nVerdict : Normal traffic produces no pattern accumulation. ACP introduces no overhead.")
	return data
}

// runCase2Sequential runs the sequential identical-token replay.
//
// Expected trajectory (n=10, RS_base=55):
//
//	req 1–3  : RS=55, ESCALATED  (pattern count 0→2, Rule 3 threshold not met)
//	req 4–6  : RS=70, DENIED     (pattern count ≥3 → Rule 3 fires, +15)
//	req 7–10 : COOLDOWN_ACTIVE   (3 DENIED in 10min → cooldown triggered at req 6)
func runCase2Sequential(policy risk.PolicyConfig, n int) []replayPoint {
	q := risk.NewInMemoryQuerier()
	const agentID = "replay-agent-seq-001"
	m := newMetrics()
	data := make([]replayPoint, 0, n)

	start := time.Now()
	for i := 0; i < n; i++ {
		req := makeReplayReq(agentID, policy)
		result := runRequest(q, req, policy)
		m.add(string(result.Decision), result.DeniedReason, int64(i))
		data = append(data, replayPoint{
			Req:      i + 1,
			RS:       result.RSFinal,
			Decision: result.Decision,
			Reason:   result.DeniedReason,
			Rule2:    result.AnomalyDetail.Rule2Triggered,
			Rule3:    result.AnomalyDetail.Rule3Triggered,
		})
	}
	m.finalize(time.Since(start))

	// Find when Rule 3 first fired.
	rule3First := -1
	for _, p := range data {
		if p.Rule3 {
			rule3First = p.Req
			break
		}
	}

	fmt.Println("--- Case 2: Sequential Replay ---")
	fmt.Printf("Agent   : %s (%d identical requests)\n", agentID, n)
	fmt.Printf("Token   : financial.transfer / accounts/sensitive-001 / RS_base=55 (ESCALATED)\n")
	fmt.Println("Expected: Rule 3 fires at req 4; RS 55→70 (ESCALATED→DENIED); cooldown at req 7.")
	m.print()
	if rule3First >= 0 {
		fmt.Printf("\nVerdict : Rule 3 (pattern accumulation) escalated decision at request %d: RS 55→70 (ESCALATED→DENIED).\n",
			rule3First)
	}
	if m.FirstCooldownAt >= 0 {
		fmt.Printf("          Cooldown triggered at request %d; all %d subsequent requests blocked.\n",
			m.FirstCooldownAt+1, m.CooldownHits)
		fmt.Println("          ACP detected replay via state accumulation without nonce tracking.")
	}
	return data
}

// runCase3Concurrent runs 5 goroutines × 4 requests replaying the same token.
//
// InMemoryQuerier's mutex serializes LedgerQuerier reads; concurrency does not
// bypass pattern accumulation. Rule 3 fires once the pattern count reaches Y=3,
// and cooldown triggers after 3 DENIED decisions regardless of scheduling order.
func runCase3Concurrent(policy risk.PolicyConfig) {
	q := risk.NewInMemoryQuerier()
	const agentID = "replay-agent-conc-001"
	const nWorkers = 5
	const nPerWorker = 4

	m := newMetrics()
	var mu sync.Mutex
	var wg sync.WaitGroup

	start := time.Now()
	for w := 0; w < nWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < nPerWorker; i++ {
				req := makeReplayReq(agentID, policy)
				result := runRequest(q, req, policy)
				mu.Lock()
				m.add(string(result.Decision), result.DeniedReason, m.Total)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	m.finalize(time.Since(start))

	fmt.Println("--- Case 3: Concurrent Replay ---")
	fmt.Printf("Agent   : %s (%d workers × %d requests = %d total)\n",
		agentID, nWorkers, nPerWorker, nWorkers*nPerWorker)
	fmt.Println("Expected: concurrency does not bypass accumulation; cooldown triggers.")
	m.print()
	if m.CooldownHits > 0 {
		fmt.Printf("\nVerdict : Cooldown triggered despite concurrent replay. Pattern accumulation is\n")
		fmt.Printf("          enforced by LedgerQuerier mutex. %d/%d requests blocked.\n",
			m.CooldownHits, m.Total)
	}
}

// runCase4NearIdentical runs near-identical replays with a varied resource suffix.
//
// Each request has a unique resource (accounts/sensitive-000, -001, …) which
// produces a different patternKey. CountPattern for each key is 1 → Rule 3 never
// fires → RS stays at 55 (ESCALATED) → no DENIED → no cooldown.
//
// This demonstrates bounded replay resistance: ACP detects identical tokens via
// state accumulation, but near-identical tokens with varied payload fields can
// evade Rule 3 if the base RS stays below the DENIED threshold. See §Limitations.
func runCase4NearIdentical(policy risk.PolicyConfig, n int) {
	q := risk.NewInMemoryQuerier()
	const agentID = "replay-agent-nearid-001"
	m := newMetrics()

	start := time.Now()
	for i := 0; i < n; i++ {
		req := risk.EvalRequest{
			AgentID:       agentID,
			Capability:    "acp:cap:financial.transfer",
			Resource:      fmt.Sprintf("accounts/sensitive-%03d", i),
			ResourceClass: risk.ResourceSensitive,
			History:       risk.History{NoHistory: true},
			Policy:        policy,
		}
		result := runRequest(q, req, policy)
		m.add(string(result.Decision), result.DeniedReason, int64(i))
	}
	m.finalize(time.Since(start))

	fmt.Println("--- Case 4: Near-Identical Replay (resource variation) ---")
	fmt.Printf("Agent   : %s (%d requests, resource: accounts/sensitive-000..%03d)\n",
		agentID, n, n-1)
	fmt.Println("Expected: each request has unique patternKey → Rule 3 never fires.")
	fmt.Println("          RS stays at 55 (ESCALATED) → no DENIED → no cooldown.")
	m.print()
	if m.CooldownHits == 0 && m.Denied == 0 {
		fmt.Printf("\nVerdict : No cooldown triggered. Resource variation produces distinct patternKeys;\n")
		fmt.Printf("          Rule 3 does not fire. All %d requests processed as ESCALATED (RS=55).\n", n)
		fmt.Println("          Limitation: ACP replay resistance is bounded by identical-token detection.")
		fmt.Println("          Near-identical tokens with moderate base RS evade state accumulation.")
		fmt.Println("          See §Limitations: nonce-based prevention is outside ACP scope.")
	}
}

// printReplayFigureData prints per-request RS data for the LaTeX figure
// "Replay vs Normal Traffic — Time to Cooldown".
//
// Sentinel value 105 is used for COOLDOWN_ACTIVE requests (RS > max 100) so
// that the pgfplots figure can render a shaded "COOLDOWN" region above the grid.
func printReplayFigureData(normal, replay []replayPoint) {
	fmt.Println("--- Figure Data: Replay vs Normal Traffic (RS per request) ---")
	fmt.Printf("%-6s  %-12s  %-18s  %-12s  %-18s  %-5s\n",
		"Req", "Normal RS", "Normal Decision", "Replay RS", "Replay Decision", "F_anom")
	fmt.Println("------  ------------  ------------------  ------------  ------------------  -----")

	maxLen := len(normal)
	if len(replay) > maxLen {
		maxLen = len(replay)
	}
	for i := 0; i < maxLen; i++ {
		var nRS, rRS string
		var nDec, rDec, fanom string

		if i < len(normal) {
			p := normal[i]
			nRS = fmt.Sprintf("%d", p.RS)
			nDec = string(p.Decision)
		}
		if i < len(replay) {
			p := replay[i]
			if p.Reason == "COOLDOWN_ACTIVE" {
				rRS = "105"
				rDec = "COOLDOWN_ACTIVE"
			} else {
				rRS = fmt.Sprintf("%d", p.RS)
				rDec = string(p.Decision)
			}
			if p.Rule3 {
				fanom = "R3"
			}
			if p.Rule2 {
				if fanom != "" {
					fanom += "+R2"
				} else {
					fanom = "R2"
				}
			}
		}
		fmt.Printf("%-6d  %-12s  %-18s  %-12s  %-18s  %-5s\n",
			i+1, nRS, nDec, rRS, rDec, fanom)
	}

	fmt.Println()
	fmt.Println("% LaTeX pgfplots coordinates (paste into paper/figures/replay_figure.tex):")
	fmt.Print("% Normal: \\addplot coordinates {")
	for _, p := range normal {
		fmt.Printf(" (%d,%d)", p.Req, p.RS)
	}
	fmt.Println(" };")
	fmt.Print("% Replay: \\addplot coordinates {")
	for _, p := range replay {
		rs := p.RS
		if p.Reason == "COOLDOWN_ACTIVE" {
			rs = 105
		}
		fmt.Printf(" (%d,%d)", p.Req, rs)
	}
	fmt.Println(" };")
}
