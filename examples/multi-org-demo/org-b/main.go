// org-b: ACP multi-org demo — verifier and decision maker.
//
// Org-B receives the bundle from Org-A and:
//  1. Verifies the PolicyContextSnapshot signature and freshness.
//  2. Validates the ReputationSnapshot (structural + signature).
//  3. Checks score divergence against its own local score for the same agent.
//     If divergence exceeds 0.30 → emits REP-WARN-002 (non-blocking).
//  4. Makes the final ACCEPT / DENY decision using its own policy.
//
// ACP principle: "ACP reports divergence. ACP does not resolve divergence."
// Org-B's decision is sovereign — it is NOT overridden by Org-A's approval.
//
// Endpoint: GET /request[?agent_id=<id>]
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/policyctx"
	"github.com/chelof100/acp-framework/acp-go/pkg/reputation"
)

// orgAURL is set via ORG_A_URL env var; defaults to docker-compose service name.
var orgAURL = "http://org-a:8080"

// orgBLocalScore is Org-B's own reputation score for the demo agent.
// Deliberately set to 0.55 (divergence from Org-A's 0.82 = 0.27, below threshold).
// Change to e.g. 0.40 to trigger REP-WARN-002.
const orgBLocalScore = 0.55

// divergenceThreshold triggers REP-WARN-002 when exceeded (§7, recommended default).
const divergenceThreshold = 0.30

// acceptScoreFloor is Org-B's minimum reputation score to ACCEPT.
const acceptScoreFloor = 0.50

// Bundle mirrors the payload emitted by Org-A.
type Bundle struct {
	OrgAPubKey    string                          `json:"org_a_pub_key"`
	PolicyContext policyctx.PolicyContextSnapshot `json:"policy_context"`
	Reputation    *reputation.ReputationSnapshot  `json:"reputation"`
}

// ValidationResult is the JSON response from Org-B.
type ValidationResult struct {
	Decision         string   `json:"decision"`
	AgentID          string   `json:"agent_id"`
	PolicyCtxStatus  string   `json:"policy_ctx_status"`
	RepStatus        string   `json:"rep_status"`
	OrgAScore        float64  `json:"org_a_score"`
	OrgBScore        float64  `json:"org_b_score"`
	Divergence       float64  `json:"divergence"`
	DivergenceWarn   *string  `json:"divergence_warning,omitempty"`
	Log              []string `json:"log"`
}

func main() {
	if u := os.Getenv("ORG_A_URL"); u != "" {
		orgAURL = u
	}
	log.Printf("[org-b] using org-a at %s", orgAURL)

	http.HandleFunc("/request", handleRequest)
	log.Println("[org-b] listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	agentParam := ""
	if agentID != "" {
		agentParam = "?agent_id=" + agentID
	}

	var logs []string
	addLog := func(msg string) {
		log.Printf("[org-b] %s", msg)
		logs = append(logs, msg)
	}

	// ── Step 1: Fetch bundle from Org-A ──────────────────────────────────────
	url := orgAURL + "/snapshot" + agentParam
	addLog(fmt.Sprintf("fetching bundle from %s", url))

	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch bundle: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var bundle Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		http.Error(w, fmt.Sprintf("parse bundle: %v", err), http.StatusBadRequest)
		return
	}
	addLog(fmt.Sprintf("bundle received — snapshot_id=%s rep_id=%s",
		bundle.PolicyContext.SnapshotID, bundle.Reputation.RepID))

	// ── Step 2: Decode Org-A public key ──────────────────────────────────────
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(bundle.OrgAPubKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode pubkey: %v", err), http.StatusBadRequest)
		return
	}

	result := ValidationResult{
		AgentID:   bundle.PolicyContext.EvaluationContext.AgentID,
		OrgAScore: bundle.Reputation.Score,
		OrgBScore: orgBLocalScore,
	}

	// ── Step 3: Validate PolicyContextSnapshot ────────────────────────────────
	// ACP-POLICY-CTX-1.1 §6 steps 12 + freshness check
	addLog("verifying PolicyContextSnapshot (ACP-POLICY-CTX-1.1 §6)...")
	if sigErr := policyctx.VerifySig(bundle.PolicyContext, pubKeyBytes); sigErr != nil {
		result.PolicyCtxStatus = fmt.Sprintf("SIG_INVALID: %v", sigErr)
		addLog(fmt.Sprintf("  [FAIL] signature: %v", sigErr))
	} else {
		addLog("  [OK] signature verified")
		freshnessErr := policyctx.VerifyCaptureFreshness(bundle.PolicyContext, 300*time.Second)
		if freshnessErr != nil {
			result.PolicyCtxStatus = fmt.Sprintf("STALE: %v", freshnessErr)
			addLog(fmt.Sprintf("  [FAIL] freshness: %v", freshnessErr))
		} else {
			result.PolicyCtxStatus = "VALID"
			addLog(fmt.Sprintf("  [OK] freshness — delta_max=%ds within verifier limit 300s",
				bundle.PolicyContext.DeltaMax))
		}
	}

	// ── Step 4: Validate ReputationSnapshot ──────────────────────────────────
	// ACP-REP-PORTABILITY-1.1 §6: structural then cryptographic
	addLog("validating ReputationSnapshot (ACP-REP-PORTABILITY-1.1 §6)...")
	if valErr := reputation.Validate(bundle.Reputation, time.Now()); valErr != nil {
		result.RepStatus = fmt.Sprintf("INVALID: %v", valErr)
		addLog(fmt.Sprintf("  [FAIL] structural: %v", valErr))
	} else {
		addLog("  [OK] structural validation passed")
		if sigErr := reputation.VerifySig(bundle.Reputation, pubKeyBytes); sigErr != nil {
			result.RepStatus = fmt.Sprintf("SIG_INVALID: %v", sigErr)
			addLog(fmt.Sprintf("  [FAIL] signature: %v", sigErr))
		} else {
			result.RepStatus = "VALID"
			addLog(fmt.Sprintf("  [OK] signature verified — issuer=%s score=%.4f scale=%s",
				bundle.Reputation.Issuer, bundle.Reputation.Score, bundle.Reputation.Scale))
		}
	}

	// ── Step 5: Divergence check (ACP-REP-PORTABILITY-1.1 §7) ────────────────
	// Org-B has its own score for this agent. ACP reports divergence — does NOT resolve it.
	addLog("checking score divergence (ACP-REP-PORTABILITY-1.1 §7)...")
	orgBRep := &reputation.ReputationSnapshot{
		Score: orgBLocalScore,
		Scale: bundle.Reputation.Scale,
	}
	exceeded, divergence := reputation.CheckDivergence(bundle.Reputation, orgBRep, divergenceThreshold)
	result.Divergence = divergence

	if exceeded {
		warn := fmt.Sprintf(
			"REP-WARN-002: score divergence %.4f exceeds threshold %.2f (org-a=%.4f, org-b=%.4f — ACP reports, does NOT resolve)",
			divergence, divergenceThreshold, bundle.Reputation.Score, orgBLocalScore,
		)
		result.DivergenceWarn = &warn
		addLog(fmt.Sprintf("  [WARN] %s", warn))
	} else {
		addLog(fmt.Sprintf("  [OK] divergence=%.4f within threshold %.2f — no warning emitted",
			divergence, divergenceThreshold))
	}

	// ── Step 6: Org-B's sovereign decision ───────────────────────────────────
	// Org-B decides based on its own validation results.
	// REP-WARN-002 is informational — it does not block ACCEPT.
	addLog("computing Org-B decision...")
	if result.PolicyCtxStatus == "VALID" &&
		result.RepStatus == "VALID" &&
		bundle.Reputation.Score >= acceptScoreFloor {
		result.Decision = "ACCEPT"
		addLog(fmt.Sprintf("  DECISION: ACCEPT (pctx=VALID, rep=VALID, org-a-score=%.4f >= floor %.2f)",
			bundle.Reputation.Score, acceptScoreFloor))
	} else {
		result.Decision = "DENY"
		addLog(fmt.Sprintf("  DECISION: DENY (pctx=%s, rep=%s, org-a-score=%.4f)",
			result.PolicyCtxStatus, result.RepStatus, bundle.Reputation.Score))
	}

	result.Log = logs

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}
