// org-a: ACP multi-org demo — issuer.
//
// Org-A generates and signs two artifacts per request:
//   - PolicyContextSnapshot  (ACP-POLICY-CTX-1.1)
//   - ReputationSnapshot     (ACP-REP-PORTABILITY-1.1)
//
// Both are signed with the same Ed25519 key, generated at startup.
// The public key is included in every bundle response so Org-B can verify.
//
// Endpoint: GET /snapshot[?agent_id=<id>]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/policyctx"
	"github.com/chelof100/acp-framework/acp-go/pkg/reputation"
)

var (
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
)

// Bundle is the payload Org-A sends to Org-B.
// OrgAPubKey is base64url (no padding), matching ACP-SIGN-1.0.
type Bundle struct {
	OrgAPubKey    string                          `json:"org_a_pub_key"`
	PolicyContext policyctx.PolicyContextSnapshot `json:"policy_context"`
	Reputation    *reputation.ReputationSnapshot  `json:"reputation"`
}

func main() {
	var err error
	pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("[org-a] keygen: %v", err)
	}
	log.Printf("[org-a] started — public key: %s", base64.RawURLEncoding.EncodeToString(pubKey))

	http.HandleFunc("/snapshot", handleSnapshot)
	log.Println("[org-a] listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleSnapshot(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		agentID = "agent.example.shopping-assistant"
	}

	now := time.Now().Unix()
	riskScore := 0.12

	// --- PolicyContextSnapshot (ACP-POLICY-CTX-1.1) ---
	pcs, err := policyctx.Capture(policyctx.CaptureRequest{
		ExecutionID:      fmt.Sprintf("exec-%d", now),
		ProvenanceID:     "prov-org-a-demo",
		PolicyCapturedAt: now - 10, // policy was loaded 10s ago
		DeltaMax:         300,      // org-a allows up to 5 min staleness
		Policy: policyctx.PolicyBlock{
			PolicyID:      "pol.ecommerce.v2",
			PolicyVersion: "2.3.1",
			PolicyHash:    "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
			PolicyEngine:  "rego",
		},
		EvaluationContext: policyctx.EvaluationContext{
			AgentID:             agentID,
			RequestedCapability: "checkout.finalize",
			Resource:            "order/98765",
			RiskScore:           &riskScore,
			DelegationActive:    false,
		},
		EvaluationResult: policyctx.EvaluationResult{
			Decision:     "APPROVED",
			DenialReason: nil,
			Checks: []policyctx.EvaluationCheck{
				{CheckName: "risk_score_below_threshold", Result: "passed", Value: "0.12"},
				{CheckName: "delegation_not_required", Result: "passed"},
				{CheckName: "resource_within_scope", Result: "passed"},
			},
		},
	}, privKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("policyctx.Capture: %v", err), http.StatusInternalServerError)
		return
	}

	// --- ReputationSnapshot (ACP-REP-PORTABILITY-1.1) ---
	rep, err := reputation.Capture(reputation.CaptureRequest{
		SubjectID: agentID,
		Issuer:    "org-a.example.com",
		Score:     0.82,
		Scale:     "0-1",
		ModelID:   "risk-v3",
		ValidFor:  5 * time.Minute,
	}, privKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("reputation.Capture: %v", err), http.StatusInternalServerError)
		return
	}

	bundle := Bundle{
		OrgAPubKey:    base64.RawURLEncoding.EncodeToString(pubKey),
		PolicyContext: pcs,
		Reputation:    rep,
	}

	log.Printf("[org-a] issued bundle — agent=%s exec=%s snapshot=%s rep=%s score=%.2f",
		agentID, pcs.ExecutionID, pcs.SnapshotID, rep.RepID, rep.Score)

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(bundle)
}
