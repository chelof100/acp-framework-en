// acp-server is the ACP Reference Implementation HTTP server.
// Implements ACP-HP-1.0 (Handshake Protocol) endpoints:
//   - GET  /acp/v1/challenge   — Issue a one-time challenge nonce
//   - POST /acp/v1/verify      — Verify capability token + PoP and authorize action
//   - GET  /acp/v1/health      — Health check
//
// This is a reference implementation. Production deployments should add:
//   - TLS termination
//   - Authentication for the /acp/v1/verify endpoint
//   - Persistent nonce store (Redis/PostgreSQL)
//   - Revocation endpoint integration (ACP-REV-1.0)
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/handshake"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Server State ─────────────────────────────────────────────────────────────

var (
	challengeStore *handshake.ChallengeStore

	// institutionPublicKey is loaded from environment at startup.
	// In production: load from HSM or secure key store.
	institutionPublicKey ed25519.PublicKey
)

func main() {
	// Load institution public key from env (base64url-encoded 32 bytes).
	pkB64 := os.Getenv("ACP_INSTITUTION_PUBLIC_KEY")
	if pkB64 == "" {
		log.Fatal("[ACP] ACP_INSTITUTION_PUBLIC_KEY environment variable is required")
	}
	pkBytes, err := base64.RawURLEncoding.DecodeString(pkB64)
	if err != nil || len(pkBytes) != 32 {
		log.Fatalf("[ACP] Invalid ACP_INSTITUTION_PUBLIC_KEY: must be 32-byte base64url")
	}
	institutionPublicKey = ed25519.PublicKey(pkBytes)

	// Initialize challenge store.
	challengeStore = handshake.NewChallengeStore()

	// Periodic pruning of expired challenges.
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			challengeStore.Prune()
		}
	}()

	// Register routes.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /acp/v1/challenge", handleChallenge)
	mux.HandleFunc("POST /acp/v1/verify", handleVerify)
	mux.HandleFunc("GET /acp/v1/health", handleHealth)

	addr := os.Getenv("ACP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("[ACP] Reference Implementation server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[ACP] Server error: %v", err)
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleChallenge issues a one-time 128-bit CSPRNG challenge nonce.
// GET /acp/v1/challenge
func handleChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := challengeStore.GenerateChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CSPRNG failure")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"challenge":  challenge,
		"expires_in": "30s",
	})
}

// VerifyRequest is the POST body for /acp/v1/verify.
type VerifyRequest struct {
	// CapabilityToken is the raw JSON ACP-CT-1.0 token.
	CapabilityToken json.RawMessage `json:"capability_token"`
	// RequestedCapability identifies the capability being exercised.
	RequestedCapability string `json:"requested_capability"`
	// RequestedResource identifies the resource being accessed.
	RequestedResource string `json:"requested_resource"`
}

// VerifyResponse is returned on successful verification.
type VerifyResponse struct {
	Authorized  bool   `json:"authorized"`
	AgentID     string `json:"agent_id"`
	Capability  string `json:"capability"`
	Resource    string `json:"resource"`
	RiskLevel   string `json:"risk_level"`
	RiskScore   int    `json:"risk_score"`
	RequiresMFA bool   `json:"requires_mfa"`
}

// handleVerify performs full ACP verification:
//  1. Parse and verify the Capability Token (9 steps, ACP-CT-1.0 §6)
//  2. Verify Proof-of-Possession (ACP-HP-1.0)
//  3. Assess risk (ACP-RISK-1.0)
//  4. Return authorization decision
//
// POST /acp/v1/verify
func handleVerify(w http.ResponseWriter, r *http.Request) {
	// Parse request body.
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ── Step A: Parse and verify the Capability Token ────────────────────
	vr := tokens.VerificationRequest{
		RequestedCapability: req.RequestedCapability,
		RequestedResource:   req.RequestedResource,
		// RevocationChecker and NonceStore: set by production implementations.
	}
	token, err := tokens.ParseAndVerify(req.CapabilityToken, institutionPublicKey, vr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// ── Step B: Verify Proof-of-Possession (PoP) ─────────────────────────
	// The agent's public key is derived from the subject AgentID.
	// In production: look up agentPubKey from a registry using token.Subject.
	// For reference: we skip PoP here (requires agent pub key lookup).
	// Production MUST implement this. See handshake.VerifyProofOfPossession.

	// ── Step C: Risk Assessment ───────────────────────────────────────────
	assessment := risk.Assess(risk.Request{
		AgentID:    token.Subject,
		Capability: req.RequestedCapability,
		Resource:   req.RequestedResource,
	})

	if !assessment.Approved {
		writeError(w, http.StatusForbidden, "risk score exceeds threshold")
		return
	}

	// ── Step D: Authorization Decision ───────────────────────────────────
	writeJSON(w, http.StatusOK, VerifyResponse{
		Authorized:  true,
		AgentID:     token.Subject,
		Capability:  req.RequestedCapability,
		Resource:    req.RequestedResource,
		RiskLevel:   assessment.Level.String(),
		RiskScore:   assessment.Score,
		RequiresMFA: assessment.RequiresMFA,
	})
}

// handleHealth is a simple liveness probe.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": "ACP-1.0",
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
