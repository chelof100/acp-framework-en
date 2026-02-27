// cmd/acp-server — ACP Reference Server (ACP-HP-1.0 + ACP-CT-1.0)
//
// Environment variables:
//   ACP_INSTITUTION_PUBLIC_KEY  base64url-encoded Ed25519 public key (required)
//   ACP_ADDR                    listen address (default :8080)
//   ACP_LOG_LEVEL               log level (default info)
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/handshake"
	"github.com/chelof100/acp-framework/acp-go/pkg/registry"
	"github.com/chelof100/acp-framework/acp-go/pkg/revocation"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Server State ─────────────────────────────────────────────────────────────

type server struct {
	challenges        *handshake.ChallengeStore
	registry          *registry.InMemoryRegistry
	revChecker        tokens.RevocationChecker
	nonceStore        *tokens.InMemoryNonceStore
	institutionPubKey ed25519.PublicKey
	addr              string
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// 1. Load institution public key from environment.
	pubKeyB64 := os.Getenv("ACP_INSTITUTION_PUBLIC_KEY")
	if pubKeyB64 == "" {
		log.Fatal("[ACP] ACP_INSTITUTION_PUBLIC_KEY not set (base64url-encoded Ed25519 pubkey required)")
	}
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		log.Fatalf("[ACP] failed to decode ACP_INSTITUTION_PUBLIC_KEY: %v", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Fatalf("[ACP] ACP_INSTITUTION_PUBLIC_KEY must be %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}
	institutionPubKey := ed25519.PublicKey(pubKeyBytes)

	// 2. Determine listen address.
	addr := os.Getenv("ACP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// 3. Initialise server components.
	srv := &server{
		challenges:        handshake.NewChallengeStore(),
		registry:          registry.NewInMemoryRegistry(),
		revChecker:        revocation.NewHTTPRevocationChecker(5 * time.Second),
		nonceStore:        tokens.NewInMemoryNonceStore(),
		institutionPubKey: institutionPubKey,
		addr:              addr,
	}

	// 4. Register HTTP routes.
	mux := http.NewServeMux()
	mux.HandleFunc("/acp/v1/challenge", srv.handleChallenge)
	mux.HandleFunc("/acp/v1/verify",    srv.handleVerify)
	mux.HandleFunc("/acp/v1/register",  srv.handleRegister)
	mux.HandleFunc("/acp/v1/health",    srv.handleHealth)

	// 5. Background pruning goroutine (every 2 minutes).
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			srv.challenges.Prune() // ChallengeStore.Prune() is void
			expiredN := srv.nonceStore.Prune()
			if expiredN > 0 {
				log.Printf("[ACP] pruned %d nonces", expiredN)
			}
		}
	}()

	// 6. Start server.
	log.Printf("[ACP] server listening on %s", addr)
	log.Printf("[ACP] institution pubkey: %s...", pubKeyB64[:min(16, len(pubKeyB64))])
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[ACP] server error: %v", err)
	}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleChallenge issues a one-time challenge nonce.
// GET /acp/v1/challenge
// Response: {"challenge": "<base64url>"}
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := s.challenges.GenerateChallenge()
	if err != nil {
		log.Printf("[ACP] challenge generation failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"challenge": challenge,
	})
}

// handleVerify verifies a Capability Token + Proof-of-Possession.
// POST /acp/v1/verify
//
// Required headers:
//   Authorization:    Bearer <token_json>
//   X-ACP-Agent-ID:   <agentID>
//   X-ACP-Challenge:  <challenge>
//   X-ACP-Signature:  <pop_signature>
//
// Response 200: {"ok": true, "agent_id": "...", "capabilities": [...]}
// Response 4xx: {"ok": false, "error": "CT-xxx: ..."}
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// ── 1. Extract headers ──────────────────────────────────────────────────
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "missing or invalid Authorization header",
		})
		return
	}
	tokenJSON := strings.TrimPrefix(authHeader, "Bearer ")
	agentID   := r.Header.Get("X-ACP-Agent-ID")
	challenge := r.Header.Get("X-ACP-Challenge")
	popSig    := r.Header.Get("X-ACP-Signature")

	if agentID == "" || challenge == "" || popSig == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "error": "missing ACP headers (X-ACP-Agent-ID, X-ACP-Challenge, X-ACP-Signature)",
		})
		return
	}

	// ── 2. Resolve agent public key from registry ───────────────────────────
	agentPubKey, err := s.registry.GetPublicKey(agentID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("agent not registered: %v", err),
		})
		return
	}

	// ── 3. Verify Proof-of-Possession ───────────────────────────────────────
	if err := handshake.VerifyProofOfPossession(r, s.challenges, agentPubKey); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("PoP verification failed: %v", err),
		})
		return
	}

	// ── 4. Parse and verify Capability Token ────────────────────────────────
	token, err := tokens.ParseAndVerify([]byte(tokenJSON), s.institutionPubKey, tokens.VerificationRequest{
		RevocationChecker: s.revChecker,
		NonceStore:        s.nonceStore,
	})
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	// ── 5. Cross-check: token subject must match requesting agent ────────────
	if token.Subject != agentID {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"ok": false, "error": fmt.Sprintf("CT-011: token subject %q does not match agent %q", token.Subject, agentID),
		})
		return
	}

	// ── 6. Success ──────────────────────────────────────────────────────────
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"agent_id":     agentID,
		"capabilities": token.Cap,
		"resource":     token.Resource,
		"expires":      token.Expiration,
	})
}

// handleRegister registers an agent's public key.
// POST /acp/v1/register
// Body: {"agent_id": "...", "public_key_hex": "..."}
//
// NOTE: In production, this endpoint must be authenticated and
// restricted to institutional administrators.
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID      string `json:"agent_id"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "error": "invalid JSON body",
		})
		return
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKeyHex)
	if err != nil {
		// Try hex fallback
		pubKeyBytes, err = hexDecode(req.PublicKeyHex)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "error": "public_key_hex must be base64url or hex-encoded",
			})
			return
		}
	}

	if err := s.registry.Register(req.AgentID, ed25519.PublicKey(pubKeyBytes)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	log.Printf("[ACP] registered agent %s (pubkey %x...)", req.AgentID, pubKeyBytes[:4])
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"agent_id": req.AgentID,
	})
}

// handleHealth returns server health status.
// GET /acp/v1/health
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"version":    "1.0.0",
		"challenges": s.challenges.Size(),
		"agents":     s.registry.Size(),
		"nonces":     s.nonceStore.Size(),
		"timestamp":  time.Now().Unix(),
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var hi, lo byte
		if s[i] >= '0' && s[i] <= '9' {
			hi = s[i] - '0'
		} else if s[i] >= 'a' && s[i] <= 'f' {
			hi = s[i] - 'a' + 10
		} else if s[i] >= 'A' && s[i] <= 'F' {
			hi = s[i] - 'A' + 10
		} else {
			return nil, fmt.Errorf("invalid hex char %c", s[i])
		}
		if s[i+1] >= '0' && s[i+1] <= '9' {
			lo = s[i+1] - '0'
		} else if s[i+1] >= 'a' && s[i+1] <= 'f' {
			lo = s[i+1] - 'a' + 10
		} else if s[i+1] >= 'A' && s[i+1] <= 'F' {
			lo = s[i+1] - 'A' + 10
		} else {
			return nil, fmt.Errorf("invalid hex char %c", s[i+1])
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
