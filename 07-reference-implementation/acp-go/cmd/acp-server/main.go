// cmd/acp-server — ACP Reference Server
// Protocols: ACP-HP-1.0 + ACP-CT-1.0 + ACP-REV-1.0 + ACP-REP-1.1
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
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/handshake"
	"github.com/chelof100/acp-framework/acp-go/pkg/registry"
	"github.com/chelof100/acp-framework/acp-go/pkg/reputation"
	"github.com/chelof100/acp-framework/acp-go/pkg/revocation"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Server State ─────────────────────────────────────────────────────────────

type server struct {
	challenges        *handshake.ChallengeStore
	registry          *registry.InMemoryRegistry
	revStore          revocation.RevocationStore
	revChecker        tokens.RevocationChecker
	repEngine         *reputation.Engine
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
	//    revStore is the authoritative revocation registry (ACP-REV-1.0).
	//    StoreRevocationChecker wires it into the token verification pipeline.
	revStore := revocation.NewInMemoryRevocationStore()
	srv := &server{
		challenges:        handshake.NewChallengeStore(),
		registry:          registry.NewInMemoryRegistry(),
		revStore:          revStore,
		revChecker:        revocation.NewStoreRevocationChecker(revStore),
		repEngine:         reputation.NewDefaultEngine(reputation.NewInMemoryReputationStore()),
		nonceStore:        tokens.NewInMemoryNonceStore(),
		institutionPubKey: institutionPubKey,
		addr:              addr,
	}

	// 4. Register HTTP routes.
	mux := http.NewServeMux()

	// ACP-HP-1.0 + ACP-CT-1.0
	mux.HandleFunc("/acp/v1/challenge", srv.handleChallenge)
	mux.HandleFunc("/acp/v1/verify",    srv.handleVerify)
	mux.HandleFunc("/acp/v1/register",  srv.handleRegister)
	mux.HandleFunc("/acp/v1/health",    srv.handleHealth)

	// ACP-REV-1.0 — revocation endpoints
	mux.HandleFunc("GET /acp/v1/rev/check",   srv.handleRevCheck)
	mux.HandleFunc("POST /acp/v1/rev/revoke", srv.handleRevRevoke)

	// ACP-REP-1.1 — reputation endpoints (Go 1.22 path params)
	mux.HandleFunc("GET /acp/v1/rep/{agent_id}",              srv.handleRepGet)
	mux.HandleFunc("GET /acp/v1/rep/{agent_id}/events",       srv.handleRepEvents)
	mux.HandleFunc("POST /acp/v1/rep/{agent_id}/state",       srv.handleRepState)

	// 5. Background pruning goroutine (every 2 minutes).
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			srv.challenges.Prune()
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

// ─── ACP-HP-1.0 + ACP-CT-1.0 Handlers ───────────────────────────────────────

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
//
// ACP-REP-1.1 integration: emits reputation event on success or token failure.
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
		// ACP-REP-1.1: record reputation event for the token failure.
		s.emitRepEvent(agentID, repEventFromTokenError(err))
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

	// ── 6. Success — emit positive reputation event ──────────────────────────
	s.emitRepEvent(agentID, reputation.EvtVerifyOK)

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
		"revoked":    s.revStore.Size(),
		"timestamp":  time.Now().Unix(),
	})
}

// ─── ACP-REV-1.0 Handlers ─────────────────────────────────────────────────────

// handleRevCheck queries revocation status for a token.
// GET /acp/v1/rev/check?token_id=<nonce>
//
// Response 200: {"token_id":"...","status":"active"|"revoked","checked_at":<unix>}
// Response 404: {"error":"token not found — treat as revoked (ACP-REV-1.0 §4.2)"}
// Response 400: {"error":"missing token_id query parameter"}
func (s *server) handleRevCheck(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("token_id")
	if tokenID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "missing token_id query parameter",
		})
		return
	}

	revoked, _, err := s.revStore.IsRevoked(tokenID)
	if err != nil {
		log.Printf("[ACP/REV] store error checking %s: %v", tokenID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "internal store error",
		})
		return
	}

	status := "active"
	if revoked {
		status = "revoked"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token_id":   tokenID,
		"status":     status,
		"checked_at": time.Now().Unix(),
	})
}

// handleRevRevoke emits a revocation for a token.
// POST /acp/v1/rev/revoke
// Body: {"token_id":"...","reason_code":"REV-001","revoked_by":"..."}
//
// Response 200: {"ok":true,"token_id":"...","revoked_at":<unix>}
// Response 400: {"error":"..."}  — missing fields, invalid reason_code
// Response 409: {"error":"token already revoked (REV-E001)"}
func (s *server) handleRevRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TokenID    string `json:"token_id"`
		ReasonCode string `json:"reason_code"`
		RevokedBy  string `json:"revoked_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "invalid JSON body",
		})
		return
	}

	if req.TokenID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "token_id is required",
		})
		return
	}
	if req.RevokedBy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "revoked_by is required",
		})
		return
	}

	now := time.Now().Unix()
	record := revocation.RevocationRecord{
		TokenID:    req.TokenID,
		RevokedAt:  now,
		RevokedBy:  req.RevokedBy,
		ReasonCode: req.ReasonCode,
	}

	if err := s.revStore.Revoke(record); err != nil {
		if errors.Is(err, revocation.ErrAlreadyRevoked) {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error": "token already revoked (REV-E001)",
			})
			return
		}
		if errors.Is(err, revocation.ErrInvalidReason) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		log.Printf("[ACP/REV] revoke error for %s: %v", req.TokenID, err)
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	log.Printf("[ACP/REV] revoked token %s by %s (reason: %s)", req.TokenID, req.RevokedBy, req.ReasonCode)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"token_id":   req.TokenID,
		"revoked_at": now,
	})
}

// ─── ACP-REP-1.1 Handlers ─────────────────────────────────────────────────────

// handleRepGet returns the current reputation record for an agent.
// GET /acp/v1/rep/{agent_id}
//
// Response 200: ReputationRecord JSON
// Cold-start agents return Score=null, State="ACTIVE".
func (s *server) handleRepGet(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	record, err := s.repEngine.GetRecord(agentID)
	if err != nil {
		log.Printf("[ACP/REP] get record error for %s: %v", agentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "internal store error",
		})
		return
	}

	writeJSON(w, http.StatusOK, record)
}

// handleRepEvents returns paginated reputation events for an agent.
// GET /acp/v1/rep/{agent_id}/events?limit=20&offset=0
//
// Response 200: {"events":[...],"total":<int>,"limit":<int>,"offset":<int>}
// Events are returned most-recent-first.
func (s *server) handleRepEvents(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	events, total, err := s.repEngine.GetEvents(agentID, limit, offset)
	if err != nil {
		log.Printf("[ACP/REP] get events error for %s: %v", agentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "internal store error",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleRepState manually sets the administrative state of an agent.
// POST /acp/v1/rep/{agent_id}/state
// Body: {"state":"PROBATION","reason":"...","authorized_by":"<admin_agent_id>"}
//
// Response 200: {"ok":true,"agent_id":"...","state":"PROBATION"}
// Response 400: invalid state, missing reason, or missing authorized_by
// Response 409: agent is BANNED (terminal state)
func (s *server) handleRepState(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	var req struct {
		State        string `json:"state"`
		Reason       string `json:"reason"`
		AuthorizedBy string `json:"authorized_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "invalid JSON body",
		})
		return
	}

	// Validate state value.
	targetState := reputation.AgentState(req.State)
	switch targetState {
	case reputation.StateActive, reputation.StateProbation,
		reputation.StateSuspended, reputation.StateBanned:
		// valid
	default:
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": fmt.Sprintf("invalid state %q; valid: ACTIVE, PROBATION, SUSPENDED, BANNED", req.State),
		})
		return
	}

	if err := s.repEngine.SetState(agentID, targetState, req.Reason, req.AuthorizedBy); err != nil {
		if errors.Is(err, reputation.ErrAgentBanned) {
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error": "agent is BANNED — terminal state, no further state changes allowed",
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	log.Printf("[ACP/REP] state change for %s → %s (by %s: %s)", agentID, targetState, req.AuthorizedBy, req.Reason)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"agent_id": agentID,
		"state":    string(targetState),
	})
}

// ─── Reputation helpers ────────────────────────────────────────────────────────

// emitRepEvent records a reputation event, logging on failure (non-blocking).
func (s *server) emitRepEvent(agentID, eventType string) {
	if err := s.repEngine.RecordEvent(agentID, eventType); err != nil {
		log.Printf("[ACP/REP] failed to record %s for agent %s: %v", eventType, agentID, err)
	}
}

// repEventFromTokenError maps a token verification error to the appropriate
// ACP-REP-1.1 event type based on the CT error code in the error message.
func repEventFromTokenError(err error) string {
	msg := err.Error()
	// CT-010 = revoked token; CT-011 = subject mismatch (not a sig error)
	if strings.Contains(msg, "CT-010") || strings.Contains(msg, "revoked") {
		return reputation.EvtRevInvalid
	}
	// CT-002 = invalid institution signature
	if strings.Contains(msg, "CT-002") || strings.Contains(msg, "signature") {
		return reputation.EvtSigInvalid
	}
	// Everything else: malformed token (expired, bad structure, etc.)
	return reputation.EvtTokenMalformed
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
