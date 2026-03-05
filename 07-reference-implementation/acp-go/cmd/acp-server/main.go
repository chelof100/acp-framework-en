// cmd/acp-server — ACP Reference Server
// Protocols: ACP-HP-1.0 + ACP-CT-1.0 + ACP-REV-1.0 + ACP-REP-1.1 + ACP-API-1.0 + ACP-EXEC-1.0
//
// Environment variables:
//   ACP_INSTITUTION_PUBLIC_KEY   base64url-encoded Ed25519 public key (required)
//   ACP_INSTITUTION_PRIVATE_KEY  base64url-encoded Ed25519 private key (optional; enables response signing)
//   ACP_ADDR                     listen address (default :8080)
//   ACP_LOG_LEVEL                log level (default info)
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

	acpapi "github.com/chelof100/acp-framework/acp-go/pkg/api"
	"github.com/chelof100/acp-framework/acp-go/pkg/execution"
	"github.com/chelof100/acp-framework/acp-go/pkg/handshake"
	"github.com/chelof100/acp-framework/acp-go/pkg/registry"
	"github.com/chelof100/acp-framework/acp-go/pkg/reputation"
	"github.com/chelof100/acp-framework/acp-go/pkg/revocation"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Server State ─────────────────────────────────────────────────────────────

type server struct {
	challenges         *handshake.ChallengeStore
	registry           *registry.InMemoryRegistry
	revStore           revocation.RevocationStore
	revChecker         tokens.RevocationChecker
	repEngine          *reputation.Engine
	nonceStore         *tokens.InMemoryNonceStore
	etRegistry         *execution.InMemoryETRegistry // ACP-EXEC-1.0
	institutionPubKey  ed25519.PublicKey
	institutionPrivKey ed25519.PrivateKey // nil if ACP_INSTITUTION_PRIVATE_KEY not set
	addr               string
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// 1. Load institution public key.
	pubKeyB64 := os.Getenv("ACP_INSTITUTION_PUBLIC_KEY")
	if pubKeyB64 == "" {
		log.Fatal("[ACP] ACP_INSTITUTION_PUBLIC_KEY not set")
	}
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		log.Fatalf("[ACP] failed to decode ACP_INSTITUTION_PUBLIC_KEY: %v", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Fatalf("[ACP] ACP_INSTITUTION_PUBLIC_KEY must be %d bytes, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	// 2. Load institution private key (optional — enables response signing).
	var institutionPrivKey ed25519.PrivateKey
	if privKeyB64 := os.Getenv("ACP_INSTITUTION_PRIVATE_KEY"); privKeyB64 != "" {
		privKeyBytes, err := base64.RawURLEncoding.DecodeString(privKeyB64)
		if err != nil {
			log.Fatalf("[ACP] failed to decode ACP_INSTITUTION_PRIVATE_KEY: %v", err)
		}
		if len(privKeyBytes) != ed25519.PrivateKeySize {
			log.Fatalf("[ACP] ACP_INSTITUTION_PRIVATE_KEY must be %d bytes, got %d", ed25519.PrivateKeySize, len(privKeyBytes))
		}
		institutionPrivKey = ed25519.PrivateKey(privKeyBytes)
		log.Printf("[ACP] response signing enabled")
	} else {
		log.Printf("[ACP] ACP_INSTITUTION_PRIVATE_KEY not set — responses will not be signed (dev mode)")
	}

	// 3. Determine listen address.
	addr := os.Getenv("ACP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// 4. Initialise server components.
	revStore := revocation.NewInMemoryRevocationStore()
	srv := &server{
		challenges:         handshake.NewChallengeStore(),
		registry:           registry.NewInMemoryRegistry(),
		revStore:           revStore,
		revChecker:         revocation.NewStoreRevocationChecker(revStore),
		repEngine:          reputation.NewDefaultEngine(reputation.NewInMemoryReputationStore()),
		nonceStore:         tokens.NewInMemoryNonceStore(),
		etRegistry:         execution.NewInMemoryETRegistry(),
		institutionPubKey:  ed25519.PublicKey(pubKeyBytes),
		institutionPrivKey: institutionPrivKey,
		addr:               addr,
	}

	// 5. Build mux and apply ACP-API-1.0 middleware.
	mux := http.NewServeMux()

	// ── ACP-HP-1.0: Handshake ────────────────────────────────────────────────
	mux.HandleFunc("GET /acp/v1/handshake/challenge",  srv.handleChallenge)
	mux.HandleFunc("/acp/v1/challenge",                srv.handleChallenge) // legacy alias

	// ── ACP-CT-1.0: Token verification (legacy path, kept for SDK compat) ───
	mux.HandleFunc("POST /acp/v1/verify", srv.handleVerify)

	// ── ACP-API-1.0 §4: Agent Registry ───────────────────────────────────────
	mux.HandleFunc("POST /acp/v1/agents",                    srv.handleAgentRegister)
	mux.HandleFunc("GET /acp/v1/agents/{agent_id}",          srv.handleAgentGet)
	mux.HandleFunc("POST /acp/v1/agents/{agent_id}/state",   srv.handleAgentState)

	// ── ACP-API-1.0 §5: Authorization ────────────────────────────────────────
	mux.HandleFunc("POST /acp/v1/authorize",                                           srv.handleAuthorize)
	mux.HandleFunc("POST /acp/v1/authorize/escalations/{escalation_id}/resolve",       srv.handleEscalationResolve)

	// ── ACP-API-1.0 §6: Capability Tokens (stub) ─────────────────────────────
	mux.HandleFunc("POST /acp/v1/tokens", srv.handleTokensIssue)

	// ── ACP-API-1.0 §7: Audit (stubs — ACP-LEDGER-1.0 will implement) ────────
	mux.HandleFunc("POST /acp/v1/audit/query",               srv.handleAuditQuery)
	mux.HandleFunc("GET /acp/v1/audit/verify/{event_id}",    srv.handleAuditVerify)

	// ── ACP-API-1.0 §8: Execution Tokens (stubs — ACP-EXEC-1.0 will implement)
	mux.HandleFunc("POST /acp/v1/exec-tokens/{et_id}/consume", srv.handleExecTokenConsume)
	mux.HandleFunc("GET /acp/v1/exec-tokens/{et_id}/status",   srv.handleExecTokenStatus)

	// ── ACP-REV-1.0 ──────────────────────────────────────────────────────────
	mux.HandleFunc("GET /acp/v1/rev/check",   srv.handleRevCheck)
	mux.HandleFunc("POST /acp/v1/rev/revoke", srv.handleRevRevoke)

	// ── ACP-REP-1.1 ──────────────────────────────────────────────────────────
	mux.HandleFunc("GET /acp/v1/rep/{agent_id}",         srv.handleRepGet)
	mux.HandleFunc("GET /acp/v1/rep/{agent_id}/events",  srv.handleRepEvents)
	mux.HandleFunc("POST /acp/v1/rep/{agent_id}/state",  srv.handleRepState)

	// ── Health ────────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /acp/v1/health", srv.handleHealth)
	mux.HandleFunc("/acp/v1/health",     srv.handleHealth) // legacy alias

	// ── Legacy register (kept for SDK backward compat) ────────────────────────
	mux.HandleFunc("POST /acp/v1/register", srv.handleRegisterLegacy)

	// 6. Apply ACP-API-1.0 middleware (X-ACP-Version, X-ACP-Request-ID).
	handler := acpapi.Middleware(mux)

	// 7. Background pruning goroutine (every 2 minutes).
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			srv.challenges.Prune()
			if n := srv.nonceStore.Prune(); n > 0 {
				log.Printf("[ACP] pruned %d nonces", n)
			}
			if n := srv.etRegistry.Prune(); n > 0 {
				log.Printf("[ACP/EXEC] pruned %d expired/used ETs", n)
			}
		}
	}()

	// 8. Start server.
	log.Printf("[ACP] server listening on %s", addr)
	log.Printf("[ACP] institution pubkey: %s...", pubKeyB64[:min(16, len(pubKeyB64))])
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("[ACP] server error: %v", err)
	}
}

// ─── ACP-API-1.0 §4: Agent Registry Handlers ─────────────────────────────────

// handleAgentRegister registers a new agent with full metadata.
// POST /acp/v1/agents
// Capability required: acp:cap:agent.register
//
// Body: {agent_id, public_key (base64url), institution_id, autonomy_level,
//        authority_domain, metadata{}, sig}
// Response 201: data.{agent_id, status, registered_at}
func (s *server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID         string            `json:"agent_id"`
		PublicKey       string            `json:"public_key"` // base64url
		InstitutionID   string            `json:"institution_id"`
		AutonomyLevel   int               `json:"autonomy_level"`
		AuthorityDomain string            `json:"authority_domain"`
		Metadata        map[string]string `json:"metadata"`
		Sig             string            `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}

	// Validate required fields.
	if req.AgentID == "" || req.PublicKey == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "agent_id and public_key are required")
		return
	}
	if req.AutonomyLevel < 0 || req.AutonomyLevel > 4 {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrAGENT002, fmt.Sprintf("autonomy_level %d out of range [0,4]", req.AutonomyLevel))
		return
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "public_key must be base64url-encoded")
		return
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrAGENT001, fmt.Sprintf("public_key must be %d bytes", ed25519.PublicKeySize))
		return
	}

	now := time.Now().Unix()
	rec := registry.AgentRecord{
		AgentID:         req.AgentID,
		PublicKey:       ed25519.PublicKey(pubKeyBytes),
		PublicKeyB64:    req.PublicKey,
		InstitutionID:   req.InstitutionID,
		AutonomyLevel:   req.AutonomyLevel,
		AuthorityDomain: req.AuthorityDomain,
		Status:          registry.StatusActive,
		Metadata:        req.Metadata,
		RegisteredAt:    now,
		LastActiveAt:    now,
	}

	if err := s.registry.RegisterFull(rec); err != nil {
		if errors.Is(err, registry.ErrAgentAlreadyRegistered) {
			acpapi.WriteError(w, r, http.StatusConflict, acpapi.ErrAGENT004, fmt.Sprintf("agent %q already registered", req.AgentID))
			return
		}
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
		return
	}

	log.Printf("[ACP/AGENTS] registered agent %s (autonomy=%d domain=%s)", req.AgentID, req.AutonomyLevel, req.AuthorityDomain)
	acpapi.WriteSuccess(w, r, http.StatusCreated, map[string]interface{}{
		"agent_id":      req.AgentID,
		"status":        string(registry.StatusActive),
		"registered_at": now,
	}, s.institutionPrivKey)
}

// handleAgentGet returns the current state of an agent.
// GET /acp/v1/agents/{agent_id}
// Capability required: acp:cap:agent.read
//
// Response 200: data.{agent_id, status, autonomy_level, authority_domain,
//                     registered_at, last_active_at, trust_score}
func (s *server) handleAgentGet(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	rec, err := s.registry.GetRecord(agentID)
	if err != nil {
		if errors.Is(err, registry.ErrAgentNotFound) {
			acpapi.WriteError(w, r, http.StatusNotFound, acpapi.ErrAGENT005, fmt.Sprintf("agent %q not found", agentID))
			return
		}
		acpapi.WriteError(w, r, http.StatusServiceUnavailable, acpapi.ErrSYS001, "registry unavailable")
		return
	}

	// ACP-REP-1.1 integration: include trust score (MAY be null in v1.0).
	var trustScore interface{} = nil
	if repRec, err := s.repEngine.GetRecord(agentID); err == nil && repRec.Score != nil {
		trustScore = *repRec.Score
	}

	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"agent_id":         rec.AgentID,
		"status":           string(rec.Status),
		"autonomy_level":   rec.AutonomyLevel,
		"authority_domain": rec.AuthorityDomain,
		"institution_id":   rec.InstitutionID,
		"registered_at":    rec.RegisteredAt,
		"last_active_at":   rec.LastActiveAt,
		"trust_score":      trustScore,
	}, s.institutionPrivKey)
}

// handleAgentState transitions an agent to a new status.
// POST /acp/v1/agents/{agent_id}/state
// Capability required: acp:cap:agent.modify / agent.suspend / agent.revoke
//
// Body: {state, reason, authorized_by}
// Response 200: data.{agent_id, state}
func (s *server) handleAgentState(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	var req struct {
		State        string `json:"state"`
		Reason       string `json:"reason"`
		AuthorizedBy string `json:"authorized_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}

	newStatus := registry.AgentStatus(req.State)
	switch newStatus {
	case registry.StatusActive, registry.StatusRestricted,
		registry.StatusSuspended, registry.StatusRevoked:
		// valid
	default:
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSTATE001,
			fmt.Sprintf("invalid state %q; valid: active, restricted, suspended, revoked", req.State))
		return
	}

	if err := s.registry.UpdateStatus(agentID, newStatus); err != nil {
		if errors.Is(err, registry.ErrAgentNotFound) {
			acpapi.WriteError(w, r, http.StatusNotFound, acpapi.ErrAGENT005, fmt.Sprintf("agent %q not found", agentID))
			return
		}
		if errors.Is(err, registry.ErrAgentRevoked) {
			acpapi.WriteError(w, r, http.StatusConflict, acpapi.ErrSTATE002, "agent is revoked — irreversible state")
			return
		}
		if errors.Is(err, registry.ErrInvalidTransition) {
			acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSTATE001, err.Error())
			return
		}
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
		return
	}

	log.Printf("[ACP/AGENTS] state change %s → %s (by %s: %s)", agentID, newStatus, req.AuthorizedBy, req.Reason)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"agent_id": agentID,
		"state":    string(newStatus),
	}, s.institutionPrivKey)
}

// ─── ACP-API-1.0 §5: Authorization Handler ───────────────────────────────────

// handleAuthorize evaluates an authorization request (ACP-API-1.0 §5).
// POST /acp/v1/authorize
//
// Body: {request_id, agent_id, capability, resource, action_parameters, context, sig}
// Response 200: {decision: APPROVED|DENIED|ESCALATED, risk_score, ...}
//
// Processing order per §5:
//  1. Validate request JSON
//  2. Check agent status
//  3. autonomy_level == 0 → DENIED (AUTH-008)
//  4. Run ACP-RISK-1.0
//  5. Apply thresholds by autonomy_level → decision
//  6. Return decision
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID        string                 `json:"request_id"`
		AgentID          string                 `json:"agent_id"`
		Capability       string                 `json:"capability"`
		Resource         string                 `json:"resource"`
		ActionParameters map[string]interface{} `json:"action_parameters"`
		Context          map[string]interface{} `json:"context"`
		Sig              string                 `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}
	if req.AgentID == "" || req.Capability == "" || req.Resource == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "agent_id, capability, and resource are required")
		return
	}

	// Step 2: Check agent status.
	rec, err := s.registry.GetRecord(req.AgentID)
	if err != nil {
		// Agent may be registered via legacy path — treat as active with level 2.
		rec = registry.AgentRecord{AgentID: req.AgentID, AutonomyLevel: 2, Status: registry.StatusActive}
	}
	if rec.Status == registry.StatusSuspended || rec.Status == registry.StatusRevoked {
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
			"decision":    "DENIED",
			"risk_score":  100,
			"reason_code": acpapi.ErrAUTH005,
			"message":     fmt.Sprintf("agent %s is %s", req.AgentID, rec.Status),
		}, s.institutionPrivKey)
		return
	}

	// Step 3: autonomy_level == 0 → DENIED (AUTH-008).
	if rec.AutonomyLevel == 0 {
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
			"decision":    "DENIED",
			"risk_score":  100,
			"reason_code": acpapi.ErrAUTH008,
			"message":     "agent has no execution autonomy (level 0)",
		}, s.institutionPrivKey)
		return
	}

	// Step 4: ACP-RISK-1.0 assessment.
	riskReq := risk.Request{
		AgentID:    req.AgentID,
		Capability: req.Capability,
		Resource:   req.Resource,
	}
	// Extract amount from action_parameters if present.
	if amt, ok := req.ActionParameters["amount"]; ok {
		if amtFloat, ok := toFloat64(amt); ok {
			riskReq.Amount = &amtFloat
		}
	}
	assessment := risk.Assess(riskReq)

	// Step 5: Apply thresholds by autonomy_level.
	//   Level 1: approve < 25, escalate 25–89, deny ≥ 90
	//   Level 2: approve < 60, escalate 60–89, deny ≥ 90
	//   Level 3+: approve < 90, deny ≥ 90
	decision := decisionByLevel(rec.AutonomyLevel, assessment.Score)

	// Update reputation + last active.
	s.registry.TouchLastActive(req.AgentID)

	switch decision {
	case "APPROVED":
		// ACP-EXEC-1.0 §7: Issue Execution Token from APPROVED authorization.
		etReq := execution.IssueRequest{
			AgentID:          req.AgentID,
			AuthorizationID:  req.RequestID,
			Capability:       req.Capability,
			Resource:         req.Resource,
			ActionParameters: req.ActionParameters,
		}
		et, etErr := execution.Issue(etReq, s.institutionPrivKey)
		var etData interface{}
		if etErr == nil {
			if regErr := s.etRegistry.Register(et); regErr == nil {
				etData = et
				log.Printf("[ACP/EXEC] issued ET %s for agent=%s cap=%s", et.ETID, req.AgentID, req.Capability)
			} else {
				log.Printf("[ACP/EXEC] register ET failed: %v", regErr)
			}
		} else {
			log.Printf("[ACP/EXEC] issue ET failed: %v", etErr)
		}
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
			"decision":        "APPROVED",
			"risk_score":      assessment.Score,
			"risk_level":      assessment.Level.String(),
			"execution_token": etData,
		}, s.institutionPrivKey)

	case "DENIED":
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
			"decision":      "DENIED",
			"risk_score":    assessment.Score,
			"risk_level":    assessment.Level.String(),
			"reason_code":   "RISK-005",
			"retry_allowed": false,
		}, s.institutionPrivKey)

	case "ESCALATED":
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
			"decision":      "ESCALATED",
			"risk_score":    assessment.Score,
			"risk_level":    assessment.Level.String(),
			"escalation_id": acpapi.GetRequestID(r), // reuse request ID as escalation ID
			"escalated_to":  "review_queue",
			"expires_at":    time.Now().Add(1 * time.Hour).Unix(),
		}, s.institutionPrivKey)
	}

	log.Printf("[ACP/AUTH] %s agent=%s cap=%s score=%d decision=%s",
		req.RequestID, req.AgentID, req.Capability, assessment.Score, decision)
}

// handleEscalationResolve resolves an escalated authorization.
// POST /acp/v1/authorize/escalations/{escalation_id}/resolve
// Capability required: acp:cap:agent.modify with autonomy_level ≥ 3.
//
// Body: {resolution: "APPROVED"|"DENIED", resolved_by, sig}
func (s *server) handleEscalationResolve(w http.ResponseWriter, r *http.Request) {
	escalationID := r.PathValue("escalation_id")

	var req struct {
		Resolution string `json:"resolution"`
		ResolvedBy string `json:"resolved_by"`
		Sig        string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}

	if req.Resolution != "APPROVED" && req.Resolution != "DENIED" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004,
			"resolution must be APPROVED or DENIED")
		return
	}

	log.Printf("[ACP/AUTH] escalation %s resolved as %s by %s", escalationID, req.Resolution, req.ResolvedBy)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"escalation_id": escalationID,
		"resolution":    req.Resolution,
		"resolved_by":   req.ResolvedBy,
		"resolved_at":   time.Now().Unix(),
	}, s.institutionPrivKey)
}

// ─── ACP-API-1.0 §6: Token Issuance (stub) ───────────────────────────────────

// handleTokensIssue is a stub for CT issuance (ACP-API-1.0 §6).
// POST /acp/v1/tokens
// Capability required: acp:cap:agent.delegate
//
// Full implementation deferred — will be completed alongside ACP-EXEC-1.0.
func (s *server) handleTokensIssue(w http.ResponseWriter, r *http.Request) {
	acpapi.WriteError(w, r, http.StatusNotImplemented, "CT-STUB",
		"token issuance not yet implemented — coming in ACP-EXEC-1.0")
}

// ─── ACP-API-1.0 §7: Audit Stubs (ACP-LEDGER-1.0 will replace) ──────────────

// handleAuditQuery is a stub for audit ledger query (ACP-API-1.0 §7).
// POST /acp/v1/audit/query
func (s *server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	acpapi.WriteError(w, r, http.StatusNotImplemented, "LEDGER-STUB",
		"audit ledger not yet implemented — coming in ACP-LEDGER-1.0")
}

// handleAuditVerify is a stub for event integrity verification (ACP-API-1.0 §7).
// GET /acp/v1/audit/verify/{event_id}
func (s *server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	acpapi.WriteError(w, r, http.StatusNotImplemented, "LEDGER-STUB",
		"audit verification not yet implemented — coming in ACP-LEDGER-1.0")
}

// ─── ACP-EXEC-1.0 §9: Execution Token Handlers ───────────────────────────────

// handleExecTokenConsume reports ET consumption by a target system (ACP-EXEC-1.0 §9).
// POST /acp/v1/exec-tokens/{et_id}/consume
//
// Body: {et_id, consumed_at, execution_result, sig}
// Response 200: {et_id, state, consumed_at, consumed_by, execution_result}
func (s *server) handleExecTokenConsume(w http.ResponseWriter, r *http.Request) {
	etID := r.PathValue("et_id")

	var req execution.ConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}

	// Use provided consumed_at or default to now.
	consumedAt := req.ConsumedAt
	if consumedAt == 0 {
		consumedAt = time.Now().Unix()
	}

	// Identify the consuming system via header (preferred) or "unknown".
	consumerSystem := r.Header.Get("X-ACP-Agent-ID")
	if consumerSystem == "" {
		consumerSystem = "unknown"
	}

	if err := s.etRegistry.Consume(etID, consumerSystem, consumedAt); err != nil {
		switch {
		case errors.Is(err, execution.ErrTokenNotFound):
			acpapi.WriteError(w, r, http.StatusNotFound, "EXEC-008", "execution token not found")
		case errors.Is(err, execution.ErrTokenAlreadyConsumed):
			acpapi.WriteError(w, r, http.StatusConflict, "EXEC-004", "token already consumed")
		case errors.Is(err, execution.ErrTokenExpired):
			acpapi.WriteError(w, r, http.StatusGone, "EXEC-003", "token expired")
		default:
			acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, err.Error())
		}
		return
	}

	log.Printf("[ACP/EXEC] consumed ET %s by %s (result: %s)", etID, consumerSystem, req.ExecutionResult)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"et_id":            etID,
		"state":            string(execution.StateUsed),
		"consumed_at":      consumedAt,
		"consumed_by":      consumerSystem,
		"execution_result": req.ExecutionResult,
	}, s.institutionPrivKey)
}

// handleExecTokenStatus returns the current state of an Execution Token (ACP-EXEC-1.0 §9).
// GET /acp/v1/exec-tokens/{et_id}/status
//
// Response 200: {et_id, authorization_id, agent_id, capability, resource,
//               issued_at, expires_at, state[, consumed_at, consumed_by_system]}
func (s *server) handleExecTokenStatus(w http.ResponseWriter, r *http.Request) {
	etID := r.PathValue("et_id")

	entry, err := s.etRegistry.Get(etID)
	if err != nil {
		if errors.Is(err, execution.ErrTokenNotFound) {
			acpapi.WriteError(w, r, http.StatusNotFound, "EXEC-008", "execution token not found")
			return
		}
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, err.Error())
		return
	}

	data := map[string]interface{}{
		"et_id":            entry.ETID,
		"authorization_id": entry.AuthorizationID,
		"agent_id":         entry.AgentID,
		"capability":       entry.Capability,
		"resource":         entry.Resource,
		"issued_at":        entry.IssuedAt,
		"expires_at":       entry.ExpiresAt,
		"state":            string(entry.State),
	}
	if entry.ConsumedAt != nil {
		data["consumed_at"] = *entry.ConsumedAt
	}
	if entry.ConsumedBySystem != nil {
		data["consumed_by_system"] = *entry.ConsumedBySystem
	}

	acpapi.WriteSuccess(w, r, http.StatusOK, data, s.institutionPrivKey)
}

// ─── ACP-API-1.0 §9: Health ───────────────────────────────────────────────────

// handleHealth returns server health in ACP-API-1.0 §9 format.
// GET /acp/v1/health — no authentication required.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Determine overall status: operational unless a component is degraded.
	status := "operational"

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"acp_version": "1.0",
		"status":      status,
		"timestamp":   time.Now().Unix(),
		"components": map[string]string{
			"policy_engine":  "operational",
			"audit_ledger":   "not_implemented",
			"agent_registry": "operational",
			"rev_endpoint":   "operational",
			"rep_engine":     "operational",
		},
		// Internal counters (informational).
		"_counters": map[string]interface{}{
			"agents":     s.registry.Size(),
			"challenges": s.challenges.Size(),
			"nonces":     s.nonceStore.Size(),
			"revoked":    s.revStore.Size(),
		},
	})
}

// ─── ACP-HP-1.0 + ACP-CT-1.0: Handshake & Verify ────────────────────────────

// handleChallenge issues a one-time challenge nonce.
// GET /acp/v1/handshake/challenge  (also: GET /acp/v1/challenge for legacy)
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		acpapi.WriteError(w, r, http.StatusMethodNotAllowed, acpapi.ErrSYS004, "method not allowed")
		return
	}
	challenge, err := s.challenges.GenerateChallenge()
	if err != nil {
		log.Printf("[ACP] challenge generation failed: %v", err)
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS002, "challenge generation failed")
		return
	}
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]string{
		"challenge": challenge,
	}, s.institutionPrivKey)
}

// handleVerify verifies a Capability Token + Proof-of-Possession.
// POST /acp/v1/verify
//
// Required headers:
//   Authorization:    Bearer <token_json>
//   X-ACP-Agent-ID:   <agentID>
//   X-ACP-Challenge:  <challenge>
//   X-ACP-Signature:  <pop_signature>
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		acpapi.WriteError(w, r, http.StatusMethodNotAllowed, acpapi.ErrSYS004, "method not allowed")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		acpapi.WriteError(w, r, http.StatusUnauthorized, acpapi.ErrAUTH001, "missing or invalid Authorization header")
		return
	}
	tokenJSON := strings.TrimPrefix(authHeader, "Bearer ")
	agentID   := r.Header.Get("X-ACP-Agent-ID")
	challenge := r.Header.Get("X-ACP-Challenge")
	popSig    := r.Header.Get("X-ACP-Signature")

	if agentID == "" || challenge == "" || popSig == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrHP004, "missing ACP headers (X-ACP-Agent-ID, X-ACP-Challenge, X-ACP-Signature)")
		return
	}

	agentPubKey, err := s.registry.GetPublicKey(agentID)
	if err != nil {
		acpapi.WriteError(w, r, http.StatusUnauthorized, acpapi.ErrAGENT005, fmt.Sprintf("agent not registered: %v", err))
		return
	}

	if err := handshake.VerifyProofOfPossession(r, s.challenges, agentPubKey); err != nil {
		acpapi.WriteError(w, r, http.StatusUnauthorized, acpapi.ErrHP009, fmt.Sprintf("PoP verification failed: %v", err))
		return
	}

	token, err := tokens.ParseAndVerify([]byte(tokenJSON), s.institutionPubKey, tokens.VerificationRequest{
		RevocationChecker: s.revChecker,
		NonceStore:        s.nonceStore,
	})
	if err != nil {
		s.emitRepEvent(agentID, repEventFromTokenError(err))
		code := acpapi.ErrAUTH001
		if strings.Contains(err.Error(), "CT-010") || strings.Contains(err.Error(), "revoked") {
			code = acpapi.ErrAUTH006
		}
		acpapi.WriteError(w, r, http.StatusForbidden, code, err.Error())
		return
	}

	if token.Subject != agentID {
		acpapi.WriteError(w, r, http.StatusForbidden, acpapi.ErrHP010,
			fmt.Sprintf("token subject %q does not match agent %q", token.Subject, agentID))
		return
	}

	s.emitRepEvent(agentID, reputation.EvtVerifyOK)
	s.registry.TouchLastActive(agentID)

	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"agent_id":     agentID,
		"capabilities": token.Cap,
		"resource":     token.Resource,
		"expires":      token.Expiration,
	}, s.institutionPrivKey)
}

// ─── ACP-REV-1.0 Handlers ─────────────────────────────────────────────────────

// handleRevCheck queries revocation status for a token.
// GET /acp/v1/rev/check?token_id=<nonce>
func (s *server) handleRevCheck(w http.ResponseWriter, r *http.Request) {
	tokenID := r.URL.Query().Get("token_id")
	if tokenID == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "missing token_id query parameter")
		return
	}

	revoked, _, err := s.revStore.IsRevoked(tokenID)
	if err != nil {
		log.Printf("[ACP/REV] store error checking %s: %v", tokenID, err)
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, "internal store error")
		return
	}

	status := "active"
	if revoked {
		status = "revoked"
	}
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"token_id":   tokenID,
		"status":     status,
		"checked_at": time.Now().Unix(),
	}, s.institutionPrivKey)
}

// handleRevRevoke emits a revocation for a token.
// POST /acp/v1/rev/revoke
// Body: {token_id, reason_code, revoked_by}
func (s *server) handleRevRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TokenID    string `json:"token_id"`
		ReasonCode string `json:"reason_code"`
		RevokedBy  string `json:"revoked_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}
	if req.TokenID == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "token_id is required")
		return
	}
	if req.RevokedBy == "" {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "revoked_by is required")
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
			acpapi.WriteError(w, r, http.StatusConflict, "REV-E001", "token already revoked")
			return
		}
		if errors.Is(err, revocation.ErrInvalidReason) {
			acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
			return
		}
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
		return
	}

	log.Printf("[ACP/REV] revoked token %s by %s (reason: %s)", req.TokenID, req.RevokedBy, req.ReasonCode)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"token_id":   req.TokenID,
		"revoked_at": now,
	}, s.institutionPrivKey)
}

// ─── ACP-REP-1.1 Handlers ─────────────────────────────────────────────────────

// handleRepGet returns the current reputation record for an agent.
// GET /acp/v1/rep/{agent_id}
func (s *server) handleRepGet(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")
	record, err := s.repEngine.GetRecord(agentID)
	if err != nil {
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, "internal store error")
		return
	}
	acpapi.WriteSuccess(w, r, http.StatusOK, record, s.institutionPrivKey)
}

// handleRepEvents returns paginated reputation events for an agent.
// GET /acp/v1/rep/{agent_id}/events?limit=20&offset=0
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
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, "internal store error")
		return
	}
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}, s.institutionPrivKey)
}

// handleRepState manually sets the administrative state of an agent.
// POST /acp/v1/rep/{agent_id}/state
// Body: {state, reason, authorized_by}
func (s *server) handleRepState(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("agent_id")

	var req struct {
		State        string `json:"state"`
		Reason       string `json:"reason"`
		AuthorizedBy string `json:"authorized_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "malformed JSON body")
		return
	}

	targetState := reputation.AgentState(req.State)
	switch targetState {
	case reputation.StateActive, reputation.StateProbation,
		reputation.StateSuspended, reputation.StateBanned:
		// valid
	default:
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004,
			fmt.Sprintf("invalid state %q; valid: ACTIVE, PROBATION, SUSPENDED, BANNED", req.State))
		return
	}

	if err := s.repEngine.SetState(agentID, targetState, req.Reason, req.AuthorizedBy); err != nil {
		if errors.Is(err, reputation.ErrAgentBanned) {
			acpapi.WriteError(w, r, http.StatusConflict, acpapi.ErrSTATE002, "agent is BANNED — terminal state")
			return
		}
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
		return
	}

	log.Printf("[ACP/REP] state change for %s → %s (by %s: %s)", agentID, targetState, req.AuthorizedBy, req.Reason)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"agent_id": agentID,
		"state":    string(targetState),
	}, s.institutionPrivKey)
}

// ─── Legacy Register (backward compat for SDKs) ───────────────────────────────

// handleRegisterLegacy is the pre-ACP-API-1.0 agent registration endpoint.
// POST /acp/v1/register
// Body: {"agent_id": "...", "public_key_hex": "..."}
//
// Deprecated: use POST /acp/v1/agents instead.
func (s *server) handleRegisterLegacy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID      string `json:"agent_id"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "invalid JSON body")
		return
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKeyHex)
	if err != nil {
		pubKeyBytes, err = hexDecode(req.PublicKeyHex)
		if err != nil {
			acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "public_key_hex must be base64url or hex-encoded")
			return
		}
	}

	if err := s.registry.Register(req.AgentID, ed25519.PublicKey(pubKeyBytes)); err != nil {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, err.Error())
		return
	}

	log.Printf("[ACP] registered agent %s (legacy path)", req.AgentID)
	acpapi.WriteSuccess(w, r, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"agent_id": req.AgentID,
	}, s.institutionPrivKey)
}

// ─── Reputation helpers ────────────────────────────────────────────────────────

func (s *server) emitRepEvent(agentID, eventType string) {
	if err := s.repEngine.RecordEvent(agentID, eventType); err != nil {
		log.Printf("[ACP/REP] failed to record %s for agent %s: %v", eventType, agentID, err)
	}
}

func repEventFromTokenError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "CT-010") || strings.Contains(msg, "revoked") {
		return reputation.EvtRevInvalid
	}
	if strings.Contains(msg, "CT-002") || strings.Contains(msg, "signature") {
		return reputation.EvtSigInvalid
	}
	return reputation.EvtTokenMalformed
}

// ─── Authorization helpers ────────────────────────────────────────────────────

// decisionByLevel maps autonomy_level + risk score to an authorization decision.
//
//	Level 1: approve < 25, escalate [25,90), deny ≥ 90
//	Level 2: approve < 60, escalate [60,90), deny ≥ 90
//	Level 3+: approve < 90, deny ≥ 90
func decisionByLevel(level, score int) string {
	const thresholdDeny = 90
	switch {
	case score >= thresholdDeny:
		return "DENIED"
	case level >= 3:
		return "APPROVED"
	case level == 2 && score < 60:
		return "APPROVED"
	case level == 1 && score < 25:
		return "APPROVED"
	default:
		return "ESCALATED"
	}
}

// toFloat64 converts an interface{} to float64 (for JSON numbers).
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// ─── Low-level helpers ────────────────────────────────────────────────────────

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err1 := hexNibble(s[i])
		lo, err2 := hexNibble(s[i+1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid hex at position %d", i)
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex char %c", c)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
