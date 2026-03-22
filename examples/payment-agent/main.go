// payment-agent: ACP RISK-2.0 killer demo.
//
// Scenario: a financial agent (PayAgent-001) attempts payments.
// ACP evaluates each request using the RISK-2.0 formula, logs every decision
// to an immutable in-memory ledger, and auto-triggers cooldown after 3 DENIED
// in 10 minutes.
//
// This demo makes the ACP value proposition concrete in 30 seconds:
//
//	"An agent tries to pay. ACP decides. The log is immutable."
//
// Endpoints:
//
//	POST /admission            — evaluate an admission request
//	GET  /audit/agent/{id}     — agent decision timeline
//	GET  /ledger               — full immutable audit log
//	GET  /health               — server status
//
// Run:
//
//	go run . [-port 8080]
//
// Then try the quick scenario in README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// ── Policy (ACP-RISK-2.0 §Appendix A defaults) ───────────────────────────────

var defaultPolicy = risk.PolicyConfig{
	AutonomyLevel:            2,
	ApprovedMax:              39,
	EscalatedMax:             69,
	AnomalyRule1ThresholdN:   10,
	AnomalyRule2ThresholdX:   3,
	AnomalyRule3ThresholdY:   3,
	CooldownTriggerDenials:   3,
	CooldownPeriodSeconds:    300,
	PolicyHash:               "sha256:payment-agent-demo-policy-v1",
}

// ── Admission request / response ─────────────────────────────────────────────

// AdmissionRequest mirrors POST /admission body (ACP-API-1.0 §5 / RISK-2.0 §4).
type AdmissionRequest struct {
	AgentID       string         `json:"agent_id"`
	Capability    string         `json:"capability"`
	Resource      string         `json:"resource"`
	ResourceClass string         `json:"resource_class"`
	Context       risk.Context   `json:"context"`
	History       risk.History   `json:"history"`
	Anomaly       risk.AnomalyIn `json:"anomaly"`
}

// AdmissionResponse is the structured decision returned by POST /admission.
type AdmissionResponse struct {
	AgentID      string         `json:"agent_id"`
	Capability   string         `json:"capability"`
	Resource     string         `json:"resource"`
	RiskScore    int            `json:"risk_score"`
	Decision     string         `json:"decision"`
	DeniedReason string         `json:"denied_reason,omitempty"`
	Factors      risk.Factors   `json:"factors"`
	AnomalyDetail risk.AnomalyDetail `json:"anomaly_detail"`
	PolicyHash   string         `json:"policy_hash"`
	EventID      int            `json:"event_id"`
	Timestamp    int64          `json:"timestamp"`
}

// ── Immutable ledger (in-memory append-only) ─────────────────────────────────

// LedgerEntry records a single decision event — append-only, never modified.
type LedgerEntry struct {
	Seq          int                `json:"seq"`
	EventID      int                `json:"event_id"`
	AgentID      string             `json:"agent_id"`
	Capability   string             `json:"capability"`
	Resource     string             `json:"resource"`
	RiskScore    int                `json:"risk_score"`
	Decision     string             `json:"decision"`
	DeniedReason string             `json:"denied_reason,omitempty"`
	Factors      risk.Factors       `json:"factors"`
	AnomalyDetail risk.AnomalyDetail `json:"anomaly_detail"`
	PolicyHash   string             `json:"policy_hash"`
	Timestamp    int64              `json:"timestamp"`
}

// ── Server state ─────────────────────────────────────────────────────────────

type Server struct {
	mu      sync.Mutex
	querier *risk.InMemoryQuerier
	ledger  []LedgerEntry
	nextSeq int
}

func NewServer() *Server {
	return &Server{
		querier: risk.NewInMemoryQuerier(),
		nextSeq: 1,
	}
}

// appendLedger records a decision to the immutable log and updates the querier
// with the outcome so subsequent requests see the updated F_anom inputs.
func (s *Server) appendLedger(result *risk.EvalResult, req AdmissionRequest, now time.Time) LedgerEntry {
	entry := LedgerEntry{
		Seq:           s.nextSeq,
		EventID:       s.nextSeq,
		AgentID:       req.AgentID,
		Capability:    req.Capability,
		Resource:      req.Resource,
		RiskScore:     result.RSFinal,
		Decision:      string(result.Decision),
		DeniedReason:  result.DeniedReason,
		Factors:       result.Factors,
		AnomalyDetail: result.AnomalyDetail,
		PolicyHash:    result.PolicyHash,
		Timestamp:     now.Unix(),
	}
	s.ledger = append(s.ledger, entry)
	s.nextSeq++

	// Feed outcome back into the querier so F_anom rules see real history.
	s.querier.AddRequest(req.AgentID, now)
	if result.Decision == risk.DENIED {
		s.querier.AddDenial(req.AgentID, now)
	}
	patKey := risk.PatternKey(req.AgentID, req.Capability, req.Resource)
	s.querier.AddPattern(patKey, now)

	// Trigger cooldown if threshold reached (per ACP-RISK-2.0 §3.5).
	entered, _ := risk.ShouldEnterCooldown(req.AgentID, defaultPolicy, s.querier, now)
	if entered {
		until := now.Add(time.Duration(defaultPolicy.CooldownPeriodSeconds) * time.Second)
		s.querier.SetCooldown(req.AgentID, until)
		log.Printf("[COOLDOWN] agent=%s blocked until %s", req.AgentID, until.Format(time.RFC3339))
	}

	return entry
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// POST /admission — evaluate an admission request using ACP-RISK-2.0.
func (s *Server) handleAdmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AdmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
		return
	}

	// Apply defaults for optional fields.
	if req.AgentID == "" {
		req.AgentID = "acp:agent:org.example:PayAgent-001"
	}
	if req.Capability == "" {
		req.Capability = "acp:cap:financial.payment"
	}
	if req.Resource == "" {
		req.Resource = "org.example/accounts/ACC-001"
	}
	if req.ResourceClass == "" {
		req.ResourceClass = "restricted"
	}

	evalReq := risk.EvalRequest{
		AgentID:       req.AgentID,
		Capability:    req.Capability,
		Resource:      req.Resource,
		ResourceClass: risk.ResourceClass(req.ResourceClass),
		Context:       req.Context,
		History:       req.History,
		Anomaly:       req.Anomaly,
		Policy:        defaultPolicy,
		Now:           time.Now(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := risk.Evaluate(evalReq, s.querier)
	if err != nil {
		http.Error(w, fmt.Sprintf("evaluation error: %v", err), http.StatusInternalServerError)
		return
	}

	entry := s.appendLedger(result, req, evalReq.Now)

	resp := AdmissionResponse{
		AgentID:       req.AgentID,
		Capability:    req.Capability,
		Resource:      req.Resource,
		RiskScore:     result.RSFinal,
		Decision:      string(result.Decision),
		DeniedReason:  result.DeniedReason,
		Factors:       result.Factors,
		AnomalyDetail: result.AnomalyDetail,
		PolicyHash:    result.PolicyHash,
		EventID:       entry.EventID,
		Timestamp:     entry.Timestamp,
	}

	log.Printf("[DECISION] agent=%s cap=%s rs=%d decision=%s",
		req.AgentID, req.Capability, result.RSFinal, result.Decision)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// GET /audit/agent/{id} — agent decision timeline (ACP-API-1.0 endpoint 18).
func (s *Server) handleAgentAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract agent_id from path: /audit/agent/{id}
	agentID := strings.TrimPrefix(r.URL.Path, "/audit/agent/")
	if agentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect events for this agent.
	var events []LedgerEntry
	var denials, escalations int
	for _, e := range s.ledger {
		if e.AgentID == agentID {
			events = append(events, e)
			if e.Decision == "DENIED" {
				denials++
			} else if e.Decision == "ESCALATED" {
				escalations++
			}
		}
	}

	// Cooldown state.
	cooldownActive := s.querier.CooldownActive(agentID, time.Now())
	cooldownUntil := s.querier.CooldownUntil(agentID)

	type cooldownInfo struct {
		Active      bool   `json:"active"`
		Until       *int64 `json:"until"`
		TriggeredBy string `json:"triggered_by,omitempty"`
	}
	cd := cooldownInfo{Active: cooldownActive}
	if cooldownActive && !cooldownUntil.IsZero() {
		u := cooldownUntil.Unix()
		cd.Until = &u
		cd.TriggeredBy = "3_DENIED_in_10min"
	}

	type auditResponse struct {
		AgentID    string `json:"agent_id"`
		Window     string `json:"window"`
		Cooldown   cooldownInfo `json:"cooldown"`
		AnomalySummary struct {
			RequestCount   int `json:"request_count"`
			DenialCount    int `json:"denial_count"`
			EscalationCount int `json:"escalation_count"`
		} `json:"anomaly_summary"`
		Events     []LedgerEntry `json:"events"`
		TotalCount int           `json:"total_count"`
	}

	resp := auditResponse{
		AgentID:    agentID,
		Window:     "all",
		Cooldown:   cd,
		Events:     events,
		TotalCount: len(events),
	}
	resp.AnomalySummary.RequestCount = len(events)
	resp.AnomalySummary.DenialCount = denials
	resp.AnomalySummary.EscalationCount = escalations

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /ledger — full immutable audit log.
func (s *Server) handleLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	type ledgerResponse struct {
		TotalEvents int           `json:"total_events"`
		AppendOnly  bool          `json:"append_only"`
		Note        string        `json:"note"`
		Events      []LedgerEntry `json:"events"`
	}

	resp := ledgerResponse{
		TotalEvents: len(s.ledger),
		AppendOnly:  true,
		Note:        "ACP-LEDGER-1.3: events are immutable once written. Each decision is permanently recorded.",
		Events:      s.ledger,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /health — server status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	events := len(s.ledger)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "operational",
		"acp_version":   "1.16",
		"spec":          "ACP-RISK-2.0",
		"ledger_events": events,
		"policy_hash":   defaultPolicy.PolicyHash,
		"timestamp":     time.Now().Unix(),
	})
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	port := flag.Int("port", 8080, "HTTP port")
	flag.Parse()

	srv := NewServer()
	mux := http.NewServeMux()

	mux.HandleFunc("/admission", srv.handleAdmission)
	mux.HandleFunc("/audit/agent/", srv.handleAgentAudit)
	mux.HandleFunc("/ledger", srv.handleLedger)
	mux.HandleFunc("/health", srv.handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("ACP payment-agent demo listening on %s", addr)
	log.Printf("Policy: autonomy=L%d approved≤%d escalated≤%d denied>%d",
		defaultPolicy.AutonomyLevel,
		defaultPolicy.ApprovedMax,
		defaultPolicy.EscalatedMax,
		defaultPolicy.EscalatedMax)
	log.Printf("Cooldown: %d DENIED in 10min → block %ds",
		defaultPolicy.CooldownTriggerDenials,
		defaultPolicy.CooldownPeriodSeconds)
	log.Printf("Try: curl -s -X POST http://localhost%s/admission -H 'Content-Type: application/json' -d '{}'", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
